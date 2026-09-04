// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#ifdef ESP_PLATFORM

#include "wg_lwip.h"

#include <stdlib.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"        /* esp_netif_get_netif_impl */
#include "lwip/esp_netif_net_stack.h"   /* struct esp_netif_netstack_config */
#include "lwip/def.h"     /* lwip_htonl */
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"

#include "wg_netif.h"

static const char *TAG = "wg_lwip";

/* Custom esp_netif driver that bridges plaintext IP between lwIP and
 * the WG protocol engine in wg_netif. */
typedef struct {
    esp_netif_driver_base_t base;
} wg_driver_t;

static esp_netif_t *s_netif;
static wg_driver_t *s_driver;
static struct netif *s_lwn;   /* underlying lwIP netif (cached for tcpip_input bypass) */

/* lwIP → WG: called by lwIP when it has an IP packet to send out the
 * tunnel netif. We pass the buffer to wg_netif which encrypts and
 * sends via the underlying UDP socket. (Unused after we override
 * lwn->linkoutput; kept for esp_netif's driver_ifconfig contract.) */
static esp_err_t wg_transmit(void *h, void *buffer, size_t len)
{
    (void)h;
    return wg_netif_send_plaintext((const uint8_t *)buffer, len);
}

/* Direct lwIP linkoutput: bypasses PPP framing on egress. lwIP's
 * `netif->output` chain for a PPP-flagged netif wraps each IP packet
 * in HDLC/PPP encapsulation (0x7e flag, 0xff 0x03 address+control,
 * 0x00 0x21 PPP protocol = IP, payload, FCS, 0x7e). We encrypt those
 * framed bytes and send them, but the peer's WG decrypts them and
 * sees garbage instead of an IP packet — silently dropped. Mirror of
 * the ingress fix: just like `wg_rx_inject` calls `tcpip_input` to
 * skip the PPP `input_fn`, here we override `linkoutput` to ship the
 * raw IP payload straight to wg_netif. */
static err_t wg_lwip_linkoutput(struct netif *netif, struct pbuf *p)
{
    (void)netif;
    /* Single-segment pbuf is the common case for our 1280-MTU packets.
     * For the rare chained pbuf, copy into a contiguous scratch — the
     * encrypt path needs contiguous bytes anyway. */
    if (p->next == NULL) {
        esp_err_t err = wg_netif_send_plaintext((const uint8_t *)p->payload,
                                                p->len);
        return (err == ESP_OK) ? ERR_OK : ERR_IF;
    }
    uint8_t __attribute__((aligned(4))) scratch[1536];
    if (p->tot_len > sizeof(scratch)) return ERR_BUF;
    if (pbuf_copy_partial(p, scratch, p->tot_len, 0) != p->tot_len) {
        return ERR_BUF;
    }
    esp_err_t err = wg_netif_send_plaintext(scratch, p->tot_len);
    return (err == ESP_OK) ? ERR_OK : ERR_IF;
}

/* lwIP IPv4 output for our raw-IP tunnel netif. The pbuf already has
 * the IP header in place; we just hand it to linkoutput. (Default
 * PPP netif `output` would wrap it in PPP encapsulation first.) */
static err_t wg_lwip_ip4_output(struct netif *netif, struct pbuf *p,
                                const ip4_addr_t *ipaddr)
{
    (void)ipaddr;
    return wg_lwip_linkoutput(netif, p);
}

/* WG → lwIP: invoked from wg_netif's RX path after a transport
 * record has been authenticated and decrypted. Injects the plaintext
 * IP packet directly into lwIP's tcpip_input bypassing
 * esp_netif_receive — the PPP-flagged netif's `input_fn` is
 * `esp_netif_lwip_ppp_input` which calls `pppos_input_tcpip_as_ram_pbuf`,
 * a HDLC-framed-PPP-bytes parser. Feeding raw IP through that layer
 * silently drops every packet at the PPP framing stage (it sees
 * `0x45` as a corrupt non-flag byte, not the `0x7e` HDLC flag).
 * `tcpip_input` is the lwIP-native receive entry point any netif
 * driver uses to hand packets to the IP stack — we go straight
 * there with a pbuf wrapping the plaintext bytes. */
static void wg_rx_inject(const uint8_t *plaintext, size_t len, void *user)
{
    (void)user;
    if (s_lwn == NULL || len == 0) return;

    /* TSMP (IP protocol 99) is Tailscale's in-tunnel side channel. Since
     * CapVer 144 (tailscale b87203b83 / 3799eaf26, 2026-07) tailscaled
     * sends a TSMPDiscoKeyAdvertisement — a 20-byte IPv4 header with
     * proto 99 and a 33-byte payload ('a' + 32-byte disco key) — into
     * the tunnel right after EVERY WireGuard handshake and rekey, to any
     * disco-speaking peer, with no receiver-side capver gate. lwIP has
     * no handler for proto 99: ip4_input's default branch answers each
     * one with an ICMP "protocol unreachable" (ip4.c: icmp_dest_unreach
     * ICMP_DUR_PROTO) — one wasted encrypt + TX per handshake/rekey and
     * a pbuf churn on the RX task for nothing. tinylink learns peer disco
     * keys from the netmap, exactly like a pre-144 client, so the advert
     * carries nothing we need. Drop it here, before it costs a pbuf.
     * Also drop anything shorter than an IPv4 header. */
    if (len < 20 || (plaintext[0] >> 4) != 4) return;
    if (plaintext[9] == 99) return;

    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)len, PBUF_RAM);
    if (p == NULL) {
        ESP_LOGW(TAG, "pbuf_alloc(%u) failed — dropping inbound", (unsigned)len);
        return;
    }
    memcpy(p->payload, plaintext, len);

    err_t e = tcpip_input(p, s_lwn);
    if (e != ERR_OK) {
        pbuf_free(p);
        ESP_LOGW(TAG, "tcpip_input err=%d (len=%u)", (int)e, (unsigned)len);
    }
}

/* MTU pending — set in wg_lwip_attach() before esp_netif_action_start()
 * triggers netif_add() → wg_lwip_netif_init() (where it's applied to
 * the lwIP netif). Avoids passing it through the netstack init signature. */
static uint16_t s_pending_mtu;

/* Custom lwIP netif init for the WG raw-IP carrier. lwIP netif_add()
 * (lwip/.../netif.c:321-339) zeros ip_addr/netmask/gw/output/mtu/flags
 * BEFORE calling init_fn, then (line 392) re-applies ip_addr/netmask/gw
 * from the netif_add() params (which esp_netif sourced from base.ip_info)
 * BEFORE init_fn (line 396). Anything not in init_fn that we set on the
 * netif before action_start is wiped.
 *
 * Avoids the two problems caused by ESP_NETIF_NETSTACK_DEFAULT_ETH:
 *   1. ethernetif_init() sets netif->output = etharp_output and
 *      netif->linkoutput = ethernet_low_level_output. ARP is meaningless
 *      on a tunnel netif and would cause every outbound packet to wait
 *      for an ARP response that never arrives.
 *   2. ethernetif_init() raises NETIF_FLAG_ETHARP, which makes
 *      tcpip_input() route inbound pbufs through ethernet_input
 *      (lwip/api/tcpip.c:288-296). Our pbufs are raw IP without an
 *      Ethernet header, so ethernet_input parses the first 14 bytes
 *      as an Eth header, finds an EtherType derived from the IPv4
 *      version+IHL byte (0x45..) instead of 0x0800, and silently drops.
 *
 * What this init_fn does:
 *   - sets netif->name for diagnostics ("wg")
 *   - applies the MTU (zeroed by netif_add)
 *   - installs the WG-aware output and linkoutput (so ip4_output's
 *     send chain reaches wg_netif_send_plaintext, not netif_null_output)
 *   - brings the netif up at admin and link level so ip4_input_accept
 *     accepts inbound pbufs delivered via tcpip_input from wg_rx_inject
 *   - leaves NETIF_FLAG_ETHARP/ETHERNET unset so tcpip_input() dispatches
 *     inbound to ip_input rather than ethernet_input
 *   - caches the lwIP netif pointer for wg_rx_inject's tcpip_input call */
static err_t wg_lwip_netif_init(struct netif *netif)
{
    netif->name[0] = 'w';
    netif->name[1] = 'g';
    netif->mtu        = s_pending_mtu;
    netif->output     = wg_lwip_ip4_output;
    netif->linkoutput = wg_lwip_linkoutput;
    s_lwn = netif;
    /* Intentionally NOT calling netif_set_up/netif_set_link_up here.
     * netif_add() (lwip/.../netif.c:436-438) only links the netif into
     * netif_list AFTER init_fn returns, so calling netif_set_up here
     * fires ext_callbacks (LWIP_NSC_STATUS_CHANGED) on a netif that
     * isn't reachable via the global list yet — observed empirically
     * to correlate with multi-second jitter and ~23% ICMP loss.
     * Bringing the netif up is done post-action_start in wg_lwip_attach. */
    return ERR_OK;
}

/* Stub input_fn. RX never goes through esp_netif_receive — wg_rx_inject
 * calls tcpip_input(p, s_lwn) directly. But esp_netif_start_api runs
 * esp_netif_config_sanity_check (esp_netif_lwip.c:1171) which rejects
 * a NULL lwip_input_fn with ESP_ERR_INVALID_STATE, so provide a stub
 * that returns failure if anything ever does call it. */
static esp_netif_recv_ret_t wg_lwip_netif_input(void *netif, void *buffer,
                                                size_t len, void *eb)
{
    (void)netif; (void)buffer; (void)len; (void)eb;
    return ESP_NETIF_OPTIONAL_RETURN_CODE(ESP_FAIL);
}

/* Custom netstack config: minimal init_fn, stub input_fn. */
static const struct esp_netif_netstack_config s_wg_netstack_config = {
    .lwip = {
        .init_fn  = wg_lwip_netif_init,
        .input_fn = wg_lwip_netif_input,
    },
};

static esp_err_t wg_post_attach(esp_netif_t *netif, void *driver_handle)
{
    wg_driver_t *drv = (wg_driver_t *)driver_handle;
    drv->base.netif = netif;

    /* Hook our transmit so esp_netif/lwIP route packets through us. */
    esp_netif_driver_ifconfig_t ifcfg = {
        .handle                 = driver_handle,
        .transmit               = wg_transmit,
        .driver_free_rx_buffer  = NULL,
    };
    return esp_netif_set_driver_config(netif, &ifcfg);
}

esp_err_t wg_lwip_attach(uint32_t local_ip_be, uint16_t mtu)
{
    if (s_netif != NULL) return ESP_ERR_INVALID_STATE;

    /* Inherent (base) config. AUTOUP flag tells esp_netif to bring the
     * netif up automatically on action_start; we still call
     * netif_set_up/netif_set_link_up below as defense-in-depth.
     *
     * Pre-Build-C this used ESP_NETIF_FLAG_IS_PPP to sidestep the IDF
     * v5.5 panic in esp_netif_internal_dhcpc_cb. That panic was the
     * symptom of dhcp_ip_addr_store() being called on a netif with no
     * DHCP started; with the IDF whitelist+null-guard patch
     * (fix/dhcpc-cb-whitelist-and-null-guard) the panic is gated by
     * ESP_NETIF_DHCP_CLIENT, so any non-DHCP netif (including this
     * AUTOUP one) is safe. Removing IS_PPP saves the ~30 s of LCP
     * Configure-Request retries the PPP FSM does at boot trying to
     * negotiate against a non-existent serial peer, plus ~1-2 KB of
     * heap (ppp_pcb). */
    esp_netif_inherent_config_t base = {
        .flags     = (esp_netif_flags_t)(ESP_NETIF_FLAG_AUTOUP),
        .if_key    = "WG_DEF",
        .if_desc   = "wg",
        .route_prio = 5,
    };
    /* Static IP. Netmask /10 (255.192.0.0) covers the entire CGNAT
     * tailnet range 100.64.0.0/10 so lwIP routes peer traffic via this
     * netif by subnet-match — without us having to make WG the default
     * netif. Default stays on WiFi so the control plane long-poll over
     * HTTPS keeps working even before NAT traversal lands. */
    esp_netif_ip_info_t ip = {0};
    ip.ip.addr      = local_ip_be;
    ip.netmask.addr = lwip_htonl(0xFFC00000UL);  /* 255.192.0.0 = /10 */
    ip.gw.addr      = 0;
    base.ip_info    = &ip;

    /* Stack glue: custom no-op netstack defined above. Avoids
     * ETH/PPP init clobbering our output overrides and avoids
     * NETIF_FLAG_ETHARP redirecting inbound pbufs through
     * ethernet_input. */
    esp_netif_config_t cfg = {
        .base    = &base,
        .driver  = NULL,
        .stack   = &s_wg_netstack_config,
    };

    s_netif = esp_netif_new(&cfg);
    if (s_netif == NULL) {
        ESP_LOGE(TAG, "esp_netif_new failed");
        return ESP_FAIL;
    }

    s_driver = calloc(1, sizeof(*s_driver));
    if (s_driver == NULL) {
        esp_netif_destroy(s_netif);
        s_netif = NULL;
        return ESP_ERR_NO_MEM;
    }
    s_driver->base.post_attach = wg_post_attach;

    esp_err_t err = esp_netif_attach(s_netif, s_driver);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_netif_attach: %s", esp_err_to_name(err));
        free(s_driver);
        s_driver = NULL;
        esp_netif_destroy(s_netif);
        s_netif = NULL;
        return err;
    }

    /* Stash MTU for wg_lwip_netif_init() to apply. Doing the netif
     * setup inside init_fn is mandatory because lwIP netif_add()
     * (lwip/.../netif.c:321-339) zeros mtu/output/linkoutput/flags
     * BEFORE init_fn runs — anything we set on the netif outside of
     * init_fn would be wiped. ip_addr/netmask/gw are an exception:
     * netif_add() applies them from its parameters (esp_netif sources
     * them from base.ip_info above) at line 392, BEFORE init_fn,
     * so they survive without a manual netif_set_addr in init_fn. */
    s_pending_mtu = mtu;

    /* Register the RX callback on the WG protocol engine; from now on
     * decrypted plaintext IP is injected into this netif. */
    wg_netif_set_rx_callback(wg_rx_inject, s_netif);

    /* Bring the netif up so lwIP starts routing the tunnel CIDR
     * through it. We deliberately do NOT call esp_netif_set_default_netif
     * here — that would steal *all* outbound traffic (including HTTPS to
     * the control plane) into the WG tunnel, which is fatal as long as
     * the tunnel can't actually carry packets (no DISCO/STUN/DERP yet).
     * The /10 netmask above gives lwIP the subnet-match it needs to
     * route the 100.64.0.0/10 tailnet through this netif while leaving
     * the default route on WiFi.
     *
     * action_start triggers esp_netif_lwip_add → lwIP netif_add →
     * wg_lwip_netif_init() (our init_fn), which applies MTU + output
     * overrides onto the freshly-zeroed netif and caches s_lwn. */
    esp_netif_action_start(s_netif, NULL, 0, NULL);

    /* Bring the netif up AFTER action_start has returned and netif_add
     * has linked it into netif_list. Calling netif_set_up from inside
     * init_fn fires ext_callbacks while the netif is invisible to
     * netif_list iteration — empirically this caused jitter and packet
     * loss on the raw-IP ingress path. */
    if (s_lwn != NULL) {
        netif_set_up(s_lwn);
        netif_set_link_up(s_lwn);
    }

    ESP_LOGI(TAG, "WG netif up: ip=%u.%u.%u.%u/32 mtu=%u",
             (unsigned)((local_ip_be      ) & 0xFF),
             (unsigned)((local_ip_be >>  8) & 0xFF),
             (unsigned)((local_ip_be >> 16) & 0xFF),
             (unsigned)((local_ip_be >> 24) & 0xFF),
             (unsigned)mtu);
    return ESP_OK;
}

void wg_lwip_detach(void)
{
    if (s_netif == NULL) return;
    wg_netif_set_rx_callback(NULL, NULL);
    esp_netif_action_stop(s_netif, NULL, 0, NULL);
    esp_netif_destroy(s_netif);
    s_netif = NULL;
    free(s_driver);
    s_driver = NULL;
}

#endif /* ESP_PLATFORM */
