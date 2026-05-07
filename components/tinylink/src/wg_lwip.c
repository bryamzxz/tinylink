// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#ifdef ESP_PLATFORM

#include "wg_lwip.h"

#include <stdlib.h>
#include <string.h>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
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
    uint8_t scratch[1536];
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

    /* Inherent (base) config: PPP flag tells esp_netif this is a
     * point-to-point virtual link with no DHCP/ARP/ND. That sidesteps
     * the IDF v5.5 panic in esp_netif_internal_dhcpc_cb that killed
     * trombik's WG netif. */
    esp_netif_inherent_config_t base = {
        .flags     = (esp_netif_flags_t)(ESP_NETIF_FLAG_IS_PPP),
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

    /* Stack glue: PPP stack is the closest fit in IDF for "raw IP, no
     * link-layer protocol". It still uses lwIP under the hood. */
    esp_netif_config_t cfg = {
        .base    = &base,
        .driver  = NULL,
        .stack   = ESP_NETIF_NETSTACK_DEFAULT_PPP,
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

    /* Apply MTU. esp_netif_set_mtu doesn't exist on PPP-flagged netifs
     * in some IDF versions; we set it via the underlying lwIP netif.
     *
     * Force admin-UP and link-UP on the lwIP netif. esp_netif_action_start
     * below dispatches via esp_netif_start_api → esp_netif_start_ppp for
     * any netif with ESP_NETIF_FLAG_IS_PPP, and that path waits on a real
     * PPP LCP/IPCP negotiation that never completes (we use the netif as
     * a raw IP carrier, not as PPP). It returns before the AUTOUP block
     * that would set both flags, so without these two calls
     * netif_is_up() and netif_is_link_up() both stay 0 — egress still
     * works (ip4_output resolves the route by subnet match against
     * ip_info, doesn't gate hard on is_up), but ingress local-delivery
     * fails: ip4_input_accept checks netif_is_up(inp) and drops inbound
     * before ICMP can reply. Symptom: telemetry tx flows, real
     * `ping <our-tailnet-ip>` from a peer goes 100% packet loss. */
    struct netif *lwn = (struct netif *)esp_netif_get_netif_impl(s_netif);
    if (lwn != NULL) {
        lwn->mtu = mtu;
        /* Force address application onto the lwIP netif. esp_netif's
         * `ip_info` is consumed by `esp_netif_up_api` (line 1821 of
         * `esp_netif_lwip.c`) but the PPP `start` path returns before
         * that, so without an explicit `netif_set_addr` here lwn's
         * ip_addr stays 0.0.0.0 and `ip4_input` fails to match
         * inbound packets destined for our tailnet IP — they're
         * delivered to lwIP via tcpip_input but ip4_input_accept
         * has no matching local netif and the packet is dropped
         * before the ICMP echo handler can reply. */
        ip4_addr_t ip4_ip   = { .addr = local_ip_be };
        ip4_addr_t ip4_mask = { .addr = lwip_htonl(0xFFC00000UL) };
        ip4_addr_t ip4_gw   = { .addr = 0 };
        netif_set_addr(lwn, &ip4_ip, &ip4_mask, &ip4_gw);
        /* Override the egress chain so lwIP doesn't PPP-frame outbound
         * IP packets. The default `output`/`linkoutput` for a PPP netif
         * wraps each datagram in HDLC + PPP-protocol headers; we ship
         * raw IP only. Without this, every reply (ICMP echo,
         * application TCP/UDP) reached the peer encrypted but
         * structurally garbled — peer's WireGuard decoded fine and
         * dropped on inner-IP parse. */
        lwn->output      = wg_lwip_ip4_output;
        lwn->linkoutput  = wg_lwip_linkoutput;
        netif_set_up(lwn);
        netif_set_link_up(lwn);
        s_lwn = lwn;   /* cache for wg_rx_inject's tcpip_input bypass */
        ESP_LOGI(TAG, "lwn ip=%u.%u.%u.%u flags=0x%02x",
                 (unsigned)((local_ip_be      ) & 0xFF),
                 (unsigned)((local_ip_be >>  8) & 0xFF),
                 (unsigned)((local_ip_be >> 16) & 0xFF),
                 (unsigned)((local_ip_be >> 24) & 0xFF),
                 (unsigned)lwn->flags);
    }

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
     * the default route on WiFi. */
    esp_netif_action_start(s_netif, NULL, 0, NULL);

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
