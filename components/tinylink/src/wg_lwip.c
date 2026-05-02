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

#include "wg_netif.h"

static const char *TAG = "wg_lwip";

/* Custom esp_netif driver that bridges plaintext IP between lwIP and
 * the WG protocol engine in wg_netif. */
typedef struct {
    esp_netif_driver_base_t base;
} wg_driver_t;

static esp_netif_t *s_netif;
static wg_driver_t *s_driver;

/* lwIP → WG: called by lwIP when it has an IP packet to send out the
 * tunnel netif. We pass the buffer to wg_netif which encrypts and
 * sends via the underlying UDP socket. */
static esp_err_t wg_transmit(void *h, void *buffer, size_t len)
{
    (void)h;
    return wg_netif_send_plaintext((const uint8_t *)buffer, len);
}

/* WG → lwIP: invoked from wg_netif's RX path after a transport
 * record has been authenticated and decrypted. Injects the plaintext
 * IP into the netif so lwIP routes it as if it came in on a wire. */
static void wg_rx_inject(const uint8_t *plaintext, size_t len, void *user)
{
    esp_netif_t *netif = (esp_netif_t *)user;
    if (netif == NULL || len == 0) return;
    (void)esp_netif_receive(netif, (void *)plaintext, len, NULL);
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
     * in some IDF versions; we set it via the underlying lwIP netif. */
    struct netif *lwn = (struct netif *)esp_netif_get_netif_impl(s_netif);
    if (lwn != NULL) {
        lwn->mtu = mtu;
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
