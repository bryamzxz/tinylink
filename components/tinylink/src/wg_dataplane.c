// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// WireGuard dataplane bring-up. Replaced the trombik/esp_wireguard
// shim with the native tinylink_wg stack on 2026-05-02 after the
// trombik path crashed in esp_netif_internal_dhcpc_cb on the first
// real-hardware boot under ESP-IDF v5.5 (Option C step 6).

#ifdef ESP_PLATFORM

#include "wg_dataplane.h"

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"

#include "wg_lwip.h"
#include "wg_netif.h"

static const char *TAG = "wg";

static bool     s_started;
static char     s_endpoint_host[64];   /* string form of last applied endpoint */
static uint16_t s_endpoint_port;

/* Parse "1.2.3.4/32" → host out + numeric prefix length. Tailscale
 * always assigns each node a /32 host route, but parse defensively. */
static int parse_cidr(const char *cidr, char *host_out, size_t host_size,
                      int *prefix_out)
{
    const char *slash = strchr(cidr, '/');
    if (slash == NULL) return -1;
    size_t hlen = (size_t)(slash - cidr);
    if (hlen + 1 > host_size) return -1;
    memcpy(host_out, cidr, hlen);
    host_out[hlen] = '\0';
    *prefix_out = atoi(slash + 1);
    if (*prefix_out < 0 || *prefix_out > 32) return -1;
    return 0;
}

/* "ip:port" → ip out + port out. v6 was filtered upstream. */
static int parse_endpoint(const char *ep, char *host_out, size_t host_size,
                          int *port_out)
{
    const char *colon = strchr(ep, ':');
    if (colon == NULL) return -1;
    size_t hlen = (size_t)(colon - ep);
    if (hlen + 1 > host_size) return -1;
    memcpy(host_out, ep, hlen);
    host_out[hlen] = '\0';
    *port_out = atoi(colon + 1);
    if (*port_out <= 0 || *port_out > 65535) return -1;
    return 0;
}

esp_err_t wg_dataplane_start(const tinylink_keys_t *keys,
                             const tl_netmap_t *nm)
{
    if (keys == NULL || nm == NULL) return ESP_ERR_INVALID_ARG;
    if (s_started) return ESP_ERR_INVALID_STATE;
    if (nm->n_peers == 0) {
        ESP_LOGE(TAG, "no peers in netmap");
        return ESP_ERR_INVALID_STATE;
    }
    if (nm->n_self_addresses == 0) {
        ESP_LOGE(TAG, "self has no v4 address");
        return ESP_ERR_INVALID_STATE;
    }
    const tl_peer_t *peer = &nm->peers[0];
    if (peer->n_endpoints == 0) {
        ESP_LOGE(TAG, "peer has no v4 endpoint — DERP-only path is M5");
        return ESP_ERR_NOT_SUPPORTED;
    }

    /* Local v4 (tunnel side). */
    char self_ip_str[16];
    int  self_prefix = 32;
    if (parse_cidr(nm->self_addresses[0].str,
                   self_ip_str, sizeof(self_ip_str), &self_prefix) != 0) {
        ESP_LOGE(TAG, "self CIDR malformed: %s", nm->self_addresses[0].str);
        return ESP_ERR_INVALID_ARG;
    }
    uint32_t local_ip_be = 0;
    if (inet_pton(AF_INET, self_ip_str, &local_ip_be) != 1) {
        ESP_LOGE(TAG, "inet_pton(%s) failed", self_ip_str);
        return ESP_ERR_INVALID_ARG;
    }

    /* Peer endpoint. */
    int port = 41641;
    if (parse_endpoint(peer->endpoints[0].str,
                       s_endpoint_host, sizeof(s_endpoint_host), &port) != 0) {
        ESP_LOGE(TAG, "peer endpoint malformed: %s", peer->endpoints[0].str);
        return ESP_ERR_INVALID_ARG;
    }
    uint32_t peer_v4_be = 0;
    if (inet_pton(AF_INET, s_endpoint_host, &peer_v4_be) != 1) {
        ESP_LOGE(TAG, "inet_pton peer(%s) failed", s_endpoint_host);
        return ESP_ERR_INVALID_ARG;
    }
    s_endpoint_port = (uint16_t)port;

    /* 1) WG protocol engine (UDP socket + handshake state machine). */
    struct wg_netif_local_config local = {0};
    memcpy(local.static_priv, keys->node_priv, WG_KEY_LEN);
    memcpy(local.static_pub,  keys->node_pub,  WG_KEY_LEN);
    local.bind_port = 0;  /* let the kernel pick an ephemeral source port */
    esp_err_t err = wg_netif_init(&local);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wg_netif_init: %s", esp_err_to_name(err));
        return err;
    }

    struct wg_netif_peer_config peer_cfg = {0};
    memcpy(peer_cfg.peer_static_pub, peer->node_pub, WG_KEY_LEN);
    peer_cfg.peer_endpoint_v4_be = peer_v4_be;
    peer_cfg.peer_endpoint_port  = s_endpoint_port;
    err = wg_netif_start(&peer_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wg_netif_start: %s", esp_err_to_name(err));
        wg_netif_stop();
        return err;
    }

    /* 2) lwIP integration. WG_LWIP_MTU = 1280 (the WG default). The
     * 40-byte WG transport header doesn't need MSS clamp here — lwIP
     * will path-MTU per its own rules once we tell it our MTU. */
    err = wg_lwip_attach(local_ip_be, /*mtu=*/1280);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wg_lwip_attach: %s", esp_err_to_name(err));
        wg_netif_stop();
        return err;
    }

    s_started = true;
    ESP_LOGI(TAG, "WG bringup (tinylink_wg): self=%s/%d peer=%s:%u",
             self_ip_str, self_prefix,
             s_endpoint_host, (unsigned)s_endpoint_port);
    return ESP_OK;
}

esp_err_t wg_dataplane_peer_is_up(void)
{
    if (!s_started) return ESP_ERR_INVALID_STATE;
    return wg_netif_is_up() ? ESP_OK : ESP_ERR_INVALID_STATE;
}

void wg_dataplane_stop(void)
{
    if (!s_started) return;
    wg_lwip_detach();
    wg_netif_stop();
    s_started = false;
}

esp_err_t wg_dataplane_update_peer(const tinylink_keys_t *keys,
                                   const tl_netmap_t *nm)
{
    if (keys == NULL || nm == NULL) return ESP_ERR_INVALID_ARG;
    if (nm->n_peers == 0 || nm->peers[0].n_endpoints == 0) {
        return ESP_OK;
    }

    /* Parse the new endpoint and compare with what we have. */
    char  new_host[64];
    int   new_port = 0;
    if (parse_endpoint(nm->peers[0].endpoints[0].str,
                       new_host, sizeof(new_host), &new_port) != 0) {
        return ESP_OK;  /* malformed; leave the live session alone */
    }
    if (s_started &&
        strcmp(new_host, s_endpoint_host) == 0 &&
        (uint16_t)new_port == s_endpoint_port) {
        return ESP_OK;  /* unchanged */
    }

    /* Endpoint changed. With tinylink_wg, roaming does NOT require a
     * fresh handshake — we just point the UDP socket at the new
     * sockaddr. The transport keys remain valid. */
    if (s_started) {
        uint32_t v4_be = 0;
        if (inet_pton(AF_INET, new_host, &v4_be) != 1) {
            return ESP_ERR_INVALID_ARG;
        }
        ESP_LOGI(TAG, "peer endpoint changed: %s:%u → %s:%d",
                 s_endpoint_host, (unsigned)s_endpoint_port,
                 new_host, new_port);
        memcpy(s_endpoint_host, new_host, sizeof(s_endpoint_host));
        s_endpoint_port = (uint16_t)new_port;
        return wg_netif_update_peer_endpoint(v4_be, (uint16_t)new_port);
    }

    /* Not started yet — go through the full bring-up. */
    return wg_dataplane_start(keys, nm);
}

#endif /* ESP_PLATFORM */
