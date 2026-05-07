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

/* True iff `v4_be` (network-byte-order IPv4) is publicly routable from
 * the ESP32 — i.e. NOT RFC1918, link-local, loopback, or this-network.
 * The control plane often advertises a peer's LAN address alongside its
 * public NAT address; on a different LAN we can never reach the LAN
 * one, so trying it first wastes the WG handshake budget on guaranteed
 * ENETUNREACH/timeouts. Upstream tailscale ranks rather than filters,
 * but the minimal client doesn't track per-endpoint latency, so we
 * filter conservatively and let the DERP relay path (M5+) cover the
 * cases where no public endpoint exists. */
static bool ipv4_is_public(uint32_t v4_be)
{
    uint32_t a = ntohl(v4_be);
    uint8_t  b0 = (a >> 24) & 0xFF;
    uint8_t  b1 = (a >> 16) & 0xFF;
    if (b0 == 10) return false;                            /* 10/8 */
    if (b0 == 172 && (b1 & 0xF0) == 16) return false;      /* 172.16/12 */
    if (b0 == 192 && b1 == 168) return false;              /* 192.168/16 */
    if (b0 == 127) return false;                           /* 127/8 loopback */
    if (b0 == 169 && b1 == 254) return false;              /* link-local */
    if (b0 == 0) return false;                             /* this-network / unspecified */
    if (b0 >= 224) return false;                           /* multicast / reserved */
    return true;
}

/* Walk peer->endpoints[] and pick the first publicly-routable one.
 * Falls back to endpoints[0] when none qualify, preserving prior
 * behavior for LAN-only test setups. Returns 0 on success and writes
 * the parsed host string + port + binary v4 into the out params. */
static int pick_peer_endpoint(const tl_peer_t *peer,
                              char *host_out, size_t host_size,
                              int *port_out, uint32_t *v4_be_out,
                              size_t *picked_index_out)
{
    int      best_port = 0;
    uint32_t best_v4 = 0;
    char     best_host[64] = {0};
    size_t   best_idx = (size_t)-1;

    for (size_t i = 0; i < peer->n_endpoints; i++) {
        char     h[64];
        int      p = 0;
        uint32_t v4 = 0;
        if (parse_endpoint(peer->endpoints[i].str, h, sizeof(h), &p) != 0) {
            continue;
        }
        if (inet_pton(AF_INET, h, &v4) != 1) {
            continue;
        }
        if (ipv4_is_public(v4)) {
            memcpy(best_host, h, sizeof(h));
            best_port = p;
            best_v4 = v4;
            best_idx = i;
            break;
        }
        /* Remember endpoints[0] (or the first parsed one) as the
         * fallback if nothing public turns up. */
        if (best_idx == (size_t)-1) {
            memcpy(best_host, h, sizeof(h));
            best_port = p;
            best_v4 = v4;
            best_idx = i;
        }
    }
    if (best_idx == (size_t)-1) return -1;
    if (host_size < sizeof(best_host)) return -1;
    memcpy(host_out, best_host, sizeof(best_host));
    *port_out = best_port;
    *v4_be_out = best_v4;
    if (picked_index_out) *picked_index_out = best_idx;
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

    /* Peer endpoint — prefer the first publicly-routable candidate so
     * we don't waste the handshake budget dialing a peer's LAN address
     * from a different network. */
    int      port = 41641;
    uint32_t peer_v4_be = 0;
    size_t   picked_idx = 0;
    if (pick_peer_endpoint(peer, s_endpoint_host, sizeof(s_endpoint_host),
                           &port, &peer_v4_be, &picked_idx) != 0) {
        ESP_LOGE(TAG, "no usable peer endpoint among %u candidates",
                 (unsigned)peer->n_endpoints);
        return ESP_ERR_INVALID_ARG;
    }
    if (picked_idx != 0) {
        ESP_LOGI(TAG, "skipped %u non-public endpoint(s); using #%u: %s",
                 (unsigned)picked_idx, (unsigned)picked_idx, s_endpoint_host);
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

    /* Re-pick the best endpoint from the fresh peer list and compare
     * with what we have. Same public-first preference as the initial
     * bring-up so a roam doesn't downgrade us to a LAN address. */
    char     new_host[64];
    int      new_port = 0;
    uint32_t v4_be = 0;
    if (pick_peer_endpoint(&nm->peers[0], new_host, sizeof(new_host),
                           &new_port, &v4_be, NULL) != 0) {
        return ESP_OK;  /* nothing usable; leave the live session alone */
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
