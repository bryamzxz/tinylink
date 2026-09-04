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

#include "tinylink.h"   /* tinylink_get_public_endpoint */
#include "wg_lwip.h"
#include "wg_netif.h"

static const char *TAG = "wg";

static bool     s_started;
static char     s_endpoint_host[64];   /* string form of last applied endpoint */
static uint16_t s_endpoint_port;
static uint8_t  s_peer_node_pub[32];   /* node_pub of the peer we handshook with */

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

/* Walk peer->endpoints[] and pick the best dial target.
 *
 * Decision tree:
 *   1. Parse every endpoint up front into a small candidate table.
 *   2. If our STUN-discovered public IP matches one of the peer's
 *      public endpoints, we are behind the same NAT. The peer's
 *      "public" address is then a hairpin to our own external IP and
 *      most consumer routers refuse to route hairpin UDP. Prefer the
 *      first NON-public (LAN-side) endpoint instead — it's the only
 *      one that crosses the internal switch.
 *   3. Otherwise prefer the first publicly-routable endpoint.
 *   4. If neither pass yields a candidate, fall back to the first
 *      parseable endpoint (preserves prior behavior for LAN-only test
 *      setups, e.g. headscale on a developer LAN).
 *
 * Returns 0 on success.
 */
static int pick_peer_endpoint(const tl_peer_t *peer,
                              char *host_out, size_t host_size,
                              int *port_out, uint32_t *v4_be_out,
                              size_t *picked_index_out)
{
    /* Build a parsed candidate table sized to TL_MAX_PEER_ENDPOINTS. */
    struct cand {
        char     host[64];
        int      port;
        uint32_t v4_be;
        bool     valid;
        bool     is_public;
    } cands[TL_MAX_PEER_ENDPOINTS];

    bool have_any = false;
    size_t first_parseable = (size_t)-1;
    size_t first_public    = (size_t)-1;
    size_t first_private   = (size_t)-1;

    for (size_t i = 0; i < peer->n_endpoints && i < TL_MAX_PEER_ENDPOINTS; i++) {
        cands[i].valid = false;
        if (parse_endpoint(peer->endpoints[i].str,
                           cands[i].host, sizeof(cands[i].host),
                           &cands[i].port) != 0) {
            continue;
        }
        if (inet_pton(AF_INET, cands[i].host, &cands[i].v4_be) != 1) {
            continue;
        }
        cands[i].is_public = ipv4_is_public(cands[i].v4_be);
        cands[i].valid = true;
        have_any = true;
        if (first_parseable == (size_t)-1) first_parseable = i;
        if (cands[i].is_public  && first_public  == (size_t)-1) first_public  = i;
        if (!cands[i].is_public && first_private == (size_t)-1) first_private = i;
    }
    if (!have_any) return -1;

    /* Same-NAT detection: ask the STUN cache for our public endpoint
     * and check whether the peer announced a matching public IP.
     * Detection is by IP only (NAT remaps the source port; the IP is
     * shared). If STUN never produced a result, treat as cross-NAT. */
    bool same_nat = false;
    uint8_t  our_addr[4];
    uint16_t our_port_unused;
    if (tinylink_get_public_endpoint(our_addr, &our_port_unused)) {
        uint32_t our_v4_be = 0;
        memcpy(&our_v4_be, our_addr, sizeof(our_v4_be));
        for (size_t i = 0; i < peer->n_endpoints; i++) {
            if (cands[i].valid && cands[i].is_public &&
                cands[i].v4_be == our_v4_be) {
                same_nat = true;
                break;
            }
        }
    }

    size_t pick = (size_t)-1;
    if (same_nat && first_private != (size_t)-1) {
        pick = first_private;
    } else if (first_public != (size_t)-1) {
        pick = first_public;
    } else {
        pick = first_parseable;
    }

    if (host_size < sizeof(cands[pick].host)) return -1;
    memcpy(host_out, cands[pick].host, sizeof(cands[pick].host));
    *port_out  = cands[pick].port;
    *v4_be_out = cands[pick].v4_be;
    if (picked_index_out) *picked_index_out = pick;
    if (same_nat) {
        ESP_LOGI(TAG, "same-NAT detected (peer announces our public IP); "
                      "preferring LAN endpoint #%u", (unsigned)pick);
    }
    return 0;
}

/* True iff `peer` has at least one public endpoint whose IP differs
 * from our STUN-discovered public IP. Such an endpoint is reachable
 * via straight UDP (cross-NAT) without hairpinning.
 *
 * If STUN never produced a result we return `peer->n_endpoints > 0`
 * with any public — we can't tell hairpin from cross-NAT, so we
 * optimistically allow it. */
static bool peer_has_directly_reachable_endpoint(const tl_peer_t *peer,
                                                 bool have_our_public,
                                                 uint32_t our_public_v4_be)
{
    for (size_t i = 0; i < peer->n_endpoints; i++) {
        char     h[64];
        int      p = 0;
        uint32_t v4 = 0;
        if (parse_endpoint(peer->endpoints[i].str, h, sizeof(h), &p) != 0) continue;
        if (inet_pton(AF_INET, h, &v4) != 1) continue;
        if (!ipv4_is_public(v4)) continue;
        if (!have_our_public) return true;             /* unknown → optimistic */
        if (v4 != our_public_v4_be) return true;       /* truly cross-NAT */
    }
    return false;
}

/* Pick the peer to bring up the WG datapath against. The current
 * netif is single-peer; in multi-peer netmaps (e.g. a Tailscale tailnet
 * with several nodes the ESP32 has ACL access to) we want to avoid
 * peers[0] when the control plane happens to list the user's phone
 * (sharing our CGNAT public) before a remote node we can actually
 * reach. Prefer the first peer with at least one cross-NAT public
 * endpoint; fall back to peers[0] when no peer qualifies (DERP-relay
 * territory — that's the M5+ work). */
static const tl_peer_t *select_target_peer(const tl_netmap_t *nm)
{
    uint8_t  our_addr[4];
    uint16_t our_port_unused;
    bool     have_our_public = tinylink_get_public_endpoint(our_addr, &our_port_unused);
    uint32_t our_v4_be = 0;
    if (have_our_public) {
        memcpy(&our_v4_be, our_addr, sizeof(our_v4_be));
    }

    for (size_t i = 0; i < nm->n_peers; i++) {
        const tl_peer_t *p = &nm->peers[i];
        if (peer_has_directly_reachable_endpoint(p, have_our_public, our_v4_be)) {
            if (i != 0) {
                const char *addr = (p->n_addresses > 0)
                    ? p->addresses[0].str : "(no-addr)";
                ESP_LOGI(TAG, "selected peer #%u (%s) over peers[0] — "
                              "first peer with cross-NAT-reachable endpoint",
                         (unsigned)i, addr);
            }
            return p;
        }
    }
    /* Every peer's only public endpoint is our own public IP — pure
     * CGNAT scenario. Fall through to peers[0]; direct path will fail
     * but we keep the legacy behavior so DERP-relay (M5+) can take
     * over once it lands. */
    if (nm->n_peers > 0) {
        ESP_LOGW(TAG, "no peer has a cross-NAT public endpoint; "
                      "falling back to peers[0] — DERP relay required for ping");
    }
    return &nm->peers[0];
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
    const tl_peer_t *peer = select_target_peer(nm);
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
        ESP_LOGI(TAG, "selected endpoint #%u of %u: %s (skipped %u earlier)",
                 (unsigned)picked_idx, (unsigned)peer->n_endpoints,
                 s_endpoint_host, (unsigned)picked_idx);
    }
    s_endpoint_port = (uint16_t)port;

    /* 1) WG protocol engine (UDP socket + handshake state machine).
     * If tinylink_wg_socket_init already brought up wg_netif (so STUN
     * could probe through the same socket), this call is a no-op —
     * the local config we pass here is ignored. */
    struct wg_netif_local_config local = {0};
    memcpy(local.static_priv, keys->node_priv,  WG_KEY_LEN);
    memcpy(local.static_pub,  keys->node_pub,   WG_KEY_LEN);
    memcpy(local.disco_priv,  keys->disco_priv, WG_KEY_LEN);
    memcpy(local.disco_pub,   keys->disco_pub,  WG_KEY_LEN);
    local.bind_port = 0;  /* let the kernel pick an ephemeral source port */
    esp_err_t err = wg_netif_init(&local);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wg_netif_init: %s", esp_err_to_name(err));
        return err;
    }

    struct wg_netif_peer_config peer_cfg = {0};
    memcpy(peer_cfg.peer_static_pub, peer->node_pub, WG_KEY_LEN);
    if (peer->has_disco_pub) {
        memcpy(peer_cfg.peer_disco_pub, peer->disco_pub, WG_KEY_LEN);
        peer_cfg.has_peer_disco_pub = true;
    }
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
    memcpy(s_peer_node_pub, peer->node_pub, sizeof(s_peer_node_pub));
    const char *peer_ts_ip = (peer->n_addresses > 0) ? peer->addresses[0].str
                                                     : "(no-ts-ip)";
    ESP_LOGI(TAG, "WG bringup (tinylink_wg): self=%s/%d peer=%s @ %s:%u",
             self_ip_str, self_prefix, peer_ts_ip,
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
    if (nm->n_peers == 0) return ESP_OK;
    /* Not started yet — go through the full bring-up (which runs
     * select_target_peer itself). */
    if (!s_started) return wg_dataplane_start(keys, nm);
    return wg_dataplane_update_peers(keys, nm->peers, nm->n_peers);
}

esp_err_t wg_dataplane_update_peers(const tinylink_keys_t *keys,
                                    const tl_peer_t *peers, size_t n_peers)
{
    if (keys == NULL || peers == NULL) return ESP_ERR_INVALID_ARG;
    if (!s_started || n_peers == 0) return ESP_OK;

    /* Lock onto the peer we handshook with by matching s_peer_node_pub.
     * Re-running select_target_peer here could pick a different peer
     * mid-session, which would point encrypted traffic at a peer that
     * holds different keys. Roaming the *endpoint* of the same peer is
     * fine; switching peers is not — leave the live session alone. */
    const tl_peer_t *peer = NULL;
    for (size_t i = 0; i < n_peers; i++) {
        if (memcmp(peers[i].node_pub, s_peer_node_pub,
                   sizeof(s_peer_node_pub)) == 0) {
            peer = &peers[i];
            break;
        }
    }
    if (peer == NULL || peer->n_endpoints == 0) {
        /* Peer dropped from the table or lost endpoints. We don't tear
         * down here — the WG handshake retry budget will surface the
         * dead path eventually, and a future netmap may re-add the
         * peer. */
        return ESP_OK;
    }

    char     new_host[64];
    int      new_port = 0;
    uint32_t v4_be = 0;
    if (pick_peer_endpoint(peer, new_host, sizeof(new_host),
                           &new_port, &v4_be, NULL) != 0) {
        return ESP_OK;  /* nothing usable; leave the live session alone */
    }
    if (strcmp(new_host, s_endpoint_host) == 0 &&
        (uint16_t)new_port == s_endpoint_port) {
        return ESP_OK;  /* unchanged */
    }

    /* Endpoint changed. With tinylink_wg, roaming does NOT require a
     * fresh handshake — we just point the UDP socket at the new
     * sockaddr. The transport keys remain valid. */
    ESP_LOGI(TAG, "peer endpoint changed: %s:%u → %s:%d",
             s_endpoint_host, (unsigned)s_endpoint_port,
             new_host, new_port);
    memcpy(s_endpoint_host, new_host, sizeof(s_endpoint_host));
    s_endpoint_port = (uint16_t)new_port;
    return wg_netif_update_peer_endpoint(v4_be, (uint16_t)new_port);
}

#endif /* ESP_PLATFORM */
