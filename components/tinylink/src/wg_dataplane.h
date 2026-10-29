// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Glue between tinylink's merged netmap and the WireGuard runtime:
// picks the one peer the session runs against, brings up wg_netif +
// the lwIP tunnel netif, and applies later netmap changes (endpoint
// roam, peer NodeKey / DiscoKey rotation) to the live session.
//
// Single-peer by design (README §Scope): the session is pinned to one
// peer, tracked by NodeID for its whole lifetime.

#pragma once

#ifdef ESP_PLATFORM

#include "esp_err.h"

#include "netmap.h"
#include "tinylink.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Bring up the WG netif. `self_addrs[0]` is the local 100.x address;
 * the target is the first peer in `peers` with a cross-NAT public
 * endpoint (else peers[0]). Takes the caller's merged peer table, not a
 * single MapResponse frame, so a start after delta frames sees the
 * merged state.
 *
 * ESP_OK means the handshake INIT is out, not that it completed — poll
 * `wg_dataplane_peer_is_up()`. */
esp_err_t wg_dataplane_start(const tinylink_keys_t *keys,
                             const tl_cidr_t *self_addrs, size_t n_self,
                             const tl_peer_t *peers, size_t n_peers);

/* Returns ESP_OK if the peer has completed at least one WG handshake. */
esp_err_t wg_dataplane_peer_is_up(void);

/* Tunnel-side IPv4 (network order) the netif was attached with, or 0
 * before start. The caller compares it against later self Addresses:
 * a re-registered (deleted) node can come back with a new address. */
uint32_t wg_dataplane_self_v4(void);

/* Tear down. Safe to call even if start() was never called. */
void wg_dataplane_stop(void);

/* Apply the caller's merged peer table (tinylink.c keeps it across
 * Peers / PeersChanged / PeersRemoved / PeersChangedPatch frames) to the
 * live session: the session's peer is found by NodeID; a changed
 * NodeKey or DiscoKey goes to wg_netif_update_peer_keys, a changed
 * endpoint roams the WG target without a new handshake. Runs X25519 on
 * a DiscoKey change — call from the long-poll task. */
esp_err_t wg_dataplane_update_peers(const tinylink_keys_t *keys,
                                    const tl_peer_t *peers, size_t n_peers);

#ifdef __cplusplus
}
#endif

#endif /* ESP_PLATFORM */
