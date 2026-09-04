// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Thin shim translating tinylink's parsed netmap into the
// `wireguard_config_t` struct that trombik/esp_wireguard expects, then
// driving its init / connect cycle.
//
// Single-peer only for M2. trombik's API exposes one peer per
// `wireguard_config_t`; the multi-peer case is the explicit non-goal
// for tinylink (see README §Non-goals). The "demuxer for multiplexed
// DISCO/STUN" patch the research artifact references is deferred to
// M3 — until DISCO actually needs the same UDP socket, the bare
// `udp_bind(IP_ADDR_ANY, port)` that the upstream component does is
// fine.

#pragma once

#ifdef ESP_PLATFORM

#include "esp_err.h"

#include "netmap.h"
#include "tinylink.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Bring up the WG netif against the home peer announced in `nm`. The
 * function picks `nm->peers[0]` (single-peer client by design) and uses
 * `nm->self_addresses[0]` as the local 100.x address.
 *
 * Returns ESP_OK once `esp_wireguard_init` + `esp_wireguard_connect`
 * succeed. Note that ESP_OK does not yet mean a handshake has
 * completed — callers should poll `wg_dataplane_peer_is_up()`. */
esp_err_t wg_dataplane_start(const tinylink_keys_t *keys,
                             const tl_netmap_t *nm);

/* Returns ESP_OK if the peer has completed at least one WG handshake. */
esp_err_t wg_dataplane_peer_is_up(void);

/* Tear down. Safe to call even if start() was never called. */
void wg_dataplane_stop(void);

/* Hot-path update: the long-poll MapRequest loop calls this when the
 * peer's endpoint changes between MapResponses. tinylink reuses
 * peers[0] (single-peer model) and only acts on a real change to
 * `peer->endpoints[0]`; same-endpoint calls are no-ops.
 *
 * For now this tears down the WG netif and brings it back up against
 * the new endpoint. trombik/esp_wireguard does not expose a stable
 * "update peer" entry point, so a reconnect is the cleanest option.
 * Frequency in practice is "rare" — magicsock-equivalent endpoint
 * churn after DISCO lands in M3 will replace this with a less
 * disruptive update.
 */
esp_err_t wg_dataplane_update_peer(const tinylink_keys_t *keys,
                                   const tl_netmap_t *nm);

/* Same, from the caller's merged peer table (tinylink.c keeps the
 * canonical table across Peers / PeersChanged / PeersRemoved frames). */
esp_err_t wg_dataplane_update_peers(const tinylink_keys_t *keys,
                                    const tl_peer_t *peers, size_t n_peers);

#ifdef __cplusplus
}
#endif

#endif /* ESP_PLATFORM */
