// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// In-memory state extracted from a single tailcfg.MapResponse. tinylink
// keeps only the fields the data plane actually consumes — the live
// Tailscale Go client retains hundreds of fields, most of them ACL or
// MagicDNS metadata we deliberately do not enforce on-device (see
// docs/SECURITY-MODEL.md non-goals).
//
// Sizing rationale: 4 peers covers the M1/M2 sensor → home topology.
// DERP regions are sized to 28 (the full Tailscale DERPMap) because
// capping below the production region count silently drops whichever
// region the parser hits last — observed loss of mia/region 16 at
// cap=4 left every peer in this tailnet unreachable.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Avoid pulling in tinylink.h (and therefore esp_err.h) so this header
 * stays compilable on the host for the parser KAT. The key length is
 * fixed at 32 bytes by Curve25519. */
#ifndef TINYLINK_KEY_LEN
#define TINYLINK_KEY_LEN 32
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define TL_MAX_PEERS            4
/* Per-frame caps for the delta lists. Overflowing either one sets the
 * matching *_overflow flag and the streaming caller recycles the stream
 * for a full netmap instead of applying a partial delta. headscale folds
 * one batching tick into a single frame (a5d5e838, 7a2335dc), so these
 * can be exceeded by mass changes — rare, and the full map is correct. */
#define TL_MAX_PEERS_REMOVED    8
#define TL_MAX_PEER_PATCHES     4
#define TL_MAX_PEER_ENDPOINTS   4
#define TL_MAX_PEER_ADDRESSES   2
/* Tailscale ships 28 DERP regions today (mia/region 16 is the closest
 * to most peers in this tailnet). Capping below that silently dropped
 * region 16 from the parsed netmap, leaving the device unable to reach
 * any peer that homes there. Max nodes per region observed in prod = 5;
 * 3 covers all current regions with headroom. BSS cost: ~6 KiB. */
#define TL_MAX_DERP_REGIONS     28
#define TL_MAX_DERP_NODES       3

/* "ip:port" form for an IPv4 endpoint. ESP32 lwIP build is v4-only at the
 * netif layer, so v6 endpoints announced by the control plane are dropped
 * during parsing. 21 = "255.255.255.255:65535\0" + slack. */
#define TL_ENDPOINT_STRLEN      32

/* "100.x.y.z/32" form. Same v4-only constraint. */
#define TL_CIDR_STRLEN          24

/* DERP region hostname (e.g. "derp1.tailscale.com"). 64 covers everything
 * Tailscale ships today + headroom. */
#define TL_DERP_HOSTNAME_LEN    64

typedef struct {
    char     str[TL_ENDPOINT_STRLEN];
} tl_endpoint_t;

typedef struct {
    char     str[TL_CIDR_STRLEN];
} tl_cidr_t;

typedef struct {
    uint64_t      id;                              /* tailcfg.NodeID */
    uint8_t       node_pub[TINYLINK_KEY_LEN];      /* unhexed key.NodePublic */
    uint8_t       disco_pub[TINYLINK_KEY_LEN];
    bool          has_disco_pub;
    int           home_derp;                       /* DERP region ID, 0 = unknown */
    size_t        n_endpoints;
    tl_endpoint_t endpoints[TL_MAX_PEER_ENDPOINTS];
    size_t        n_addresses;
    tl_cidr_t     addresses[TL_MAX_PEER_ADDRESSES];
} tl_peer_t;

/* One tailcfg.PeerChange (PeersChangedPatch entry), reduced to the
 * fields the data plane consumes. Applied by NodeID to a peer already in
 * the caller's table (upstream map.go updatePeersStateFromResponse);
 * a patch for an unknown NodeID is ignored, like upstream. headscale
 * sends peer endpoint/DERP changes (59f3ff12) and peer re-logins /
 * tailscaled restarts (Key / DiscoKey, NodeKeyRotated) this way. */
typedef struct {
    uint64_t      id;                              /* NodeID */
    bool          has_key;
    uint8_t       node_pub[TINYLINK_KEY_LEN];
    bool          has_disco;
    uint8_t       disco_pub[TINYLINK_KEY_LEN];
    bool          has_endpoints;                   /* Endpoints present → replace */
    size_t        n_endpoints;
    tl_endpoint_t endpoints[TL_MAX_PEER_ENDPOINTS];
    int           derp_region;                     /* 0 = unchanged */
} tl_peer_patch_t;

typedef struct {
    int      region_id;
    char     hostname[TL_DERP_HOSTNAME_LEN];
    uint16_t port;                                 /* 0 → use default 443 */
} tl_derp_node_t;

typedef struct {
    int            region_id;
    size_t         n_nodes;
    tl_derp_node_t nodes[TL_MAX_DERP_NODES];
} tl_derp_region_t;

typedef struct {
    /* Self */
    uint64_t  self_id;
    size_t    n_self_addresses;
    tl_cidr_t self_addresses[TL_MAX_PEER_ADDRESSES];
    /* Self node expiry. `self_expired` = explicit "Expired":true;
     * `self_key_expiry` = KeyExpiry as Unix seconds, 0 when absent or the
     * Go zero time (= never expires). headscale ≥0.29.4 answers the map
     * stream of a deleted node with HTTP 200 and a single self node
     * {"Key","KeyExpiry":"1970-01-01T00:00:01Z","Expired":true}
     * (noise.go, juanfont/headscale#3410) instead of a 404, and keeps an
     * expired node's stream open with Expired set; upstream clients go to
     * NeedsLogin on either (capver 53: respects Expired, derives it from
     * KeyExpiry). The streaming caller re-registers. */
    bool      self_expired;
    int64_t   self_key_expiry;

    /* Peers. `peers_is_delta` = the array came from PeersChanged (an
     * upsert into the caller's peer table) rather than Peers (a full
     * replacement). `removed_ids` = PeersRemoved NodeIDs to delete from
     * that table. Merge semantics live in tinylink.c (M16, 2026-09);
     * before that every frame replaced the table and a delta carrying
     * only another peer wiped the WG peer's cached endpoints. */
    size_t    n_peers;
    tl_peer_t peers[TL_MAX_PEERS];
    bool      peers_is_delta;
    size_t    n_removed;
    uint64_t  removed_ids[TL_MAX_PEERS_REMOVED];
    bool      removed_overflow;
    size_t          n_patches;
    tl_peer_patch_t patches[TL_MAX_PEER_PATCHES];
    bool            patches_overflow;

    /* DERP map (M5) */
    size_t           n_derp_regions;
    tl_derp_region_t derp_regions[TL_MAX_DERP_REGIONS];

    /* Bookkeeping for the streaming caller. */
    bool    have_self;
    bool    have_derp_map;
} tl_netmap_t;

void tl_netmap_clear(tl_netmap_t *nm);

#ifdef __cplusplus
}
#endif
