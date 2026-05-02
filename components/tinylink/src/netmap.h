// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// In-memory state extracted from a single tailcfg.MapResponse. tinylink
// keeps only the fields the data plane actually consumes — the live
// Tailscale Go client retains hundreds of fields, most of them ACL or
// MagicDNS metadata we deliberately do not enforce on-device (see
// docs/SECURITY-MODEL.md non-goals).
//
// Sizing rationale: the M1 device targets one peer (sensor → home node).
// We over-budget to 4 peers + 4 DERP regions so the same struct can
// serve M2 (data plane bringup) and an eventual M5 DERP fallback
// without rework, while still fitting the ~4 KiB SRAM cap from
// research §J.

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
#define TL_MAX_PEER_ENDPOINTS   4
#define TL_MAX_PEER_ADDRESSES   2
#define TL_MAX_DERP_REGIONS     4
#define TL_MAX_DERP_NODES       2

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

    /* Peers */
    size_t    n_peers;
    tl_peer_t peers[TL_MAX_PEERS];

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
