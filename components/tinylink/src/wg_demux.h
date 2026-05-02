// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Pure-C UDP datagram classifier. The single UDP socket the WG engine
// owns multiplexes WireGuard handshake / transport, DISCO ping-pong
// (step 7), and STUN binding requests (M4). This module classifies an
// incoming datagram by inspecting its first bytes — no I/O, no state —
// so the policy is host-testable and shared between the WG dispatcher
// and any future DISCO/STUN handlers.
//
// Routing keys (per WG whitepaper §5.4 + Tailscale DISCO §C):
//
//   first byte 0x01 → MessageInitiation       (148 B exactly)
//   first byte 0x02 → MessageResponse         ( 92 B exactly)
//   first byte 0x03 → MessageCookieReply      ( 64 B exactly)
//   first byte 0x04 → MessageTransport        (≥ 32 B; 16 hdr + 16 tag)
//   first byte 0x00 0x01 → STUN binding request (RFC 5389 first 2 bytes)
//   6-byte prefix "TS💬" (\x54\x53\xf0\x9f\x92\xac) → DISCO v1 (step 7)
//   anything else → discard

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WG_DEMUX_DISCARD = 0,
    WG_DEMUX_HANDSHAKE_INIT,
    WG_DEMUX_HANDSHAKE_RESP,
    WG_DEMUX_HANDSHAKE_COOKIE,
    WG_DEMUX_TRANSPORT,
    WG_DEMUX_STUN,
    WG_DEMUX_DISCO,
} wg_demux_kind_t;

/* Classify a UDP datagram by inspecting its leading bytes. Pure
 * function: same input always returns the same kind, no side effects.
 * Discards any datagram that does not match a known shape (including
 * size mismatches that would crash a downstream parser). */
wg_demux_kind_t wg_demux_classify(const uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif
