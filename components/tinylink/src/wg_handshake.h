// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// WireGuard initiator-side handshake state machine. tinylink only ever
// initiates a handshake (we never accept incoming) which lets us drop
// half the spec — no cookie generation, no rate-limiting on receive,
// no responder mac2 validation. The flow is:
//
//   1. wg_handshake_init(state, local_static_priv, local_static_pub,
//                        peer_static_pub, optional_psk)
//   2. wg_handshake_create_initiation(state, &msg) -> 148 B on the wire
//   3. send msg over UDP, wait for MessageResponse
//   4. wg_handshake_process_response(state, &resp, send_key, recv_key)
//                                                          [step 3b]
//
// All intermediate Noise state lives in `struct wg_handshake_state`.
// The struct holds private keys and the chaining key, so callers MUST
// scrub it (memset 0) once transport keys have been derived.

#pragma once

#include <stdint.h>

#include "wg_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

struct wg_handshake_state {
    /* --- Long-term identity (caller-provided, not owned) ----------- */
    uint8_t  local_static_priv[WG_KEY_LEN];
    uint8_t  local_static_pub[WG_KEY_LEN];
    uint8_t  peer_static_pub[WG_KEY_LEN];
    uint8_t  preshared_key[WG_KEY_LEN];   /* zero if no PSK */

    /* --- Per-peer cached derivations -------------------------------- */
    uint8_t  mac1_key[WG_HASH_LEN];        /* BLAKE2s(LABEL_MAC1 || peer_pub) */
    uint8_t  static_static_dh[WG_KEY_LEN]; /* X25519(local_priv, peer_pub) */

    /* --- Live handshake state --------------------------------------- */
    uint8_t  chain_key[WG_HASH_LEN];
    uint8_t  hash[WG_HASH_LEN];
    uint8_t  ephemeral_priv[WG_KEY_LEN];
    uint8_t  ephemeral_pub[WG_KEY_LEN];
    uint32_t local_index;                  /* sender_index we picked */
};

/* One-time setup. Caches mac1_key and static_static_dh (the long-lived
 * X25519 of our private with the peer's public) so subsequent handshake
 * attempts don't re-do the work. Returns 0 on success or -1 if the
 * static DH lands on a low-order point (impossible with valid keys). */
int wg_handshake_init(struct wg_handshake_state *st,
                      const uint8_t local_static_priv[WG_KEY_LEN],
                      const uint8_t local_static_pub[WG_KEY_LEN],
                      const uint8_t peer_static_pub[WG_KEY_LEN],
                      const uint8_t preshared_key[WG_KEY_LEN]);

/* Build a fresh MessageInitiation. Generates a new ephemeral pair,
 * derives the chaining state, encrypts our static pubkey + a TAI64N
 * timestamp, computes mac1, and writes 148 bytes to *msg. mac2 is
 * always zero (we never receive a cookie reply because we never get
 * rate-limited as an outbound-only initiator).
 *
 * `local_index` is the sender_index assigned to this attempt; pass a
 * non-zero, never-reused value (typically a random uint32). The
 * responder will echo it back as receiver_index in MessageResponse. */
int wg_handshake_create_initiation(struct wg_handshake_state *st,
                                   uint32_t local_index,
                                   struct wg_msg_initiation *msg);

/* Wipe sensitive material in the state. Call after transport keys have
 * been split, or on abort. */
void wg_handshake_scrub(struct wg_handshake_state *st);

#ifdef __cplusplus
}
#endif
