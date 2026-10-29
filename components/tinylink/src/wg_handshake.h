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
// The struct holds private keys and the chaining key: once transport
// keys have been derived, wipe the live Noise material with
// wg_handshake_scrub_live() (keeps the per-peer cache for the next
// attempt) and everything with wg_handshake_scrub() on teardown.

#pragma once

#include <stdint.h>

#include "wg_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

struct wg_handshake_state {
    /* --- Long-term identity (copied in by wg_handshake_init) -------- */
    uint8_t  local_static_priv[WG_KEY_LEN];
    uint8_t  local_static_pub[WG_KEY_LEN];
    uint8_t  peer_static_pub[WG_KEY_LEN];
    uint8_t  preshared_key[WG_KEY_LEN];   /* zero if no PSK */

    /* --- Per-peer cached derivations (valid while identity_valid) --- */
    uint8_t  mac1_key[WG_HASH_LEN];        /* BLAKE2s(LABEL_MAC1 || peer_pub):
                                            * mac1 of our INIT */
    uint8_t  mac1_key_self[WG_HASH_LEN];   /* BLAKE2s(LABEL_MAC1 || local_pub):
                                            * mac1 check of the response */
    uint8_t  static_static_dh[WG_KEY_LEN]; /* X25519(local_priv, peer_pub) */
    uint8_t  identity_valid;               /* identity + caches above are set */

    /* --- Live handshake state --------------------------------------- */
    uint8_t  chain_key[WG_HASH_LEN];
    uint8_t  hash[WG_HASH_LEN];
    uint8_t  ephemeral_priv[WG_KEY_LEN];
    uint8_t  ephemeral_pub[WG_KEY_LEN];
    uint32_t local_index;                  /* sender_index we picked */
    uint8_t  armed;                        /* an INIT was built and no response
                                            * accepted since: process_response
                                            * refuses an unarmed state */
};

/* Arm the state for a new handshake attempt. The per-peer derivations
 * (both mac1 keys and the static-static X25519) are computed only when
 * the identity differs from the one cached in *st — a new peer static
 * key, a regenerated local key or a new PSK — or the state was scrubbed;
 * otherwise only the live Noise material is reset, so a rekey or retry
 * costs no static DH (round 1.3.2, B11; wireguard-go likewise keeps
 * precomputedStaticStatic and the cookie generator's mac1 key per peer
 * and recomputes them on SetPrivateKey / a peer key change). The output
 * of wg_handshake_create_initiation is byte-identical either way.
 * Returns 0 on success or -1 if the static DH lands on a low-order point
 * (impossible with valid keys); *st is then wiped. */
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

/* Process a 92-byte MessageResponse from the responder. Validates
 * type, receiver_index against the local_index we picked, decrypts
 * the empty AEAD payload (the tag check is the actual handshake
 * authentication), derives transport keys via KDF2(C, ""), and
 * writes them into *send_key / *recv_key. Also returns the
 * responder's sender_index in *out_remote_index for transport-layer
 * routing.
 *
 *   send_key — encrypts our outbound transport packets (initiator → responder).
 *   recv_key — decrypts inbound transport packets (responder → initiator).
 *
 * Returns 0 on success, -1 on validation or decrypt failure. On
 * failure no transport keys are leaked. After a successful return,
 * the handshake state still holds long-term identity but its live
 * Noise material is no longer needed — the caller should eventually
 * scrub it. */
int wg_handshake_process_response(struct wg_handshake_state *st,
                                  const struct wg_msg_response *msg,
                                  uint8_t send_key[WG_KEY_LEN],
                                  uint8_t recv_key[WG_KEY_LEN],
                                  uint32_t *out_remote_index);

/* Wipe the live Noise material (chaining key, hash, ephemeral pair,
 * local index, armed) and keep the identity + per-peer cache for the
 * next attempt. Call once transport keys have been split. A scrubbed
 * state accepts no response until the next
 * wg_handshake_create_initiation. */
void wg_handshake_scrub_live(struct wg_handshake_state *st);

/* Wipe everything, cache included. Call on teardown or abort. */
void wg_handshake_scrub(struct wg_handshake_state *st);

#ifdef __cplusplus
}
#endif
