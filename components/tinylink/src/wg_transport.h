// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// WireGuard transport layer — encrypt/decrypt of data packets after the
// handshake has split the chain key into per-direction transport keys.
//
// Wire format (per WG whitepaper §5.4.6, total = 16 + plaintext + 16):
//
//   u8  message_type    = 4
//   u8  reserved[3]     = 0
//   u32 receiver_index  (peer's sender_index from the handshake)
//   u64 counter         (LE, monotonic per session)
//   u8  encrypted[len + 16]   AEAD ciphertext + tag, AAD empty
//
// The 12-byte ChaCha20-Poly1305 nonce is constructed as 4 zero bytes
// followed by the 8-byte LE counter, matching RFC 8439's nonce shape.
//
// Anti-replay uses an RFC 6479 sliding window of 8192 bits per session.

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "wg_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WG_TRANSPORT_HEADER_LEN 16   /* type+reserved+receiver_index+counter */
#define WG_TRANSPORT_OVERHEAD   (WG_TRANSPORT_HEADER_LEN + WG_TAG_LEN)

/* RFC 6479 anti-replay window: 8192 bits = 1 KiB bitmap. */
#define WG_REPLAY_WINDOW_BITS   8192
#define WG_REPLAY_WINDOW_BYTES  (WG_REPLAY_WINDOW_BITS / 8)

struct wg_replay_window {
    uint64_t highest;  /* highest counter accepted so far */
    uint8_t  bitmap[WG_REPLAY_WINDOW_BYTES];
};

struct wg_transport_session {
    uint8_t  send_key[WG_KEY_LEN];
    uint8_t  recv_key[WG_KEY_LEN];
    uint32_t local_index;     /* our sender_index */
    uint32_t remote_index;    /* peer's sender_index */
    uint64_t send_counter;    /* increments per send; the value used by
                                 next encrypt is *post*-fetch-and-add */
    struct wg_replay_window replay;
};

/* Initialize a session from handshake outputs. Copies keys (so the
 * caller can scrub their handshake state immediately) and zeroes the
 * counter and replay window. */
void wg_transport_session_init(struct wg_transport_session *s,
                               uint32_t local_index,
                               uint32_t remote_index,
                               const uint8_t send_key[WG_KEY_LEN],
                               const uint8_t recv_key[WG_KEY_LEN]);

/* Encrypt a plaintext IP packet for the wire. Writes 16 + plen + 16
 * bytes to `out` (header + ciphertext + tag) and returns the total
 * wire length. Increments the session's send_counter.
 *
 * Returns negative on failure (out_size too small, counter exhausted). */
int wg_transport_encrypt(struct wg_transport_session *s,
                         uint8_t *out, size_t out_size,
                         const uint8_t *plaintext, size_t plen);

/* Decrypt an on-wire packet. Validates header, runs the replay window
 * check, AEAD-decrypts. On success writes the recovered plaintext to
 * `out` (size at most wire_len - 32) and stores its length in
 * *out_len. On failure (header mismatch, replay, bad tag) returns -1
 * and `out` / *out_len are not touched in a way that could leak. */
int wg_transport_decrypt(struct wg_transport_session *s,
                         const uint8_t *wire, size_t wire_len,
                         uint8_t *out, size_t out_size,
                         size_t *out_len);

/* Test-friendly hook: check + update the replay window for a counter,
 * without doing any AEAD work. Returns 0 if accepted, -1 if rejected
 * (replay, too old, or counter at sentinel). */
int wg_replay_check_and_update(struct wg_replay_window *w, uint64_t counter);

#ifdef __cplusplus
}
#endif
