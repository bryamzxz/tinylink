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
//
// Split encrypt / decrypt (round 1.3.3, C2). Until 1.3.2 the caller held
// its session lock across the whole AEAD (~400 µs per MTU), so RX and TX
// could never run their crypto on both cores at once. Now each direction
// is two or three steps and only the short ones touch the session:
//
//   TX:  lock { wg_transport_tx_reserve }   seal (AEAD, unlocked)
//   RX:  lock { wg_transport_rx_begin }     open (AEAD, unlocked)
//        lock { wg_transport_rx_commit }
//
// The unlocked steps work on a ticket that holds a COPY of the key, made
// under the lock, so no AEAD ever reads key bytes a rekey or a scrub is
// rewriting (seal and open wipe the copy before they return). An RX
// ticket also carries the session's keypair generation: every
// wg_transport_session_init and wg_transport_session_scrub takes a new
// one, and rx_commit refuses a ticket of an older keypair — its packet
// was authenticated under keys whose replay window no longer exists. The
// replay window is checked in rx_begin (cheap reject before the AEAD,
// S1) and checked again and updated in rx_commit, only after the tag
// verified: a second task may have accepted the same counter in between
// (the DERP and direct copies of one packet, dual-path send).

#pragma once

#include <stdbool.h>
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
    uint32_t gen;             /* keypair generation (C2), see above */
    bool     valid;           /* keys installed and not scrubbed */
    struct wg_replay_window replay;
};

/* One outbound packet between reserve and seal: a copy of the send key
 * with the counter reserved for it, so (key, counter) always come from
 * the same keypair and no counter is handed out twice. */
struct wg_tx_ticket {
    uint8_t  key[WG_KEY_LEN];
    uint64_t counter;
    uint32_t remote_index;
};

/* One inbound packet between rx_begin and rx_commit. */
struct wg_rx_ticket {
    uint8_t  key[WG_KEY_LEN];
    uint64_t counter;
    uint32_t gen;
    size_t   plen;            /* plaintext length the packet opens to */
};

/* wg_transport_rx_commit results besides 0. */
#define WG_TRANSPORT_RX_REPLAY  (-1)   /* counter accepted meanwhile / now too old */
#define WG_TRANSPORT_RX_STALE   (-2)   /* keypair replaced or scrubbed since begin */

/* Initialize a session from handshake outputs. Copies keys (so the
 * caller can scrub their handshake state immediately), zeroes the
 * counter and replay window and takes a new keypair generation. Need
 * not be zeroed first. */
void wg_transport_session_init(struct wg_transport_session *s,
                               uint32_t local_index,
                               uint32_t remote_index,
                               const uint8_t send_key[WG_KEY_LEN],
                               const uint8_t recv_key[WG_KEY_LEN]);

/* Wipe the session (keys, indices, window) and take a new generation:
 * outstanding RX tickets fail their commit, reserve / rx_begin refuse
 * until the next session_init. */
void wg_transport_session_scrub(struct wg_transport_session *s);

/* TX, under the caller's session lock: reserve the next counter and copy
 * the send key and peer index into `t`. -1 (nothing reserved) when no
 * keys are installed or the counter is exhausted. */
int wg_transport_tx_reserve(struct wg_transport_session *s,
                            struct wg_tx_ticket *t);

/* TX, no lock: write header + AEAD(plaintext) for the ticket's counter
 * to `out` and return the wire length (16 + plen + 16), or -1 if
 * out_size is too small (the reserved counter is then simply never
 * used). Scrubs t->key in both cases. */
int wg_transport_tx_seal(struct wg_tx_ticket *t,
                         uint8_t *out, size_t out_size,
                         const uint8_t *plaintext, size_t plen);

/* RX, under the lock: validate the header and receiver index, run the
 * replay pre-check and, if the packet may be accepted and opens to at
 * most max_plen bytes, fill `t` (key copy, counter, generation, plen) and
 * return 0. -1 otherwise; `t` then holds no key material. */
int wg_transport_rx_begin(const struct wg_transport_session *s,
                          const uint8_t *wire, size_t wire_len,
                          size_t max_plen, struct wg_rx_ticket *t);

/* RX, no lock: verify the tag of the packet given to rx_begin and decrypt
 * it into `out` (t->plen bytes; may be NULL when t->plen is 0). 0 on
 * success, -1 on a bad tag (out untouched) or a wire_len that is not the
 * one rx_begin saw. Scrubs t->key in every case. */
int wg_transport_rx_open(struct wg_rx_ticket *t,
                         const uint8_t *wire, size_t wire_len,
                         uint8_t *out);

/* RX, under the lock, after a successful rx_open: 0 = accepted and
 * recorded in the window; WG_TRANSPORT_RX_STALE = the ticket's keypair
 * is gone; WG_TRANSPORT_RX_REPLAY = another task accepted this counter
 * since rx_begin, or the window moved past it. Drop the packet on any
 * non-zero result. */
int wg_transport_rx_commit(struct wg_transport_session *s,
                           const struct wg_rx_ticket *t);

/* Scrub a ticket that will not reach seal / open (an error path between
 * the steps). */
void wg_transport_ticket_scrub(void *ticket, size_t len);

/* Encrypt a plaintext IP packet for the wire. Writes 16 + plen + 16
 * bytes to `out` (header + ciphertext + tag) and returns the total
 * wire length. Increments the session's send_counter. tx_reserve +
 * tx_seal in one call, for a caller that owns `s` outright (tests).
 *
 * Returns negative on failure (out_size too small, counter exhausted,
 * no keys). */
int wg_transport_encrypt(struct wg_transport_session *s,
                         uint8_t *out, size_t out_size,
                         const uint8_t *plaintext, size_t plen);

/* Decrypt an on-wire packet: rx_begin + rx_open + rx_commit in one call
 * (same single-owner caveat). Validates header, runs the replay window check, AEAD-decrypts, and
 * only then records the counter in the window (a forgery never moves
 * it). On success writes the recovered plaintext to `out` (size at most
 * wire_len - 32) and stores its length in *out_len. On failure (header
 * mismatch, replay, bad tag) returns -1 and `out` / *out_len are not
 * touched in a way that could leak. */
int wg_transport_decrypt(struct wg_transport_session *s,
                         const uint8_t *wire, size_t wire_len,
                         uint8_t *out, size_t out_size,
                         size_t *out_len);

/* Anti-replay window, split so the decrypt path can authenticate
 * between the two steps: wg_replay_check() returns 0 if `counter` would
 * be accepted and -1 if rejected (replay, too old, or the sentinel)
 * without touching the window; wg_replay_update() records an accepted
 * counter. wg_replay_check_and_update() is both, for tests. */
int  wg_replay_check(const struct wg_replay_window *w, uint64_t counter);
void wg_replay_update(struct wg_replay_window *w, uint64_t counter);
int  wg_replay_check_and_update(struct wg_replay_window *w, uint64_t counter);

#ifdef __cplusplus
}
#endif
