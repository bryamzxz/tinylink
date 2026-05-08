// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// WireGuard wire-format constants, message layouts and protocol-level
// helpers used by the handshake and transport layers. This is the
// "what's on the wire" file; the actual handshake state machine lives
// in wg_handshake.{c,h} and transport encryption in wg_transport.{c,h}.
//
// Reference: WireGuard whitepaper (Donenfeld 2017), §5.4 "Handshake
// and Data Messages".

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Sizes ----------------------------------------------------------- */

#define WG_KEY_LEN          32   /* X25519 public/private + symmetric keys */
#define WG_HASH_LEN         32   /* BLAKE2s digest used everywhere */
#define WG_TAI64N_LEN       12   /* 8 B big-endian secs + 4 B big-endian ns */
#define WG_TAG_LEN          16   /* AEAD tag */
#define WG_MAC_LEN          16   /* mac1 / mac2 */
#define WG_INDEX_LEN         4   /* sender / receiver index */

/* --- Message types --------------------------------------------------- */

#define WG_MSG_INITIATION    1
#define WG_MSG_RESPONSE      2
#define WG_MSG_COOKIE_REPLY  3
#define WG_MSG_TRANSPORT     4

/* --- Protocol constants (Noise IKpsk2 + WireGuard) ------------------- */

/* "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" — exactly 37 bytes. */
extern const uint8_t WG_CONSTRUCTION[37];
/* "WireGuard v1 zx2c4 Jason@zx2c4.com" — exactly 34 bytes. */
extern const uint8_t WG_IDENTIFIER[34];
/* "mac1----" — 8 bytes. */
extern const uint8_t WG_LABEL_MAC1[8];
/* "cookie--" — 8 bytes. */
extern const uint8_t WG_LABEL_COOKIE[8];

/* --- Wire-format messages -------------------------------------------- */

/* MessageInitiation, 148 bytes, all integers little-endian. */
struct __attribute__((packed)) wg_msg_initiation {
    uint8_t  message_type;        /* WG_MSG_INITIATION = 1 */
    uint8_t  reserved[3];         /* zero */
    uint32_t sender_index;        /* random; we choose */
    uint8_t  ephemeral[WG_KEY_LEN];
    uint8_t  encrypted_static[WG_KEY_LEN + WG_TAG_LEN];
    uint8_t  encrypted_timestamp[WG_TAI64N_LEN + WG_TAG_LEN];
    uint8_t  mac1[WG_MAC_LEN];
    uint8_t  mac2[WG_MAC_LEN];
};
_Static_assert(sizeof(struct wg_msg_initiation) == 148,
               "wg_msg_initiation must be 148 bytes");

/* MessageResponse, 92 bytes. */
struct __attribute__((packed)) wg_msg_response {
    uint8_t  message_type;        /* WG_MSG_RESPONSE = 2 */
    uint8_t  reserved[3];
    uint32_t sender_index;        /* responder's index */
    uint32_t receiver_index;      /* echoes our sender_index */
    uint8_t  ephemeral[WG_KEY_LEN];
    uint8_t  encrypted_nothing[0 + WG_TAG_LEN];  /* empty payload, just tag */
    uint8_t  mac1[WG_MAC_LEN];
    uint8_t  mac2[WG_MAC_LEN];
};
_Static_assert(sizeof(struct wg_msg_response) == 92,
               "wg_msg_response must be 92 bytes");

/* --- Initial constants (lazy-initialized at first call) -------------- */

/* INITIAL_CHAIN_KEY = BLAKE2s(WG_CONSTRUCTION).
 * INITIAL_HASH      = BLAKE2s(INITIAL_CHAIN_KEY || WG_IDENTIFIER).
 * Both are deterministic 32-byte values; we compute them once and
 * cache. Use wg_proto_init_constants() lazily via wg_*_chain_key/hash. */
const uint8_t *wg_initial_chain_key(void);
const uint8_t *wg_initial_hash(void);

/* --- Protocol helpers ------------------------------------------------- */

/* Noise/WG mix-hash:  H ← BLAKE2s(H || data). In place on h. */
void wg_mix_hash(uint8_t h[WG_HASH_LEN],
                 const uint8_t *data, size_t data_len);

/* Noise/WG mix-key:  (C, k) ← KDF2(C, x). C in place on ck, k written
 * to *out_key. */
void wg_mix_key(uint8_t ck[WG_HASH_LEN],
                const uint8_t *x, size_t x_len,
                uint8_t out_key[WG_KEY_LEN]);

/* WG KDF1 wrapper:  C ← KDF1(C, x). In place on ck. */
void wg_mix_chain_only(uint8_t ck[WG_HASH_LEN],
                       const uint8_t *x, size_t x_len);

/* mac1 key derivation: K = BLAKE2s(LABEL_MAC1 || responder_static_pub).
 * The result can be cached per peer. */
void wg_mac1_key(uint8_t out_key[WG_HASH_LEN],
                 const uint8_t responder_static_pub[WG_KEY_LEN]);

/* Keyed BLAKE2s-128 over `data` with the given 32-byte key, producing
 * a 16-byte MAC. Used for mac1 and mac2 fields. */
void wg_keyed_mac16(uint8_t out_mac[WG_MAC_LEN],
                    const uint8_t key[WG_HASH_LEN],
                    const uint8_t *data, size_t data_len);

/* TAI64N "now". Falls back to seconds-since-boot if the clock has not
 * been synced (we have no SNTP yet). The WG responder accepts any
 * monotonically-increasing value from the same peer, so an unsynced
 * clock works for first-handshake bring-up; it will misorder against
 * a peer that knew us pre-reboot. Real wall-clock sync lands in M7. */
void wg_tai64n_now(uint8_t out[WG_TAI64N_LEN]);

#ifdef __cplusplus
}
#endif
