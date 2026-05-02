// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// ChaCha20-Poly1305 AEAD per RFC 8439 §2.8. Wraps the lifted ChaCha20
// keystream and Andrew Moon's poly1305-donna MAC into the IETF AEAD
// construction (the actual security-critical glue: pad16 of AAD,
// pad16 of ciphertext, LE u64 length encoding, constant-time tag
// verify). This wrapper is tinylink's own code, not lifted, because
// the AEAD composition is exactly where most ChaCha20-Poly1305 CVEs
// historically live.
//
// Validated end-to-end by the host KAT against RFC 8439 §2.8.2.

#pragma once

#include <stddef.h>
#include <stdint.h>

#define CHACHA20POLY1305_KEY_LEN   32
#define CHACHA20POLY1305_NONCE_LEN 12
#define CHACHA20POLY1305_TAG_LEN   16

#ifdef __cplusplus
extern "C" {
#endif

/* AEAD encryption per RFC 8439 §2.8.1.
 *
 *   out: caller-allocated, mlen + 16 bytes (ciphertext || tag).
 *   m:   plaintext, mlen bytes (may be NULL iff mlen == 0).
 *   aad: associated data, aad_len bytes (may be NULL iff aad_len == 0).
 *   key: 32-byte key.
 *   nonce: 12-byte nonce. Must be unique per (key, nonce) pair —
 *          reuse breaks both confidentiality and authenticity. WG
 *          callers construct this as 4 zero bytes || 8 LE counter
 *          bytes; that maps directly to RFC 8439's nonce shape.
 *
 * mlen is bounded by 2^32-1 (chacha20() takes uint32_t). For WG
 * transport packets (≤ ~64 KB) this is far above any expected use. */
void chacha20poly1305_encrypt(uint8_t *out,
                              const uint8_t *m, size_t mlen,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t key[CHACHA20POLY1305_KEY_LEN],
                              const uint8_t nonce[CHACHA20POLY1305_NONCE_LEN]);

/* AEAD decryption with constant-time tag verification.
 *
 *   out: caller-allocated, clen - 16 bytes (plaintext).
 *   c:   ciphertext || tag, clen bytes (must be ≥ 16).
 *   Other params as above.
 *
 * Returns 0 on success. Returns -1 if clen < 16 or if the tag does
 * not match — in either case, *out is untouched and no plaintext is
 * leaked. */
int chacha20poly1305_decrypt(uint8_t *out,
                             const uint8_t *c, size_t clen,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t key[CHACHA20POLY1305_KEY_LEN],
                             const uint8_t nonce[CHACHA20POLY1305_NONCE_LEN]);

#ifdef __cplusplus
}
#endif
