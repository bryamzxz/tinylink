// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// NaCl crypto_box: Curve25519 + XSalsa20 + Poly1305. Used by tinylink for
// the EarlyNoise NodeKey signature step in ts2021.
//
// API differs from the original NaCl in that we DO NOT require the
// 32-byte / 16-byte zero-prefix convention. Callers pass plain (m, mlen)
// and we return ciphertext of length mlen + NACL_BOX_TAG_LEN.

#pragma once

#include <stddef.h>
#include <stdint.h>

#define NACL_BOX_KEY_LEN   32
#define NACL_BOX_NONCE_LEN 24
#define NACL_BOX_TAG_LEN   16

#ifdef __cplusplus
extern "C" {
#endif

/* c is mlen + NACL_BOX_TAG_LEN bytes long.
 * Returns 0 on success, -1 if the X25519 produces an all-zero shared. */
int nacl_box(uint8_t *c,
             const uint8_t *m, size_t mlen,
             const uint8_t nonce[NACL_BOX_NONCE_LEN],
             const uint8_t peer_pub[NACL_BOX_KEY_LEN],
             const uint8_t my_priv[NACL_BOX_KEY_LEN]);

/* m is clen - NACL_BOX_TAG_LEN bytes long.
 * Returns 0 on success, -1 on auth failure (constant-time tag compare). */
int nacl_box_open(uint8_t *m,
                  const uint8_t *c, size_t clen,
                  const uint8_t nonce[NACL_BOX_NONCE_LEN],
                  const uint8_t peer_pub[NACL_BOX_KEY_LEN],
                  const uint8_t my_priv[NACL_BOX_KEY_LEN]);

#ifdef __cplusplus
}
#endif
