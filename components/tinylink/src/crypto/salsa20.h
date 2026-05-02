// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Salsa20, HSalsa20 and XSalsa20 (DJB). Used by NaCl-box and not by
// anything else in tinylink — keep them internal to crypto/.
//
// VERIFY against the reference test vectors in the Salsa20/XSalsa20
// specs before trusting in production.

#pragma once

#include <stddef.h>
#include <stdint.h>

#define SALSA20_KEY_LEN  32
#define SALSA20_NONCE_LEN 8
#define XSALSA20_NONCE_LEN 24
#define HSALSA20_OUT_LEN 32

#ifdef __cplusplus
extern "C" {
#endif

/* Subkey derivation. nonce is 16 bytes (the first half of an XSalsa20 nonce
 * or a fixed all-zero buffer for crypto_box_beforenm). */
void hsalsa20(uint8_t out[HSALSA20_OUT_LEN],
              const uint8_t key[SALSA20_KEY_LEN],
              const uint8_t nonce[16]);

/* Salsa20 stream cipher with a 32-byte key and 8-byte nonce. Generates
 * out_len bytes of keystream starting at block counter 0. */
void salsa20_keystream(uint8_t *out, size_t out_len,
                       const uint8_t key[SALSA20_KEY_LEN],
                       const uint8_t nonce[SALSA20_NONCE_LEN]);

/* XSalsa20 stream: 32-byte key + 24-byte nonce. */
void xsalsa20_keystream(uint8_t *out, size_t out_len,
                        const uint8_t key[SALSA20_KEY_LEN],
                        const uint8_t nonce[XSALSA20_NONCE_LEN]);

#ifdef __cplusplus
}
#endif
