// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// X25519 (Curve25519 Diffie-Hellman) wrapper.
//
// The scalarmult primitive is curve25519-donna (Adam Langley, Google
// BSD-3, see crypto/curve25519_donna.c). Donna is the canonical
// constant-time 32-bit X25519 implementation and is the right fit for
// the Xtensa LX6. RFC 7748 §5.2 / §6.1 vectors are checked in
// tools/test/test_curve25519.c.

#pragma once

#include <stdint.h>

#define CURVE25519_KEY_LEN 32

#ifdef __cplusplus
extern "C" {
#endif

/* q = scalar * p. Returns 0 on success, -1 if p is a low-order point. */
int curve25519_scalarmult(uint8_t q[CURVE25519_KEY_LEN],
                          const uint8_t scalar[CURVE25519_KEY_LEN],
                          const uint8_t p[CURVE25519_KEY_LEN]);

/* Generates a Curve25519 keypair using esp_fill_random as the entropy
 * source. The private key is clamped per RFC 7748 §5. */
int curve25519_keypair(uint8_t priv[CURVE25519_KEY_LEN],
                       uint8_t pub[CURVE25519_KEY_LEN]);

/* Standard X25519 DH: shared = my_priv * peer_pub. Returns 0 on success
 * and -1 if peer_pub is a low-order point (the shared secret is then all
 * zero, which we treat as a hard failure). */
int curve25519_dh(uint8_t shared[CURVE25519_KEY_LEN],
                  const uint8_t my_priv[CURVE25519_KEY_LEN],
                  const uint8_t peer_pub[CURVE25519_KEY_LEN]);

/* Derives the public key from a clamped private key, no DH involved. */
int curve25519_derive_pub(uint8_t pub[CURVE25519_KEY_LEN],
                          const uint8_t priv[CURVE25519_KEY_LEN]);

#ifdef __cplusplus
}
#endif
