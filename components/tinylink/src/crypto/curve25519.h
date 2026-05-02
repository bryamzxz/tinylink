// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// X25519 (Curve25519 Diffie-Hellman) wrapper.
//
// IMPLEMENTATION NOTE — READ BEFORE PRODUCTION:
//
//   The curve25519.c file shipped here is a TweetNaCl-derived reference.
//   TweetNaCl was *designed* to be constant-time, but it is not as
//   carefully audited as the canonical "donna" implementation.
//
//   For production use, drop in the constant-time curve25519-donna
//   sources from trombik/esp_wireguard (src/crypto/x25519.c, ~600 LoC,
//   BSD-3) by replacing this file. Keep the public symbols
//   (curve25519_scalarmult, curve25519_keypair, curve25519_dh,
//   curve25519_derive_pub) so call sites compile unchanged.
//
//   tinylink uses X25519 on every ts2021 handshake, so the long-term
//   MachineKey private key is exposed to timing-channel attacks if this
//   placeholder is shipped to a production sensor. See
//   docs/SECURITY-MODEL.md.
//
// VERIFY against RFC 7748 §6 test vectors before trusting in production.

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
