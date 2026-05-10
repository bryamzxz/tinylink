// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// X25519 (Curve25519 Diffie-Hellman) — thin shim over agl's
// constant-time curve25519-donna. The scalarmult primitive itself
// lives in curve25519_donna.c (Google BSD-3, see file header). This
// shim adds: clamping is delegated to donna, low-order rejection,
// keypair generation against esp_fill_random, and pub-key derivation
// from a private key.

#include "curve25519.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include "esp_random.h"
#else
extern void esp_fill_random(void *buf, size_t len);
#endif

/* Provided by curve25519_donna.c — verbatim upstream agl/curve25519-donna. */
int curve25519_donna(uint8_t *mypublic, const uint8_t *secret,
                     const uint8_t *basepoint);

int curve25519_scalarmult(uint8_t q[CURVE25519_KEY_LEN],
                          const uint8_t n[CURVE25519_KEY_LEN],
                          const uint8_t p[CURVE25519_KEY_LEN])
{
    (void)curve25519_donna(q, n, p);

    /* Reject low-order outputs: an all-zero shared secret means the peer
     * fed us a low-order point. Constant-time check. */
    uint8_t acc = 0;
    for (int i = 0; i < CURVE25519_KEY_LEN; i++) acc |= q[i];
    return (acc == 0) ? -1 : 0;
}

int curve25519_keypair(uint8_t priv[CURVE25519_KEY_LEN],
                       uint8_t pub[CURVE25519_KEY_LEN])
{
    esp_fill_random(priv, CURVE25519_KEY_LEN);
    /* Clamp per RFC 7748 §5 — donna re-clamps internally but we keep the
     * stored priv in canonical clamped form so callers see a well-formed
     * scalar. */
    priv[0]  &= 0xF8;
    priv[31] &= 0x7F;
    priv[31] |= 0x40;
    return curve25519_derive_pub(pub, priv);
}

int curve25519_derive_pub(uint8_t pub[CURVE25519_KEY_LEN],
                          const uint8_t priv[CURVE25519_KEY_LEN])
{
    static const uint8_t basepoint[CURVE25519_KEY_LEN] = { 9 };
    /* Deriving the pub from a clamped priv against the basepoint cannot
     * land on a low-order output, so we ignore the low-order check here. */
    (void)curve25519_donna(pub, priv, basepoint);
    return 0;
}

int curve25519_dh(uint8_t shared[CURVE25519_KEY_LEN],
                  const uint8_t my_priv[CURVE25519_KEY_LEN],
                  const uint8_t peer_pub[CURVE25519_KEY_LEN])
{
    return curve25519_scalarmult(shared, my_priv, peer_pub);
}
