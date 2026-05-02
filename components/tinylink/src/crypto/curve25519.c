// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// X25519 (Curve25519) — TweetNaCl-derived reference implementation.
// Original public-domain code by Bernstein/Janssen/Lange/Schwabe/van
// Gastel <https://tweetnacl.cr.yp.to/>. Re-formatted for the tinylink
// coding style; algorithm is unchanged.
//
// READ THE WARNING IN curve25519.h BEFORE TRUSTING THIS FILE IN
// PRODUCTION. Swap with constant-time donna from trombik/esp_wireguard
// (src/crypto/x25519.c).

#include "curve25519.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include "esp_random.h"
#else
/* Host build: tests must provide their own esp_fill_random definition. */
extern void esp_fill_random(void *buf, size_t len);
#endif

typedef int64_t gf[16];

static const gf gf_121665 = {0xDB41, 1};

static void car25519(gf o)
{
    int64_t c;
    for (int i = 0; i < 16; i++) {
        o[i] += (1LL << 16);
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel25519(gf p, gf q, int b)
{
    int64_t t;
    int64_t c = ~(b - 1);
    for (int i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n)
{
    gf t, m;
    int b;

    for (int i = 0; i < 16; i++) t[i] = n[i];
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; j++) {
        m[0] = t[0] - 0xFFED;
        for (int i = 1; i < 15; i++) {
            m[i] = t[i] - 0xFFFF - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xFFFF;
        }
        m[15] = t[15] - 0x7FFF - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xFFFF;
        sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; i++) {
        o[2 * i]     = (uint8_t)(t[i] & 0xFF);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const uint8_t *n)
{
    for (int i = 0; i < 16; i++) {
        o[i] = (int64_t)n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    }
    o[15] &= 0x7FFF;
}

static void A(gf o, const gf a, const gf b)
{
    for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
}

static void Z(gf o, const gf a, const gf b)
{
    for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
}

static void M(gf o, const gf a, const gf b)
{
    int64_t t[31] = {0};
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 16; j++) {
            t[i + j] += a[i] * b[j];
        }
    }
    for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; i++) o[i] = t[i];
    car25519(o);
    car25519(o);
}

static void S(gf o, const gf a)
{
    M(o, a, a);
}

static void inv25519(gf o, const gf i)
{
    gf c;
    for (int a = 0; a < 16; a++) c[a] = i[a];
    for (int a = 253; a >= 0; a--) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    for (int a = 0; a < 16; a++) o[a] = c[a];
}

int curve25519_scalarmult(uint8_t q[CURVE25519_KEY_LEN],
                          const uint8_t n[CURVE25519_KEY_LEN],
                          const uint8_t p[CURVE25519_KEY_LEN])
{
    uint8_t z[32];
    int64_t r;
    gf x, a, b, c, d, e, f;

    for (int i = 0; i < 31; i++) z[i] = n[i];
    z[31] = (uint8_t)((n[31] & 0x7F) | 0x40);
    z[0] &= 0xF8;
    unpack25519(x, p);
    for (int i = 0; i < 16; i++) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (int i = 254; i >= 0; i--) {
        r = (z[i >> 3] >> (i & 7)) & 1;
        sel25519(a, b, (int)r);
        sel25519(c, d, (int)r);
        A(e, a, c);
        Z(a, a, c);
        A(c, b, d);
        Z(b, b, d);
        S(d, e);
        S(f, a);
        M(a, c, a);
        M(c, b, e);
        A(e, a, c);
        Z(a, a, c);
        S(b, a);
        Z(c, d, f);
        M(a, c, gf_121665);
        A(a, a, d);
        M(c, c, a);
        M(a, d, f);
        M(d, b, x);
        S(b, e);
        sel25519(a, b, (int)r);
        sel25519(c, d, (int)r);
    }
    inv25519(c, c);
    M(a, a, c);
    pack25519(q, a);

    /* Reject low-order outputs: an all-zero shared secret means the peer
     * fed us a low-order point. Constant-time check. */
    int nonzero = 0;
    for (int i = 0; i < 32; i++) nonzero |= q[i];
    return (nonzero == 0) ? -1 : 0;
}

int curve25519_keypair(uint8_t priv[CURVE25519_KEY_LEN],
                       uint8_t pub[CURVE25519_KEY_LEN])
{
    esp_fill_random(priv, CURVE25519_KEY_LEN);
    /* Clamp per RFC 7748 §5. */
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
    (void)curve25519_scalarmult(pub, priv, basepoint);
    return 0;
}

int curve25519_dh(uint8_t shared[CURVE25519_KEY_LEN],
                  const uint8_t my_priv[CURVE25519_KEY_LEN],
                  const uint8_t peer_pub[CURVE25519_KEY_LEN])
{
    return curve25519_scalarmult(shared, my_priv, peer_pub);
}
