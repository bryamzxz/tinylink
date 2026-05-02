// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Salsa20 / HSalsa20 / XSalsa20, derived from DJB's public-domain
// reference implementations and NaCl's xsalsa20.c. Restructured for the
// tinylink coding style.

#include "salsa20.h"

#include <string.h>

static inline uint32_t load32_le(const uint8_t *p)
{
    return ((uint32_t)p[0])       |
           ((uint32_t)p[1] <<  8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline void store32_le(uint8_t *p, uint32_t w)
{
    p[0] = (uint8_t)(w);
    p[1] = (uint8_t)(w >>  8);
    p[2] = (uint8_t)(w >> 16);
    p[3] = (uint8_t)(w >> 24);
}

static inline uint32_t rotl32(uint32_t x, unsigned n)
{
    return (x << n) | (x >> (32 - n));
}

#define QR(a, b, c, d)                  \
    do {                                 \
        b ^= rotl32(a + d,  7);          \
        c ^= rotl32(b + a,  9);          \
        d ^= rotl32(c + b, 13);          \
        a ^= rotl32(d + c, 18);          \
    } while (0)

static void salsa20_doublerounds(uint32_t x[16], unsigned rounds)
{
    for (unsigned i = 0; i < rounds; i++) {
        QR(x[ 0], x[ 4], x[ 8], x[12]);
        QR(x[ 5], x[ 9], x[13], x[ 1]);
        QR(x[10], x[14], x[ 2], x[ 6]);
        QR(x[15], x[ 3], x[ 7], x[11]);
        QR(x[ 0], x[ 1], x[ 2], x[ 3]);
        QR(x[ 5], x[ 6], x[ 7], x[ 4]);
        QR(x[10], x[11], x[ 8], x[ 9]);
        QR(x[15], x[12], x[13], x[14]);
    }
}

/* "expand 32-byte k" split into four little-endian words. */
static const uint32_t SIGMA[4] = {
    0x61707865, 0x3320646E, 0x79622D32, 0x6B206574
};

static void salsa20_block(uint8_t out[64],
                          const uint32_t key0[8],
                          const uint32_t blk[4])
{
    uint32_t x[16];
    uint32_t in[16];

    in[ 0] = SIGMA[0];
    in[ 1] = key0[0];
    in[ 2] = key0[1];
    in[ 3] = key0[2];
    in[ 4] = key0[3];
    in[ 5] = SIGMA[1];
    in[ 6] = blk[0];
    in[ 7] = blk[1];
    in[ 8] = blk[2];
    in[ 9] = blk[3];
    in[10] = SIGMA[2];
    in[11] = key0[4];
    in[12] = key0[5];
    in[13] = key0[6];
    in[14] = key0[7];
    in[15] = SIGMA[3];

    memcpy(x, in, sizeof(x));
    salsa20_doublerounds(x, 10);
    for (int i = 0; i < 16; i++) {
        store32_le(out + 4 * i, x[i] + in[i]);
    }
}

void hsalsa20(uint8_t out[HSALSA20_OUT_LEN],
              const uint8_t key[SALSA20_KEY_LEN],
              const uint8_t nonce[16])
{
    uint32_t x[16];

    x[ 0] = SIGMA[0];
    x[ 1] = load32_le(key + 0);
    x[ 2] = load32_le(key + 4);
    x[ 3] = load32_le(key + 8);
    x[ 4] = load32_le(key + 12);
    x[ 5] = SIGMA[1];
    x[ 6] = load32_le(nonce + 0);
    x[ 7] = load32_le(nonce + 4);
    x[ 8] = load32_le(nonce + 8);
    x[ 9] = load32_le(nonce + 12);
    x[10] = SIGMA[2];
    x[11] = load32_le(key + 16);
    x[12] = load32_le(key + 20);
    x[13] = load32_le(key + 24);
    x[14] = load32_le(key + 28);
    x[15] = SIGMA[3];

    salsa20_doublerounds(x, 10);

    /* HSalsa20 output: x[0,5,10,15,6,7,8,9], no final add. */
    store32_le(out +  0, x[ 0]);
    store32_le(out +  4, x[ 5]);
    store32_le(out +  8, x[10]);
    store32_le(out + 12, x[15]);
    store32_le(out + 16, x[ 6]);
    store32_le(out + 20, x[ 7]);
    store32_le(out + 24, x[ 8]);
    store32_le(out + 28, x[ 9]);
}

void salsa20_keystream(uint8_t *out, size_t out_len,
                       const uint8_t key[SALSA20_KEY_LEN],
                       const uint8_t nonce[SALSA20_NONCE_LEN])
{
    uint32_t key0[8];
    uint32_t blk[4];
    uint8_t  block[64];
    uint64_t counter = 0;

    for (int i = 0; i < 8; i++) key0[i] = load32_le(key + 4 * i);
    blk[0] = load32_le(nonce + 0);
    blk[1] = load32_le(nonce + 4);
    blk[2] = 0;
    blk[3] = 0;

    while (out_len >= 64) {
        blk[2] = (uint32_t)(counter & 0xFFFFFFFFULL);
        blk[3] = (uint32_t)(counter >> 32);
        salsa20_block(out, key0, blk);
        counter++;
        out += 64;
        out_len -= 64;
    }
    if (out_len > 0) {
        blk[2] = (uint32_t)(counter & 0xFFFFFFFFULL);
        blk[3] = (uint32_t)(counter >> 32);
        salsa20_block(block, key0, blk);
        memcpy(out, block, out_len);
    }
}

void xsalsa20_keystream(uint8_t *out, size_t out_len,
                        const uint8_t key[SALSA20_KEY_LEN],
                        const uint8_t nonce[XSALSA20_NONCE_LEN])
{
    uint8_t subkey[HSALSA20_OUT_LEN];
    hsalsa20(subkey, key, nonce);
    salsa20_keystream(out, out_len, subkey, nonce + 16);
    /* Best-effort scrub. */
    memset(subkey, 0, sizeof(subkey));
}
