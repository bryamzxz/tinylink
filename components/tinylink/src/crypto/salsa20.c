// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Salsa20 / HSalsa20 / XSalsa20, derived from DJB's public-domain
// reference implementations and NaCl's xsalsa20.c. Restructured for the
// tinylink coding style.

#include "salsa20.h"

#include <string.h>

#include "secure_zero.h"

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

/* Quarter-round (Salsa20 spec §3), two of them in lockstep so the two
 * rotates of a step share one SAR write. Xtensa: rotl(v, n) is SRC v,v
 * with SAR = 32 − n (ISA RM §8.3.2); GCC sets SAR before every `src`
 * itself, so it is set by hand once per step and each rotate is a bare
 * `src` — the scheme of chacha20.c / blake2s.c (round 1.3.3), on 16
 * scalar locals in pairs. Both asm statements are volatile, so their
 * order holds; nothing else in this file uses SAR. Hosts: C rotate. */
#if defined(__XTENSA__)
#define SET_SAR_ROTL(n) __asm__ volatile ("ssai %0" : : "i"(32 - (n)))
#define ROTL_SAR(v, n)  ({ uint32_t _r; \
                           __asm__ volatile ("src %0, %1, %1" : "=a"(_r) : "a"(v)); \
                           _r; })
#else
#define SET_SAR_ROTL(n) do { } while (0)
#define ROTL_SAR(v, n)  rotl32((v), (n))
#endif

#define QR_PAIR(a0, b0, c0, d0, a1, b1, c1, d1)                               \
    do {                                                                      \
        SET_SAR_ROTL(7);                                                      \
        b0 ^= ROTL_SAR(a0 + d0, 7);  b1 ^= ROTL_SAR(a1 + d1, 7);              \
        SET_SAR_ROTL(9);                                                      \
        c0 ^= ROTL_SAR(b0 + a0, 9);  c1 ^= ROTL_SAR(b1 + a1, 9);              \
        SET_SAR_ROTL(13);                                                     \
        d0 ^= ROTL_SAR(c0 + b0, 13); d1 ^= ROTL_SAR(c1 + b1, 13);             \
        SET_SAR_ROTL(18);                                                     \
        a0 ^= ROTL_SAR(d0 + c0, 18); a1 ^= ROTL_SAR(d1 + c1, 18);             \
    } while (0)

static void salsa20_doublerounds(uint32_t x[16], unsigned rounds)
{
    uint32_t x0 = x[0],   x1 = x[1],   x2 = x[2],   x3 = x[3];
    uint32_t x4 = x[4],   x5 = x[5],   x6 = x[6],   x7 = x[7];
    uint32_t x8 = x[8],   x9 = x[9],   x10 = x[10], x11 = x[11];
    uint32_t x12 = x[12], x13 = x[13], x14 = x[14], x15 = x[15];

    for (unsigned i = 0; i < rounds; i++) {
        /* columns */
        QR_PAIR(x0,  x4,  x8,  x12,  x5,  x9,  x13, x1);
        QR_PAIR(x10, x14, x2,  x6,   x15, x3,  x7,  x11);
        /* rows */
        QR_PAIR(x0,  x1,  x2,  x3,   x5,  x6,  x7,  x4);
        QR_PAIR(x10, x11, x8,  x9,   x15, x12, x13, x14);
    }

    x[0] = x0;   x[1] = x1;   x[2] = x2;   x[3] = x3;
    x[4] = x4;   x[5] = x5;   x[6] = x6;   x[7] = x7;
    x[8] = x8;   x[9] = x9;   x[10] = x10; x[11] = x11;
    x[12] = x12; x[13] = x13; x[14] = x14; x[15] = x15;
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
    /* Scrub the derived subkey (CWE-14). */
    tl_secure_zero(subkey, sizeof(subkey));
}
