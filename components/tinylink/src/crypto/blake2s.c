// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// BLAKE2s-256, derived from the RFC 7693 reference C implementation
// (Markku-Juhani O. Saarinen, public domain / CC0). Restructured for the
// tinylink coding style. Algorithm and constants are unchanged from the
// RFC reference.
//
// VERIFY against RFC 7693 Appendix A test vectors before trusting in
// production. tinylink uses BLAKE2s as the hash inside Noise IK and HKDF
// — a wrong byte here breaks the whole control-plane handshake.

#include "blake2s.h"

#include <string.h>

static const uint32_t blake2s_iv[8] = {
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL,
};

static const uint8_t blake2s_sigma[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
};

static inline uint32_t load32(const void *src)
{
    const uint8_t *p = (const uint8_t *)src;
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] <<  8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static inline void store32(void *dst, uint32_t w)
{
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)(w);
    p[1] = (uint8_t)(w >>  8);
    p[2] = (uint8_t)(w >> 16);
    p[3] = (uint8_t)(w >> 24);
}

static inline uint32_t rotr32(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

#define G(r, i, a, b, c, d)                          \
    do {                                              \
        a = a + b + m[blake2s_sigma[r][2*i+0]];       \
        d = rotr32(d ^ a, 16);                        \
        c = c + d;                                    \
        b = rotr32(b ^ c, 12);                        \
        a = a + b + m[blake2s_sigma[r][2*i+1]];       \
        d = rotr32(d ^ a, 8);                         \
        c = c + d;                                    \
        b = rotr32(b ^ c, 7);                         \
    } while (0)

#define ROUND(r)                                      \
    do {                                              \
        G(r, 0, v[ 0], v[ 4], v[ 8], v[12]);          \
        G(r, 1, v[ 1], v[ 5], v[ 9], v[13]);          \
        G(r, 2, v[ 2], v[ 6], v[10], v[14]);          \
        G(r, 3, v[ 3], v[ 7], v[11], v[15]);          \
        G(r, 4, v[ 0], v[ 5], v[10], v[15]);          \
        G(r, 5, v[ 1], v[ 6], v[11], v[12]);          \
        G(r, 6, v[ 2], v[ 7], v[ 8], v[13]);          \
        G(r, 7, v[ 3], v[ 4], v[ 9], v[14]);          \
    } while (0)

static void blake2s_compress(blake2s_state *S, const uint8_t block[BLAKE2S_BLOCK_LEN])
{
    uint32_t m[16];
    uint32_t v[16];

    for (int i = 0; i < 16; i++) {
        m[i] = load32(block + i * 4);
    }
    for (int i = 0; i < 8; i++) {
        v[i] = S->h[i];
    }
    v[ 8] = blake2s_iv[0];
    v[ 9] = blake2s_iv[1];
    v[10] = blake2s_iv[2];
    v[11] = blake2s_iv[3];
    v[12] = S->t[0] ^ blake2s_iv[4];
    v[13] = S->t[1] ^ blake2s_iv[5];
    v[14] = S->f[0] ^ blake2s_iv[6];
    v[15] = S->f[1] ^ blake2s_iv[7];

    ROUND(0); ROUND(1); ROUND(2); ROUND(3); ROUND(4);
    ROUND(5); ROUND(6); ROUND(7); ROUND(8); ROUND(9);

    for (int i = 0; i < 8; i++) {
        S->h[i] ^= v[i] ^ v[i + 8];
    }
}

static void blake2s_increment_counter(blake2s_state *S, uint32_t inc)
{
    S->t[0] += inc;
    S->t[1] += (S->t[0] < inc);
}

int blake2s_init(blake2s_state *S, size_t outlen)
{
    return blake2s_init_key(S, outlen, NULL, 0);
}

int blake2s_init_key(blake2s_state *S, size_t outlen,
                     const void *key, size_t keylen)
{
    if (S == NULL) return -1;
    if (outlen == 0 || outlen > BLAKE2S_OUT_LEN) return -1;
    if (key == NULL && keylen != 0) return -1;
    if (keylen > BLAKE2S_KEY_MAX) return -1;

    memset(S, 0, sizeof(*S));
    for (int i = 0; i < 8; i++) {
        S->h[i] = blake2s_iv[i];
    }
    /* Parameter block (xor'd into h, RFC 7693 §2.5):
     *   byte 0  : digest length
     *   byte 1  : key length
     *   byte 2  : fanout (1 for sequential)
     *   byte 3  : depth  (1 for sequential)
     *   bytes 4-15: leaf len, node offset, node depth, inner len, salt(8)+pers(8)
     * For our usage all extras are zero. */
    S->h[0] ^= 0x01010000UL ^ ((uint32_t)keylen << 8) ^ (uint32_t)outlen;
    S->outlen = outlen;

    if (keylen > 0) {
        uint8_t block[BLAKE2S_BLOCK_LEN] = {0};
        memcpy(block, key, keylen);
        blake2s_update(S, block, BLAKE2S_BLOCK_LEN);
    }
    return 0;
}

int blake2s_update(blake2s_state *S, const void *in, size_t inlen)
{
    const uint8_t *p = (const uint8_t *)in;

    if (S == NULL) return -1;
    if (inlen == 0) return 0;
    if (in == NULL) return -1;

    if (S->buflen > 0) {
        size_t fill = BLAKE2S_BLOCK_LEN - S->buflen;
        if (inlen <= fill) {
            memcpy(S->buf + S->buflen, p, inlen);
            S->buflen += inlen;
            return 0;
        }
        memcpy(S->buf + S->buflen, p, fill);
        blake2s_increment_counter(S, BLAKE2S_BLOCK_LEN);
        blake2s_compress(S, S->buf);
        S->buflen = 0;
        p += fill;
        inlen -= fill;
    }
    while (inlen > BLAKE2S_BLOCK_LEN) {
        blake2s_increment_counter(S, BLAKE2S_BLOCK_LEN);
        blake2s_compress(S, p);
        p += BLAKE2S_BLOCK_LEN;
        inlen -= BLAKE2S_BLOCK_LEN;
    }
    memcpy(S->buf, p, inlen);
    S->buflen = inlen;
    return 0;
}

int blake2s_final(blake2s_state *S, void *out, size_t outlen)
{
    uint8_t buffer[BLAKE2S_OUT_LEN] = {0};

    if (S == NULL || out == NULL) return -1;
    if (outlen != S->outlen) return -1;
    if (S->f[0] != 0) return -1; /* already finalized */

    blake2s_increment_counter(S, (uint32_t)S->buflen);
    S->f[0] = 0xFFFFFFFFUL; /* set "last block" flag */
    /* Pad remaining input with zeros. */
    memset(S->buf + S->buflen, 0, BLAKE2S_BLOCK_LEN - S->buflen);
    blake2s_compress(S, S->buf);

    for (int i = 0; i < 8; i++) {
        store32(buffer + i * 4, S->h[i]);
    }
    memcpy(out, buffer, outlen);
    /* Best-effort scrub. */
    memset(S, 0, sizeof(*S));
    return 0;
}

int blake2s(void *out, size_t outlen,
            const void *in, size_t inlen,
            const void *key, size_t keylen)
{
    blake2s_state S;
    if (blake2s_init_key(&S, outlen, key, keylen) != 0) return -1;
    if (blake2s_update(&S, in, inlen) != 0) return -1;
    return blake2s_final(&S, out, outlen);
}
