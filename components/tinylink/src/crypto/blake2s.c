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

#include "secure_zero.h"

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

/* G (RFC 7693 §3.1) split into its four steps, and run on two columns
 * (or diagonals) in lockstep so the two rotates of a step share one SAR
 * write. Xtensa note (ISA RM §8.3.2): a constant rotate is `ssai n;
 * src x, x, x`, and GCC never merges the SAR writes of consecutive
 * rotates by the same amount (one `ssai` per `src`), so SAR is set by
 * hand once per step (rotr(v, n) = SRC v,v with SAR = n) and each rotate
 * is a bare `src`; both asm statements are volatile, so their order
 * holds, and nothing else in this file uses SAR. Pairs rather than all
 * four G's of a half round: on 16 scalar locals the pair keeps 8 words
 * hot, which the 14 windowed-ABI registers can hold (the ChaCha20
 * measurement of round 1.3.3, C4). Hosts keep the plain C rotate. */
#if defined(__XTENSA__)
#define SET_SAR_ROTR(n) __asm__ volatile ("ssai %0" : : "i"(n))
#define ROTR_SAR(v, n)  ({ uint32_t _r; \
                           __asm__ volatile ("src %0, %1, %1" : "=a"(_r) : "a"(v)); \
                           _r; })
#else
#define SET_SAR_ROTR(n) do { } while (0)
#define ROTR_SAR(v, n)  rotr32((v), (n))
#endif

#define G1(a, b, c, d, x) a = a + b + (x); d = ROTR_SAR(d ^ a, 16)
#define G2(a, b, c, d)    c = c + d;       b = ROTR_SAR(b ^ c, 12)
#define G3(a, b, c, d, y) a = a + b + (y); d = ROTR_SAR(d ^ a, 8)
#define G4(a, b, c, d)    c = c + d;       b = ROTR_SAR(b ^ c, 7)

/* G(r, i) and G(r, j) in lockstep on (a0..d0) and (a1..d1). */
#define G_PAIR(r, i, a0, b0, c0, d0, j, a1, b1, c1, d1)                       \
    do {                                                                      \
        SET_SAR_ROTR(16);                                                     \
        G1(a0, b0, c0, d0, m[blake2s_sigma[r][2*(i)]]);                       \
        G1(a1, b1, c1, d1, m[blake2s_sigma[r][2*(j)]]);                       \
        SET_SAR_ROTR(12);                                                     \
        G2(a0, b0, c0, d0); G2(a1, b1, c1, d1);                               \
        SET_SAR_ROTR(8);                                                      \
        G3(a0, b0, c0, d0, m[blake2s_sigma[r][2*(i)+1]]);                     \
        G3(a1, b1, c1, d1, m[blake2s_sigma[r][2*(j)+1]]);                     \
        SET_SAR_ROTR(7);                                                      \
        G4(a0, b0, c0, d0); G4(a1, b1, c1, d1);                               \
    } while (0)

#define ROUND(r)                                                              \
    do {                                                                      \
        G_PAIR(r, 0, v0, v4, v8,  v12,  1, v1, v5, v9,  v13);                 \
        G_PAIR(r, 2, v2, v6, v10, v14,  3, v3, v7, v11, v15);                 \
        G_PAIR(r, 4, v0, v5, v10, v15,  5, v1, v6, v11, v12);                 \
        G_PAIR(r, 6, v2, v7, v8,  v13,  7, v3, v4, v9,  v14);                 \
    } while (0)

static void blake2s_compress(blake2s_state *S, const uint8_t block[BLAKE2S_BLOCK_LEN])
{
    uint32_t m[16];

    for (int i = 0; i < 16; i++) {
        m[i] = load32(block + i * 4);
    }
    uint32_t v0 = S->h[0], v1 = S->h[1], v2 = S->h[2], v3 = S->h[3];
    uint32_t v4 = S->h[4], v5 = S->h[5], v6 = S->h[6], v7 = S->h[7];
    uint32_t v8  = blake2s_iv[0];
    uint32_t v9  = blake2s_iv[1];
    uint32_t v10 = blake2s_iv[2];
    uint32_t v11 = blake2s_iv[3];
    uint32_t v12 = S->t[0] ^ blake2s_iv[4];
    uint32_t v13 = S->t[1] ^ blake2s_iv[5];
    uint32_t v14 = S->f[0] ^ blake2s_iv[6];
    uint32_t v15 = S->f[1] ^ blake2s_iv[7];

    ROUND(0); ROUND(1); ROUND(2); ROUND(3); ROUND(4);
    ROUND(5); ROUND(6); ROUND(7); ROUND(8); ROUND(9);

    S->h[0] ^= v0 ^ v8;   S->h[1] ^= v1 ^ v9;
    S->h[2] ^= v2 ^ v10;  S->h[3] ^= v3 ^ v11;
    S->h[4] ^= v4 ^ v12;  S->h[5] ^= v5 ^ v13;
    S->h[6] ^= v6 ^ v14;  S->h[7] ^= v7 ^ v15;
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
    /* Scrub the state (holds the key block for keyed / HMAC use) and the
     * local digest copy (an HKDF output is key material). */
    tl_secure_zero(S, sizeof(*S));
    tl_secure_zero(buffer, sizeof(buffer));
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
