// SPDX-License-Identifier: MIT
//
// tinylink note: lifted verbatim from
// https://github.com/floodyberry/poly1305-donna (Andrew Moon).
// "poly1305 implementation using 32 bit * 32 bit = 64 bit
//  multiplication and 64 bit addition".
// The upstream license is "public domain or MIT"; we declare MIT
// here for SPDX clarity. Validated by host KAT against RFC 8439
// §2.5.2.

#include <stdint.h>

#include "tl_hot.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER)
    #define POLY1305_NOINLINE __declspec(noinline)
#elif defined(__GNUC__)
    #define POLY1305_NOINLINE __attribute__((noinline))
#else
    #define POLY1305_NOINLINE
#endif

#define poly1305_block_size 16

/* 17 + sizeof(size_t) + 14*sizeof(unsigned long) */
typedef struct poly1305_state_internal_t {
    unsigned long r[5];
    unsigned long h[5];
    unsigned long pad[4];
    size_t leftover;
    unsigned char buffer[poly1305_block_size];
    unsigned char final;
} poly1305_state_internal_t;

/* interpret four 8 bit unsigned integers as a 32 bit unsigned integer in little endian.
 *
 * tinylink change (2026-09): register-only byte assembly for pointers of
 * unknown alignment. The previous `__builtin_memcpy(&v, p, 4)` form
 * compiled on Xtensa LX6 (no unaligned access, no byte-insert) to
 * 4× l8ui + 4× s8i to the stack + 1× l32i — a store→load round trip
 * per word, five of them per 16-byte block. This form is 4× l8ui +
 * 3× slli + 3× or with no memory traffic; x86-64/AArch64 fold it to a
 * single load. Never UB, never traps. */
static uint32_t
U8TO32(const unsigned char *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

/* Same, for a pointer the CALLER has checked is 4-byte aligned:
 * __builtin_assume_aligned lets GCC emit a single l32i. */
static inline uint32_t
U8TO32_ALIGNED(const unsigned char *p) {
    const unsigned char *ap = __builtin_assume_aligned(p, 4);
    uint32_t v;
    __builtin_memcpy(&v, ap, sizeof(v));
    return v;
}

/* store a 32 bit unsigned integer as four 8 bit unsigned integers in little endian */
static void
U32TO8(unsigned char *p, unsigned long v) {
    p[0] = (v      ) & 0xff;
    p[1] = (v >>  8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

TL_HOT_ATTR void
poly1305_init(poly1305_context *ctx, const unsigned char key[32]) {
    poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;

    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff
     *
     * tinylink change: the 26-bit limbs are carved out of FOUR
     * word-aligned loads with funnel shifts (Xtensa `ssr`+`src`)
     * instead of five loads at byte offsets 0/3/6/9/12 — three of which
     * can never be aligned no matter what the caller does. Bit-identical
     * to the upstream donna form: U8TO32(key+3) >> 2 == (t0 >> 26) |
     * (t1 << 6) on the low 26 bits, etc. */
    {
        const uint32_t t0 = U8TO32(&key[ 0]);
        const uint32_t t1 = U8TO32(&key[ 4]);
        const uint32_t t2 = U8TO32(&key[ 8]);
        const uint32_t t3 = U8TO32(&key[12]);
        st->r[0] = ( t0                      ) & 0x3ffffff;
        st->r[1] = ((t0 >> 26) | (t1 <<  6)) & 0x3ffff03;
        st->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
        st->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
        st->r[4] = ( t3 >>  8                ) & 0x00fffff;
    }

    /* h = 0 */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->h[3] = 0;
    st->h[4] = 0;

    /* save pad for later */
    st->pad[0] = U8TO32(&key[16]);
    st->pad[1] = U8TO32(&key[20]);
    st->pad[2] = U8TO32(&key[24]);
    st->pad[3] = U8TO32(&key[28]);

    st->leftover = 0;
    st->final = 0;
}

static TL_HOT_ATTR void
poly1305_blocks(poly1305_state_internal_t *st, const unsigned char *m, size_t bytes) {
    const unsigned long hibit = (st->final) ? 0 : (1UL << 24); /* 1 << 128 */
    unsigned long r0,r1,r2,r3,r4;
    unsigned long s1,s2,s3,s4;
    unsigned long h0,h1,h2,h3,h4;
    unsigned long long d0,d1,d2,d3,d4;
    unsigned long c;

    r0 = st->r[0];
    r1 = st->r[1];
    r2 = st->r[2];
    r3 = st->r[3];
    r4 = st->r[4];

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];
    h3 = st->h[3];
    h4 = st->h[4];

    /* tinylink change: load each 16-byte block as four LE words and
     * carve the 26-bit limbs with funnel shifts, instead of five loads
     * at byte offsets 0/3/6/9/12 (three of them inherently unaligned →
     * on Xtensa each was 4× l8ui + a stack bounce). The alignment of m
     * is invariant across the loop (16-byte stride), so it is decided
     * once, on the buffer ADDRESS — never on data — and the aligned
     * case (every WG packet: ciphertext at offset 16 of a word-aligned
     * packet buffer; st->buffer in poly1305_finish) is 4× l32i. */
    const int m_aligned = (((uintptr_t)m) & 3u) == 0;

    while (bytes >= poly1305_block_size) {
        uint32_t t0, t1, t2, t3;
        if (m_aligned) {
            t0 = U8TO32_ALIGNED(m +  0);
            t1 = U8TO32_ALIGNED(m +  4);
            t2 = U8TO32_ALIGNED(m +  8);
            t3 = U8TO32_ALIGNED(m + 12);
        } else {
            t0 = U8TO32(m +  0);
            t1 = U8TO32(m +  4);
            t2 = U8TO32(m +  8);
            t3 = U8TO32(m + 12);
        }
        /* h += m[i]  (bit-identical to the upstream byte-offset form:
         * U8TO32(m+3) >> 2 == (t0 >> 26) | (t1 << 6) on the low 26 bits,
         * and so on) */
        h0 += ( t0                      ) & 0x3ffffff;
        h1 += ((t0 >> 26) | (t1 <<  6)) & 0x3ffffff;
        h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        h4 += ( t3 >>  8                ) | hibit;

        /* h *= r */
        d0 = ((unsigned long long)h0 * r0) + ((unsigned long long)h1 * s4) + ((unsigned long long)h2 * s3) + ((unsigned long long)h3 * s2) + ((unsigned long long)h4 * s1);
        d1 = ((unsigned long long)h0 * r1) + ((unsigned long long)h1 * r0) + ((unsigned long long)h2 * s4) + ((unsigned long long)h3 * s3) + ((unsigned long long)h4 * s2);
        d2 = ((unsigned long long)h0 * r2) + ((unsigned long long)h1 * r1) + ((unsigned long long)h2 * r0) + ((unsigned long long)h3 * s4) + ((unsigned long long)h4 * s3);
        d3 = ((unsigned long long)h0 * r3) + ((unsigned long long)h1 * r2) + ((unsigned long long)h2 * r1) + ((unsigned long long)h3 * r0) + ((unsigned long long)h4 * s4);
        d4 = ((unsigned long long)h0 * r4) + ((unsigned long long)h1 * r3) + ((unsigned long long)h2 * r2) + ((unsigned long long)h3 * r1) + ((unsigned long long)h4 * r0);

        /* (partial) h %= p */
                      c = (unsigned long)(d0 >> 26); h0 = (unsigned long)d0 & 0x3ffffff;
        d1 += c;      c = (unsigned long)(d1 >> 26); h1 = (unsigned long)d1 & 0x3ffffff;
        d2 += c;      c = (unsigned long)(d2 >> 26); h2 = (unsigned long)d2 & 0x3ffffff;
        d3 += c;      c = (unsigned long)(d3 >> 26); h3 = (unsigned long)d3 & 0x3ffffff;
        d4 += c;      c = (unsigned long)(d4 >> 26); h4 = (unsigned long)d4 & 0x3ffffff;
        h0 += c * 5;  c =                (h0 >> 26); h0 =                h0 & 0x3ffffff;
        h1 += c;

        m += poly1305_block_size;
        bytes -= poly1305_block_size;
    }

    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
    st->h[3] = h3;
    st->h[4] = h4;
}

POLY1305_NOINLINE TL_HOT_ATTR void
poly1305_finish(poly1305_context *ctx, unsigned char mac[16]) {
    poly1305_state_internal_t *st = (poly1305_state_internal_t *)ctx;
    unsigned long h0,h1,h2,h3,h4,c;
    unsigned long g0,g1,g2,g3,g4;
    unsigned long mask;

    /* process the remaining block */
    if (st->leftover) {
        size_t i = st->leftover;
        st->buffer[i++] = 1;
        for (; i < poly1305_block_size; i++)
            st->buffer[i] = 0;
        st->final = 1;
        poly1305_blocks(st, st->buffer, poly1305_block_size);
    }

    /* fully carry h */
    h0 = st->h[0];
    h1 = st->h[1];
    h2 = st->h[2];
    h3 = st->h[3];
    h4 = st->h[4];

                 c = h1 >> 26; h1 = h1 & 0x3ffffff;
    h2 +=     c; c = h2 >> 26; h2 = h2 & 0x3ffffff;
    h3 +=     c; c = h3 >> 26; h3 = h3 & 0x3ffffff;
    h4 +=     c; c = h4 >> 26; h4 = h4 & 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
    h1 +=     c;

    /* compute h + -p */
    g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + c - (1UL << 26);

    /* select h if h < p, or h + -p if h >= p */
    mask = (g4 >> ((sizeof(unsigned long) * 8) - 1)) - 1;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h % (2^128) */
    h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

    /* mac = (h + pad) % (2^128)
     *
     * tinylink change: the upstream donna code uses a 64-bit `f` to fold
     * the carry between adds (`f >> 32` extracts the carry-out of step n
     * for step n+1). On Xtensa LX6 — which has no add-with-carry
     * instruction — GCC compiles each `(uint64_t)h + pad + (f >> 32)`
     * down to a 32-bit `add.n` followed by `bgeu Aresult, Aoperand` to
     * detect overflow. That conditional branch is taken on values
     * derived from the secret state (message ⊕ key), and disassembly of
     * post-#51 builds confirmed five `bgeu` sites in the carry region
     * (see docs/SECURITY-MODEL.md). Net leak: ~4 bits per MAC of
     * timing-side-channel information.
     *
     * Rewrite as a branch-free 32-bit chain. Standard carry-out for an
     * unsigned add `sum = a + b + cin` (cin ∈ {0,1}, Hacker's Delight
     * §2-13):
     *
     *   cout = ((a & b) | ((a | b) & ~sum)) >> 31
     *
     * which compiles to a straight run of `and`/`or`/`xor`/`srli` on
     * LX6 — zero conditional branches. The output mac bytes are bit-
     * identical to the upstream donna version (verified against RFC
     * 8439 §2.5.2 + the streamed-chunk KAT in tools/test/test_poly1305). */
    {
        uint32_t a, b, sum, carry;

        a     = (uint32_t)h0;
        b     = (uint32_t)st->pad[0];
        sum   = a + b;
        carry = ((a & b) | ((a | b) & ~sum)) >> 31;
        h0    = sum;

        a     = (uint32_t)h1;
        b     = (uint32_t)st->pad[1];
        sum   = a + b + carry;
        carry = ((a & b) | ((a | b) & ~sum)) >> 31;
        h1    = sum;

        a     = (uint32_t)h2;
        b     = (uint32_t)st->pad[2];
        sum   = a + b + carry;
        carry = ((a & b) | ((a | b) & ~sum)) >> 31;
        h2    = sum;

        a     = (uint32_t)h3;
        b     = (uint32_t)st->pad[3];
        sum   = a + b + carry;
        /* Final carry-out is discarded — MAC is computed mod 2^128. */
        h3    = sum;
    }

    U32TO8(mac +  0, h0);
    U32TO8(mac +  4, h1);
    U32TO8(mac +  8, h2);
    U32TO8(mac + 12, h3);

    /* zero out the state */
    st->h[0] = 0;
    st->h[1] = 0;
    st->h[2] = 0;
    st->h[3] = 0;
    st->h[4] = 0;
    st->r[0] = 0;
    st->r[1] = 0;
    st->r[2] = 0;
    st->r[3] = 0;
    st->r[4] = 0;
    st->pad[0] = 0;
    st->pad[1] = 0;
    st->pad[2] = 0;
    st->pad[3] = 0;
}

#ifdef __cplusplus
}
#endif
