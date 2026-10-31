// SPDX-License-Identifier: BSD-3-Clause
//
// tinylink note: lifted verbatim from trombik/esp_wireguard
// (src/crypto/refc/chacha20.c). Endian/clamp macros that the original
// pulled from "../../crypto.h" are inlined here so the file is self-
// contained and host-buildable without the trombik tree. Held under
// the BSD-3-Clause notice below. Audit notes are in chacha20.h;
// validated by host KAT against RFC 8439 §2.4.2.
//
// ----------------------------------------------------------------------
// Copyright (c) 2021 Daniel Hope (www.floorsense.nz)
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
// 3. Neither the name of "Floorsense Ltd", "Agile Workspace Ltd" nor
//    the names of its contributors may be used to endorse or promote
//    products derived from this software without specific prior
//    written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
// ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Author: Daniel Hope <daniel.hope@smartalock.com>

#include "chacha20.h"

#include <stdint.h>
#include <string.h>

#include "tl_hot.h"

/* Endian/clamp macros — inlined from trombik/esp_wireguard's crypto.h
 * so this file is self-contained. */
#define U8C(v)  (v##U)
#define U32C(v) (v##U)
#define U8V(v)  ((uint8_t)(v) & U8C(0xFF))
#define U32V(v) ((uint32_t)(v) & U32C(0xFFFFFFFF))

/* Xtensa LX6 is little-endian, so a u32 read is byte-identical to the
 * macro form. __builtin_memcpy folds to:
 *   - 1× l32i / 1× s32i when alignment is provable;
 *   - 4× l8ui / 4× s8i otherwise (same as the original macro).
 * Strict-aliasing-safe by construction. */
#define U8TO32_LITTLE(p) ({               \
    uint32_t _v;                          \
    __builtin_memcpy(&_v, (p), 4);        \
    _v;                                   \
})

#define U32TO8_LITTLE(p, v)               \
    do {                                  \
        uint32_t _v = (v);                \
        __builtin_memcpy((p), &_v, 4);    \
    } while (0)

/* 2.3. The ChaCha20 Block Function — first four words are the
 * "expand 32-byte k" constants. */
static const uint32_t CHACHA20_CONSTANT_1 = 0x61707865;
static const uint32_t CHACHA20_CONSTANT_2 = 0x3320646e;
static const uint32_t CHACHA20_CONSTANT_3 = 0x79622d32;
static const uint32_t CHACHA20_CONSTANT_4 = 0x6b206574;

#define ROTL32(v, n) (U32V((v) << (n)) | ((v) >> (32 - (n))))
#define PLUS(v, w)   (U32V((v) + (w)))
#define PLUSONE(v)   (PLUS((v), 1))

/* 2.1. The ChaCha Quarter Round (RFC 8439):
 *   a += b; d ^= a; d <<<= 16;   c += d; b ^= c; b <<<= 12;
 *   a += b; d ^= a; d <<<=  8;   c += d; b ^= c; b <<<=  7;
 * applied to the columns (0,4,8,12) (1,5,9,13) (2,6,10,14) (3,7,11,15)
 * and then the diagonals (0,5,10,15) (1,6,11,12) (2,7,8,13) (3,4,9,14).
 *
 * Xtensa note (ISA RM §8.3.2, table 8-246): a constant rotate is the
 * two-instruction idiom `ssai n; src ax, ay, ay` — the amount lives in
 * the special register SAR, and GCC never merges the SAR writes of
 * consecutive rotates by the same amount (one `ssai` per `src`, verified
 * on the 2026-09 objects). So SAR is set by hand once per step of
 * quarter-rounds run in lockstep (rotl(v, n) = SRC v,v with SAR = 32-n:
 * "left funnel shifts are done by swapping the operands and setting SAR
 * to 32 minus the shift amount") and each rotate is a bare `src`. Both
 * asm statements are volatile, so their relative order is preserved;
 * nothing else in this translation unit touches SAR (no variable or
 * 64-bit shifts). Hosts / other targets keep the plain C rotate. */
#if defined(__XTENSA__)
#define SET_SAR_ROTL(n)  __asm__ volatile ("ssai %0" : : "i"(32 - (n)))
#define ROTL_SAR(v, n)   ({ uint32_t _r; \
                            __asm__ volatile ("src %0, %1, %1" : "=a"(_r) : "a"(v)); \
                            _r; })
#else
#define SET_SAR_ROTL(n)  do { } while (0)
#define ROTL_SAR(v, n)   ROTL32((v), (n))
#endif

#define QR_STEP(a, b, c, d, n)  a += b;  d ^= a;  d = ROTL_SAR(d, n)
#define QR_STEP2(a, b, c, d, n) c += d;  b ^= c;  b = ROTL_SAR(b, n)

/* Two quarter-rounds in lockstep (round 1.3.3, C4). Until 1.3.2 all four
 * quarter-rounds of a half round ran in lockstep on a uint32_t[16]
 * (8 `ssai` per double round), which needs all 16 state words live at
 * every step: with a0 (return address) and a1 (stack) taken, the
 * windowed ABI leaves 14 address registers, so GCC kept the array on
 * the stack — 35 a1-relative loads/stores per double round. Pairs keep
 * 8 words hot while the other 8 sit idle (the compiler parks the few
 * that do not fit), for 16 `ssai` per double round: 19 spills, −18 %
 * instructions per block (measured, Xtensa GCC 14.2 -O2). */
#define QR_PAIR(a0, b0, c0, d0, a1, b1, c1, d1)                           \
    SET_SAR_ROTL(16);                                                     \
    QR_STEP (a0, b0, c0, d0, 16); QR_STEP (a1, b1, c1, d1, 16);           \
    SET_SAR_ROTL(12);                                                     \
    QR_STEP2(a0, b0, c0, d0, 12); QR_STEP2(a1, b1, c1, d1, 12);           \
    SET_SAR_ROTL(8);                                                      \
    QR_STEP (a0, b0, c0, d0,  8); QR_STEP (a1, b1, c1, d1,  8);           \
    SET_SAR_ROTL(7);                                                      \
    QR_STEP2(a0, b0, c0, d0,  7); QR_STEP2(a1, b1, c1, d1,  7)

/* 2.3. The ChaCha20 block function on scalar locals, with the final
 * "state += working state" fused into the output:
 *   out[i] = in[i] ^ (rounds(st)[i] + st[i])   (in != NULL: encrypt)
 *   out[i] =          rounds(st)[i] + st[i]    (in == NULL: keystream)
 * `in` is a constant NULL or a pointer at each inlined call site, so the
 * test folds away. The fused form is the C4 gain beyond the pairs: the
 * keystream block is never stored to the stack and re-read (the 1.3.2
 * code wrote it out, then XORed it in a second loop — 10 instructions
 * per word against 5 here).
 *
 * Force-inlined into its callers so the words stay in registers; the 10
 * double rounds are a counted loop rather than unrolled (the body is
 * ~130 instructions, above GCC's complete-unroll threshold at -O2, so
 * it stays a loop: one copy, fixed trip count, no data-dependent
 * control flow). At -O2 GCC left the old double round out of line and
 * the 10 calls per block compiled to `l32r` + `callx8` + windowed
 * `entry`/`retw` each; always_inline keeps that from coming back. */
static inline __attribute__((always_inline))
void chacha20_block(uint32_t out[16], const uint32_t *in, const uint32_t st[16])
{
    uint32_t x0 = st[0],   x1 = st[1],   x2 = st[2],   x3 = st[3];
    uint32_t x4 = st[4],   x5 = st[5],   x6 = st[6],   x7 = st[7];
    uint32_t x8 = st[8],   x9 = st[9],   x10 = st[10], x11 = st[11];
    uint32_t x12 = st[12], x13 = st[13], x14 = st[14], x15 = st[15];

    for (int r = 10; r != 0; --r) {
        /* columns */
        QR_PAIR(x0, x4, x8,  x12,  x1, x5, x9,  x13);
        QR_PAIR(x2, x6, x10, x14,  x3, x7, x11, x15);
        /* diagonals */
        QR_PAIR(x0, x5, x10, x15,  x1, x6, x11, x12);
        QR_PAIR(x2, x7, x8,  x13,  x3, x4, x9,  x14);
    }

#define BLOCK_OUT(i, x) out[i] = (in ? in[i] : 0u) ^ PLUS((x), st[i])
    BLOCK_OUT(0, x0);   BLOCK_OUT(1, x1);   BLOCK_OUT(2, x2);   BLOCK_OUT(3, x3);
    BLOCK_OUT(4, x4);   BLOCK_OUT(5, x5);   BLOCK_OUT(6, x6);   BLOCK_OUT(7, x7);
    BLOCK_OUT(8, x8);   BLOCK_OUT(9, x9);   BLOCK_OUT(10, x10); BLOCK_OUT(11, x11);
    BLOCK_OUT(12, x12); BLOCK_OUT(13, x13); BLOCK_OUT(14, x14); BLOCK_OUT(15, x15);
#undef BLOCK_OUT
}

/* Little-endian u32 load/store from a pointer of UNKNOWN alignment,
 * without bouncing through the stack.
 *
 * Xtensa LX6 has no unaligned load/store at all (LoadStoreAlignment
 * exception, EXCCAUSE=9) and no byte-insert instruction, so for a
 * `__builtin_memcpy(&v, p, 4)` into a local whose alignment it cannot
 * prove, GCC 14 emits 4× l8ui + 4× s8i (spilling the bytes to the
 * stack) + 1× l32i — a store→load round trip per word (verified in the
 * -O2 disassembly of the previous version: ~19 instructions per XORed
 * word). The explicit shift/or form is 4× l8ui + 3× slli + 3× or, all
 * in registers. Hosts with unaligned access (x86-64, AArch64) fold it
 * to a single mov, so the KATs see the same code shape. */
static inline uint32_t load32_le_unaligned(const uint8_t *p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}
static inline void store32_le_unaligned(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/* XOR one keystream block (16 LE words) into n <= 64 bytes. Used for
 * the last partial block and for buffers that are not word-aligned;
 * aligned full blocks take the fused loop in chacha20() instead.
 *
 * Two loops, selected once per call on the ACTUAL alignment of in/out:
 *   - aligned:   l32i + xor + s32i per word (a partial last block of an
 *                aligned buffer: every WireGuard packet ends here);
 *   - unaligned: register-only byte assembly (above), for callers that
 *                hand us an odd offset (scratch buffers, tests).
 * The branch is on buffer ADDRESSES, never on data, so timing stays
 * independent of the key/plaintext. */
static inline void xor_block_u32(uint8_t *out, const uint8_t *in,
                                 const uint32_t *ks, size_t n) {
    size_t i = 0;
    const size_t bulk = n & ~(size_t)3;
    if (((((uintptr_t)out) | ((uintptr_t)in)) & 3u) == 0) {
        /* Pointer-bumping form: with an index GCC re-derived the
         * keystream address (extui+slli+add) and re-loaded the spilled
         * `out` pointer on every word — 11 instructions/word. Three
         * post-incremented pointers keep it at l32i + l32i + xor + s32i
         * + 3× addi under one zero-overhead `loop`. */
        const uint8_t  *ai = __builtin_assume_aligned(in, 4);
        uint8_t        *ao = __builtin_assume_aligned(out, 4);
        const uint32_t *k  = ks;
        for (size_t w = bulk >> 2; w != 0; --w) {
            uint32_t a;
            __builtin_memcpy(&a, ai, 4);
            a ^= *k++;
            __builtin_memcpy(ao, &a, 4);
            ai += 4;
            ao += 4;
        }
        i = bulk;
    } else {
        for (; i < bulk; i += 4) {
            store32_le_unaligned(out + i, load32_le_unaligned(in + i) ^ ks[i >> 2]);
        }
    }
    /* Tail (< 4 bytes): byte i of the LE word array is keystream byte i. */
    const uint8_t *ks8 = (const uint8_t *)ks;
    for (; i < n; ++i) {
        out[i] = in[i] ^ ks8[i];
    }
}

TL_HOT_ATTR void chacha20(struct chacha20_ctx *ctx, uint8_t *out, const uint8_t *in, uint32_t len) {
    /* Aligned full blocks: one fused pass per block straight into out[]
     * (in place is fine: word i is read before it is written). Every
     * WireGuard packet takes this path for all but its last block (the
     * transport payload sits at offset 16 of a word-aligned packet
     * buffer, wg_netif.c, and lwIP pbuf payloads are
     * MEM_ALIGNMENT(4)-aligned). Branches are on lengths and buffer
     * addresses only. */
    if (((((uintptr_t)out) | ((uintptr_t)in)) & 3u) == 0) {
        const uint32_t *ai = __builtin_assume_aligned(in, 4);
        uint32_t       *ao = __builtin_assume_aligned(out, 4);
        for (; len >= CHACHA20_BLOCK_SIZE; len -= CHACHA20_BLOCK_SIZE) {
            chacha20_block(ao, ai, ctx->state);
            ctx->state[12] = PLUSONE(ctx->state[12]);
            ai += 16;
            ao += 16;
        }
        in = (const uint8_t *)ai;
        out = (uint8_t *)ao;
    }

    /* The last partial block, and every block of a buffer that is not
     * word-aligned: keystream block, then XOR. Word-typed so it is
     * 4-byte aligned by construction (Xtensa requires it for l32i). */
    uint32_t ks[CHACHA20_BLOCK_SIZE / 4];
    while (len) {
        chacha20_block(ks, NULL, ctx->state);
        ctx->state[12] = PLUSONE(ctx->state[12]);
        const uint32_t n = len < CHACHA20_BLOCK_SIZE ? len : CHACHA20_BLOCK_SIZE;
        xor_block_u32(out, in, ks, n);
        len -= n;
        out += n;
        in += n;
    }
}

/* For wireguard: nonce composed of 32 bits of zeros followed by the
 * 64-bit little-endian counter; word 12 holds the per-block counter.
 * Runs once per AEAD call, so it sits in IRAM with the rest of the hot
 * path (before 1.3.2 it and mbedtls_platform_zeroize were the AEAD's
 * last calls into flash). */
TL_HOT_ATTR void chacha20_init(struct chacha20_ctx *ctx, const uint8_t *key, uint64_t nonce) {
    ctx->state[ 0] = CHACHA20_CONSTANT_1;
    ctx->state[ 1] = CHACHA20_CONSTANT_2;
    ctx->state[ 2] = CHACHA20_CONSTANT_3;
    ctx->state[ 3] = CHACHA20_CONSTANT_4;
    /* Bulk-copy the 32-byte key into state[4..11]. GCC schedules this
     * as 8× l32i / 8× s32i (interleaved) when key is aligned, which
     * beats 8 separate U8TO32_LITTLE expansions because the loads can
     * issue without the rotate/or chain in between. */
    __builtin_memcpy(&ctx->state[4], key, 32);
    ctx->state[12] = 0;
    ctx->state[13] = 0;
    ctx->state[14] = (uint32_t)(nonce & 0xFFFFFFFFu);
    ctx->state[15] = (uint32_t)(nonce >> 32);
}

/* 2.2. HChaCha20 — 128-bit nonce, no counter. Used by XChaCha20.
 * Keep for completeness; tinylink WG transport uses ChaCha20 only. */
void hchacha20(uint8_t *out, const uint8_t *nonce, const uint8_t *key) {
    uint32_t state[16];
    state[ 0] = CHACHA20_CONSTANT_1;
    state[ 1] = CHACHA20_CONSTANT_2;
    state[ 2] = CHACHA20_CONSTANT_3;
    state[ 3] = CHACHA20_CONSTANT_4;
    state[ 4] = U8TO32_LITTLE(key +  0);
    state[ 5] = U8TO32_LITTLE(key +  4);
    state[ 6] = U8TO32_LITTLE(key +  8);
    state[ 7] = U8TO32_LITTLE(key + 12);
    state[ 8] = U8TO32_LITTLE(key + 16);
    state[ 9] = U8TO32_LITTLE(key + 20);
    state[10] = U8TO32_LITTLE(key + 24);
    state[11] = U8TO32_LITTLE(key + 28);
    state[12] = U8TO32_LITTLE(nonce +  0);
    state[13] = U8TO32_LITTLE(nonce +  4);
    state[14] = U8TO32_LITTLE(nonce +  8);
    state[15] = U8TO32_LITTLE(nonce + 12);

    /* HChaCha20 is the 20 rounds without the feed-forward add: take the
     * block and subtract the state back out (cold path, one block). */
    uint32_t x[16];
    chacha20_block(x, NULL, state);

    U32TO8_LITTLE(out +  0, x[ 0] - state[ 0]);
    U32TO8_LITTLE(out +  4, x[ 1] - state[ 1]);
    U32TO8_LITTLE(out +  8, x[ 2] - state[ 2]);
    U32TO8_LITTLE(out + 12, x[ 3] - state[ 3]);
    U32TO8_LITTLE(out + 16, x[12] - state[12]);
    U32TO8_LITTLE(out + 20, x[13] - state[13]);
    U32TO8_LITTLE(out + 24, x[14] - state[14]);
    U32TO8_LITTLE(out + 28, x[15] - state[15]);
}
