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

/* 2.1. The ChaCha Quarter Round (RFC 8439). */
#define QUARTERROUND(a, b, c, d)                  \
    a += b;  d ^= a;  d = ROTL32(d, 16);          \
    c += d;  b ^= c;  b = ROTL32(b, 12);          \
    a += b;  d ^= a;  d = ROTL32(d,  8);          \
    c += d;  b ^= c;  b = ROTL32(b,  7)

/* One double round (column + diagonal). Force-inlined: at -O2 GCC left
 * this out of line and the 10 calls per block compiled to 10× `l32r` +
 * `callx8` (-mlongcalls) plus 10 windowed `entry`/`retw` pairs, each a
 * potential window-overflow exception on the deep wg_rx → transport →
 * AEAD call chain. With a single inlined body inside a counted loop the
 * rounds run under one Xtensa zero-overhead `loop` with no calls. */
static inline __attribute__((always_inline)) void INNER_BLOCK(uint32_t *block) {
    QUARTERROUND(block[0], block[4], block[ 8], block[12]); /* column 0 */
    QUARTERROUND(block[1], block[5], block[ 9], block[13]); /* column 1 */
    QUARTERROUND(block[2], block[6], block[10], block[14]); /* column 2 */
    QUARTERROUND(block[3], block[7], block[11], block[15]); /* column 3 */
    QUARTERROUND(block[0], block[5], block[10], block[15]); /* diagonal 1 */
    QUARTERROUND(block[1], block[6], block[11], block[12]); /* diagonal 2 */
    QUARTERROUND(block[2], block[7], block[ 8], block[13]); /* diagonal 3 */
    QUARTERROUND(block[3], block[4], block[ 9], block[14]); /* diagonal 4 */
}

/* 20 rounds = 10 double rounds. A counted loop rather than 10 textual
 * calls: the body is ~100 instructions, well above GCC's complete-unroll
 * threshold at -O2, so it stays a loop — one copy in the I-cache/flash
 * cache instead of ten, and fixed trip count (no data-dependent
 * control flow). */
#define TWENTY_ROUNDS(x)                                   \
    do {                                                   \
        for (int _r = 0; _r < 10; ++_r) INNER_BLOCK(x);    \
    } while (0)

/* Keystream block as 16 little-endian words. Word-typed on purpose: the
 * writer below and the XOR reader both touch it with plain l32i/s32i,
 * and reading a uint32_t[] through a uint8_t* (for the tail bytes) is
 * always legal, whereas the reverse is not. */
static void chacha20_block(struct chacha20_ctx *ctx, uint32_t stream[16]) {
    uint32_t working_state[16];
    int i;

    for (i = 0; i < 16; ++i) {
        working_state[i] = ctx->state[i];
    }

    TWENTY_ROUNDS(working_state);

    for (i = 0; i < 16; ++i) {
        stream[i] = PLUS(working_state[i], ctx->state[i]);
    }
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

/* Hot path: XOR one keystream block into the data, a word at a time.
 *
 * Two loops, selected once per call on the ACTUAL alignment of in/out:
 *   - aligned:   __builtin_assume_aligned lets GCC emit one l32i, one
 *                xor and one s32i per word — no aliasing games, no UB.
 *                This is the path every WireGuard packet takes: the
 *                transport payload sits at offset 16 of a word-aligned
 *                packet buffer (wg_netif.c) and lwIP pbuf payloads are
 *                MEM_ALIGNMENT(4)-aligned.
 *   - unaligned: register-only byte assembly (above), for callers that
 *                hand us an odd offset (DISCO / DERP scratch, tests).
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

void chacha20(struct chacha20_ctx *ctx, uint8_t *out, const uint8_t *in, uint32_t len) {
    /* Keystream block; word-typed so it is 4-byte aligned by
     * construction (Xtensa requires it for l32i/s32i). */
    uint32_t output[CHACHA20_BLOCK_SIZE / 4];

    if (len) {
        for (;;) {
            chacha20_block(ctx, output);
            ctx->state[12] = PLUSONE(ctx->state[12]);
            if (len <= 64) {
                xor_block_u32(out, in, output, len);
                return;
            }
            xor_block_u32(out, in, output, 64);
            len -= 64;
            out += 64;
            in += 64;
        }
    }
}

/* For wireguard: nonce composed of 32 bits of zeros followed by the
 * 64-bit little-endian counter; word 12 holds the per-block counter. */
void chacha20_init(struct chacha20_ctx *ctx, const uint8_t *key, uint64_t nonce) {
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

    TWENTY_ROUNDS(state);

    U32TO8_LITTLE(out +  0, state[ 0]);
    U32TO8_LITTLE(out +  4, state[ 1]);
    U32TO8_LITTLE(out +  8, state[ 2]);
    U32TO8_LITTLE(out + 12, state[ 3]);
    U32TO8_LITTLE(out + 16, state[12]);
    U32TO8_LITTLE(out + 20, state[13]);
    U32TO8_LITTLE(out + 24, state[14]);
    U32TO8_LITTLE(out + 28, state[15]);
}
