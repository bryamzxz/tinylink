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

#define U8TO32_LITTLE(p)                            \
    (((uint32_t)((p)[0])      ) |                   \
     ((uint32_t)((p)[1]) <<  8) |                   \
     ((uint32_t)((p)[2]) << 16) |                   \
     ((uint32_t)((p)[3]) << 24))

#define U32TO8_LITTLE(p, v)        \
    do {                           \
        (p)[0] = U8V((v)      );   \
        (p)[1] = U8V((v) >>  8);   \
        (p)[2] = U8V((v) >> 16);   \
        (p)[3] = U8V((v) >> 24);   \
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

static inline void INNER_BLOCK(uint32_t *block) {
    QUARTERROUND(block[0], block[4], block[ 8], block[12]); /* column 0 */
    QUARTERROUND(block[1], block[5], block[ 9], block[13]); /* column 1 */
    QUARTERROUND(block[2], block[6], block[10], block[14]); /* column 2 */
    QUARTERROUND(block[3], block[7], block[11], block[15]); /* column 3 */
    QUARTERROUND(block[0], block[5], block[10], block[15]); /* diagonal 1 */
    QUARTERROUND(block[1], block[6], block[11], block[12]); /* diagonal 2 */
    QUARTERROUND(block[2], block[7], block[ 8], block[13]); /* diagonal 3 */
    QUARTERROUND(block[3], block[4], block[ 9], block[14]); /* diagonal 4 */
}

#define TWENTY_ROUNDS(x) ( \
    INNER_BLOCK(x), INNER_BLOCK(x), INNER_BLOCK(x), INNER_BLOCK(x), \
    INNER_BLOCK(x), INNER_BLOCK(x), INNER_BLOCK(x), INNER_BLOCK(x), \
    INNER_BLOCK(x), INNER_BLOCK(x))

static void chacha20_block(struct chacha20_ctx *ctx, uint8_t *stream) {
    uint32_t working_state[16];
    int i;

    for (i = 0; i < 16; ++i) {
        working_state[i] = ctx->state[i];
    }

    TWENTY_ROUNDS(working_state);

    for (i = 0; i < 16; ++i) {
        U32TO8_LITTLE(stream + (4 * i), PLUS(working_state[i], ctx->state[i]));
    }
}

void chacha20(struct chacha20_ctx *ctx, uint8_t *out, const uint8_t *in, uint32_t len) {
    uint8_t output[CHACHA20_BLOCK_SIZE];
    uint32_t i;

    if (len) {
        for (;;) {
            chacha20_block(ctx, output);
            ctx->state[12] = PLUSONE(ctx->state[12]);
            if (len <= 64) {
                for (i = 0; i < len; ++i) {
                    out[i] = in[i] ^ output[i];
                }
                return;
            }
            for (i = 0; i < 64; ++i) {
                out[i] = in[i] ^ output[i];
            }
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
    ctx->state[ 4] = U8TO32_LITTLE(key +  0);
    ctx->state[ 5] = U8TO32_LITTLE(key +  4);
    ctx->state[ 6] = U8TO32_LITTLE(key +  8);
    ctx->state[ 7] = U8TO32_LITTLE(key + 12);
    ctx->state[ 8] = U8TO32_LITTLE(key + 16);
    ctx->state[ 9] = U8TO32_LITTLE(key + 20);
    ctx->state[10] = U8TO32_LITTLE(key + 24);
    ctx->state[11] = U8TO32_LITTLE(key + 28);
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
