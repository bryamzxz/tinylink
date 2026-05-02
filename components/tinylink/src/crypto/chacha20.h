// SPDX-License-Identifier: BSD-3-Clause
//
// tinylink note: lifted verbatim from trombik/esp_wireguard
// (src/crypto/refc/chacha20.h), itself adapted from D. J. Bernstein's
// public-domain reference. Held under the BSD-3-Clause notice below.
//
// Audit (2026-05-02): line-by-line vs RFC 8439 §2.1 (QR), §2.3 (block),
// §2.4 (encryption). Constants 0x61707865/0x3320646e/0x79622d32/
// 0x6b206574 = "expand 32-byte k" LE. Column rounds {(0,4,8,12),
// (1,5,9,13),(2,6,10,14),(3,7,11,15)} and diagonal rounds {(0,5,10,15),
// (1,6,11,12),(2,7,8,13),(3,4,9,14)} match spec. Block: 20 rounds
// (10 inner_blocks of 8 QRs each), then state' += state, serialize LE.
// Validated by host KAT against RFC 8439 §2.4.2.
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

#ifndef TINYLINK_CHACHA20_H_
#define TINYLINK_CHACHA20_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CHACHA20_BLOCK_SIZE  (64)
#define CHACHA20_KEY_SIZE    (32)

/* Note: nonce here is the WireGuard-shaped 8-byte LE counter. RFC 8439
 * standard ChaCha20 uses a 12-byte nonce; the first 4 bytes go into
 * state[13] and the remaining 8 are state[14..15] LE. This API hard-
 * wires state[13]=0, which matches the WG nonce shape and ALSO matches
 * any RFC 8439 nonce whose first 4 bytes are zero (notably the
 * §2.4.2 KAT vector). For non-WG callers with a non-zero state[13],
 * write to ctx->state[13] manually after init. */
struct chacha20_ctx {
    uint32_t state[16];
};

void chacha20_init(struct chacha20_ctx *ctx, const uint8_t *key, uint64_t nonce);
void chacha20(struct chacha20_ctx *ctx, uint8_t *out, const uint8_t *in, uint32_t len);
void hchacha20(uint8_t *out, const uint8_t *nonce, const uint8_t *key);

#ifdef __cplusplus
}
#endif

#endif /* TINYLINK_CHACHA20_H_ */
