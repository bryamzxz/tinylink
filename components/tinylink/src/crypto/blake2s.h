// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// BLAKE2s-256, hand-derived from RFC 7693 reference (CC0). Output is
// always 32 bytes for the tinylink call sites; we only need the keyed
// variant for HKDF.
//
// VERIFY: this implementation must be checked against the RFC 7693
// Appendix A test vectors before being trusted in production.

#pragma once

#include <stddef.h>
#include <stdint.h>

#define BLAKE2S_BLOCK_LEN 64
#define BLAKE2S_OUT_LEN   32
#define BLAKE2S_KEY_MAX   32

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[BLAKE2S_BLOCK_LEN];
    size_t   buflen;
    size_t   outlen;
} blake2s_state;

int blake2s_init(blake2s_state *S, size_t outlen);
int blake2s_init_key(blake2s_state *S, size_t outlen,
                     const void *key, size_t keylen);
int blake2s_update(blake2s_state *S, const void *in, size_t inlen);
int blake2s_final(blake2s_state *S, void *out, size_t outlen);

/* One-shot helper: BLAKE2s(in, key?). Always produces BLAKE2S_OUT_LEN bytes. */
int blake2s(void *out, size_t outlen,
            const void *in, size_t inlen,
            const void *key, size_t keylen);

#ifdef __cplusplus
}
#endif
