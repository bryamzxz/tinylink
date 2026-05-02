// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// HMAC-BLAKE2s and the Noise-flavored HKDF on top of it. tinylink uses
// these inside Noise IK's MixKey and Split steps. RFC 5869 HKDF is also
// exposed in case future M-stages need a non-Noise HKDF.

#pragma once

#include <stddef.h>
#include <stdint.h>

#define HKDF_BLAKE2S_HASHLEN 32

#ifdef __cplusplus
extern "C" {
#endif

/* HMAC-BLAKE2s over arbitrary key/data. Output is HKDF_BLAKE2S_HASHLEN. */
int hmac_blake2s(uint8_t out[HKDF_BLAKE2S_HASHLEN],
                 const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len);

/* Noise §4.3 HKDF — single output. Equivalent to the first 32 bytes of
 * noise_hkdf2 / noise_hkdf3. Used by WG's KDF1(c, x) calls (e.g. when
 * mixing only the chaining-key, no key material). */
int noise_hkdf1(const uint8_t ck[HKDF_BLAKE2S_HASHLEN],
                const uint8_t *input, size_t input_len,
                uint8_t out1[HKDF_BLAKE2S_HASHLEN]);

/* Noise §4.3 HKDF — two outputs. ck' goes in out1, k goes in out2. */
int noise_hkdf2(const uint8_t ck[HKDF_BLAKE2S_HASHLEN],
                const uint8_t *input, size_t input_len,
                uint8_t out1[HKDF_BLAKE2S_HASHLEN],
                uint8_t out2[HKDF_BLAKE2S_HASHLEN]);

/* Noise §4.3 HKDF — three outputs (used by some PSK patterns; included
 * for completeness, not strictly needed for IK). */
int noise_hkdf3(const uint8_t ck[HKDF_BLAKE2S_HASHLEN],
                const uint8_t *input, size_t input_len,
                uint8_t out1[HKDF_BLAKE2S_HASHLEN],
                uint8_t out2[HKDF_BLAKE2S_HASHLEN],
                uint8_t out3[HKDF_BLAKE2S_HASHLEN]);

/* Standard RFC 5869 HKDF over HMAC-BLAKE2s. */
int hkdf_blake2s_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm,  size_t ikm_len,
                         uint8_t prk[HKDF_BLAKE2S_HASHLEN]);

int hkdf_blake2s_expand(const uint8_t prk[HKDF_BLAKE2S_HASHLEN],
                        const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif
