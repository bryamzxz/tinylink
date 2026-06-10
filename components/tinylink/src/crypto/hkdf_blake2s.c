// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "hkdf_blake2s.h"

#include <string.h>

#include "blake2s.h"
#include "secure_zero.h"

#define BLOCK_LEN 64

int hmac_blake2s(uint8_t out[HKDF_BLAKE2S_HASHLEN],
                 const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len)
{
    uint8_t k[BLOCK_LEN] = {0};
    uint8_t ipad[BLOCK_LEN];
    uint8_t opad[BLOCK_LEN];
    uint8_t inner[HKDF_BLAKE2S_HASHLEN];

    if (out == NULL) return -1;
    if (key == NULL && key_len != 0) return -1;
    if (data == NULL && data_len != 0) return -1;

    if (key_len > BLOCK_LEN) {
        if (blake2s(k, HKDF_BLAKE2S_HASHLEN, key, key_len, NULL, 0) != 0) {
            return -1;
        }
        /* k[HASHLEN..BLOCK_LEN] stays zero from the initializer above. */
    } else if (key_len > 0) {
        memcpy(k, key, key_len);
    }
    for (int i = 0; i < BLOCK_LEN; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    /* inner = BLAKE2s(ipad || data). */
    blake2s_state S;
    if (blake2s_init(&S, HKDF_BLAKE2S_HASHLEN) != 0) return -1;
    if (blake2s_update(&S, ipad, BLOCK_LEN) != 0) return -1;
    if (data_len > 0 && blake2s_update(&S, data, data_len) != 0) return -1;
    if (blake2s_final(&S, inner, HKDF_BLAKE2S_HASHLEN) != 0) return -1;

    /* out = BLAKE2s(opad || inner). */
    if (blake2s_init(&S, HKDF_BLAKE2S_HASHLEN) != 0) return -1;
    if (blake2s_update(&S, opad, BLOCK_LEN) != 0) return -1;
    if (blake2s_update(&S, inner, HKDF_BLAKE2S_HASHLEN) != 0) return -1;
    if (blake2s_final(&S, out, HKDF_BLAKE2S_HASHLEN) != 0) return -1;

    /* Best-effort scrub. */
    tl_secure_zero(k, sizeof(k));
    tl_secure_zero(ipad, sizeof(ipad));
    tl_secure_zero(opad, sizeof(opad));
    memset(inner, 0, sizeof(inner));
    return 0;
}

int noise_hkdf1(const uint8_t ck[HKDF_BLAKE2S_HASHLEN],
                const uint8_t *input, size_t input_len,
                uint8_t out1[HKDF_BLAKE2S_HASHLEN])
{
    uint8_t temp_key[HKDF_BLAKE2S_HASHLEN];
    uint8_t one = 0x01;

    if (hmac_blake2s(temp_key, ck, HKDF_BLAKE2S_HASHLEN,
                     input, input_len) != 0) return -1;
    if (hmac_blake2s(out1, temp_key, HKDF_BLAKE2S_HASHLEN, &one, 1) != 0) {
        tl_secure_zero(temp_key, sizeof(temp_key));
        return -1;
    }
    tl_secure_zero(temp_key, sizeof(temp_key));
    return 0;
}

int noise_hkdf2(const uint8_t ck[HKDF_BLAKE2S_HASHLEN],
                const uint8_t *input, size_t input_len,
                uint8_t out1[HKDF_BLAKE2S_HASHLEN],
                uint8_t out2[HKDF_BLAKE2S_HASHLEN])
{
    uint8_t temp_key[HKDF_BLAKE2S_HASHLEN];
    uint8_t one  = 0x01;
    uint8_t two  = 0x02;
    uint8_t buf[HKDF_BLAKE2S_HASHLEN + 1];

    if (hmac_blake2s(temp_key, ck, HKDF_BLAKE2S_HASHLEN,
                     input, input_len) != 0) return -1;
    if (hmac_blake2s(out1, temp_key, HKDF_BLAKE2S_HASHLEN, &one, 1) != 0) {
        tl_secure_zero(temp_key, sizeof(temp_key));
        return -1;
    }
    memcpy(buf, out1, HKDF_BLAKE2S_HASHLEN);
    buf[HKDF_BLAKE2S_HASHLEN] = two;
    if (hmac_blake2s(out2, temp_key, HKDF_BLAKE2S_HASHLEN,
                     buf, HKDF_BLAKE2S_HASHLEN + 1) != 0) {
        tl_secure_zero(temp_key, sizeof(temp_key));
        tl_secure_zero(buf, sizeof(buf));
        return -1;
    }
    tl_secure_zero(temp_key, sizeof(temp_key));
    tl_secure_zero(buf, sizeof(buf));
    return 0;
}

int noise_hkdf3(const uint8_t ck[HKDF_BLAKE2S_HASHLEN],
                const uint8_t *input, size_t input_len,
                uint8_t out1[HKDF_BLAKE2S_HASHLEN],
                uint8_t out2[HKDF_BLAKE2S_HASHLEN],
                uint8_t out3[HKDF_BLAKE2S_HASHLEN])
{
    if (noise_hkdf2(ck, input, input_len, out1, out2) != 0) return -1;

    uint8_t temp_key[HKDF_BLAKE2S_HASHLEN];
    uint8_t buf[HKDF_BLAKE2S_HASHLEN + 1];

    if (hmac_blake2s(temp_key, ck, HKDF_BLAKE2S_HASHLEN,
                     input, input_len) != 0) return -1;
    memcpy(buf, out2, HKDF_BLAKE2S_HASHLEN);
    buf[HKDF_BLAKE2S_HASHLEN] = 0x03;
    if (hmac_blake2s(out3, temp_key, HKDF_BLAKE2S_HASHLEN,
                     buf, HKDF_BLAKE2S_HASHLEN + 1) != 0) {
        tl_secure_zero(temp_key, sizeof(temp_key));
        tl_secure_zero(buf, sizeof(buf));
        return -1;
    }
    tl_secure_zero(temp_key, sizeof(temp_key));
    tl_secure_zero(buf, sizeof(buf));
    return 0;
}

int hkdf_blake2s_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm,  size_t ikm_len,
                         uint8_t prk[HKDF_BLAKE2S_HASHLEN])
{
    static const uint8_t empty_salt[HKDF_BLAKE2S_HASHLEN] = {0};
    if (salt == NULL || salt_len == 0) {
        return hmac_blake2s(prk, empty_salt, HKDF_BLAKE2S_HASHLEN,
                            ikm, ikm_len);
    }
    return hmac_blake2s(prk, salt, salt_len, ikm, ikm_len);
}

int hkdf_blake2s_expand(const uint8_t prk[HKDF_BLAKE2S_HASHLEN],
                        const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len)
{
    if (out_len > 255 * HKDF_BLAKE2S_HASHLEN) return -1;

    uint8_t t[HKDF_BLAKE2S_HASHLEN];
    uint8_t buf[HKDF_BLAKE2S_HASHLEN + 256 + 1];
    size_t prev_len = 0;
    size_t off = 0;
    uint8_t counter = 1;

    if (info_len > 256) return -1; /* keep buf bounded; tinylink uses small info */

    while (off < out_len) {
        size_t buf_len = 0;
        if (prev_len > 0) {
            memcpy(buf, t, prev_len);
            buf_len = prev_len;
        }
        if (info_len > 0) {
            memcpy(buf + buf_len, info, info_len);
            buf_len += info_len;
        }
        buf[buf_len++] = counter;
        if (hmac_blake2s(t, prk, HKDF_BLAKE2S_HASHLEN, buf, buf_len) != 0) {
            return -1;
        }
        size_t take = (out_len - off < HKDF_BLAKE2S_HASHLEN)
                       ? (out_len - off) : HKDF_BLAKE2S_HASHLEN;
        memcpy(out + off, t, take);
        prev_len = HKDF_BLAKE2S_HASHLEN;
        off += take;
        counter++;
    }
    tl_secure_zero(t, sizeof(t));
    tl_secure_zero(buf, sizeof(buf));
    return 0;
}
