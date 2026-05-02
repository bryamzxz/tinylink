// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "noise_ik.h"

#include <string.h>

#include "esp_log.h"
#include "mbedtls/chachapoly.h"

#include "blake2s.h"
#include "curve25519.h"
#include "hkdf_blake2s.h"

static const char *TAG = "noise_ik";

/* MixHash(data): h = HASH(h || data). */
static esp_err_t mix_hash(noise_ik_state_t *st,
                          const uint8_t *data, size_t data_len)
{
    blake2s_state S;
    if (blake2s_init(&S, NOISE_HASHLEN) != 0) return ESP_FAIL;
    if (blake2s_update(&S, st->h, NOISE_HASHLEN) != 0) return ESP_FAIL;
    if (data_len > 0 && blake2s_update(&S, data, data_len) != 0) return ESP_FAIL;
    if (blake2s_final(&S, st->h, NOISE_HASHLEN) != 0) return ESP_FAIL;
    return ESP_OK;
}

/* MixKey(input): (ck, k) = HKDF(ck, input, 2); n = 0; have_k = true. */
static esp_err_t mix_key(noise_ik_state_t *st,
                         const uint8_t *input, size_t input_len)
{
    uint8_t new_ck[NOISE_HASHLEN];
    uint8_t new_k[NOISE_HASHLEN];

    if (noise_hkdf2(st->ck, input, input_len, new_ck, new_k) != 0) {
        return ESP_FAIL;
    }
    memcpy(st->ck, new_ck, NOISE_HASHLEN);
    /* Noise truncates HASHLEN > KEYLEN to first 32 bytes; for BLAKE2s they
     * are equal, so the copy is straightforward. */
    memcpy(st->k, new_k, NOISE_KEYLEN);
    st->have_k = true;
    st->n = 0;
    memset(new_ck, 0, sizeof(new_ck));
    memset(new_k, 0, sizeof(new_k));
    return ESP_OK;
}

/* Build the 12-byte ChaCha20-Poly1305 nonce from a 64-bit counter
 * (Noise §5.1: 4 zero bytes, then LE64 counter). */
static void noise_nonce(uint8_t out[12], uint64_t n)
{
    memset(out, 0, 4);
    for (int i = 0; i < 8; i++) {
        out[4 + i] = (uint8_t)((n >> (8 * i)) & 0xFF);
    }
}

/* EncryptAndHash(plaintext) → ciphertext (plaintext_len + TAGLEN). */
static esp_err_t encrypt_and_hash(noise_ik_state_t *st,
                                  uint8_t *out, size_t out_max,
                                  const uint8_t *plaintext, size_t plaintext_len)
{
    if (out_max < plaintext_len + NOISE_TAGLEN) return ESP_ERR_INVALID_SIZE;

    uint8_t nonce[12];
    noise_nonce(nonce, st->n);

    mbedtls_chachapoly_context cp;
    mbedtls_chachapoly_init(&cp);
    int rc = mbedtls_chachapoly_setkey(&cp, st->k);
    if (rc == 0) {
        rc = mbedtls_chachapoly_encrypt_and_tag(&cp, plaintext_len,
                                                nonce,
                                                st->h, NOISE_HASHLEN,
                                                plaintext, out,
                                                out + plaintext_len);
    }
    mbedtls_chachapoly_free(&cp);
    if (rc != 0) {
        ESP_LOGE(TAG, "chachapoly_encrypt failed: %d", rc);
        return ESP_FAIL;
    }
    if (mix_hash(st, out, plaintext_len + NOISE_TAGLEN) != ESP_OK) {
        return ESP_FAIL;
    }
    st->n++;
    return ESP_OK;
}

/* DecryptAndHash(ciphertext) → plaintext (ciphertext_len - TAGLEN). */
static esp_err_t decrypt_and_hash(noise_ik_state_t *st,
                                  uint8_t *out, size_t out_max,
                                  const uint8_t *ciphertext, size_t ciphertext_len)
{
    if (ciphertext_len < NOISE_TAGLEN) return ESP_ERR_INVALID_SIZE;
    size_t plaintext_len = ciphertext_len - NOISE_TAGLEN;
    if (out_max < plaintext_len) return ESP_ERR_INVALID_SIZE;

    uint8_t nonce[12];
    noise_nonce(nonce, st->n);

    mbedtls_chachapoly_context cp;
    mbedtls_chachapoly_init(&cp);
    int rc = mbedtls_chachapoly_setkey(&cp, st->k);
    if (rc == 0) {
        rc = mbedtls_chachapoly_auth_decrypt(&cp, plaintext_len,
                                             nonce,
                                             st->h, NOISE_HASHLEN,
                                             ciphertext + plaintext_len,
                                             ciphertext, out);
    }
    mbedtls_chachapoly_free(&cp);
    if (rc != 0) {
        ESP_LOGE(TAG, "chachapoly_decrypt failed: %d", rc);
        return ESP_FAIL;
    }
    /* MixHash uses the ciphertext, not the plaintext. */
    if (mix_hash(st, ciphertext, ciphertext_len) != ESP_OK) {
        return ESP_FAIL;
    }
    st->n++;
    return ESP_OK;
}

esp_err_t noise_ik_init(noise_ik_state_t *st,
                        const uint8_t s_priv[NOISE_DHLEN],
                        const uint8_t s_pub[NOISE_DHLEN],
                        const uint8_t rs[NOISE_DHLEN],
                        const char *protocol_name,
                        const uint8_t *prologue, size_t prologue_len)
{
    if (st == NULL || s_priv == NULL || s_pub == NULL || rs == NULL ||
        protocol_name == NULL) return ESP_ERR_INVALID_ARG;

    memset(st, 0, sizeof(*st));
    memcpy(st->s_priv, s_priv, NOISE_DHLEN);
    memcpy(st->s_pub,  s_pub,  NOISE_DHLEN);
    memcpy(st->rs,     rs,     NOISE_DHLEN);

    /* Initialize h: if name length > HASHLEN, h = HASH(name). Otherwise
     * pad with zeros up to HASHLEN. The Tailscale ts2021 name
     * "Noise_IK_25519_ChaChaPoly_BLAKE2s" is 33 chars, > 32, so we hash. */
    size_t name_len = strlen(protocol_name);
    if (name_len > NOISE_HASHLEN) {
        if (blake2s(st->h, NOISE_HASHLEN, protocol_name, name_len, NULL, 0) != 0) {
            return ESP_FAIL;
        }
    } else {
        memset(st->h, 0, NOISE_HASHLEN);
        memcpy(st->h, protocol_name, name_len);
    }
    memcpy(st->ck, st->h, NOISE_HASHLEN);

    /* MixHash(prologue). */
    if (mix_hash(st, prologue, prologue_len) != ESP_OK) return ESP_FAIL;
    /* IK pre-message: <- s. Initiator already knows rs. MixHash(rs). */
    if (mix_hash(st, rs, NOISE_DHLEN) != ESP_OK) return ESP_FAIL;
    return ESP_OK;
}

esp_err_t noise_ik_write_msg1(noise_ik_state_t *st,
                              uint8_t out[NOISE_IK_MSG1_LEN])
{
    if (st == NULL || out == NULL) return ESP_ERR_INVALID_ARG;

    /* -> e */
    if (curve25519_keypair(st->e_priv, st->e_pub) != 0) return ESP_FAIL;
    memcpy(out, st->e_pub, NOISE_DHLEN);
    if (mix_hash(st, st->e_pub, NOISE_DHLEN) != ESP_OK) return ESP_FAIL;

    /* es: MixKey(DH(e, rs)) */
    uint8_t dh[NOISE_DHLEN];
    if (curve25519_dh(dh, st->e_priv, st->rs) != 0) return ESP_FAIL;
    if (mix_key(st, dh, NOISE_DHLEN) != ESP_OK) return ESP_FAIL;

    /* s: write EncryptAndHash(s_pub) — 48 bytes (32 + 16 tag). */
    if (encrypt_and_hash(st, out + NOISE_DHLEN,
                         NOISE_IK_MSG1_LEN - NOISE_DHLEN,
                         st->s_pub, NOISE_DHLEN) != ESP_OK) return ESP_FAIL;

    /* ss: MixKey(DH(s, rs)) */
    if (curve25519_dh(dh, st->s_priv, st->rs) != 0) return ESP_FAIL;
    if (mix_key(st, dh, NOISE_DHLEN) != ESP_OK) return ESP_FAIL;

    /* Empty payload → 16-byte auth tag at the tail. */
    if (encrypt_and_hash(st, out + NOISE_DHLEN + NOISE_DHLEN + NOISE_TAGLEN,
                         NOISE_TAGLEN, NULL, 0) != ESP_OK) return ESP_FAIL;

    memset(dh, 0, sizeof(dh));
    return ESP_OK;
}

esp_err_t noise_ik_read_msg2(noise_ik_state_t *st,
                             const uint8_t in[NOISE_IK_MSG2_LEN])
{
    if (st == NULL || in == NULL) return ESP_ERR_INVALID_ARG;

    /* <- e */
    memcpy(st->re, in, NOISE_DHLEN);
    if (mix_hash(st, st->re, NOISE_DHLEN) != ESP_OK) return ESP_FAIL;

    /* ee: MixKey(DH(e, re)) */
    uint8_t dh[NOISE_DHLEN];
    if (curve25519_dh(dh, st->e_priv, st->re) != 0) return ESP_FAIL;
    if (mix_key(st, dh, NOISE_DHLEN) != ESP_OK) return ESP_FAIL;

    /* se: MixKey(DH(s, re)) */
    if (curve25519_dh(dh, st->s_priv, st->re) != 0) return ESP_FAIL;
    if (mix_key(st, dh, NOISE_DHLEN) != ESP_OK) return ESP_FAIL;

    /* Empty payload at in[32..48]: just the 16-byte tag. */
    uint8_t dummy[1] = {0};
    if (decrypt_and_hash(st, dummy, sizeof(dummy),
                         in + NOISE_DHLEN, NOISE_TAGLEN) != ESP_OK) {
        return ESP_FAIL;
    }

    /* Split: (k_send, k_recv) = HKDF(ck, "", 2). */
    if (noise_hkdf2(st->ck, NULL, 0,
                    st->k_send, st->k_recv) != 0) return ESP_FAIL;
    st->n_send = 0;
    st->n_recv = 0;
    st->transport_ready = true;

    memset(dh, 0, sizeof(dh));
    return ESP_OK;
}

esp_err_t noise_ik_encrypt(noise_ik_state_t *st,
                           uint8_t *out, size_t out_max,
                           const uint8_t *plaintext, size_t plaintext_len,
                           size_t *out_len)
{
    if (st == NULL || out == NULL || out_len == NULL) return ESP_ERR_INVALID_ARG;
    if (!st->transport_ready) return ESP_ERR_INVALID_STATE;
    if (plaintext == NULL && plaintext_len != 0) return ESP_ERR_INVALID_ARG;
    if (out_max < plaintext_len + NOISE_TAGLEN) return ESP_ERR_INVALID_SIZE;

    uint8_t nonce[12];
    noise_nonce(nonce, st->n_send);

    mbedtls_chachapoly_context cp;
    mbedtls_chachapoly_init(&cp);
    int rc = mbedtls_chachapoly_setkey(&cp, st->k_send);
    if (rc == 0) {
        rc = mbedtls_chachapoly_encrypt_and_tag(&cp, plaintext_len,
                                                nonce,
                                                NULL, 0,
                                                plaintext, out,
                                                out + plaintext_len);
    }
    mbedtls_chachapoly_free(&cp);
    if (rc != 0) {
        ESP_LOGE(TAG, "transport encrypt failed: %d", rc);
        return ESP_FAIL;
    }
    *out_len = plaintext_len + NOISE_TAGLEN;
    st->n_send++;
    return ESP_OK;
}

esp_err_t noise_ik_decrypt(noise_ik_state_t *st,
                           uint8_t *out, size_t out_max,
                           const uint8_t *ciphertext, size_t ciphertext_len,
                           size_t *out_len)
{
    if (st == NULL || out == NULL || out_len == NULL) return ESP_ERR_INVALID_ARG;
    if (!st->transport_ready) return ESP_ERR_INVALID_STATE;
    if (ciphertext_len < NOISE_TAGLEN) return ESP_ERR_INVALID_SIZE;

    size_t plaintext_len = ciphertext_len - NOISE_TAGLEN;
    if (out_max < plaintext_len) return ESP_ERR_INVALID_SIZE;

    uint8_t nonce[12];
    noise_nonce(nonce, st->n_recv);

    mbedtls_chachapoly_context cp;
    mbedtls_chachapoly_init(&cp);
    int rc = mbedtls_chachapoly_setkey(&cp, st->k_recv);
    if (rc == 0) {
        rc = mbedtls_chachapoly_auth_decrypt(&cp, plaintext_len,
                                             nonce,
                                             NULL, 0,
                                             ciphertext + plaintext_len,
                                             ciphertext, out);
    }
    mbedtls_chachapoly_free(&cp);
    if (rc != 0) {
        ESP_LOGW(TAG, "transport decrypt failed: %d", rc);
        return ESP_FAIL;
    }
    *out_len = plaintext_len;
    st->n_recv++;
    return ESP_OK;
}
