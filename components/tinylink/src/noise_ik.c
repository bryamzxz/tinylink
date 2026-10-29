// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "noise_ik.h"

#include <string.h>

#include "esp_log.h"

#include "blake2s.h"
#include "chacha20poly1305.h"
#include "curve25519.h"
#include "hkdf_blake2s.h"
#include "secure_zero.h"

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
    tl_secure_zero(new_ck, sizeof(new_ck));
    tl_secure_zero(new_k, sizeof(new_k));
    return ESP_OK;
}

/* Build the 12-byte ChaCha20-Poly1305 nonce from a 64-bit counter.
 *
 * IMPORTANT: tinylink uses this with the Tailscale ts2021 transport,
 * not pure Noise. Tailscale's controlbase/conn.go encodes the
 * 8-byte counter portion as BIG-ENDIAN (see `nonce.Increment` in
 * upstream: `binary.BigEndian.PutUint64(n[4:], …)`), deviating from
 * the Noise spec's little-endian. The handshake's per-message AEADs
 * always run with n=0 (each MixKey resets the counter) so the
 * endianness doesn't matter there; on the transport path n>0
 * happens immediately on the second record and a LE encoding makes
 * the AEAD auth-fail with -86. We follow Tailscale and emit BE.
 *
 * Discovered 2026-05-02 on first hardware boot: first transport
 * record decrypted (n=0, both encodings produce all-zero counter
 * bytes), second one failed. Hex dumps confirmed the nonce
 * mismatch at counter=1.
 *
 * The 12 bytes are handed to the AEAD as an opaque RFC 8439 nonce
 * (state words 13..15 = LE loads of bytes 0..3, 4..7, 8..11), exactly
 * as mbedtls_chachapoly_* consumed them before round 1.3.2 — so the
 * BE counter reaches the wire unchanged. Pinned against the pre-1.3.2
 * mbedTLS path by tools/test/test_noise_ik.c. */
static void noise_nonce(uint8_t out[CHACHA20POLY1305_NONCE_LEN], uint64_t n)
{
    memset(out, 0, 4);
    for (int i = 0; i < 8; i++) {
        out[4 + i] = (uint8_t)((n >> (8 * (7 - i))) & 0xFF);
    }
}

/* EncryptAndHash(plaintext) → ciphertext (plaintext_len + TAGLEN). */
static esp_err_t encrypt_and_hash(noise_ik_state_t *st,
                                  uint8_t *out, size_t out_max,
                                  const uint8_t *plaintext, size_t plaintext_len)
{
    if (out_max < plaintext_len + NOISE_TAGLEN) return ESP_ERR_INVALID_SIZE;

    uint8_t nonce[CHACHA20POLY1305_NONCE_LEN];
    noise_nonce(nonce, st->n);

    /* AAD = h. ciphertext || tag lands in out[0 .. plaintext_len + 16). */
    chacha20poly1305_encrypt(out, plaintext, plaintext_len,
                             st->h, NOISE_HASHLEN, st->k, nonce);
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

    uint8_t nonce[CHACHA20POLY1305_NONCE_LEN];
    noise_nonce(nonce, st->n);

    /* Constant-time tag check before any plaintext is written; on
     * failure out is untouched and neither h nor n moves. */
    if (chacha20poly1305_decrypt(out, ciphertext, ciphertext_len,
                                 st->h, NOISE_HASHLEN, st->k, nonce) != 0) {
        /* %u, not %llu: newlib nano printf has no 64-bit conversions. */
        ESP_LOGE(TAG, "handshake AEAD auth failed (n=%u)", (unsigned)st->n);
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
    tl_secure_zero(dh, sizeof(dh));  /* last use; before the next fallible step */

    /* Empty payload → 16-byte auth tag at the tail. */
    if (encrypt_and_hash(st, out + NOISE_DHLEN + NOISE_DHLEN + NOISE_TAGLEN,
                         NOISE_TAGLEN, NULL, 0) != ESP_OK) return ESP_FAIL;

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
    tl_secure_zero(dh, sizeof(dh));  /* last use; the tag check may fail */

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

    uint8_t nonce[CHACHA20POLY1305_NONCE_LEN];
    noise_nonce(nonce, st->n_send);

    /* Transport records carry no AAD. Runs on the in-tree IRAM AEAD the
     * WireGuard data plane uses (round 1.3.2; mbedTLS chachapoly before). */
    chacha20poly1305_encrypt(out, plaintext, plaintext_len,
                             NULL, 0, st->k_send, nonce);
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

    uint8_t nonce[CHACHA20POLY1305_NONCE_LEN];
    noise_nonce(nonce, st->n_recv);

    if (chacha20poly1305_decrypt(out, ciphertext, ciphertext_len,
                                 NULL, 0, st->k_recv, nonce) != 0) {
        ESP_LOGW(TAG, "transport decrypt failed (n=%u)",
                 (unsigned)st->n_recv);
        return ESP_FAIL;
    }
    *out_len = plaintext_len;
    st->n_recv++;
    return ESP_OK;
}
