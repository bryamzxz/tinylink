// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Noise_IK_25519_ChaChaPoly_BLAKE2s state machine. Initiator-only, which
// is all tinylink needs as a control-plane client.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#define NOISE_HASHLEN  32
#define NOISE_KEYLEN   32
#define NOISE_DHLEN    32
#define NOISE_TAGLEN   16

#define NOISE_IK_MSG1_LEN 96  /* e(32) || es-encrypted s(48) || empty payload tag(16) */
#define NOISE_IK_MSG2_LEN 48  /* e(32) || empty payload tag(16) */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /* Symmetric state */
    uint8_t h[NOISE_HASHLEN];
    uint8_t ck[NOISE_HASHLEN];
    uint8_t k[NOISE_KEYLEN];
    bool    have_k;
    uint64_t n;

    /* Local static + ephemeral */
    uint8_t s_priv[NOISE_DHLEN];
    uint8_t s_pub[NOISE_DHLEN];
    uint8_t e_priv[NOISE_DHLEN];
    uint8_t e_pub[NOISE_DHLEN];

    /* Remote static (pre-known) + ephemeral (learned in msg2) */
    uint8_t rs[NOISE_DHLEN];
    uint8_t re[NOISE_DHLEN];

    /* Transport keys after Split() */
    uint8_t  k_send[NOISE_KEYLEN];
    uint8_t  k_recv[NOISE_KEYLEN];
    uint64_t n_send;
    uint64_t n_recv;
    bool     transport_ready;
} noise_ik_state_t;

/* Initialize the initiator state. protocol_name is the literal Noise
 * protocol string ("Noise_IK_25519_ChaChaPoly_BLAKE2s", 33 bytes).
 * prologue may be NULL/0. */
esp_err_t noise_ik_init(noise_ik_state_t *st,
                        const uint8_t s_priv[NOISE_DHLEN],
                        const uint8_t s_pub[NOISE_DHLEN],
                        const uint8_t rs[NOISE_DHLEN],
                        const char *protocol_name,
                        const uint8_t *prologue, size_t prologue_len);

/* Write the IK initiator message (-> e, es, s, ss). out must be
 * NOISE_IK_MSG1_LEN bytes. payload is empty in the tinylink call site. */
esp_err_t noise_ik_write_msg1(noise_ik_state_t *st,
                              uint8_t out[NOISE_IK_MSG1_LEN]);

/* Read the IK responder message (<- e, ee, se). After this returns
 * ESP_OK, k_send / k_recv are valid for subsequent transport encryption. */
esp_err_t noise_ik_read_msg2(noise_ik_state_t *st,
                             const uint8_t in[NOISE_IK_MSG2_LEN]);

/* Transport-mode encrypt/decrypt. Each direction has its own counter. */
esp_err_t noise_ik_encrypt(noise_ik_state_t *st,
                           uint8_t *out, size_t out_max,
                           const uint8_t *plaintext, size_t plaintext_len,
                           size_t *out_len);

esp_err_t noise_ik_decrypt(noise_ik_state_t *st,
                           uint8_t *out, size_t out_max,
                           const uint8_t *ciphertext, size_t ciphertext_len,
                           size_t *out_len);

#ifdef __cplusplus
}
#endif
