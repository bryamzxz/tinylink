// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// ts2021 client: TLS to controlplane.tailscale.com, HTTP/1.1 Upgrade,
// Noise IK handshake, then ChaCha20-Poly1305 framed records carrying the
// inner control-plane traffic (HTTP/2 in the canonical Tailscale client).
//
// Wire format constants come from upstream
// `tailscale/control/controlbase/messages.go` and
// `tailscale/control/controlhttp/{client,controlhttpcommon}.go`.
// h2_client.c sits on top of ts2021_send / ts2021_recv to carry HTTP/2
// frames; do not call ts2021_send with raw HTTP/1.1 bytes — the control
// plane runs http2.Server.ServeConn after the Upgrade.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_tls.h"

#include "noise_ik.h"

#define TS2021_PROTOCOL_NAME    "Noise_IK_25519_ChaChaPoly_BLAKE2s"
#define TS2021_PROTOCOL_VERSION 1
#define TS2021_PROLOGUE_PREFIX  "Tailscale Control Protocol v"

/* controlbase wire format: */
#define TS2021_INIT_HEADER_LEN  5  /* BE16 version || type(1) || BE16 length */
#define TS2021_HEADER_LEN       3  /* type(1)      || BE16 length            */

#define TS2021_MSG_INITIATION   0x01
#define TS2021_MSG_RESPONSE     0x02
#define TS2021_MSG_ERROR        0x03
#define TS2021_MSG_RECORD       0x04

/* maxMessageSize in upstream controlbase. Plaintext max = wire - 3 - 16. */
#define TS2021_MAX_MESSAGE      4096
#define TS2021_RECORD_PLAINTEXT_MAX (TS2021_MAX_MESSAGE - TS2021_HEADER_LEN - NOISE_TAGLEN)

/* EarlyPayload sentinel sent (optionally) by the server before HTTP/2
 * begins: 5-byte magic || BE32 length || JSON-encoded tailcfg.EarlyNoise.
 * The current Tailscale client reads it but never acts on the
 * NodeKeyChallenge; we skip it on receive. */
#define TS2021_EARLY_PAYLOAD_HDR_LEN 9
#define TS2021_EARLY_PAYLOAD_MAGIC   "\xFF\xFF\xFFTS"
#define TS2021_EARLY_PAYLOAD_MAGIC_LEN 5

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    esp_tls_t        *tls;
    noise_ik_state_t  noise;
    bool              connected;

    /* Plaintext that has been decrypted but not yet returned to a
     * ts2021_recv() caller (e.g. the 9 EarlyPayload bytes that turned out
     * to be plain HTTP/2). */
    uint8_t  rx_residual[TS2021_RECORD_PLAINTEXT_MAX];
    size_t   rx_residual_len;
    size_t   rx_residual_off;
} ts2021_conn_t;

/* Connect, perform Noise IK, swallow optional EarlyPayload. The Noise
 * channel is then ready for HTTP/2 framing via h2_client. */
esp_err_t ts2021_connect(ts2021_conn_t *out,
                         const uint8_t machine_priv[NOISE_DHLEN],
                         const uint8_t machine_pub[NOISE_DHLEN],
                         const uint8_t control_pub[NOISE_DHLEN]);

/* Encrypt and write `data` as one Noise transport record (msg type 4). */
esp_err_t ts2021_send(ts2021_conn_t *c,
                      const uint8_t *data, size_t data_len);

/* Read up to out_max plaintext bytes. Drains rx_residual first, then
 * reads + decrypts the next record. Returns ESP_OK with *out_len set. */
esp_err_t ts2021_recv(ts2021_conn_t *c,
                      uint8_t *out, size_t out_max, size_t *out_len);

void ts2021_close(ts2021_conn_t *c);

#ifdef __cplusplus
}
#endif
