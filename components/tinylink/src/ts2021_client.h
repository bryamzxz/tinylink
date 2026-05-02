// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// ts2021 client: TLS to controlplane.tailscale.com, HTTP/1.1 Upgrade,
// Noise IK handshake, then ChaCha20-Poly1305 framed records carrying the
// inner control-plane traffic (HTTP/2 in the canonical Tailscale client).
//
// LAYERING
// --------
// This file owns: TLS connect, HTTP Upgrade, Noise IK handshake, and
// length-prefixed Noise transport records (ts2021_send / ts2021_recv).
//
// HTTP/2 framing on top of those records lives in h2_client.c, which
// uses nghttp2 (espressif/nghttp managed component). Tailscale's control
// plane runs http2.Server.ServeConn after the Upgrade and rejects
// HTTP/1.1, so /machine/register must go via h2_post_json() and not
// ts2021_send() directly with raw HTTP/1.1 bytes.
//
// In M2, the same h2_client will host the long-lived /machine/map
// stream; the framing here doesn't change.
//
// TS2021_VERIFY tags throughout mark spots where the exact wire format
// needs to be cross-checked against tailscale/control/ts2021/*.go and
// tailscale/control/controlclient/direct.go.

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_tls.h"

#include "noise_ik.h"

#define TS2021_PROTOCOL_NAME "Noise_IK_25519_ChaChaPoly_BLAKE2s"

/* Tailscale's framing: 1 byte version, 1 byte type, 2 bytes BE length. */
#define TS2021_FRAME_HEADER_LEN 4
#define TS2021_FRAME_VERSION    0x01

/* Frame types observed in the public Tailscale source. TS2021_VERIFY:
 * confirm against control/ts2021/types.go. */
#define TS2021_FRAME_HANDSHAKE  0x01
#define TS2021_FRAME_RECORD     0x02

/* Maximum inner Noise plaintext we will ever transmit / accept. Tailscale's
 * canonical client splits at ~16 KiB; we are stricter for the M1 register
 * path. */
#define TS2021_RECORD_PLAINTEXT_MAX 4096

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    esp_tls_t        *tls;
    noise_ik_state_t  noise;
    bool              connected;
    /* NodeKeyChallenge response that the caller (register.c) needs to
     * include in the RegisterRequest. May be empty if the server does not
     * send EarlyNoise. */
    uint8_t  node_key_signature[256];
    size_t   node_key_signature_len;
} ts2021_conn_t;

/* Establish TLS, do HTTP Upgrade, complete Noise IK, optionally collect
 * the EarlyNoise NodeKeyChallenge, and leave the connection ready for
 * application-level requests. */
esp_err_t ts2021_connect(ts2021_conn_t *out,
                         const uint8_t machine_priv[NOISE_DHLEN],
                         const uint8_t machine_pub[NOISE_DHLEN],
                         const uint8_t control_pub[NOISE_DHLEN],
                         const uint8_t node_priv[NOISE_DHLEN]);

/* Send `data` as one Noise record. */
esp_err_t ts2021_send(ts2021_conn_t *c,
                      const uint8_t *data, size_t data_len);

/* Receive one Noise record. Blocks. Returns ESP_OK with *out_len set on
 * success, ESP_ERR_TIMEOUT if no data within the underlying TLS timeout,
 * ESP_FAIL on parse / auth failure. */
esp_err_t ts2021_recv(ts2021_conn_t *c,
                      uint8_t *out, size_t out_max, size_t *out_len);

void ts2021_close(ts2021_conn_t *c);

#ifdef __cplusplus
}
#endif
