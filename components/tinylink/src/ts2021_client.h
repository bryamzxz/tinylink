// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// ts2021 client: TLS to controlplane.tailscale.com, HTTP/1.1 Upgrade,
// Noise IK handshake, then ChaCha20-Poly1305 framed records carrying the
// inner control-plane traffic (HTTP/2 in the canonical Tailscale client).
//
// SCOPE NOTE — KNOWN GAP
// ----------------------
// M1 implements: TLS connect, HTTP Upgrade, Noise IK handshake (msg1/msg2),
// transport encrypt/decrypt of length-prefixed records, and an HTTP/1.1
// request/response round-trip inside the Noise channel.
//
// PROBLEM: the Tailscale control plane *requires HTTP/2* over the Noise
// channel for /machine/register (per the protocol research artifact §A:
// "the server insists on HTTP/2 over the Noise channel"). The HTTP/1.1
// path shipped today will be rejected by `controlplane.tailscale.com`
// and most likely also by any current Headscale.
//
// To make M1 actually work end-to-end, the inner protocol must be
// HTTP/2 via nghttp2 (espressif/nghttp managed component). The framing
// helpers (ts2021_send / ts2021_recv) are stream-agnostic so the swap
// is additive: an nghttp2 callback layer wraps ts2021_send for outgoing
// frame chunks and ts2021_recv for incoming, with the existing handshake
// and Noise transport untouched.
//
// This nghttp2 wiring is the next thing to land before flashing onto a
// real device and expecting a successful register.
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
