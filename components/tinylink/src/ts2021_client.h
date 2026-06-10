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

#include "nghttp2/nghttp2.h"

#include "noise_ik.h"
#include "tinylink.h"  /* TINYLINK_CAPVER — single source of truth */

#define TS2021_PROTOCOL_NAME    "Noise_IK_25519_ChaChaPoly_BLAKE2s"
/* The version carried in the controlbase initiation: BE16 header field
 * + decimal suffix of the Noise prologue. The server derives its own
 * prologue from this client-claimed value (controlbase handshake.go),
 * so both ends stay in agreement by construction. Must equal
 * tailcfg.CurrentCapabilityVersion to clear headscale's earlyNoise
 * MinSupportedCapabilityVersion gate — see TINYLINK_CAPVER. */
#define TS2021_PROTOCOL_VERSION TINYLINK_CAPVER
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

/* Streaming-callback shape used by h2_post_json_stream(). Defined here
 * so it can be embedded in ts2021_conn_t below without h2_client.h
 * pulling ts2021_client.h transitively (which would create a cycle).
 * h2_client.h aliases this as `h2_data_callback` for the public API. */
typedef int (*h2_stream_fn_t)(const uint8_t *buf, size_t len, void *ctx);

/* Cap on the SETTINGS handshake pump in h2_session_init(). The exchange
 * we drive is: client SETTINGS → server SETTINGS+ACK → our ACK. Each
 * iteration of the pump is one nghttp2_session_send + one
 * nghttp2_session_recv; in practice 3 iterations suffice but we cap
 * at 20 as a safety bound against an unresponsive peer. */
#define H2_SETTINGS_PUMP_MAX 20

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

    /* ---- Persistent HTTP/2 session state (M5 step 2c) ----
     *
     * The session is created once by h2_session_init() at the end of
     * ts2021_connect (when only the long-poll TLS conn is alive and
     * ~24 KiB of contiguous heap is still available) and torn down by
     * h2_session_destroy() at the start of ts2021_close. This avoids
     * the per-request session_client_new/del cycle that returned
     * NGHTTP2_ERR_NOMEM (-901) once a second TLS conn (the DERP
     * supervisor) had fragmented the heap.
     *
     * All h2_* fields below live in this struct so the nghttp2
     * callbacks (which receive `ts2021_conn_t *` as user_data) can
     * persist state across requests without heap allocs. */
    nghttp2_session *h2;
    bool             h2_goaway;          /* server sent GOAWAY → reconnect */
    bool             h2_settings_acked;  /* both initial SETTINGS pumped */

    /* Decrypted-Noise plaintext ring fed into nghttp2's recv_cb. Lives
     * in BSS via the file-scope ts2021_conn_t in tinylink.c — sized at
     * one Noise record so the codec can stage one frame at a time. */
    uint8_t  h2_rx[TS2021_RECORD_PLAINTEXT_MAX];
    size_t   h2_rx_len;
    size_t   h2_rx_off;

    /* One-shot permission token for h2_recv_cb. Set by h2_drive_request
     * before each session_recv; recv_cb consumes it on the first refill
     * and returns NGHTTP2_ERR_WOULDBLOCK on subsequent ones so
     * session_recv unwinds and queued outbound frames (notably
     * SETTINGS_ACK) flush. Without this the server's idle timeout
     * (~31 s) closes us before we send ACK. */
    bool     h2_may_refill;

    /* Body cursor for the in-flight POST. Cleared after each request. */
    const uint8_t *h2_req_body;
    size_t         h2_req_body_len;
    size_t         h2_req_body_off;

    /* Response status + per-stream tracking, written by the nghttp2
     * callbacks. Cleared at the start of each h2_drive_request. */
    int      h2_status;
    int32_t  h2_stream_id;
    bool     h2_stream_closed;
    int      h2_stream_error;

    /* Parsed Retry-After header value in seconds (RFC 7231 §7.1.3
     * delta-seconds form, clamped into [1, 300] by
     * h2_parse_retry_after_seconds). 0 means the response had no
     * Retry-After or the value was malformed; caller falls back to its
     * own backoff. Only meaningful when h2_status is 429 or 503 — other
     * statuses ignore the field. */
    int      h2_retry_after_s;

    /* Response collection (one-shot mode). Pointer is borrowed from
     * the h2_post_json caller — this struct is NOT the owner. */
    uint8_t *h2_resp_buf;
    size_t   h2_resp_cap;
    size_t   h2_resp_len;
    bool     h2_resp_overflow;

    /* Streaming mode (h2_post_json_stream). cb_ctx is borrowed. */
    h2_stream_fn_t h2_cb;
    void          *h2_cb_ctx;
    bool           h2_cb_stop;
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
