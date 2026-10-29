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
// plane serves HTTP/2 (prior knowledge) after the Upgrade.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_tls.h"

#include "h2_core.h"
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
/* Returned by the TLS read adapter (through tls_io_read_full) when
 * ts2021_abort_reads() was requested. Outside the 16-bit mbedtls error
 * space and distinct from TLS_IO_ERR_IDLE_TIMEOUT (-0x10000). */
#define TS2021_ERR_READ_ABORTED (-0x10001)
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

typedef struct {
    esp_tls_t        *tls;
    noise_ik_state_t  noise;
    bool              connected;

    /* (Round 1.3.4, D5: the 4 077-B `rx_residual` copy is gone. The
     * HTTP/2 bytes that follow the Noise handshake — after the optional
     * EarlyPayload — stay in h2_rx below as the window
     * [h2_rx_off, h2_rx_len), parsed before the first request.) */

    /* ---- Persistent HTTP/2 session state (M5 step 2c) ----
     *
     * One session per ts2021 conn, started by h2_session_init() at the
     * end of ts2021_connect and dropped by h2_session_destroy() in
     * ts2021_close; requests run on it one after the other (register,
     * endpoint push, then the map stream). Since round 1.3.4 (D1) it is
     * the in-tree engine (h2_core.h), embedded here — no heap: the
     * nghttp2 session (10–14 KiB, plus a 16 KiB send chunk) had to be
     * allocated while the heap was still unfragmented, which is why it
     * was created at connect time. */
    h2_core_t        h2;
    bool             h2_goaway;          /* server sent GOAWAY → reconnect */

    /* The record ring: each Noise record is decrypted into it and the
     * engine parses it where it lies; a request is built in it between
     * records (h2_io_tx_buf). Lives in BSS via the file-scope
     * ts2021_conn_t in tinylink.c — one Noise record plus the up-to-4
     * EarlyPayload magic bytes that consume_early_payload may have to
     * put back in front of a record (round 1.3.4, D5):
     * TS2021_MAX_MESSAGE ≥ 4 080 + 4. */
    uint8_t  h2_rx[TS2021_MAX_MESSAGE];
    size_t   h2_rx_len;
    size_t   h2_rx_off;

    /* Body of the in-flight POST (borrowed). Cleared after each request. */
    const uint8_t *h2_req_body;
    size_t         h2_req_body_len;

    /* Response status + stream outcome, written by the engine hooks
     * (h2_client.c). Cleared at the start of each request.
     * h2_stream_error is the HTTP/2 code the stream closed with (0 = a
     * normal end). */
    int      h2_status;
    int32_t  h2_stream_id;
    int      h2_stream_error;

    /* Retry-After of the current response (capver 147): `present` =
     * the header was there and non-empty; `_s` = its delay when valid
     * (1..3600 s, see h2_retry_after.h), else 0. Turned into a wait by
     * h2_rate_limit_wait_ms together with h2_status. */
    bool     h2_retry_after_present;
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

/* Read + decrypt the next record into out (out_max ≥ the record's
 * plaintext). Returns ESP_OK with *out_len set. Bytes left over from
 * the connect (the start of the HTTP/2 stream) are in c->h2_rx, not
 * returned here — the caller drains that window first. */
esp_err_t ts2021_recv(ts2021_conn_t *c,
                      uint8_t *out, size_t out_max, size_t *out_len);

void ts2021_close(ts2021_conn_t *c);

/* Ask the task blocked in a ts2021 record read (the long-poll) to give
 * up at its next socket poll (≤ one SO_RCVTIMEO, 30 s) with
 * TS2021_ERR_READ_ABORTED, so it drops the conn and reconnects. Safe to
 * call from any task; idempotent; automatically cleared by the next
 * ts2021_connect. Used by the endpoint push to recycle the map stream. */
void ts2021_abort_reads(void);

#ifdef __cplusplus
}
#endif
