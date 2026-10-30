// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// ts2021 client: HTTP/1.1 Upgrade to controlplane.tailscale.com — over
// plain TCP :80 when the control key is pinned (round 1.3.5), else or as
// the fallback over TLS :443 — Noise IK handshake, then ChaCha20-Poly1305
// framed records carrying the inner control-plane traffic (HTTP/2 in the
// canonical Tailscale client).
//
// Wire format constants come from upstream
// `tailscale/control/controlbase/messages.go` and
// `tailscale/control/controlhttp/{client,controlhttpcommon}.go`.
// h2_client.c sits on top of ts2021_send / ts2021_tx_send /
// ts2021_recv_record to carry HTTP/2 frames; do not send raw HTTP/1.1
// bytes — the control plane serves HTTP/2 (prior knowledge) after the
// Upgrade.

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
/* The read adapter's answer once a :80 handshake overran its deadline
 * (TS2021_PLAIN_TIMEOUT_MS after the TCP connect). */
#define TS2021_ERR_HS_DEADLINE  (-0x10003)
/* The read / write adapters' answer once a one-shot request overran its
 * deadline (ts2021_request_deadline). */
#define TS2021_ERR_REQ_DEADLINE (-0x10004)

/* One-shot requests (register, the endpoint push — h2_post_json; not the
 * map stream) get TS2021_REQ_TIMEOUT_MS from the moment they are sent
 * until the response is complete, in TS2021_REQ_POLL_MS socket polls
 * (round 1.3.5). Control answers them in ~0.2 s; without this they had
 * the stream's budget — 4 × 30-s polls, sized for the map stream's ~60-s
 * KeepAlives — and a 1.3.5 boot on the sensor sat 52 s in an endpoint
 * push ("pushing endpoint" 9.77 s → "HTTP 200" 61.94 s, nothing logged
 * in between). 10 s still covers a slow answer many times over; a poll
 * of 2 s lets the deadline bite within 2 s of its time (a blocked read
 * notices it only when its poll ends). After an expiry the next request
 * gets twice as long (h2_post_json), so a slow control plane is waited
 * out instead of cut on every retry. */
#ifndef TS2021_REQ_TIMEOUT_MS
#define TS2021_REQ_TIMEOUT_MS   10000
#endif
#ifndef TS2021_REQ_POLL_MS
#define TS2021_REQ_POLL_MS      2000
#endif
/* The ceiling h2_post_json doubles the deadline towards after expiries:
 * the 4 × 30-s budget one-shot requests had before. */
#ifndef TS2021_REQ_TIMEOUT_MAX_MS
#define TS2021_REQ_TIMEOUT_MAX_MS 120000
#endif
#define TS2021_RECORD_PLAINTEXT_MAX (TS2021_MAX_MESSAGE - TS2021_HEADER_LEN - NOISE_TAGLEN)
/* The records we send (round 1.3.4, D4): header + ciphertext ≤ 2 048 B,
 * CONFIG_MBEDTLS_SSL_OUT_CONTENT_LEN, so each one is one TLS record. */
#define TS2021_TX_RECORD_MAX        2048
#define TS2021_TX_PLAINTEXT_MAX     (TS2021_TX_RECORD_MAX - TS2021_HEADER_LEN - NOISE_TAGLEN)
/* ts2021_send's stack record: the HTTP/2 control frames (H2_CTL_CAP). */
#define TS2021_SMALL_PLAINTEXT_MAX  64

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
    esp_tls_t        *tls;        /* :443 transport (NULL on :80) */
    noise_ik_state_t  noise;
    bool              connected;

    /* :80 transport (round 1.3.5, D10a): the connected socket while
     * `plain` — no TLS under the Noise records. hs_idle / hs_deadline_us
     * bound the unauthenticated part of a :80 handshake (until Noise IK
     * completes: 0 = the stream budgets). io_failed: a transport failure
     * (not an abort) was seen; up_us: when Noise IK completed —
     * ts2021_close uses both for the early-drop heuristic. */
    bool              plain;
    bool              io_failed;
    uint8_t           hs_idle;
    int               sock;
    int64_t           hs_deadline_us;
    int64_t           up_us;

    /* The control address this conn reached (round 1.3.5, tl_addr.h;
     * 0.0.0.0 = unknown): the cached one it was dialed at (at_addr), or
     * the peer of a by-name connect. tinylink.c keeps it for the next
     * boot. */
    uint8_t           peer_v4[4];
    bool              at_addr;

    /* One-shot request deadline (round 1.3.5, ts2021_request_deadline):
     * while req_deadline_us != 0 each socket poll is TS2021_REQ_POLL_MS,
     * req_idle of them in a row at most, and the adapters fail at the
     * deadline. How the last failed transfer ended, for the layers above
     * (their log levels): `aborted` — ts2021_abort_reads asked for it (a
     * requested recycle, not a failure); `req_expired` — a one-shot
     * request ran out of its deadline (logged once, here). */
    uint8_t           req_idle;
    uint32_t          req_ms;
    bool              aborted;
    bool              req_expired;
    int64_t           req_deadline_us;

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

    /* The record ring: each Noise record's ciphertext is read into it
     * and decrypted in place, and the engine parses it where it lies;
     * between records a request is built and sealed in it, ≤ 2 KiB per
     * record (round 1.3.4, D4: no record buffer on any stack). Lives in
     * BSS via the file-scope ts2021_conn_t in tinylink.c. One ciphertext
     * long, which also covers a plaintext plus the up-to-4 EarlyPayload
     * magic bytes that consume_early_payload may have to put back in
     * front of it (D5): TS2021_MAX_MESSAGE ≥ 4 080 + 4. Word-aligned so
     * the AEAD runs its aligned loops. */
    uint8_t  h2_rx[TS2021_MAX_MESSAGE] __attribute__((aligned(4)));
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
 * channel is then ready for HTTP/2 framing via h2_client.
 *
 * Transport (round 1.3.5, D10a, as upstream controlhttp): plain HTTP :80
 * first when key_pinned — control_pub was pinned before this boot (NVS
 * pin or compile-in fallback), so the Noise IK handshake alone
 * authenticates the server — with CONFIG_TINYLINK_CONTROL_PLAIN_HTTP and
 * the default control port 443; TLS :443 otherwise, and as the fallback
 * on any :80 failure (no 101, a redirect, timeout, Noise refused). A :80
 * failure that :443 then gets past keeps the rest of the boot on :443. */
esp_err_t ts2021_connect(ts2021_conn_t *out,
                         const uint8_t machine_priv[NOISE_DHLEN],
                         const uint8_t machine_pub[NOISE_DHLEN],
                         const uint8_t control_pub[NOISE_DHLEN],
                         bool key_pinned);

/* The control address to dial first (round 1.3.5, tl_addr.h; NULL or an
 * unusable address = none): tinylink_init seeds it from NVS. A connect
 * dials it on the first transport it tries, with a 3-s budget, before
 * resolving CONFIG_TINYLINK_CONTROL_HOST; the server is authenticated
 * as without it (Noise IK on :80, the certificate against the host name
 * on :443), and a failure there is retried by name at once — never
 * counted against :80. It stays first for TS2021_ADDR_TTL_S; every conn
 * that comes up by name replaces it with the address it reached
 * (out->peer_v4) for another TS2021_ADDR_TTL_S. */
void ts2021_set_addr(const uint8_t ip_v4[4]);

/* The next connect's Noise IK DH work, ahead of it (round 1.3.7, B2):
 * ss for (machine key, control_pub) and one ephemeral e + es, which the
 * first handshake with that pair takes (and scrubs); later connects
 * reuse ss and draw a fresh e. tinylink_preload calls it at boot while
 * Wi-Fi associates — 3 X25519 (~37 ms) that ran after got-ip before.
 * Silently does nothing for a low-order control_pub. */
void ts2021_precompute(const uint8_t machine_priv[NOISE_DHLEN],
                       const uint8_t machine_pub[NOISE_DHLEN],
                       const uint8_t control_pub[NOISE_DHLEN]);

/* Arm (ms > 0) or disarm (0) the one-shot request deadline on a
 * connected conn: the socket's SO_RCVTIMEO / SO_SNDTIMEO go to
 * TS2021_REQ_POLL_MS — back to the stream's 30 s on disarm — and every
 * read and write from now on fails with TS2021_ERR_REQ_DEADLINE once
 * `ms` have passed (io_failed and req_expired set, one W line), so the
 * caller drops the conn as after any transport failure; on :80 that is
 * also an early drop (the next dial goes to :443). h2_post_json brackets
 * each one-shot request with it; the map stream arms it only until the
 * endpoint push riding with it is answered (h2_post_json_stream_side,
 * round 1.3.7), so its first frame (a netmap can take ~11 s server-side)
 * and its KeepAlives otherwise keep the stream budget. ESP_FAIL (io_failed) when the socket timeouts
 * cannot be set: a conn left at the wrong poll period must not be used. */
esp_err_t ts2021_request_deadline(ts2021_conn_t *c, uint32_t ms);

/* Encrypt and write `data` as Noise transport records (msg type 4) of
 * ≤ TS2021_SMALL_PLAINTEXT_MAX bytes, sealed in a small stack record:
 * for the HTTP/2 control frames, which may go out while h2_rx still
 * holds a record being parsed. */
esp_err_t ts2021_send(ts2021_conn_t *c,
                      const uint8_t *data, size_t data_len);

/* Bulk send through the ring (round 1.3.4, D4): ts2021_tx_buf lends
 * h2_rx (cap TS2021_TX_PLAINTEXT_MAX; only while nothing in it is left
 * to parse — it drops the window), ts2021_tx_send seals its first `len`
 * bytes in place and writes them as one record. */
uint8_t  *ts2021_tx_buf(ts2021_conn_t *c, size_t *cap);
esp_err_t ts2021_tx_send(ts2021_conn_t *c, size_t len);

/* Read the next record into h2_rx and decrypt it in place: on ESP_OK
 * the plaintext is h2_rx[0..*len), and so is the window (h2_rx_off 0,
 * h2_rx_len *len). Bytes left over from the connect (the start of the
 * HTTP/2 stream) are the window ts2021_connect returns with — the
 * caller drains it before reading a record. */
esp_err_t ts2021_recv_record(ts2021_conn_t *c, size_t *len);

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
