// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Minimal HTTP/2 client over a ts2021 Noise channel. Single-stream,
// synchronous, no server push, no HPACK dynamic-table indexing. Used by
// register.c for /machine/register and by mapreq.c for /machine/map
// (endpoint push and the long-poll stream). Since round 1.3.4 (D1) it
// runs on the in-tree engine (h2_core.h / hpack.h) instead of nghttp2.

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#include "ts2021_client.h"

#ifdef __cplusplus
extern "C" {
#endif

/* One-shot HTTP/2 POST. Sends method=POST with the supplied JSON body,
 * blocks until the stream closes, and returns the response status + body.
 *
 * - response_buf is filled up to response_buf_size; on success
 *   *response_len is the number of bytes written.
 * - The connection is left open for further requests; call ts2021_close
 *   when done with the connection.
 *
 * This is the canonical Tailscale wire path: the control plane serves
 * HTTP/2 over the Noise channel (headscale: net/http unencrypted HTTP/2
 * since 62714564, x/net http2.Server.ServeConn before), so HTTP/1.1
 * inside Noise is rejected with PROTOCOL_ERROR.
 */
esp_err_t h2_post_json(ts2021_conn_t *conn,
                       const char *path,
                       const char *authority,
                       const uint8_t *body, size_t body_len,
                       int *status_out,
                       uint8_t *response_buf, size_t response_buf_size,
                       size_t *response_len);

/* Streaming variant: every DATA frame chunk is delivered to `cb` as it
 * arrives. The function blocks until the stream closes (server EOF, the
 * conn's idle budget, or `cb` returns a negative value). The status is
 * set once headers have been received, before the first chunk is
 * delivered. Until then the conn is under the first-response deadline
 * (round 1.3.8, C1, TS2021_RESP_TIMEOUT_MS: ts2021_response_deadline) —
 * no response headers in time and ESP_FAIL comes back with
 * conn->resp_expired set, the conn to be recycled; the next stream gets
 * twice as long, up to the stream budget, and one after an answer twice
 * that answer's time (one I line `map stream answered: HTTP N in M ms`);
 * a stream after one the server ended (END_STREAM after its 200) gets the
 * stream budget, until a stream is answered (`map stream after a clean
 * server end: N ms for its answer`).
 *
 * Used by the M2 long-poll MapRequest loop: the body is a single
 * MapRequest with `Stream:true`, and the response is a sequence of
 * length-prefixed MapResponse JSON objects that the caller demuxes in
 * its callback.
 *
 * `h2_data_callback` is an alias for the type defined in
 * ts2021_client.h (`h2_stream_fn_t`); the alias keeps the public name
 * stable while letting ts2021_conn_t embed a function pointer of the
 * same shape without including this header. */
typedef h2_stream_fn_t h2_data_callback;

esp_err_t h2_post_json_stream(ts2021_conn_t *conn,
                              const char *path,
                              const char *authority,
                              const uint8_t *body, size_t body_len,
                              int *status_out,
                              h2_data_callback cb, void *cb_ctx);

/* The streaming request with a one-shot side request ahead of it in the
 * same burst (round 1.3.7, B1): the endpoint push and the map stream,
 * both POST `path`, as two streams instead of two round trips one after
 * the other. Only the side request's status (and Retry-After) is kept:
 * `side_cb` runs once, as soon as its stream closes, on the calling
 * task, from inside the stream loop; not at all when the stream ends or
 * fails first (the side request then counts as unanswered).
 *
 * Deadlines: until the stream's final response the conn is under the
 * one-shot request deadline (h2_post_json) — a conn that answers neither
 * is cut — or, once the side request has closed, under the stream's
 * first-response deadline from the burst (round 1.3.8, C1, as in
 * h2_post_json_stream). Once the stream has answered, the conn is under the stream
 * budget only; a side request still unanswered at its deadline is then
 * cancelled (RST_STREAM CANCEL, `expired`; checked as records arrive,
 * once those already received are read) and the stream goes on — one
 * whose final response is in is never late. Either expiry doubles the
 * next deadline.
 *
 * `side_body` need only live through the call's opening burst — it goes
 * out whole there; when it cannot (a server window under its size, or a
 * server that allows one stream at a time — remembered for later conns),
 * nothing is sent and ESP_ERR_INVALID_SIZE comes back with the session
 * intact: send the two one after the other. Otherwise the returns of
 * h2_post_json_stream. */
typedef struct {
    int  status;         /* final :status; 0: reset, refused or cancelled */
    int  stream_error;   /* the HTTP/2 code it closed with               */
    bool expired;        /* cancelled by us: no answer within its deadline */
    bool goaway;         /* refused by a GOAWAY: not processed, the conn ends */
    bool retry_after_present;
    int  retry_after_s;  /* h2_parse_retry_after_seconds; 0 = invalid     */
} h2_side_result_t;

typedef void (*h2_side_fn_t)(const h2_side_result_t *res, void *ctx);

esp_err_t h2_post_json_stream_side(ts2021_conn_t *conn,
                                   const char *path,
                                   const char *authority,
                                   const uint8_t *side_body, size_t side_len,
                                   h2_side_fn_t side_cb, void *side_ctx,
                                   const uint8_t *body, size_t body_len,
                                   int *status_out,
                                   h2_data_callback cb, void *cb_ctx);

#ifndef ESP_PLATFORM
/* Host tests: forget a one-stream server (h2_post_json_stream_side). */
void h2_client_forget_limits(void);
#endif

/* The load-balancer hint every request carries from now on (round 1.3.8,
 * C2): `ts-lb: nodekey:<hex>`, upstream's tailcfg.LBHeader — the
 * official client adds it to register, map and every other Noise request
 * (ts2021.AddLBHeader, since 2024-03), so that the control plane's
 * reverse proxy can route a request to the node's backend without
 * reading its body. "Not a security or authentication header; strictly
 * denormalized redundant data as an optimization" (tailcfg.go); headscale
 * ignores it. NULL: no hint. */
void h2_client_set_lb(const uint8_t node_pub[32]);

/* Start the persistent HTTP/2 session bound to `conn` (state embedded in
 * the conn, no heap). Called once at the end of ts2021_connect. Sends
 * the client preface + our SETTINGS and returns without waiting for the
 * server's (round 1.3.2): the first request follows immediately, and the
 * server's SETTINGS / ACK are processed by that request's recv loop.
 *
 * Returns ESP_OK on success; on failure the conn must be torn down.
 * Idempotent: calling twice on the same conn starts a fresh session. */
esp_err_t h2_session_init(ts2021_conn_t *conn);

/* Tear down the persistent session bound to `conn`. Safe to call on a
 * conn that never had h2_session_init() succeed (no-op). Called before
 * esp_tls_conn_destroy; sends nothing. */
void h2_session_destroy(ts2021_conn_t *conn);

#ifdef __cplusplus
}
#endif
