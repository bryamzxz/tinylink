// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Minimal HTTP/2 client over a ts2021 Noise channel. Single-stream,
// synchronous, no server push, no HPACK dynamic-table indexing.
// Used by register.c for /machine/register and (later) by the M2 map
// streamer for /machine/map.

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
 * This is the canonical Tailscale wire path: the control plane runs
 * http2.Server.ServeConn over the Noise channel, so HTTP/1.1 inside
 * Noise is rejected with PROTOCOL_ERROR.
 */
esp_err_t h2_post_json(ts2021_conn_t *conn,
                       const char *path,
                       const char *authority,
                       const uint8_t *body, size_t body_len,
                       int *status_out,
                       uint8_t *response_buf, size_t response_buf_size,
                       size_t *response_len);

/* Streaming variant: every DATA frame chunk is delivered to `cb` as it
 * arrives. The function blocks until the stream closes (server EOF, our
 * watchdog timeout in a future revision, or `cb` returns a negative
 * value). The status is set once headers have been received, before the
 * first chunk is delivered.
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

/* Build the persistent nghttp2 session bound to `conn`. Called once at
 * the end of ts2021_connect, while the LP TLS conn is the only one
 * alive and the heap has a contiguous ~24 KiB free block for the
 * ~10–14 KiB nghttp2_session struct. Pumps the initial SETTINGS
 * exchange (client → server → ACK) so the first request lands on a
 * synchronized session.
 *
 * Returns ESP_OK on success; on failure the conn must be torn down.
 * Idempotent: calling twice on the same conn frees the prior session
 * before allocating the new one. */
esp_err_t h2_session_init(ts2021_conn_t *conn);

/* Tear down the persistent session bound to `conn`. Safe to call on a
 * conn that never had h2_session_init() succeed (no-op). Must be
 * called BEFORE esp_tls_conn_destroy so the nghttp2 cleanup doesn't
 * touch a destroyed TLS context. */
void h2_session_destroy(ts2021_conn_t *conn);

#ifdef __cplusplus
}
#endif
