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
 */
typedef int (*h2_data_callback)(const uint8_t *buf, size_t len, void *ctx);

esp_err_t h2_post_json_stream(ts2021_conn_t *conn,
                              const char *path,
                              const char *authority,
                              const uint8_t *body, size_t body_len,
                              int *status_out,
                              h2_data_callback cb, void *cb_ctx);

#ifdef __cplusplus
}
#endif
