// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Tiny abstraction over a TLS read/write call. Exists so the
// "retry on MBEDTLS_ERR_SSL_WANT_READ / WANT_WRITE" loop is
// host-testable with a mock — without it we couldn't cover the
// regression that takes down the long-poll stream every 30 s when
// SO_RCVTIMEO fires between Tailscale KeepAlives.

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>   /* ssize_t */

#ifdef __cplusplus
extern "C" {
#endif

/* The two callbacks have the same shape as esp_tls_conn_read /
 * esp_tls_conn_write. Return value semantics also match:
 *   > 0 : bytes read/written
 *   = 0 : peer EOF (read only)
 *   < 0 : mbedtls error code (MBEDTLS_ERR_SSL_WANT_READ, etc.) */
typedef ssize_t (*tls_io_read_fn)(void *ctx, uint8_t *buf, size_t len);
typedef ssize_t (*tls_io_write_fn)(void *ctx, const uint8_t *buf, size_t len);

/* Read exactly `need` bytes, retrying transparently on WANT_READ /
 * WANT_WRITE. Returns 0 on success, the negative mbedtls error code
 * (or a synthesized -1 for EOF) on hard failure. */
int tls_io_read_full(tls_io_read_fn rd, void *ctx,
                     uint8_t *buf, size_t need);

/* Write exactly `len` bytes, retrying transparently on WANT_READ /
 * WANT_WRITE. Returns 0 on success, the negative mbedtls error code
 * on hard failure. */
int tls_io_write_full(tls_io_write_fn wr, void *ctx,
                      const uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif
