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

/* Returned when `max_idle` consecutive WANT_READ/WANT_WRITE polls pass
 * with zero forward progress. Deliberately outside the 16-bit mbedtls
 * error space (all MBEDTLS_ERR_* fit in [-0x7FFF, -1]) so callers can
 * distinguish "the stream went silent past the liveness budget" from a
 * genuine TLS/socket error. */
#define TLS_IO_ERR_IDLE_TIMEOUT (-0x10000)

/* The two callbacks have the same shape as esp_tls_conn_read /
 * esp_tls_conn_write. Return value semantics also match:
 *   > 0 : bytes read/written
 *   = 0 : peer EOF (read only)
 *   < 0 : mbedtls error code (MBEDTLS_ERR_SSL_WANT_READ, etc.) */
typedef ssize_t (*tls_io_read_fn)(void *ctx, uint8_t *buf, size_t len);
typedef ssize_t (*tls_io_write_fn)(void *ctx, const uint8_t *buf, size_t len);

/* Read exactly `need` bytes, retrying transparently on WANT_READ /
 * WANT_WRITE. Returns 0 on success, the negative mbedtls error code
 * (or a synthesized -1 for EOF) on hard failure.
 *
 * `max_idle` bounds the retry: it is the number of CONSECUTIVE
 * WANT_READ/WANT_WRITE returns tolerated without any bytes arriving.
 * On the ESP32 each such return corresponds to one SO_RCVTIMEO period
 * (30 s for the control/DERP conns), so max_idle=6 ≈ 180 s of total
 * stream silence. Any successful partial read resets the counter.
 * 0 = unlimited (the pre-2026-07 behavior — only safe for callers
 * that have their own liveness bound). On breach the function returns
 * TLS_IO_ERR_IDLE_TIMEOUT — this is what converts a half-open TCP
 * connection (control plane replaced/killed without FIN, NAT flow
 * dropped) from an infinite hang into a normal reconnect. */
/* Optional per-poll hook: invoked once per loop iteration of both
 * *_full helpers (every WANT_READ/WANT_WRITE poll — one SO_RCVTIMEO
 * period — and after every partial transfer). tinylink.c installs the
 * task-WDT feed here so a task parked in a 30-s TLS poll keeps its
 * watchdog alive without shortening the socket timeouts. NULL = none. */
typedef void (*tls_io_poll_hook_t)(void);
void tls_io_set_poll_hook(tls_io_poll_hook_t hook);

int tls_io_read_full(tls_io_read_fn rd, void *ctx,
                     uint8_t *buf, size_t need, uint32_t max_idle);

/* Write exactly `len` bytes, retrying transparently on WANT_READ /
 * WANT_WRITE. Returns 0 on success, the negative mbedtls error code
 * on hard failure. `max_idle` as in tls_io_read_full: consecutive
 * zero-progress polls (≈ one SO_SNDTIMEO period each — a full TCP
 * send buffer that never drains means the peer stopped ACKing);
 * 0 = unlimited. */
int tls_io_write_full(tls_io_write_fn wr, void *ctx,
                      const uint8_t *buf, size_t len, uint32_t max_idle);

#ifdef __cplusplus
}
#endif
