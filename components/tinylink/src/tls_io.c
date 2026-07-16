// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "tls_io.h"

#include "mbedtls/ssl.h"

int tls_io_read_full(tls_io_read_fn rd, void *ctx,
                     uint8_t *buf, size_t need, uint32_t max_idle)
{
    if (rd == NULL || buf == NULL) return -1;
    size_t   got  = 0;
    uint32_t idle = 0;
    while (got < need) {
        ssize_t r = rd(ctx, buf + got, need - got);
        if (r == MBEDTLS_ERR_SSL_WANT_READ ||
            r == MBEDTLS_ERR_SSL_WANT_WRITE) {
            /* SO_RCVTIMEO fired with no data on the wire (or the TLS
             * layer needs to flush a record before continuing). Both
             * are transient — the long-poll spends most of its time
             * blocked here waiting for the next server KeepAlive. But
             * "transient" has a budget: a half-open TCP conn (peer
             * died without FIN/RST) produces this forever, so past
             * max_idle consecutive silent polls we declare the stream
             * dead and let the caller reconnect. */
            idle++;
            if (max_idle != 0 && idle >= max_idle) {
                return TLS_IO_ERR_IDLE_TIMEOUT;
            }
            continue;
        }
        if (r < 0) return (int)r;
        if (r == 0) return -1;       /* peer FIN */
        got += (size_t)r;
        idle = 0;                    /* forward progress resets the budget */
    }
    return 0;
}

int tls_io_write_full(tls_io_write_fn wr, void *ctx,
                      const uint8_t *buf, size_t len, uint32_t max_idle)
{
    if (wr == NULL || buf == NULL) return -1;
    size_t   sent = 0;
    uint32_t idle = 0;
    while (sent < len) {
        ssize_t w = wr(ctx, buf + sent, len - sent);
        if (w == MBEDTLS_ERR_SSL_WANT_READ ||
            w == MBEDTLS_ERR_SSL_WANT_WRITE) {
            idle++;
            if (max_idle != 0 && idle >= max_idle) {
                return TLS_IO_ERR_IDLE_TIMEOUT;
            }
            continue;
        }
        if (w < 0) return (int)w;
        if (w == 0) return -1;
        sent += (size_t)w;
        idle = 0;
    }
    return 0;
}
