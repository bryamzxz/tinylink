// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "tls_io.h"

#include "mbedtls/ssl.h"

int tls_io_read_full(tls_io_read_fn rd, void *ctx,
                     uint8_t *buf, size_t need)
{
    if (rd == NULL || buf == NULL) return -1;
    size_t got = 0;
    while (got < need) {
        ssize_t r = rd(ctx, buf + got, need - got);
        if (r == MBEDTLS_ERR_SSL_WANT_READ ||
            r == MBEDTLS_ERR_SSL_WANT_WRITE) {
            /* SO_RCVTIMEO fired with no data on the wire (or the TLS
             * layer needs to flush a record before continuing). Both
             * are transient — the long-poll spends most of its time
             * blocked here waiting for the next server KeepAlive. */
            continue;
        }
        if (r < 0) return (int)r;
        if (r == 0) return -1;       /* peer FIN */
        got += (size_t)r;
    }
    return 0;
}

int tls_io_write_full(tls_io_write_fn wr, void *ctx,
                      const uint8_t *buf, size_t len)
{
    if (wr == NULL || buf == NULL) return -1;
    size_t sent = 0;
    while (sent < len) {
        ssize_t w = wr(ctx, buf + sent, len - sent);
        if (w == MBEDTLS_ERR_SSL_WANT_READ ||
            w == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (w < 0) return (int)w;
        if (w == 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}
