// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "tls_io.h"

#include <errno.h>
#include <string.h>

#include "lwip/sockets.h"
#include "mbedtls/ssl.h"

static tls_io_poll_hook_t s_poll_hook;

void tls_io_set_poll_hook(tls_io_poll_hook_t hook)
{
    s_poll_hook = hook;
}

static inline void poll_hook(void)
{
    if (s_poll_hook != NULL) s_poll_hook();
}

int tls_io_read_full(tls_io_read_fn rd, void *ctx,
                     uint8_t *buf, size_t need, uint32_t max_idle)
{
    if (rd == NULL || buf == NULL) return -1;
    size_t   got  = 0;
    uint32_t idle = 0;
    while (got < need) {
        ssize_t r = rd(ctx, buf + got, need - got);
        poll_hook();
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
        poll_hook();
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

/* errno after a failed recv() / send(): the socket timeout (and EINTR,
 * which lwIP never returns) is an idle poll, anything else a hard error. */
static ssize_t sock_err(ssize_t want)
{
    const int e = errno;
    if (e == EAGAIN || e == EINTR) return want;
#if EWOULDBLOCK != EAGAIN
    if (e == EWOULDBLOCK) return want;
#endif
    return (e > 0) ? -(ssize_t)e : -1;
}

ssize_t tls_io_sock_read(int fd, uint8_t *buf, size_t len)
{
    const ssize_t r = recv(fd, buf, len, 0);
    return (r >= 0) ? r : sock_err(MBEDTLS_ERR_SSL_WANT_READ);
}

ssize_t tls_io_sock_write(int fd, const uint8_t *buf, size_t len)
{
#ifdef MSG_NOSIGNAL
    const int flags = MSG_NOSIGNAL;   /* host: EPIPE, not SIGPIPE */
#else
    const int flags = 0;
#endif
    const ssize_t w = send(fd, buf, len, flags);
    return (w >= 0) ? w : sock_err(MBEDTLS_ERR_SSL_WANT_WRITE);
}

bool tls_io_sock_peer_v4(int fd, uint8_t ip_v4[4])
{
    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    memset(&ss, 0, sizeof(ss));
    if (fd < 0 || getpeername(fd, (struct sockaddr *)&ss, &len) != 0 ||
        ss.ss_family != AF_INET || len < sizeof(struct sockaddr_in)) {
        return false;
    }
    memcpy(ip_v4, &((const struct sockaddr_in *)&ss)->sin_addr.s_addr, 4);
    return true;
}
