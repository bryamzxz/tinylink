/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Regression KAT for tls_io_read_full / tls_io_write_full.
 *
 * The bug this gates against: in `47a72b8` and earlier, ts2021_client.c
 * treated MBEDTLS_ERR_SSL_WANT_READ (-26880) returned by esp_tls_conn_read
 * as fatal. Tailscale's /machine/map server sits idle ~50–60 s between
 * KeepAlives, longer than our SO_RCVTIMEO of 30 s, so the long-poll
 * stream got torn down every cycle — node bounced offline/online in
 * admin.tailscale.com.
 *
 * These tests use a scripted mock for the read/write callback so we can
 * deterministically verify:
 *   - WANT_READ (-26880) and WANT_WRITE (-26368) are retried, not
 *     propagated as failure.
 *   - A real negative mbedtls error code IS surfaced.
 *   - A peer FIN (return 0) on read is reported as failure (-1) — for
 *     the framed-record reader, EOF mid-record is unrecoverable.
 *   - Partial-success returns are accumulated until `need` is satisfied.
 *   - Long sequences of WANT_READ before data work without bound.
 *   - NULL-arg guards reject misuse.
 *   - round 1.3.5 (ts2021 on :80): tls_io_sock_read / _write over a real
 *     socketpair keep that contract without TLS — an SO_RCVTIMEO expiry
 *     is WANT_READ (one idle poll, so the *_full budget counts socket
 *     timeouts as over esp_tls), a FIN is 0, a write to a closed peer
 *     is -EPIPE and not a SIGPIPE, a bad fd is -EBADF.
 */

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "mbedtls/ssl.h"
#include "tls_io.h"

static int fails = 0;

static int eq_int(const char *name, int got, int want) {
    if (got == want) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL got=%d want=%d\n", name, got, want);
    return 1;
}

static int eq_bytes(const char *name, const uint8_t *a, const uint8_t *b, size_t n) {
    if (memcmp(a, b, n) == 0) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL\n", name);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Scripted mock                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    /* Each call to the mock returns the next entry. Negative = error
     * code (returned verbatim), 0 = EOF, positive = bytes to deliver
     * (capped at the caller's `len`). */
    const ssize_t *script;
    size_t         script_len;
    size_t         script_idx;

    /* Source bytes for positive returns. The mock copies up to N bytes
     * into the caller's buffer where N = min(script[i], len). */
    const uint8_t *src;
    size_t         src_off;

    /* For write tests: where the mock copies bytes to (and how far it
     * has progressed). */
    uint8_t       *dst;
    size_t         dst_off;
    size_t         dst_cap;
} mock_t;

static ssize_t mock_read(void *ctx, uint8_t *buf, size_t len) {
    mock_t *m = (mock_t *)ctx;
    if (m->script_idx >= m->script_len) return -1;
    ssize_t r = m->script[m->script_idx++];
    if (r > 0) {
        size_t take = ((size_t)r > len) ? len : (size_t)r;
        memcpy(buf, m->src + m->src_off, take);
        m->src_off += take;
        return (ssize_t)take;
    }
    return r;   /* propagate negative or zero verbatim */
}

static ssize_t mock_write(void *ctx, const uint8_t *buf, size_t len) {
    mock_t *m = (mock_t *)ctx;
    if (m->script_idx >= m->script_len) return -1;
    ssize_t r = m->script[m->script_idx++];
    if (r > 0) {
        size_t take = ((size_t)r > len) ? len : (size_t)r;
        if (m->dst_off + take > m->dst_cap) take = m->dst_cap - m->dst_off;
        memcpy(m->dst + m->dst_off, buf, take);
        m->dst_off += take;
        return (ssize_t)take;
    }
    return r;
}

/* ------------------------------------------------------------------ */
/* read_full tests                                                     */
/* ------------------------------------------------------------------ */

static void test_read_full_simple(void) {
    static const ssize_t script[] = { 16 };
    static const uint8_t src[]    = "Hello, World!!!";
    mock_t m = { .script = script, .script_len = 1, .src = src };

    uint8_t buf[16] = {0};
    int rc = tls_io_read_full(mock_read, &m, buf, 16, 0);
    fails += eq_int("read/simple/rc", rc, 0);
    fails += eq_bytes("read/simple/buf", buf, src, 16);
    fails += eq_int("read/simple/calls", (int)m.script_idx, 1);
}

/* The exact regression that took down the long-poll: many WANT_READs in
 * a row, then real data. Pre-fix tls_read_full would fail on the first
 * WANT_READ. */
static void test_read_full_retry_on_want_read(void) {
    static const ssize_t script[] = {
        MBEDTLS_ERR_SSL_WANT_READ,
        MBEDTLS_ERR_SSL_WANT_READ,
        MBEDTLS_ERR_SSL_WANT_READ,
        MBEDTLS_ERR_SSL_WANT_READ,
        MBEDTLS_ERR_SSL_WANT_READ,
        13,    /* finally, the data */
    };
    static const uint8_t src[] = "Hello, World!";
    mock_t m = { .script = script, .script_len = 6, .src = src };

    uint8_t buf[13] = {0};
    int rc = tls_io_read_full(mock_read, &m, buf, 13, 0);
    fails += eq_int("read/want-read-retry/rc", rc, 0);
    fails += eq_bytes("read/want-read-retry/buf", buf, src, 13);
    fails += eq_int("read/want-read-retry/calls", (int)m.script_idx, 6);
}

/* WANT_WRITE on a read is also transient (mbedtls can need to flush
 * a re-handshake-induced outbound record before delivering plaintext).
 * Same retry behavior expected. */
static void test_read_full_retry_on_want_write(void) {
    static const ssize_t script[] = {
        MBEDTLS_ERR_SSL_WANT_WRITE,
        4,
        MBEDTLS_ERR_SSL_WANT_WRITE,
        4,
    };
    static const uint8_t src[] = "ABCDEFGH";
    mock_t m = { .script = script, .script_len = 4, .src = src };

    uint8_t buf[8] = {0};
    int rc = tls_io_read_full(mock_read, &m, buf, 8, 0);
    fails += eq_int("read/want-write-retry/rc", rc, 0);
    fails += eq_bytes("read/want-write-retry/buf", buf, src, 8);
}

/* The long-poll spends most of its time blocked here. Verify that
 * with max_idle=0 (unlimited — the pre-2026-07 semantics) the retry
 * loop has no implicit cap: 1000 WANT_READs in a row must still
 * resolve to a successful read when data finally arrives. */
static void test_read_full_long_idle(void) {
    enum { N_IDLE = 1000 };
    static ssize_t script[N_IDLE + 1];
    for (int i = 0; i < N_IDLE; i++) script[i] = MBEDTLS_ERR_SSL_WANT_READ;
    script[N_IDLE] = 4;
    static const uint8_t src[] = "Beat";
    mock_t m = { .script = script, .script_len = N_IDLE + 1, .src = src };

    uint8_t buf[4] = {0};
    int rc = tls_io_read_full(mock_read, &m, buf, 4, 0);
    fails += eq_int("read/long-idle/rc", rc, 0);
    fails += eq_bytes("read/long-idle/buf", buf, src, 4);
    fails += eq_int("read/long-idle/calls", (int)m.script_idx, N_IDLE + 1);
}

static void test_read_full_partial_returns(void) {
    /* Real esp_tls_conn_read often returns less than requested
     * (e.g. one TLS record at a time). Verify we accumulate. */
    static const ssize_t script[] = { 3, 5, 2, 6 };
    static const uint8_t src[]    = "ABCDEFGHIJKLMNOP";
    mock_t m = { .script = script, .script_len = 4, .src = src };

    uint8_t buf[16] = {0};
    int rc = tls_io_read_full(mock_read, &m, buf, 16, 0);
    fails += eq_int("read/partial/rc", rc, 0);
    fails += eq_bytes("read/partial/buf", buf, src, 16);
}

/* A genuine network/peer error must surface, not get retried away. */
static void test_read_full_propagates_real_error(void) {
    /* MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY = -0x7880 = -30848 — not in
     * the WANT_* set, must be propagated. */
    static const ssize_t script[] = {
        MBEDTLS_ERR_SSL_WANT_READ,
        MBEDTLS_ERR_SSL_WANT_READ,
        -30848,
    };
    mock_t m = { .script = script, .script_len = 3 };

    uint8_t buf[16] = {0};
    int rc = tls_io_read_full(mock_read, &m, buf, 16, 0);
    fails += eq_int("read/real-error/rc", rc, -30848);
    /* Mock saw exactly the script: 2 retries then the failure. */
    fails += eq_int("read/real-error/calls", (int)m.script_idx, 3);
}

/* Peer FIN mid-record: read returns 0. We surface as -1 because for
 * length-framed protocols a half-record is fatal. */
static void test_read_full_peer_fin(void) {
    static const ssize_t script[] = {
        MBEDTLS_ERR_SSL_WANT_READ,
        4,
        0,        /* peer closed before we got our 8 bytes */
    };
    static const uint8_t src[] = "PART";
    mock_t m = { .script = script, .script_len = 3, .src = src };

    uint8_t buf[8] = {0};
    int rc = tls_io_read_full(mock_read, &m, buf, 8, 0);
    fails += eq_int("read/peer-fin/rc", rc, -1);
}

/* Zero-need is a no-op. */
static void test_read_full_zero(void) {
    mock_t m = { .script = NULL, .script_len = 0 };
    uint8_t buf[1] = {0};
    int rc = tls_io_read_full(mock_read, &m, buf, 0, 0);
    fails += eq_int("read/zero/rc", rc, 0);
    fails += eq_int("read/zero/calls", (int)m.script_idx, 0);
}

static void test_read_full_null_args(void) {
    uint8_t buf[1] = {0};
    fails += eq_int("read/null-fn",  tls_io_read_full(NULL, NULL, buf, 1, 0), -1);
    fails += eq_int("read/null-buf", tls_io_read_full(mock_read, NULL, NULL, 1, 0), -1);
}

/* ------------------------------------------------------------------ */
/* idle-bound tests (2026-07 half-open-conn hardening)                 */
/* ------------------------------------------------------------------ */

/* The production wedge: a half-open TCP conn yields WANT_READ forever
 * (SO_RCVTIMEO keeps firing, no FIN/RST ever arrives). With a bound of
 * N the call must give up after exactly N consecutive silent polls and
 * return the dedicated idle-timeout code — this is what turns "device
 * offline until manual power cycle" into a normal reconnect. */
static void test_read_full_idle_bound_fires(void) {
    enum { N_IDLE = 8 };
    static ssize_t script[N_IDLE];
    for (int i = 0; i < N_IDLE; i++) script[i] = MBEDTLS_ERR_SSL_WANT_READ;
    mock_t m = { .script = script, .script_len = N_IDLE };

    uint8_t buf[4] = {0};
    int rc = tls_io_read_full(mock_read, &m, buf, 4, 4);
    fails += eq_int("read/idle-bound/rc", rc, TLS_IO_ERR_IDLE_TIMEOUT);
    fails += eq_int("read/idle-bound/calls", (int)m.script_idx, 4);
}

/* One silent poll below the bound + data ⇒ success, not timeout. */
static void test_read_full_idle_bound_boundary(void) {
    static const ssize_t script[] = {
        MBEDTLS_ERR_SSL_WANT_READ,
        MBEDTLS_ERR_SSL_WANT_READ,
        MBEDTLS_ERR_SSL_WANT_READ,
        4,
    };
    static const uint8_t src[] = "Data";
    mock_t m = { .script = script, .script_len = 4, .src = src };

    uint8_t buf[4] = {0};
    int rc = tls_io_read_full(mock_read, &m, buf, 4, 4);
    fails += eq_int("read/idle-boundary/rc", rc, 0);
    fails += eq_bytes("read/idle-boundary/buf", buf, src, 4);
}

/* Forward progress must reset the idle budget: a healthy long-poll
 * sees 1-2 silent polls between KeepAlives indefinitely, and that must
 * never accumulate into a timeout. Pattern: 3 idles, byte, 3 idles,
 * byte, ... with max_idle=4 — total idles far exceed the bound but no
 * consecutive run does. */
static void test_read_full_idle_reset_on_progress(void) {
    static ssize_t script[4 * 4];
    static uint8_t src[4];
    size_t n = 0;
    for (int chunk = 0; chunk < 4; chunk++) {
        script[n++] = MBEDTLS_ERR_SSL_WANT_READ;
        script[n++] = MBEDTLS_ERR_SSL_WANT_READ;
        script[n++] = MBEDTLS_ERR_SSL_WANT_READ;
        script[n++] = 1;
        src[chunk] = (uint8_t)('A' + chunk);
    }
    mock_t m = { .script = script, .script_len = n, .src = src };

    uint8_t buf[4] = {0};
    int rc = tls_io_read_full(mock_read, &m, buf, 4, 4);
    fails += eq_int("read/idle-reset/rc", rc, 0);
    fails += eq_bytes("read/idle-reset/buf", buf, src, 4);
    fails += eq_int("read/idle-reset/calls", (int)m.script_idx, (int)n);
}

/* Symmetric bound on the write side: a peer that stopped ACKing keeps
 * the TCP send buffer full ⇒ endless WANT_WRITE. */
static void test_write_full_idle_bound_fires(void) {
    enum { N_IDLE = 6 };
    static ssize_t script[N_IDLE];
    for (int i = 0; i < N_IDLE; i++) script[i] = MBEDTLS_ERR_SSL_WANT_WRITE;
    uint8_t dst[4] = {0};
    mock_t m = { .script = script, .script_len = N_IDLE,
                 .dst = dst, .dst_cap = sizeof(dst) };

    int rc = tls_io_write_full(mock_write, &m, (const uint8_t *)"abcd", 4, 3);
    fails += eq_int("write/idle-bound/rc", rc, TLS_IO_ERR_IDLE_TIMEOUT);
    fails += eq_int("write/idle-bound/calls", (int)m.script_idx, 3);
}

static void test_write_full_idle_reset_on_progress(void) {
    static const ssize_t script[] = {
        MBEDTLS_ERR_SSL_WANT_WRITE,
        MBEDTLS_ERR_SSL_WANT_WRITE,
        2,
        MBEDTLS_ERR_SSL_WANT_WRITE,
        MBEDTLS_ERR_SSL_WANT_WRITE,
        2,
    };
    static const uint8_t payload[] = "wxyz";
    uint8_t dst[4] = {0};
    mock_t m = { .script = script, .script_len = 6,
                 .dst = dst, .dst_cap = sizeof(dst) };

    int rc = tls_io_write_full(mock_write, &m, payload, 4, 3);
    fails += eq_int("write/idle-reset/rc", rc, 0);
    fails += eq_bytes("write/idle-reset/dst", dst, payload, 4);
}

/* ------------------------------------------------------------------ */
/* write_full tests                                                    */
/* ------------------------------------------------------------------ */

static void test_write_full_simple(void) {
    static const ssize_t script[] = { 11 };
    static const uint8_t payload[] = "Hello, h2!\n";
    uint8_t dst[11] = {0};
    mock_t m = {
        .script = script, .script_len = 1,
        .dst = dst, .dst_cap = sizeof(dst),
    };

    int rc = tls_io_write_full(mock_write, &m, payload, sizeof(payload) - 1, 0);
    fails += eq_int("write/simple/rc", rc, 0);
    fails += eq_bytes("write/simple/dst", dst, payload, sizeof(payload) - 1);
}

static void test_write_full_retry_on_want(void) {
    /* Symmetrical regression: a WANT_WRITE on send must be retried,
     * not propagated. (Less common in practice than the read side,
     * but the same SO_SNDTIMEO failure mode applies.) */
    static const ssize_t script[] = {
        MBEDTLS_ERR_SSL_WANT_WRITE,
        MBEDTLS_ERR_SSL_WANT_READ,
        MBEDTLS_ERR_SSL_WANT_WRITE,
        7,
    };
    static const uint8_t payload[] = "tailnet";
    uint8_t dst[7] = {0};
    mock_t m = {
        .script = script, .script_len = 4,
        .dst = dst, .dst_cap = sizeof(dst),
    };

    int rc = tls_io_write_full(mock_write, &m, payload, sizeof(payload) - 1, 0);
    fails += eq_int("write/retry/rc", rc, 0);
    fails += eq_bytes("write/retry/dst", dst, payload, 7);
    fails += eq_int("write/retry/calls", (int)m.script_idx, 4);
}

static void test_write_full_partial_returns(void) {
    static const ssize_t script[] = { 4, 4, 4, 4 };
    static const uint8_t payload[] = "0123456789ABCDEF";
    uint8_t dst[16] = {0};
    mock_t m = {
        .script = script, .script_len = 4,
        .dst = dst, .dst_cap = sizeof(dst),
    };

    int rc = tls_io_write_full(mock_write, &m, payload, 16, 0);
    fails += eq_int("write/partial/rc", rc, 0);
    fails += eq_bytes("write/partial/dst", dst, payload, 16);
}

static void test_write_full_propagates_real_error(void) {
    static const ssize_t script[] = { -30848 };
    uint8_t dst[8] = {0};
    mock_t m = {
        .script = script, .script_len = 1,
        .dst = dst, .dst_cap = sizeof(dst),
    };
    int rc = tls_io_write_full(mock_write, &m, (const uint8_t *)"abcd", 4, 0);
    fails += eq_int("write/real-error/rc", rc, -30848);
}

static void test_write_full_null_args(void) {
    fails += eq_int("write/null-fn",
                    tls_io_write_full(NULL, NULL, (const uint8_t *)"x", 1, 0), -1);
    fails += eq_int("write/null-buf",
                    tls_io_write_full(mock_write, NULL, NULL, 1, 0), -1);
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* plain-socket adapters (round 1.3.5)                                 */
/* ------------------------------------------------------------------ */

static ssize_t sock_rd(void *ctx, uint8_t *buf, size_t len) {
    return tls_io_sock_read(*(int *)ctx, buf, len);
}
static ssize_t sock_wr(void *ctx, const uint8_t *buf, size_t len) {
    return tls_io_sock_write(*(int *)ctx, buf, len);
}

static int sock_pair(int sv[2], int rcv_ms) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    struct timeval tv = { .tv_sec = rcv_ms / 1000, .tv_usec = (rcv_ms % 1000) * 1000 };
    setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return 0;
}

static long ms_since(const struct timespec *t0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (t1.tv_sec - t0->tv_sec) * 1000 + (t1.tv_nsec - t0->tv_nsec) / 1000000;
}

static void test_sock_read_write(void) {
    int sv[2];
    fails += eq_int("sock/pair", sock_pair(sv, 50), 0);
    static const uint8_t msg[] = "ts2021 over :80";
    fails += eq_int("sock/write", (int)tls_io_sock_write(sv[1], msg, sizeof(msg)),
                    (int)sizeof(msg));
    uint8_t buf[32] = {0};
    int rc = tls_io_read_full(sock_rd, &sv[0], buf, sizeof(msg), 2);
    fails += eq_int("sock/read_full/rc", rc, 0);
    fails += eq_bytes("sock/read_full/buf", buf, msg, sizeof(msg));

    /* nothing on the wire: one SO_RCVTIMEO = one WANT_READ */
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    fails += eq_int("sock/timeout_is_want_read",
                    (int)tls_io_sock_read(sv[0], buf, 1), MBEDTLS_ERR_SSL_WANT_READ);
    long ms = ms_since(&t0);
    fails += eq_int("sock/timeout_waited_rcvtimeo", ms >= 40 && ms < 1000, 1);

    /* the budget counts socket timeouts: 3 polls → idle timeout */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    rc = tls_io_read_full(sock_rd, &sv[0], buf, 1, 3);
    ms = ms_since(&t0);
    fails += eq_int("sock/idle_budget/rc", rc, TLS_IO_ERR_IDLE_TIMEOUT);
    fails += eq_int("sock/idle_budget/three_polls", ms >= 140 && ms < 2000, 1);

    /* a partial read resets the budget, then FIN ends it */
    fails += eq_int("sock/write_two", (int)write(sv[1], "ab", 2), 2);
    shutdown(sv[1], SHUT_WR);
    rc = tls_io_read_full(sock_rd, &sv[0], buf, 3, 3);
    fails += eq_int("sock/fin_mid_read/rc", rc, -1);
    fails += eq_int("sock/fin_is_zero", (int)tls_io_sock_read(sv[0], buf, 1), 0);

    /* writing to a closed peer: -EPIPE (MSG_NOSIGNAL), the process lives */
    close(sv[1]);
    ssize_t w = 0;
    for (int i = 0; i < 4 && w >= 0; i++) w = tls_io_sock_write(sv[0], msg, sizeof(msg));
    fails += eq_int("sock/write_closed_epipe", (int)w, -EPIPE);
    rc = tls_io_write_full(sock_wr, &sv[0], msg, sizeof(msg), 2);
    fails += eq_int("sock/write_full_closed", rc, -EPIPE);
    close(sv[0]);

    /* a dead fd is a hard error, not a poll */
    fails += eq_int("sock/bad_fd_read", (int)tls_io_sock_read(sv[0], buf, 1), -EBADF);
    fails += eq_int("sock/bad_fd_write", (int)tls_io_sock_write(sv[0], msg, 1), -EBADF);
    rc = tls_io_read_full(sock_rd, &sv[0], buf, 1, 0);
    fails += eq_int("sock/bad_fd_read_full_not_retried", rc, -EBADF);
}

int main(void) {
    test_read_full_simple();
    test_read_full_retry_on_want_read();
    test_read_full_retry_on_want_write();
    test_read_full_long_idle();
    test_read_full_partial_returns();
    test_read_full_propagates_real_error();
    test_read_full_peer_fin();
    test_read_full_zero();
    test_read_full_null_args();

    test_read_full_idle_bound_fires();
    test_read_full_idle_bound_boundary();
    test_read_full_idle_reset_on_progress();
    test_write_full_idle_bound_fires();
    test_write_full_idle_reset_on_progress();

    test_write_full_simple();
    test_write_full_retry_on_want();
    test_write_full_partial_returns();
    test_write_full_propagates_real_error();
    test_write_full_null_args();

    test_sock_read_write();

    if (fails) {
        printf("\n[FAIL] %d assertion(s) failed\n", fails);
        return 1;
    }
    printf("\n[PASS] all tls_io assertions passed\n");
    return 0;
}
