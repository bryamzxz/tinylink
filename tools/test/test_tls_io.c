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
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

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
    int rc = tls_io_read_full(mock_read, &m, buf, 16);
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
    int rc = tls_io_read_full(mock_read, &m, buf, 13);
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
    int rc = tls_io_read_full(mock_read, &m, buf, 8);
    fails += eq_int("read/want-write-retry/rc", rc, 0);
    fails += eq_bytes("read/want-write-retry/buf", buf, src, 8);
}

/* The long-poll spends most of its time blocked here. Verify the
 * retry loop has no implicit cap — 1000 WANT_READs in a row must
 * still resolve to a successful read when data finally arrives. */
static void test_read_full_long_idle(void) {
    enum { N_IDLE = 1000 };
    static ssize_t script[N_IDLE + 1];
    for (int i = 0; i < N_IDLE; i++) script[i] = MBEDTLS_ERR_SSL_WANT_READ;
    script[N_IDLE] = 4;
    static const uint8_t src[] = "Beat";
    mock_t m = { .script = script, .script_len = N_IDLE + 1, .src = src };

    uint8_t buf[4] = {0};
    int rc = tls_io_read_full(mock_read, &m, buf, 4);
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
    int rc = tls_io_read_full(mock_read, &m, buf, 16);
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
    int rc = tls_io_read_full(mock_read, &m, buf, 16);
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
    int rc = tls_io_read_full(mock_read, &m, buf, 8);
    fails += eq_int("read/peer-fin/rc", rc, -1);
}

/* Zero-need is a no-op. */
static void test_read_full_zero(void) {
    mock_t m = { .script = NULL, .script_len = 0 };
    uint8_t buf[1] = {0};
    int rc = tls_io_read_full(mock_read, &m, buf, 0);
    fails += eq_int("read/zero/rc", rc, 0);
    fails += eq_int("read/zero/calls", (int)m.script_idx, 0);
}

static void test_read_full_null_args(void) {
    uint8_t buf[1] = {0};
    fails += eq_int("read/null-fn",  tls_io_read_full(NULL, NULL, buf, 1), -1);
    fails += eq_int("read/null-buf", tls_io_read_full(mock_read, NULL, NULL, 1), -1);
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

    int rc = tls_io_write_full(mock_write, &m, payload, sizeof(payload) - 1);
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

    int rc = tls_io_write_full(mock_write, &m, payload, sizeof(payload) - 1);
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

    int rc = tls_io_write_full(mock_write, &m, payload, 16);
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
    int rc = tls_io_write_full(mock_write, &m, (const uint8_t *)"abcd", 4);
    fails += eq_int("write/real-error/rc", rc, -30848);
}

static void test_write_full_null_args(void) {
    fails += eq_int("write/null-fn",
                    tls_io_write_full(NULL, NULL, (const uint8_t *)"x", 1), -1);
    fails += eq_int("write/null-buf",
                    tls_io_write_full(mock_write, NULL, NULL, 1), -1);
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

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

    test_write_full_simple();
    test_write_full_retry_on_want();
    test_write_full_partial_returns();
    test_write_full_propagates_real_error();
    test_write_full_null_args();

    if (fails) {
        printf("\n[FAIL] %d assertion(s) failed\n", fails);
        return 1;
    }
    printf("\n[PASS] all tls_io assertions passed\n");
    return 0;
}
