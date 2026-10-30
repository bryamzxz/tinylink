/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host tests for tl_bodystat.h — the `map body:` line on how the map
 * stream's first message came (round 1.3.9). The client loop below is
 * h2_drive_request's, step for step, over a fake clock: a read blocks
 * until its record arrives (tl_bodystat_read gets the wait), the record's
 * HEADERS arm the timing (h2_io_on_status), its DATA is counted and
 * parsed (h2_io_on_data, a fixed busy time per record), and the message
 * completes inside the record that ends it (h2_map_body_done). The
 * server timelines are the three the line must tell apart:
 *
 *   - window-limited: the body right behind the HEADERS, in flights one
 *     RTT apart (lwIP's 4-segment window) — first DATA at once, no stall;
 *   - a loss: one flight a retransmission timeout late — one stall, the
 *     longest wait and where in the body it fell;
 *   - the server: the HEADERS at once, the body seconds later, then fast
 *     — first DATA late, no stall.
 *
 * Also: the stall threshold's clamp, the no-ops while disarmed, the
 * printed identity in = first DATA + waits + busy, saturation, the
 * incomplete variant, and the exact text of the line.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tl_bodystat.h"

static int fails = 0;

static void ok(const char *name, int cond)
{
    if (cond) { printf("[%s] OK\n", name); }
    else      { printf("[%s] FAIL\n", name); fails++; }
}

#define MS(x) ((int64_t)(x) * 1000LL)

/* One Noise record as the server's timeline has it. */
typedef struct {
    int64_t  arrive_us;   /* in the socket from then on */
    int      headers;     /* carries the map stream's final HEADERS (a 200) */
    uint32_t data;        /* map-stream DATA bytes in it */
} rec_t;

typedef struct {
    tl_bodystat_report_t r;
    int      done;        /* the message completed (else the stream ended) */
    uint32_t len;         /* the line's B figure */
} run_t;

/* h2_drive_request over `n` records: the request goes out at 0; each read
 * starts when the last record's parse ended; busy_us of parse per DATA
 * record; the message is body_len DATA bytes (its 4-byte prefix
 * included), complete inside the record that brings its last byte. */
static run_t drive(tl_bodystat_t *b, const rec_t *rec, size_t n, uint32_t body_len,
                   int64_t busy_us)
{
    run_t out;
    memset(&out, 0, sizeof(out));
    int64_t t = 0;
    uint32_t got = 0;
    for (size_t i = 0; i < n; i++) {
        const int64_t start = t;
        const int64_t armed_at_start = tl_bodystat_armed(b) ? start : 0;
        t = rec[i].arrive_us > start ? rec[i].arrive_us : start;
        if (armed_at_start != 0) tl_bodystat_read(b, t - armed_at_start);
        if (rec[i].headers) tl_bodystat_arm(b, t, t - 0);
        if (rec[i].data) {
            tl_bodystat_data(b, t, rec[i].data);
            got += rec[i].data;
            t += busy_us;
            if (got >= body_len && tl_bodystat_armed(b)) {
                tl_bodystat_report(b, t, &out.r);
                tl_bodystat_disarm(b);
                out.done = 1;
                out.len = body_len - 4;
                return out;
            }
        }
    }
    if (tl_bodystat_armed(b)) {   /* body_left */
        tl_bodystat_report(b, t, &out.r);
        tl_bodystat_disarm(b);
        out.len = out.r.bytes;
    }
    return out;
}

static int identity(const tl_bodystat_report_t *r)
{
    return r->total_ms == r->first_ms + r->wait_ms + r->busy_ms;
}

/* The sensor's boot: HEADERS one RTT (180 ms) after the request, 25 966
 * DATA bytes (25 962 + the prefix) in ~4 KB records, 5 760 B per RTT. */
#define RTT_MS 180
#define BODY   25966u

static size_t window_flights(rec_t *rec, int64_t first_data_ms, int64_t late_flight,
                             int64_t late_ms)
{
    size_t n = 0;
    rec[n++] = (rec_t){ MS(RTT_MS), 1, 0 };
    /* six records of 4 000 B and one of 1 966, ~1.4 records per flight:
     * flights at first_data + k × RTT, a flight's second record 2 ms
     * behind its first */
    static const int     flight_of[7] = { 0, 0, 1, 2, 2, 3, 4 };
    static const int64_t at_ms[7]     = { 0, 2, RTT_MS, 2 * RTT_MS, 2 * RTT_MS + 2,
                                          3 * RTT_MS, 4 * RTT_MS };
    for (int k = 0; k < 7; k++) {
        int64_t at = MS(first_data_ms) + MS(at_ms[k]);
        if (flight_of[k] >= late_flight) at += MS(late_ms);
        rec[n++] = (rec_t){ at, 0, k < 6 ? 4000u : 1966u };
    }
    return n;
}

static void test_threshold(void)
{
    tl_bodystat_t b;
    tl_bodystat_arm(&b, MS(5000), MS(175));
    ok("stall/twice-the-answer", b.stall_us == 350000 && b.reads == 1 && tl_bodystat_armed(&b));
    tl_bodystat_arm(&b, MS(5000), MS(100));
    ok("stall/floor-300", b.stall_us == 300000);
    tl_bodystat_arm(&b, MS(5000), MS(800));
    ok("stall/cap-1000", b.stall_us == 1000000);
    tl_bodystat_arm(&b, MS(5000), INT64_MAX / 2);
    ok("stall/cap-huge-answer", b.stall_us == 1000000);
    tl_bodystat_arm(&b, MS(5000), -MS(3));
    ok("stall/floor-negative-answer", b.stall_us == 300000);
    tl_bodystat_arm(&b, 0, MS(175));
    ok("arm/at-zero-still-armed", tl_bodystat_armed(&b));
}

static void test_disarmed(void)
{
    tl_bodystat_t b;
    memset(&b, 0, sizeof(b));
    ok("disarmed/zero-is-off", !tl_bodystat_armed(&b));
    tl_bodystat_read(&b, MS(900));
    tl_bodystat_data(&b, MS(1), 4000);
    tl_bodystat_t z;
    memset(&z, 0, sizeof(z));
    ok("disarmed/read-data-noop", memcmp(&b, &z, sizeof(b)) == 0);
    tl_bodystat_arm(&b, MS(100), MS(90));
    tl_bodystat_data(&b, MS(101), 10);
    tl_bodystat_read(&b, MS(50));
    tl_bodystat_disarm(&b);
    ok("disarm/clears", memcmp(&b, &z, sizeof(b)) == 0);
    /* a re-arm starts afresh */
    tl_bodystat_arm(&b, MS(100), MS(90));
    tl_bodystat_data(&b, MS(101), 10);
    tl_bodystat_read(&b, MS(700));
    tl_bodystat_arm(&b, MS(2000), MS(180));
    ok("arm/resets", b.hdr_us == MS(2000) && b.first_us == 0 && b.bytes == 0 &&
                     b.wait_us == 0 && b.max_us == 0 && b.stalls == 0 && b.reads == 1);
    ok("tl_bodystat_t/small", sizeof(tl_bodystat_t) <= 48);
}

static void test_window_limited(void)
{
    rec_t rec[8];
    const size_t n = window_flights(rec, RTT_MS, 99, 0);   /* body right behind */
    tl_bodystat_t b;
    memset(&b, 0, sizeof(b));
    const run_t o = drive(&b, rec, n, BODY, MS(2));
    const tl_bodystat_report_t *r = &o.r;
    printf("  (window: in %u, first +%u, %u reads, waits %u, longest %u at %u KB, busy %u)\n",
           r->total_ms, r->first_ms, r->reads, r->wait_ms, r->max_ms, r->max_kb, r->busy_ms);
    ok("window/complete", o.done && !tl_bodystat_armed(&b) && o.len == 25962);
    ok("window/first-data-at-once", r->first_ms == 0);
    ok("window/four-rtts", r->total_ms >= 4 * RTT_MS && r->total_ms <= 4 * RTT_MS + 20);
    ok("window/reads", r->reads == 8);
    ok("window/longest-one-rtt", r->max_ms >= RTT_MS - 10 && r->max_ms <= RTT_MS);
    ok("window/no-stall", r->stalls == 0 && r->stall_sum_ms == 0 && r->stall_ms == 2 * RTT_MS);
    ok("window/busy-is-parse", r->busy_ms >= 12 && r->busy_ms <= 16);
    ok("window/identity", identity(r));
    ok("window/bytes", r->bytes == BODY);
}

static void test_loss(void)
{
    rec_t rec[8];
    /* the third flight (body bytes 12 000 on) an RTO late: 1.2 s */
    const size_t n = window_flights(rec, RTT_MS, 2, 1200);
    tl_bodystat_t b;
    memset(&b, 0, sizeof(b));
    const run_t o = drive(&b, rec, n, BODY, MS(2));
    const tl_bodystat_report_t *r = &o.r;
    printf("  (loss: in %u, first +%u, waits %u, longest %u at %u KB, stalls %u = %u)\n",
           r->total_ms, r->first_ms, r->wait_ms, r->max_ms, r->max_kb, r->stalls,
           r->stall_sum_ms);
    ok("loss/complete", o.done);
    ok("loss/first-data-at-once", r->first_ms == 0);
    ok("loss/one-stall", r->stalls == 1);
    ok("loss/stall-is-the-gap", r->max_ms >= 1200 + RTT_MS - 10 && r->max_ms <= 1200 + RTT_MS &&
                                r->stall_sum_ms == r->max_ms);
    ok("loss/where", r->max_kb == 12000 / 1024);   /* three records in before it */
    ok("loss/tail-explained", r->total_ms - r->stall_sum_ms <= 4 * RTT_MS);
    ok("loss/identity", identity(r));
}

static void test_server(void)
{
    rec_t rec[8];
    /* HEADERS at 180 ms, the body 4.3 s after them, then window-limited */
    const size_t n = window_flights(rec, RTT_MS + 4300, 99, 0);
    tl_bodystat_t b;
    memset(&b, 0, sizeof(b));
    const run_t o = drive(&b, rec, n, BODY, MS(2));
    const tl_bodystat_report_t *r = &o.r;
    printf("  (server: in %u, first +%u, waits %u, longest %u, stalls %u)\n",
           r->total_ms, r->first_ms, r->wait_ms, r->max_ms, r->stalls);
    ok("server/complete", o.done);
    ok("server/first-data-late", r->first_ms == 4300);
    ok("server/not-a-stall", r->stalls == 0 && r->max_ms <= RTT_MS);
    ok("server/rest-is-the-floor", r->total_ms - r->first_ms <= 4 * RTT_MS + 20);
    ok("server/identity", identity(r));
}

/* A long wait for the record with the first DATA belongs to first DATA,
 * never to the gaps — the read's wait is reported before its DATA. */
static void test_first_wait_not_a_gap(void)
{
    tl_bodystat_t b;
    tl_bodystat_arm(&b, MS(1000), MS(180));
    tl_bodystat_read(&b, MS(2500));   /* a PING ack, then the DATA record */
    tl_bodystat_read(&b, MS(1500));
    tl_bodystat_data(&b, MS(5000), 4000);
    tl_bodystat_read(&b, MS(10));
    tl_bodystat_data(&b, MS(5012), 4000);
    tl_bodystat_report_t r;
    tl_bodystat_report(&b, MS(5020), &r);
    ok("first-wait/not-a-gap", r.first_ms == 4000 && r.wait_ms == 10 && r.max_ms == 10 &&
                               r.stalls == 0 && r.reads == 4 && r.max_kb == 3);
    ok("first-wait/identity", identity(&r) && r.busy_ms == 10);
}

/* A record with DATA but no wait (already buffered) and HEADERS + DATA in
 * one record: first DATA +0, the HEADERS' record counted once. */
static void test_headers_and_data_together(void)
{
    const rec_t rec[] = {
        { MS(180), 1, 0 },
        { MS(180), 0, 4000 },       /* same flight: no wait */
        { MS(181), 0, 4000 },
        { MS(360), 0, BODY - 8000 },
    };
    tl_bodystat_t b;
    memset(&b, 0, sizeof(b));
    const run_t o = drive(&b, rec, 4, BODY, 0);
    ok("together/first-0", o.done && o.r.first_ms == 0 && o.r.reads == 4);
    ok("together/waits", o.r.wait_ms == 180 && o.r.max_ms == 179 && o.r.max_kb == 7 &&
                         o.r.busy_ms == 0 && identity(&o.r));
}

static void test_incomplete(void)
{
    rec_t rec[8];
    (void)window_flights(rec, RTT_MS, 2, 30000);   /* the third flight never comes: */
    const size_t n = 4;                            /* HEADERS + 3 DATA records, then the end */
    tl_bodystat_t b;
    memset(&b, 0, sizeof(b));
    const run_t o = drive(&b, rec, n, BODY, MS(2));
    ok("incomplete/reported", !o.done && !tl_bodystat_armed(&b) && o.len == 12000 &&
                              o.r.bytes == 12000 && identity(&o.r));
    /* HEADERS, then the stream ends with no DATA at all */
    const rec_t only[] = { { MS(180), 1, 0 } };
    memset(&b, 0, sizeof(b));
    const run_t e = drive(&b, only, 1, BODY, 0);
    ok("incomplete/no-data", !e.done && e.r.bytes == 0 && e.r.first_ms == e.r.total_ms &&
                             e.r.wait_ms == 0 && e.r.busy_ms == 0 && e.r.reads == 1);
}

static void test_saturation(void)
{
    tl_bodystat_t b;
    tl_bodystat_arm(&b, MS(1), MS(180));
    tl_bodystat_data(&b, MS(2), 1);
    for (int i = 0; i < 70000; i++) tl_bodystat_read(&b, 0);
    ok("sat/reads", b.reads == UINT16_MAX);
    tl_bodystat_read(&b, INT64_MAX / 2);
    tl_bodystat_read(&b, INT64_MAX / 2);
    ok("sat/wait", b.wait_us == UINT32_MAX && b.max_us == UINT32_MAX &&
                   b.stall_sum_us == UINT32_MAX && b.stalls == 2);
    tl_bodystat_read(&b, -MS(5));   /* a clock step back: no wait */
    ok("sat/negative-wait", b.stalls == 2 && b.max_us == UINT32_MAX);
    tl_bodystat_data(&b, MS(3), (size_t)UINT32_MAX);
    ok("sat/bytes", b.bytes == UINT32_MAX);
    tl_bodystat_report_t r;
    tl_bodystat_report(&b, MS(10), &r);   /* waits beyond the elapsed time */
    ok("sat/report-clamped", r.wait_ms == r.total_ms - r.first_ms && r.busy_ms == 0 &&
                             identity(&r));
    tl_bodystat_report(&b, MS(0), &r);    /* report before the arm */
    ok("sat/report-before-arm", r.total_ms == 0 && r.first_ms == 0 && identity(&r));
    /* DATA stamped before the HEADERS: first DATA +0 */
    tl_bodystat_arm(&b, MS(100), MS(180));
    tl_bodystat_data(&b, MS(50), 10);
    tl_bodystat_report(&b, MS(120), &r);
    ok("sat/data-before-hdr", r.first_ms == 0 && r.total_ms == 20 && identity(&r));
}

static void test_line(void)
{
    tl_bodystat_t b;
    tl_bodystat_arm(&b, MS(4590), MS(175));
    tl_bodystat_read(&b, MS(4));
    tl_bodystat_data(&b, MS(4600), 4000);
    tl_bodystat_read(&b, MS(178));
    tl_bodystat_data(&b, MS(4790), 4000);
    tl_bodystat_read(&b, MS(1100));
    tl_bodystat_data(&b, MS(5900), 4000);
    tl_bodystat_report_t r;
    tl_bodystat_report(&b, MS(6590), &r);
    char line[256];
    snprintf(line, sizeof(line), TL_BODYSTAT_LINE, "", TL_BODYSTAT_ARGS(25962u, &r));
    printf("  (%s)\n", line);
    ok("line/text", strcmp(line, "map body: 25962 B in 2000 ms after HEADERS (first DATA +10 ms, "
                                 "4 reads, waits 1278 ms, longest 1100 ms at 7 KB, "
                                 "stalls > 350 ms: 1 = 1100 ms, busy 712 ms)") == 0);
    snprintf(line, sizeof(line), TL_BODYSTAT_LINE, "incomplete, ", TL_BODYSTAT_ARGS(r.bytes, &r));
    ok("line/incomplete", strncmp(line, "map body: incomplete, 12000 B in 2000 ms", 40) == 0);
    ok("line/fits-a-log-line", strlen(line) < 200);
}

int main(void)
{
    test_threshold();
    test_disarmed();
    test_window_limited();
    test_loss();
    test_server();
    test_first_wait_not_a_gap();
    test_headers_and_data_together();
    test_incomplete();
    test_saturation();
    test_line();
    if (fails) {
        printf("\n[FAIL] %d bodystat assertion(s) failed\n", fails);
        return 1;
    }
    printf("\n[PASS] all bodystat assertions passed\n");
    return 0;
}
