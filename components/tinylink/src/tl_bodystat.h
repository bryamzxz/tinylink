// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// The map stream's first response body, timed (round 1.3.9). On the
// sensor the ~26 KB initial netmap took 720 ms to 6.2 s from the stream's
// HEADERS (10 boots of 1.3.8; the HEADERS ~180 ms, one RTT, after the
// request), on the path reset → WireGuard up. A floor of 4 RTTs is what
// lwIP's 5 760-B receive window allows (26 KB at 4 segments per RTT);
// the tail is either the transport (a segment lost in a flight of ≤ 4
// without SACK seldom draws the 3 duplicate ACKs of a fast retransmit:
// the server's RTO, doubling) or the server (HEADERS at once, the body
// when the netmap is computed). One
// line per map stream tells them apart — h2_client.c feeds it, mapreq.c
// ends it when the stream's first message is complete:
//
//   h2: map body: 25962 B in 2000 ms after HEADERS (first DATA +10 ms, 9 reads,
//       waits 1890 ms, longest 1100 ms at 11 KB, stalls > 350 ms: 1 = 1100 ms, busy 100 ms)
//
// B           the message's length (mapreq's framing, `stream peak: body=`)
// in          the stream's final HEADERS → the message complete (parsed,
//             before its handler runs)
// first DATA  HEADERS → the end of the read that brought the stream's first
//             DATA byte: the server's time to its first body byte (plus
//             the transport's, should that byte's segment be lost)
// reads       Noise records read, the HEADERS' one included
// waits       Σ time blocked in those reads after the first DATA (socket,
//             TLS on :443, Noise decrypt): the transport's share — and
//             the server's, if it sends the body in pieces
// longest     the longest such wait, and the DATA bytes in before it
// stalls      waits over twice the request → HEADERS time (clamped to
//             TL_BODY_STALL_MIN_MS … TL_BODY_STALL_MAX_MS): their number
//             and sum. Past any window-limited wait (≤ 1 RTT: the read
//             blocks until the next flight, which our ACK of the last one
//             released) and at a retransmission timeout's scale (Linux:
//             RTO ≥ srtt + 200 ms, then doubling; a tail-loss probe after
//             2 srtt, with SACK only)
// busy        the rest after the first DATA: this side's own work between
//             reads (HTTP/2, the JSON split and parse, log lines)
//
// in = first DATA + waits + busy, exactly (the ms figures are formed so).
// A stream that ends before its first message is complete logs the same
// line as `map body: incomplete, N B in …` (N: DATA bytes received).
//
// RAM: one tl_bodystat_t (48 B, BSS); per record read two esp_timer
// reads while armed, nothing otherwise. Pure logic, header-only so the
// host tests cover it (tools/test/test_bodystat.c).

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The stall threshold's bounds: 300 ms keeps a window-limited wait at the
 * sensor's 180-ms RTT out of it; 1 000 ms keeps a slow answer (the poll
 * after a clean server end waits up to minutes for its HEADERS) from
 * lifting it past a 1-s RTO. */
#define TL_BODY_STALL_MIN_MS 300u
#define TL_BODY_STALL_MAX_MS 1000u

typedef struct {
    int64_t  hdr_us;       /* the final HEADERS (esp_timer µs); 0: not armed */
    int64_t  first_us;     /* the stream's first DATA byte read; 0: none yet */
    uint32_t bytes;        /* DATA bytes since the HEADERS */
    uint32_t stall_us;     /* a wait over this is a stall */
    uint32_t wait_us;      /* Σ waits after the first DATA */
    uint32_t max_us;       /* the longest of them … */
    uint32_t max_at;       /* … and the DATA bytes in before it */
    uint32_t stall_sum_us; /* Σ stalls */
    uint16_t reads;        /* records read, the HEADERS' one included */
    uint16_t stalls;
} tl_bodystat_t;

/* The printed figures (ms, KB). */
typedef struct {
    uint32_t total_ms, first_ms, reads, wait_ms, max_ms, max_kb;
    uint32_t stall_ms, stalls, stall_sum_ms, busy_ms, bytes;
} tl_bodystat_report_t;

static inline uint32_t tl_body_u32(int64_t v)
{
    return v <= 0 ? 0u : v >= (int64_t)UINT32_MAX ? UINT32_MAX : (uint32_t)v;
}

static inline uint32_t tl_body_add(uint32_t a, uint32_t b)
{
    return b > UINT32_MAX - a ? UINT32_MAX : a + b;
}

static inline bool tl_bodystat_armed(const tl_bodystat_t *b)
{
    return b->hdr_us != 0;
}

static inline void tl_bodystat_disarm(tl_bodystat_t *b)
{
    memset(b, 0, sizeof(*b));
}

/* The streaming request's final response HEADERS (a 200) arrived at
 * now_us, answer_us after the request went out. */
static inline void tl_bodystat_arm(tl_bodystat_t *b, int64_t now_us, int64_t answer_us)
{
    memset(b, 0, sizeof(*b));
    b->hdr_us = now_us != 0 ? now_us : 1;
    b->reads = 1;
    const int64_t lo = (int64_t)TL_BODY_STALL_MIN_MS * 1000;
    const int64_t hi = (int64_t)TL_BODY_STALL_MAX_MS * 1000;
    const int64_t twice = answer_us > hi ? hi : 2 * answer_us;
    b->stall_us = (uint32_t)(twice < lo ? lo : twice > hi ? hi : twice);
}

/* A record read that blocked wait_us, before its bytes are parsed. Until
 * the first DATA a wait is that byte's latency (first_us covers it);
 * after it, a gap in the body. */
static inline void tl_bodystat_read(tl_bodystat_t *b, int64_t wait_us)
{
    if (!tl_bodystat_armed(b)) return;
    if (b->reads < UINT16_MAX) b->reads++;
    if (b->first_us == 0) return;
    const uint32_t w = tl_body_u32(wait_us);
    b->wait_us = tl_body_add(b->wait_us, w);
    if (w > b->max_us) {
        b->max_us = w;
        b->max_at = b->bytes;
    }
    if (w > b->stall_us) {
        if (b->stalls < UINT16_MAX) b->stalls++;
        b->stall_sum_us = tl_body_add(b->stall_sum_us, w);
    }
}

/* n DATA bytes of the stream, parsed at now_us (right after the read
 * that brought them). */
static inline void tl_bodystat_data(tl_bodystat_t *b, int64_t now_us, size_t n)
{
    if (!tl_bodystat_armed(b)) return;
    if (b->first_us == 0) b->first_us = now_us > b->hdr_us ? now_us : b->hdr_us;
    b->bytes = tl_body_add(b->bytes, n > UINT32_MAX ? UINT32_MAX : (uint32_t)n);
}

/* The figures at now_us (the message complete, or the stream over). */
static inline void tl_bodystat_report(const tl_bodystat_t *b, int64_t now_us,
                                      tl_bodystat_report_t *r)
{
    const int64_t total_us = now_us - b->hdr_us;
    const int64_t first_us = b->first_us != 0 ? b->first_us - b->hdr_us : total_us;
    r->total_ms = tl_body_u32(total_us / 1000);
    r->first_ms = tl_body_u32(first_us / 1000);
    if (r->first_ms > r->total_ms) r->first_ms = r->total_ms;
    r->reads = b->reads;
    r->wait_ms = b->wait_us / 1000;
    if (r->wait_ms > r->total_ms - r->first_ms) r->wait_ms = r->total_ms - r->first_ms;
    r->busy_ms = r->total_ms - r->first_ms - r->wait_ms;
    r->max_ms = b->max_us / 1000;
    r->max_kb = b->max_at / 1024;
    r->stall_ms = b->stall_us / 1000;
    r->stalls = b->stalls;
    r->stall_sum_ms = b->stall_sum_us / 1000;
    r->bytes = b->bytes;
}

/* The line: TL_BODYSTAT_LINE with "" or "incomplete, ", then
 * TL_BODYSTAT_ARGS(len, r) — len the message's length, or r->bytes for
 * an incomplete one. */
#define TL_BODYSTAT_LINE "map body: %s" TL_BODYSTAT_FMT
#define TL_BODYSTAT_FMT                                                       \
    "%u B in %u ms after HEADERS (first DATA +%u ms, %u reads, waits %u ms, " \
    "longest %u ms at %u KB, stalls > %u ms: %u = %u ms, busy %u ms)"
#define TL_BODYSTAT_ARGS(len, r)                                              \
    (unsigned)(len), (unsigned)(r)->total_ms, (unsigned)(r)->first_ms,        \
    (unsigned)(r)->reads, (unsigned)(r)->wait_ms, (unsigned)(r)->max_ms,      \
    (unsigned)(r)->max_kb, (unsigned)(r)->stall_ms, (unsigned)(r)->stalls,    \
    (unsigned)(r)->stall_sum_ms, (unsigned)(r)->busy_ms

#ifdef __cplusplus
}
#endif
