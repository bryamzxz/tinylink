// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// HTTP/2 engine (h2_core.c, round 1.3.4 D1) against a scripted peer:
// the exact preface / SETTINGS / request bytes, frame codec round trips
// with every byte stream also fed byte by byte and at random splits,
// padding, CONTINUATION (and its limit), flow control both ways
// (WINDOW_UPDATE emission at half the window, window violations, request
// bodies held by small / negative server windows), PING / GOAWAY /
// RST_STREAM, the nghttp2-style response checks, every connection-error
// class with the GOAWAY code it sends, and fixed-seed fuzzing of the
// frame parser (run it under `make asan`).
//
// The engine's hooks are implemented here: the client's output is
// captured and parsed back into frames; tx_buf asserts the engine only
// borrows it between feeds.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "h2_core.h"

static int s_fails;

static void check(const char *name, int ok)
{
    printf("[%s] %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) s_fails++;
}

/* ---- hooks ------------------------------------------------------------- */

typedef struct {
    uint8_t  out[256 * 1024];     /* everything the client sent */
    size_t   out_len;
    int      sends;               /* h2_io_send + h2_io_tx_send calls */
    int      fail_send;           /* make the n-th send fail (1-based) */
    bool     in_feed;             /* the engine must not borrow tx_buf now */
    int      tx_buf_in_feed;
    uint8_t  tx[4077];
    size_t   tx_cap;
    int      status;
    int      n_status;
    char     hdrs[2048];          /* "name: value\n" from on_header */
    uint8_t  data[512 * 1024];
    size_t   data_len;
    int      data_calls;
    int      stop_after;          /* on_data returns -1 at this call (1-based) */
    int      goaways;
    uint32_t goaway_last, goaway_err;
} io_t;

static io_t s_io;

static int out_append(const uint8_t *b, size_t n)
{
    s_io.sends++;
    if (s_io.fail_send && s_io.sends == s_io.fail_send) return -1;
    if (s_io.out_len + n > sizeof(s_io.out)) return -1;
    memcpy(s_io.out + s_io.out_len, b, n);
    s_io.out_len += n;
    return 0;
}

int h2_io_send(void *io, const uint8_t *buf, size_t len)
{
    (void)io;
    return out_append(buf, len);
}

uint8_t *h2_io_tx_buf(void *io, size_t *cap)
{
    (void)io;
    if (s_io.in_feed) s_io.tx_buf_in_feed++;
    *cap = s_io.tx_cap ? s_io.tx_cap : sizeof(s_io.tx);
    return s_io.tx;
}

int h2_io_tx_send(void *io, size_t len)
{
    (void)io;
    return out_append(s_io.tx, len);
}

void h2_io_on_status(void *io, int status)
{
    (void)io;
    s_io.status = status;
    s_io.n_status++;
}

void h2_io_on_header(void *io, const hpack_field_t *f)
{
    (void)io;
    size_t l = strlen(s_io.hdrs);
    snprintf(s_io.hdrs + l, sizeof(s_io.hdrs) - l, "%.*s: %.*s\n",
             (int)f->name_len, (const char *)f->name,
             (int)f->value_len, (const char *)f->value);
}

int h2_io_on_data(void *io, const uint8_t *buf, size_t len)
{
    (void)io;
    s_io.data_calls++;
    if (s_io.data_len + len <= sizeof(s_io.data)) {
        memcpy(s_io.data + s_io.data_len, buf, len);
        s_io.data_len += len;
    }
    if (s_io.stop_after && s_io.data_calls >= s_io.stop_after) return -1;
    return 0;
}

void h2_io_on_goaway(void *io, uint32_t last, uint32_t err)
{
    (void)io;
    s_io.goaways++;
    s_io.goaway_last = last;
    s_io.goaway_err = err;
}

/* ---- the client's output as frames --------------------------------------- */

typedef struct { uint8_t type, flags; uint32_t sid, len; const uint8_t *p; } frm_t;

/* Frames after the preface (when present). Returns the count. */
static int out_frames(frm_t *f, int max)
{
    size_t off = 0;
    if (s_io.out_len >= H2_PREFACE_LEN && memcmp(s_io.out, H2_PREFACE, H2_PREFACE_LEN) == 0)
        off = H2_PREFACE_LEN;
    int n = 0;
    while (off + 9 <= s_io.out_len && n < max) {
        const uint8_t *b = s_io.out + off;
        f[n].len = ((uint32_t)b[0] << 16) | ((uint32_t)b[1] << 8) | b[2];
        f[n].type = b[3];
        f[n].flags = b[4];
        f[n].sid = (((uint32_t)b[5] << 24) | ((uint32_t)b[6] << 16) |
                    ((uint32_t)b[7] << 8) | b[8]) & 0x7fffffffu;
        f[n].p = b + 9;
        off += 9 + f[n].len;
        n++;
    }
    return n;
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* The GOAWAY error code the client sent, or -1. */
static long sent_goaway(void)
{
    frm_t f[512];
    int n = out_frames(f, 512);
    for (int i = n - 1; i >= 0; i--)
        if (f[i].type == H2_GOAWAY && f[i].len >= 8) return (long)be32(f[i].p + 4);
    return -1;
}

static long sent_rst(uint32_t sid)
{
    frm_t f[512];
    int n = out_frames(f, 512);
    for (int i = n - 1; i >= 0; i--)
        if (f[i].type == H2_RST_STREAM && f[i].sid == sid) return (long)be32(f[i].p);
    return -1;
}

static int count_type(uint8_t type, uint8_t flags_mask, uint8_t flags)
{
    frm_t f[2048];
    int n = out_frames(f, 2048);
    int c = 0;
    for (int i = 0; i < n; i++)
        if (f[i].type == type && (f[i].flags & flags_mask) == flags) c++;
    return c;
}

/* Sum of WINDOW_UPDATE increments sent for sid. */
static uint64_t wu_sum(uint32_t sid)
{
    frm_t f[2048];
    int n = out_frames(f, 2048);
    uint64_t s = 0;
    for (int i = 0; i < n; i++)
        if (f[i].type == H2_WINDOW_UPDATE && f[i].sid == sid) s += be32(f[i].p) & 0x7fffffffu;
    return s;
}

/* ---- the scripted server --------------------------------------------------- */

static uint8_t s_srv[600 * 1024];
static size_t  s_srv_len;

static void srv_reset(void) { s_srv_len = 0; }

static void frame(uint8_t type, uint8_t flags, uint32_t sid, const void *p, size_t n)
{
    uint8_t *b = s_srv + s_srv_len;
    b[0] = (uint8_t)(n >> 16); b[1] = (uint8_t)(n >> 8); b[2] = (uint8_t)n;
    b[3] = type; b[4] = flags;
    b[5] = (uint8_t)(sid >> 24); b[6] = (uint8_t)(sid >> 16);
    b[7] = (uint8_t)(sid >> 8); b[8] = (uint8_t)sid;
    if (n) memcpy(b + 9, p, n);
    s_srv_len += 9 + n;
}

static void frame_u32(uint8_t type, uint32_t sid, uint32_t v)
{
    uint8_t p[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    frame(type, 0, sid, p, 4);
}

static void settings(int n, const uint16_t *ids, const uint32_t *vals)
{
    uint8_t p[64];
    for (int i = 0; i < n; i++) {
        p[6 * i] = (uint8_t)(ids[i] >> 8); p[6 * i + 1] = (uint8_t)ids[i];
        p[6 * i + 2] = (uint8_t)(vals[i] >> 24); p[6 * i + 3] = (uint8_t)(vals[i] >> 16);
        p[6 * i + 4] = (uint8_t)(vals[i] >> 8); p[6 * i + 5] = (uint8_t)vals[i];
    }
    frame(H2_SETTINGS, 0, 0, p, (size_t)(6 * n));
}

/* A header block: 0x20 size update, then "name\0value\0" pairs as
 * literals without indexing (":status: 200" as the indexed 0x88). */
static size_t block(uint8_t *b, const char *const *nv, int n)
{
    size_t o = 0;
    b[o++] = 0x20;
    for (int i = 0; i < n; i++) {
        if (strcmp(nv[2 * i], ":status") == 0 && strcmp(nv[2 * i + 1], "200") == 0) {
            b[o++] = 0x88;
            continue;
        }
        o += hpack_put_field(b + o, 4096, nv[2 * i], strlen(nv[2 * i]),
                             nv[2 * i + 1], strlen(nv[2 * i + 1]));
    }
    return o;
}

static void headers(uint32_t sid, uint8_t flags, const char *const *nv, int n)
{
    uint8_t b[4096];
    size_t l = block(b, nv, n);
    frame(H2_HEADERS, flags | H2_F_END_HEADERS, sid, b, l);
}

static void data(uint32_t sid, uint8_t flags, const void *p, size_t n)
{
    frame(H2_DATA, flags, sid, p, n);
}

static void data_padded(uint32_t sid, uint8_t flags, const void *p, size_t n, uint8_t pad)
{
    uint8_t b[20000];
    b[0] = pad;
    memcpy(b + 1, p, n);
    memset(b + 1 + n, 0, pad);
    frame(H2_DATA, flags | H2_F_PADDED, sid, b, 1 + n + pad);
}

/* ---- driver ------------------------------------------------------------------ */

static h2_core_t s_h;
static uint32_t s_rng = 0xc0ffee11u;
static uint32_t rnd(void)
{
    s_rng ^= s_rng << 13; s_rng ^= s_rng >> 17; s_rng ^= s_rng << 5;
    return s_rng;
}

static void io_reset(void)
{
    memset(&s_io, 0, sizeof(s_io));
}

/* A started client with one open request (stream 1, body "hello"). */
static void client_with_request(const uint8_t *body, size_t blen)
{
    io_reset();
    h2c_init(&s_h, &s_io);
    (void)h2c_start(&s_h);
    static const h2_field_t req[] = {
        { ":method", "POST" }, { ":scheme", "https" }, { ":path", "/machine/map" },
        { ":authority", "controlplane.tailscale.com" },
        { "content-type", "application/json" }, { "content-length", "5" },
    };
    (void)h2c_request(&s_h, req, 6, body, blen);
}

/* Feed the scripted server bytes: mode 0 whole, 1 byte by byte, 2 random. */
static int feed(int mode)
{
    size_t off = 0;
    int rc = H2C_OK;
    while (off < s_srv_len && rc == H2C_OK) {
        size_t n = s_srv_len - off;
        if (mode == 1) n = 1;
        else if (mode == 2) n = 1 + rnd() % (n < 5000 ? n : 5000);
        s_io.in_feed = true;
        rc = h2c_feed(&s_h, s_srv + off, n);
        s_io.in_feed = false;
        if (rc == H2C_OK) rc = h2c_pump(&s_h);
        off += n;
    }
    return rc;
}

static const uint8_t kHello[] = "hello";

/* ---- tests ---------------------------------------------------------------- */

static void test_preface_and_request_bytes(void)
{
    io_reset();
    h2c_init(&s_h, &s_io);
    int rc = h2c_start(&s_h);
    static const uint8_t want[] =
        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        "\x00\x00\x0c\x04\x00\x00\x00\x00\x00"
        "\x00\x01\x00\x00\x00\x00" "\x00\x02\x00\x00\x00\x00";
    check("preface_settings_exact_45_bytes",
          rc == H2C_OK && s_io.out_len == 45 && memcmp(s_io.out, want, 45) == 0 && s_io.sends == 1);
    check("start_twice_refused", h2c_start(&s_h) == H2C_ERR_STATE);

    s_io.out_len = 0;
    s_io.sends = 0;
    const char *body = "{\"Version\":148}";
    static const h2_field_t req[] = {
        { ":method", "POST" }, { ":scheme", "https" }, { ":path", "/machine/register" },
        { ":authority", "controlplane.tailscale.com" },
        { "content-type", "application/json" }, { "content-length", "15" },
    };
    rc = h2c_request(&s_h, req, 6, (const uint8_t *)body, 15);
    /* HEADERS + DATA in one send: */
    static const uint8_t blk[] =
        "\x20"
        "\x02\x04" "POST"
        "\x06\x05" "https"
        "\x04\x11" "/machine/register"
        "\x01\x1a" "controlplane.tailscale.com"
        "\x0f\x10\x10" "application/json"
        "\x0f\x0d\x02" "15";
    const size_t bl = sizeof(blk) - 1;
    frm_t f[8];
    int n = out_frames(f, 8);
    check("request_one_record", rc == H2C_OK && s_io.sends == 1 && n == 2);
    check("request_headers_exact",
          f[0].type == H2_HEADERS && f[0].flags == H2_F_END_HEADERS && f[0].sid == 1 &&
          f[0].len == bl && memcmp(f[0].p, blk, bl) == 0);
    check("request_data_end_stream",
          f[1].type == H2_DATA && f[1].flags == H2_F_END_STREAM && f[1].sid == 1 &&
          f[1].len == 15 && memcmp(f[1].p, body, 15) == 0);
    check("request_busy_refused", h2c_request(&s_h, req, 6, NULL, 0) == H2C_ERR_STATE);

    /* Close stream 1, then a second request: stream 3, no size update. */
    srv_reset();
    static const char *const ok[] = { ":status", "200" };
    headers(1, H2_F_END_STREAM, ok, 1);
    rc = feed(0);
    check("stream1_closed", rc == H2C_OK && s_h.s.closed && s_h.s.close_err == 0 &&
                            s_io.status == 200);
    s_io.out_len = 0;
    rc = h2c_request(&s_h, req, 6, NULL, 0);
    n = out_frames(f, 8);
    check("second_request_stream3_no_size_update",
          rc == H2C_OK && n == 2 && f[0].sid == 3 && f[0].p[0] == 0x02 &&
          f[1].type == H2_DATA && f[1].len == 0 && f[1].flags == H2_F_END_STREAM);
}

static void test_response_paths(void)
{
    for (int mode = 0; mode < 3; mode++) {
        client_with_request(kHello, 5);
        srv_reset();
        static const uint16_t ids[] = { H2_SET_MAX_CONCURRENT_STREAMS, H2_SET_INITIAL_WINDOW_SIZE,
                                        H2_SET_MAX_FRAME_SIZE, 0x99 };
        static const uint32_t vals[] = { 250, 1048576, 1048576, 7 };
        settings(4, ids, vals);
        frame(H2_SETTINGS, H2_F_ACK, 0, NULL, 0);
        frame_u32(H2_WINDOW_UPDATE, 0, 1073741823);
        static const char *const nv[] = { ":status", "200", "content-type", "application/json",
                                          "content-length", "26", "date", "Wed, 29 Oct 2026 05:00:00 GMT",
                                          "retry-after", "30" };
        headers(1, 0, nv, 5);
        data(1, 0, "{\"MachineAuthor", 15);
        data(1, H2_F_END_STREAM, "ized\":true}", 11);
        const int rc = feed(mode);
        char nm[64];
        snprintf(nm, sizeof(nm), "response_200_body_mode%d", mode);
        check(nm, rc == H2C_OK && s_io.status == 200 && s_io.data_len == 26 &&
                  memcmp(s_io.data, "{\"MachineAuthorized\":true}", 26) == 0 &&
                  s_h.s.closed && s_h.s.close_err == 0 && s_io.tx_buf_in_feed == 0);
        snprintf(nm, sizeof(nm), "response_headers_reported_mode%d", mode);
        check(nm, strcmp(s_io.hdrs, "content-type: application/json\ncontent-length: 26\n"
                                    "date: Wed, 29 Oct 2026 05:00:00 GMT\nretry-after: 30\n") == 0);
        snprintf(nm, sizeof(nm), "settings_applied_acked_mode%d", mode);
        check(nm, count_type(H2_SETTINGS, H2_F_ACK, H2_F_ACK) == 1 && s_h.settings_unacked == 0 &&
                  s_h.peer_initial_win == 1048576 && s_h.peer_max_frame == 1048576 &&
                  s_h.conn_send_win == 65535 - 5 + 1073741823);
    }

    /* 429 + Retry-After, empty body, END_STREAM on HEADERS. */
    client_with_request(kHello, 5);
    srv_reset();
    static const char *const nv429[] = { ":status", "429", "retry-after", "120" };
    headers(1, H2_F_END_STREAM, nv429, 2);
    int rc = feed(1);
    check("response_429_retry_after", rc == H2C_OK && s_io.status == 429 &&
          strcmp(s_io.hdrs, "retry-after: 120\n") == 0 && s_h.s.closed && s_io.data_len == 0);

    /* 1xx then the final response. */
    client_with_request(kHello, 5);
    srv_reset();
    static const char *const nv103[] = { ":status", "103", "link", "</x>" };
    static const char *const nv200[] = { ":status", "200" };
    headers(1, 0, nv103, 2);
    headers(1, 0, nv200, 1);
    data(1, H2_F_END_STREAM, "x", 1);
    rc = feed(0);
    check("informational_then_final", rc == H2C_OK && s_io.n_status == 2 && s_io.status == 200 &&
          s_io.data_len == 1 && s_h.s.closed && s_h.s.close_err == 0);

    /* Trailers after the body: accepted, not reported as headers. */
    client_with_request(kHello, 5);
    srv_reset();
    static const char *const tr[] = { "grpc-status", "0" };
    headers(1, 0, nv200, 1);
    data(1, 0, "ab", 2);
    headers(1, H2_F_END_STREAM, tr, 1);
    rc = feed(2);
    check("trailers_accepted", rc == H2C_OK && s_h.s.closed && s_h.s.close_err == 0 &&
          s_io.hdrs[0] == 0 && s_io.data_len == 2);

    /* The stream callback says stop: no more DATA delivered. */
    client_with_request(kHello, 5);
    srv_reset();
    headers(1, 0, nv200, 1);
    for (int i = 0; i < 5; i++) data(1, 0, "0123456789", 10);
    s_io.stop_after = 2;
    rc = feed(0);
    check("callback_stop", rc == H2C_OK && s_h.s.stop && s_io.data_calls == 2 &&
          s_io.data_len == 20);
}

static void test_padding_priority_continuation(void)
{
    static const char *const nv200[] = { ":status", "200" };
    for (int mode = 0; mode < 3; mode++) {
        client_with_request(kHello, 5);
        srv_reset();
        /* HEADERS with PADDED + PRIORITY, split over two CONTINUATIONs. */
        uint8_t blk[256];
        static const char *const nv[] = { ":status", "200", "x-a", "1", "x-b", "2" };
        size_t bl = block(blk, nv, 3);
        uint8_t p[300];
        size_t o = 0;
        p[o++] = 7;                                     /* pad length */
        p[o++] = 0; p[o++] = 0; p[o++] = 0; p[o++] = 0; p[o++] = 16;  /* priority */
        memcpy(p + o, blk, 4);
        o += 4;
        memset(p + o, 0, 7);
        o += 7;
        frame(H2_HEADERS, H2_F_PADDED | H2_F_PRIORITY, 1, p, o);
        frame(H2_CONTINUATION, 0, 1, blk + 4, 3);
        frame(H2_CONTINUATION, H2_F_END_HEADERS, 1, blk + 7, bl - 7);
        data_padded(1, 0, "abc", 3, 20);
        data_padded(1, 0, "", 0, 0);
        data_padded(1, H2_F_END_STREAM, "de", 2, 255);
        const int rc = feed(mode);
        char nm[64];
        snprintf(nm, sizeof(nm), "padding_priority_continuation_mode%d", mode);
        check(nm, rc == H2C_OK && s_io.status == 200 && strcmp(s_io.hdrs, "x-a: 1\nx-b: 2\n") == 0 &&
                  s_io.data_len == 5 && memcmp(s_io.data, "abcde", 5) == 0 && s_h.s.closed &&
                  s_h.s.close_err == 0);
    }
    /* padding counts against flow control */
    check("padding_flow_controlled", s_h.conn_recv_win == 65535 - (21 + 3) - 1 - (1 + 2 + 255));

    /* Errors */
#define CONN_ERR(name, code, ...) do { \
        client_with_request(kHello, 5); srv_reset(); __VA_ARGS__; \
        int r_ = feed(0); \
        check(name, r_ == H2C_ERR_PROTO && s_h.dead && sent_goaway() == (code)); \
    } while (0)
    uint8_t bad[16] = { 5, 'a', 'b', 'c', 'd' };        /* pad 5 ≥ remaining 4 */
    CONN_ERR("pad_too_long_data", H2_PROTOCOL_ERROR, frame(H2_DATA, H2_F_PADDED, 1, bad, 5));
    CONN_ERR("pad_too_long_headers", H2_PROTOCOL_ERROR, frame(H2_HEADERS, H2_F_PADDED | H2_F_END_HEADERS, 1, bad, 5));
    CONN_ERR("padded_empty_data", H2_FRAME_SIZE_ERROR, frame(H2_DATA, H2_F_PADDED, 1, NULL, 0));
    CONN_ERR("priority_headers_short", H2_FRAME_SIZE_ERROR, frame(H2_HEADERS, H2_F_PRIORITY | H2_F_END_HEADERS, 1, bad, 4));
    uint8_t blk[64];
    size_t bl = block(blk, nv200, 1);
    CONN_ERR("continuation_interrupted", H2_PROTOCOL_ERROR,
             frame(H2_HEADERS, 0, 1, blk, 1); frame(H2_PING, 0, 0, "12345678", 8));
    CONN_ERR("continuation_other_stream", H2_PROTOCOL_ERROR,
             frame(H2_HEADERS, 0, 1, blk, 1); frame(H2_CONTINUATION, H2_F_END_HEADERS, 3, blk + 1, bl - 1));
    CONN_ERR("continuation_without_headers", H2_PROTOCOL_ERROR,
             frame(H2_CONTINUATION, H2_F_END_HEADERS, 1, blk, bl));
    CONN_ERR("continuation_limit_8", H2_ENHANCE_YOUR_CALM,
             frame(H2_HEADERS, 0, 1, blk, 1);
             for (int i = 0; i < 9; i++) frame(H2_CONTINUATION, 0, 1, NULL, 0));
    /* exactly 8 is fine */
    client_with_request(kHello, 5);
    srv_reset();
    frame(H2_HEADERS, 0, 1, blk, 1);
    for (int i = 0; i < 7; i++) frame(H2_CONTINUATION, 0, 1, NULL, 0);
    frame(H2_CONTINUATION, H2_F_END_HEADERS | 0, 1, blk + 1, bl - 1);
    int rc = feed(0);
    check("continuation_8_ok", rc == H2C_OK && s_io.status == 200);
}

static void test_flow_control_receive(void)
{
    static const char *const nv200[] = { ":status", "200" };
    static uint8_t chunk[16384];
    for (size_t i = 0; i < sizeof(chunk); i++) chunk[i] = (uint8_t)(i * 31);
    /* A long stream: 300 KiB in 16 KiB frames, as the server may send a
     * run of netmaps; the server's window only stays open through our
     * WINDOW_UPDATEs, so model it: never send past what we granted. */
    client_with_request(kHello, 5);
    int64_t conn_win = 65535, st_win = 65535;
    size_t sent = 0, total = 300 * 1024, granted_seen = 0;
    int rc = H2C_OK, stalls = 0;
    srv_reset();
    headers(1, 0, nv200, 1);
    rc = feed(2);
    while (rc == H2C_OK && sent < total) {
        /* credit from WINDOW_UPDATEs the client sent so far */
        frm_t f[4096];
        int n = out_frames(f, 4096);
        size_t seen = 0;
        int64_t cg = 0, sg = 0;
        for (int i = 0; i < n; i++) {
            if (f[i].type != H2_WINDOW_UPDATE) continue;
            if (seen++ < granted_seen) continue;
            if (f[i].sid == 0) cg += be32(f[i].p); else sg += be32(f[i].p);
        }
        granted_seen = seen;
        conn_win += cg;
        st_win += sg;
        int64_t room = conn_win < st_win ? conn_win : st_win;
        if (room <= 0) { stalls++; break; }
        size_t n2 = total - sent;
        if (n2 > sizeof(chunk)) n2 = sizeof(chunk);
        if ((int64_t)n2 > room) n2 = (size_t)room;
        srv_reset();
        data(1, sent + n2 == total ? H2_F_END_STREAM : 0, chunk, n2);
        conn_win -= (int64_t)n2;
        st_win -= (int64_t)n2;
        sent += n2;
        rc = feed(2);
    }
    check("long_stream_never_stalls_300k", rc == H2C_OK && stalls == 0 && s_io.data_len == total &&
          s_h.s.closed && s_h.s.close_err == 0);
    /* nghttp2's rule: WINDOW_UPDATE once ≥ 32 767 B are consumed, for the
     * consumed amount; none for the stream on the END_STREAM frame. */
    frm_t f[4096];
    int n = out_frames(f, 4096);
    int bad = 0;
    for (int i = 0; i < n; i++)
        if (f[i].type == H2_WINDOW_UPDATE && be32(f[i].p) < 32767) bad++;
    check("window_updates_at_half_window", bad == 0 && wu_sum(0) >= total - 32767 &&
          wu_sum(0) <= total && wu_sum(1) <= total);

    /* END_STREAM frame crossing the threshold: the connection window is
     * given back, the stream's is not (nghttp2: last chunk). */
    client_with_request(kHello, 5);
    srv_reset();
    headers(1, 0, nv200, 1);
    data(1, 0, chunk, 16384);
    data(1, H2_F_END_STREAM, chunk, 16384);
    rc = feed(0);
    check("no_stream_window_update_on_end_stream", rc == H2C_OK && s_h.s.closed &&
          wu_sum(0) == 32768 && wu_sum(1) == 0);
    client_with_request(kHello, 5);
    srv_reset();
    headers(1, 0, nv200, 1);
    data(1, 0, chunk, 16384);
    data(1, 0, chunk, 16384);
    rc = feed(0);
    check("stream_window_update_mid_stream", rc == H2C_OK && wu_sum(0) == 32768 &&
          wu_sum(1) == 32768);

    /* Strict: connection window 0 left, then one more byte. */
    client_with_request(kHello, 5);
    s_h.conn_recv_win = 10;
    srv_reset();
    headers(1, 0, nv200, 1);
    data(1, 0, chunk, 11);
    rc = feed(0);
    check("conn_window_exceeded", rc == H2C_ERR_PROTO && sent_goaway() == H2_FLOW_CONTROL_ERROR);
    client_with_request(kHello, 5);
    s_h.s.recv_win = 10;
    srv_reset();
    headers(1, 0, nv200, 1);
    data(1, 0, chunk, 11);
    data(1, 0, chunk, 3);
    rc = feed(0);
    check("stream_window_exceeded_rst", rc == H2C_OK && sent_rst(1) == H2_FLOW_CONTROL_ERROR &&
          s_h.s.closed && s_h.s.close_err == H2_FLOW_CONTROL_ERROR && s_io.data_len == 0);
}

static void test_flow_control_send(void)
{
    static uint8_t body[3000];
    for (size_t i = 0; i < sizeof(body); i++) body[i] = (uint8_t)('a' + i % 26);
    static const h2_field_t req[] = { { ":method", "POST" }, { ":path", "/x" } };

    /* Server window 10 (SETTINGS before the request), connection open. */
    io_reset();
    h2c_init(&s_h, &s_io);
    h2c_start(&s_h);
    srv_reset();
    static const uint16_t ids[] = { H2_SET_INITIAL_WINDOW_SIZE };
    static const uint32_t ten[] = { 10 };
    settings(1, ids, ten);
    feed(0);
    s_io.out_len = 0;
    int rc = h2c_request(&s_h, req, 2, body, sizeof(body));
    frm_t f[512];
    int n = out_frames(f, 512);
    check("send_window_10", rc == H2C_OK && n == 2 && f[1].type == H2_DATA && f[1].len == 10 &&
          f[1].flags == 0 && s_h.s.send_win == 0);
    /* Grant in steps; the body continues, END_STREAM on the last byte. */
    size_t got = 10;
    int steps = 0;
    while (!s_h.s.local_end && steps < 100) {
        srv_reset();
        frame_u32(H2_WINDOW_UPDATE, 1, 700);
        s_io.out_len = 0;
        rc = feed(0);
        n = out_frames(f, 512);
        for (int i = 0; i < n; i++) if (f[i].type == H2_DATA) got += f[i].len;
        steps++;
    }
    check("send_window_updates_resume_body", rc == H2C_OK && got == sizeof(body) &&
          s_h.s.local_end && steps == 5);

    /* SETTINGS lowers the window under what was already sent: negative,
     * no DATA until the updates bring it above zero. */
    io_reset();
    h2c_init(&s_h, &s_io);
    h2c_start(&s_h);
    srv_reset();
    static const uint32_t w100[] = { 100 };
    settings(1, ids, w100);
    feed(0);
    rc = h2c_request(&s_h, req, 2, body, sizeof(body));       /* 100 sent */
    srv_reset();
    static const uint32_t w0[] = { 0 };
    settings(1, ids, w0);                                      /* window -100 */
    frame_u32(H2_WINDOW_UPDATE, 1, 60);                        /* -40 */
    s_io.out_len = 0;
    rc = feed(0);
    int data_after = 0;
    n = out_frames(f, 512);
    for (int i = 0; i < n; i++) if (f[i].type == H2_DATA) data_after++;
    check("send_window_negative_holds", rc == H2C_OK && s_h.s.send_win == -40 && data_after == 0);
    srv_reset();
    frame_u32(H2_WINDOW_UPDATE, 1, 50);                        /* +10 */
    s_io.out_len = 0;
    rc = feed(0);
    n = out_frames(f, 512);
    check("send_window_back_positive", rc == H2C_OK && n >= 1 && f[n - 1].type == H2_DATA &&
          f[n - 1].len == 10);

    /* Window 0 before the request: HEADERS only, DATA after an update. */
    io_reset();
    h2c_init(&s_h, &s_io);
    h2c_start(&s_h);
    srv_reset();
    static const uint32_t z0[] = { 0 };
    settings(1, ids, z0);
    feed(0);
    s_io.out_len = 0;
    rc = h2c_request(&s_h, req, 2, body, 5);
    n = out_frames(f, 512);
    check("send_window_0_headers_only", rc == H2C_OK && n == 1 && f[0].type == H2_HEADERS);
    srv_reset();
    frame_u32(H2_WINDOW_UPDATE, 1, 5);
    s_io.out_len = 0;
    rc = feed(0);
    n = out_frames(f, 512);
    check("send_window_0_then_update", rc == H2C_OK && n >= 1 && f[n - 1].type == H2_DATA &&
          f[n - 1].len == 5 && (f[n - 1].flags & H2_F_END_STREAM));

    /* Connection window is the limit too. */
    io_reset();
    h2c_init(&s_h, &s_io);
    h2c_start(&s_h);
    s_h.conn_send_win = 7;
    rc = h2c_request(&s_h, req, 2, body, sizeof(body));
    n = out_frames(f, 512);
    check("send_conn_window_limit", rc == H2C_OK && f[n - 1].type == H2_DATA && f[n - 1].len == 7);

    /* A small tx buffer: the body is spread over several sends. */
    io_reset();
    s_io.tx_cap = 200;
    h2c_init(&s_h, &s_io);
    h2c_start(&s_h);
    rc = h2c_request(&s_h, req, 2, body, sizeof(body));
    n = out_frames(f, 512);
    size_t total = 0;
    int frames = 0;
    for (int i = 0; i < n; i++) if (f[i].type == H2_DATA) { total += f[i].len; frames++; }
    check("send_small_tx_buffer", rc == H2C_OK && total == sizeof(body) && frames > 10 &&
          s_h.s.local_end);

    /* Window update overflow / zero increment. */
#define CONN_ERR2(name, code, ...) do { \
        client_with_request(kHello, 5); srv_reset(); __VA_ARGS__; \
        int r_ = feed(0); \
        check(name, r_ == H2C_ERR_PROTO && sent_goaway() == (code)); \
    } while (0)
    CONN_ERR2("wu_conn_zero", H2_PROTOCOL_ERROR, frame_u32(H2_WINDOW_UPDATE, 0, 0));
    CONN_ERR2("wu_conn_overflow", H2_FLOW_CONTROL_ERROR, frame_u32(H2_WINDOW_UPDATE, 0, 0x7fffffff));
    CONN_ERR2("wu_idle_stream", H2_PROTOCOL_ERROR, frame_u32(H2_WINDOW_UPDATE, 5, 1));
    CONN_ERR2("wu_bad_length", H2_FRAME_SIZE_ERROR, frame(H2_WINDOW_UPDATE, 0, 0, "abc", 3));
    CONN_ERR2("settings_window_too_big", H2_FLOW_CONTROL_ERROR,
              { static const uint16_t i_[] = { H2_SET_INITIAL_WINDOW_SIZE };
                static const uint32_t v_[] = { 0x80000000u }; settings(1, i_, v_); });
    client_with_request(kHello, 5);
    srv_reset();
    frame_u32(H2_WINDOW_UPDATE, 1, 0);
    rc = feed(0);
    check("wu_stream_zero_rst", rc == H2C_OK && sent_rst(1) == H2_PROTOCOL_ERROR && s_h.s.closed);
    client_with_request(kHello, 5);
    srv_reset();
    frame_u32(H2_WINDOW_UPDATE, 1, 0x7fffffff);
    rc = feed(0);
    check("wu_stream_overflow_rst", rc == H2C_OK && sent_rst(1) == H2_FLOW_CONTROL_ERROR);
}

static void test_ping_goaway_rst(void)
{
    static const char *const nv200[] = { ":status", "200" };
    client_with_request(kHello, 5);
    srv_reset();
    frame(H2_PING, 0, 0, "\x01\x02\x03\x04\x05\x06\x07\x08", 8);
    frame(H2_PING, H2_F_ACK, 0, "zzzzzzzz", 8);
    for (int i = 0; i < 9; i++) frame(H2_PING, 0, 0, "abcdefgh", 8);   /* > ctl staging */
    int rc = feed(1);
    frm_t f[64];
    int n = out_frames(f, 64), acks = 0, first_ok = 0;
    for (int i = 0; i < n; i++) {
        if (f[i].type == H2_PING && f[i].flags == H2_F_ACK) {
            if (acks == 0) first_ok = memcmp(f[i].p, "\x01\x02\x03\x04\x05\x06\x07\x08", 8) == 0;
            acks++;
        }
    }
    check("ping_acked_each", rc == H2C_OK && acks == 10 && first_ok);
#define CONN_ERR3(name, code, ...) do { \
        client_with_request(kHello, 5); srv_reset(); __VA_ARGS__; \
        int r_ = feed(0); \
        check(name, r_ == H2C_ERR_PROTO && sent_goaway() == (code)); \
    } while (0)
    CONN_ERR3("ping_on_stream", H2_PROTOCOL_ERROR, frame(H2_PING, 0, 1, "abcdefgh", 8));
    CONN_ERR3("ping_bad_length", H2_FRAME_SIZE_ERROR, frame(H2_PING, 0, 0, "abc", 3));

    /* GOAWAY keeping our stream (last = 1): reported, stream stays. */
    client_with_request(kHello, 5);
    srv_reset();
    uint8_t ga[16] = { 0, 0, 0, 1, 0, 0, 0, 0, 'b', 'y', 'e' };
    frame(H2_GOAWAY, 0, 0, ga, 11);
    rc = feed(2);
    check("goaway_keeps_lower_stream", rc == H2C_OK && s_io.goaways == 1 && s_io.goaway_last == 1 &&
          s_h.goaway && s_h.s.open);
    /* ... the response still completes on it */
    srv_reset();
    headers(1, H2_F_END_STREAM, nv200, 1);
    rc = feed(0);
    check("goaway_stream_completes", rc == H2C_OK && s_h.s.closed && s_h.s.close_err == 0);
    static const h2_field_t req[] = { { ":method", "POST" }, { ":path", "/x" } };
    check("goaway_refuses_new_request", h2c_request(&s_h, req, 2, NULL, 0) == H2C_ERR_STATE);

    /* GOAWAY below our stream (last = 0): refused, no RST sent. */
    client_with_request(kHello, 5);
    srv_reset();
    uint8_t g0[8] = { 0, 0, 0, 0, 0, 0, 0, 2 };
    frame(H2_GOAWAY, 0, 0, g0, 8);
    s_io.out_len = 0;
    rc = feed(0);
    check("goaway_refuses_stream", rc == H2C_OK && s_h.s.closed &&
          s_h.s.close_err == H2_REFUSED_STREAM && s_io.goaway_err == 2 && sent_rst(1) < 0);
    /* Go's graceful shutdown: 2^31-1 first, then the real last stream. */
    client_with_request(kHello, 5);
    srv_reset();
    uint8_t gmax[8] = { 0x7f, 0xff, 0xff, 0xff, 0, 0, 0, 0 };
    uint8_t g1[8] = { 0, 0, 0, 1, 0, 0, 0, 0 };
    frame(H2_GOAWAY, 0, 0, gmax, 8);
    frame(H2_PING, 0, 0, "graceful", 8);
    frame(H2_GOAWAY, 0, 0, g1, 8);
    rc = feed(1);
    check("goaway_graceful_two_step", rc == H2C_OK && s_io.goaways == 2 && s_io.goaway_last == 1 &&
          s_h.s.open);
    CONN_ERR3("goaway_last_increases", H2_PROTOCOL_ERROR,
              frame(H2_GOAWAY, 0, 0, g0, 8); frame(H2_GOAWAY, 0, 0, g1, 8));
    uint8_t geven[8] = { 0, 0, 0, 2, 0, 0, 0, 0 };
    CONN_ERR3("goaway_even_last_stream", H2_PROTOCOL_ERROR, frame(H2_GOAWAY, 0, 0, geven, 8));
    CONN_ERR3("goaway_short", H2_FRAME_SIZE_ERROR, frame(H2_GOAWAY, 0, 0, g0, 7));
    CONN_ERR3("goaway_on_stream", H2_PROTOCOL_ERROR, frame(H2_GOAWAY, 0, 1, g0, 8));

    /* RST_STREAM from the server, before and after the response. */
    client_with_request(kHello, 5);
    srv_reset();
    frame_u32(H2_RST_STREAM, 1, H2_INTERNAL_ERROR);
    rc = feed(0);
    check("rst_before_headers", rc == H2C_OK && s_h.s.closed &&
          s_h.s.close_err == H2_INTERNAL_ERROR && s_io.status == 0);
    client_with_request(kHello, 5);
    srv_reset();
    headers(1, 0, nv200, 1);
    data(1, 0, "partial", 7);
    frame_u32(H2_RST_STREAM, 1, H2_CANCEL);
    data(1, 0, "late", 4);                    /* stream closed: ignored */
    rc = feed(2);
    check("rst_mid_body", rc == H2C_OK && s_io.status == 200 && s_h.s.close_err == H2_CANCEL &&
          s_io.data_len == 7);
    CONN_ERR3("rst_idle_stream", H2_PROTOCOL_ERROR, frame_u32(H2_RST_STREAM, 3, 0));
    CONN_ERR3("rst_stream0", H2_PROTOCOL_ERROR, frame_u32(H2_RST_STREAM, 0, 0));
    CONN_ERR3("rst_bad_length", H2_FRAME_SIZE_ERROR, frame(H2_RST_STREAM, 0, 1, "abcde", 5));
}

static void test_response_checks(void)
{
    /* Malformed responses: RST_STREAM PROTOCOL_ERROR, stream closed with
     * it (nghttp2's HTTP messaging rules). */
#define STREAM_ERR(name, want_status, ...) do { \
        client_with_request(kHello, 5); srv_reset(); __VA_ARGS__; \
        int r_ = feed(0); \
        check(name, r_ == H2C_OK && sent_rst(1) == H2_PROTOCOL_ERROR && s_h.s.closed && \
                    s_h.s.close_err == H2_PROTOCOL_ERROR && s_io.status == (want_status) && \
                    !s_h.dead); \
    } while (0)
    static const char *const nv_nostatus[] = { "content-type", "x" };
    static const char *const nv_st2[] = { ":status", "20" };
    static const char *const nv_stabc[] = { ":status", "abc" };
    static const char *const nv_101[] = { ":status", "101" };
    static const char *const nv_dup[] = { ":status", "200", ":status", "204" };
    static const char *const nv_late[] = { ":status", "200", "x", "1", ":status", "200" };
    static const char *const nv_pseudo[] = { ":status", "200", ":path", "/" };
    static const char *const nv_upper[] = { ":status", "200", "X-Up", "1" };
    static const char *const nv_conn[] = { ":status", "200", "connection", "close" };
    static const char *const nv_te[] = { ":status", "200", "te", "gzip" };
    static const char *const nv_cl[] = { ":status", "200", "content-length", "3" };
    static const char *const nv_cl2[] = { ":status", "200", "content-length", "3", "content-length", "3" };
    static const char *const nv_clbad[] = { ":status", "200", "content-length", "3x" };
    static const char *const nv_204[] = { ":status", "204", "content-length", "5" };
    static const char *const nv_304[] = { ":status", "304" };
    static const char *const nv_103[] = { ":status", "103" };
    static const char *const nv200[] = { ":status", "200" };
    static const char *const nv_trp[] = { ":status", "200" };
    STREAM_ERR("resp_no_status", 0, headers(1, 0, nv_nostatus, 1));
    STREAM_ERR("resp_status_2_digits", 0, headers(1, 0, nv_st2, 1));
    STREAM_ERR("resp_status_not_digits", 0, headers(1, 0, nv_stabc, 1));
    STREAM_ERR("resp_status_101", 0, headers(1, 0, nv_101, 1));
    STREAM_ERR("resp_status_twice", 200, headers(1, 0, nv_dup, 2));
    STREAM_ERR("resp_pseudo_after_regular", 200, headers(1, 0, nv_late, 3));
    STREAM_ERR("resp_request_pseudo", 200, headers(1, 0, nv_pseudo, 2));
    static const char *const nv_after[] = { "x", "1", ":status", "200" };
    STREAM_ERR("resp_status_after_regular", 0, headers(1, 0, nv_after, 2));
    STREAM_ERR("resp_uppercase_name", 200, headers(1, 0, nv_upper, 2));
    STREAM_ERR("resp_connection_header", 200, headers(1, 0, nv_conn, 2));
    STREAM_ERR("resp_te_not_trailers", 200, headers(1, 0, nv_te, 2));
    STREAM_ERR("resp_content_length_twice", 200, headers(1, 0, nv_cl2, 3));
    STREAM_ERR("resp_content_length_junk", 200, headers(1, 0, nv_clbad, 2));
    STREAM_ERR("resp_204_with_body_length", 204, headers(1, 0, nv_204, 2));
    STREAM_ERR("resp_data_before_headers", 0, data(1, 0, "x", 1));
    STREAM_ERR("resp_content_length_short", 200,
               headers(1, 0, nv_cl, 2); data(1, H2_F_END_STREAM, "ab", 2));
    STREAM_ERR("resp_304_with_data", 304, headers(1, 0, nv_304, 1); data(1, 0, "x", 1));
    STREAM_ERR("resp_1xx_end_stream", 103, headers(1, H2_F_END_STREAM, nv_103, 1));
    STREAM_ERR("resp_trailers_without_end_stream", 200,
               headers(1, 0, nv200, 1); headers(1, 0, nv_trp + 0, 0));
    STREAM_ERR("resp_pseudo_in_trailers", 200,
               headers(1, 0, nv200, 1); headers(1, H2_F_END_STREAM, nv_trp, 1));
    /* DATA past content-length: not delivered. */
    client_with_request(kHello, 5);
    srv_reset();
    headers(1, 0, nv_cl, 2);
    data(1, 0, "abcd", 4);
    int rc = feed(0);
    check("resp_data_past_content_length", rc == H2C_OK && sent_rst(1) == H2_PROTOCOL_ERROR &&
          s_io.data_len == 0);
    /* Dropped, not fatal: an invalid regular field. */
    static const char *const nv_odd[] = { ":status", "200", "bad name", "1", "v", " lead",
                                          "ok", "fine" };
    client_with_request(kHello, 5);
    srv_reset();
    headers(1, H2_F_END_STREAM, nv_odd, 4);
    rc = feed(0);
    check("resp_invalid_regular_dropped", rc == H2C_OK && s_h.s.close_err == 0 &&
          strcmp(s_io.hdrs, "ok: fine\n") == 0);
    /* 204 with content-length: 0 — tolerated, dropped. */
    static const char *const nv_2040[] = { ":status", "204", "content-length", "0" };
    client_with_request(kHello, 5);
    srv_reset();
    headers(1, H2_F_END_STREAM, nv_2040, 2);
    rc = feed(0);
    check("resp_204_content_length_0", rc == H2C_OK && s_h.s.close_err == 0 && s_io.hdrs[0] == 0);
    /* An exact content-length. */
    client_with_request(kHello, 5);
    srv_reset();
    headers(1, 0, nv_cl, 2);
    data(1, 0, "ab", 2);
    data(1, H2_F_END_STREAM, "c", 1);
    rc = feed(1);
    check("resp_content_length_exact", rc == H2C_OK && s_h.s.close_err == 0 && s_io.data_len == 3);
}

static void test_connection_errors(void)
{
#define CONN_ERR4(name, code, ...) do { \
        client_with_request(kHello, 5); srv_reset(); __VA_ARGS__; \
        int r_ = feed(0); \
        check(name, r_ == H2C_ERR_PROTO && s_h.dead && sent_goaway() == (code) && \
                    h2c_feed(&s_h, (const uint8_t *)"x", 1) == H2C_ERR_STATE); \
    } while (0)
    static uint8_t big[16385];
    static const char *const nv200[] = { ":status", "200" };
    CONN_ERR4("frame_too_big", H2_FRAME_SIZE_ERROR, data(1, 0, big, sizeof(big)));
    CONN_ERR4("push_promise", H2_PROTOCOL_ERROR, frame(H2_PUSH_PROMISE, H2_F_END_HEADERS, 1, "\0\0\0\2", 4));
    CONN_ERR4("headers_stream0", H2_PROTOCOL_ERROR, headers(0, 0, nv200, 1));
    CONN_ERR4("headers_even_stream", H2_PROTOCOL_ERROR, headers(2, 0, nv200, 1));
    CONN_ERR4("headers_idle_stream", H2_PROTOCOL_ERROR, headers(5, 0, nv200, 1));
    CONN_ERR4("data_stream0", H2_PROTOCOL_ERROR, data(0, 0, "x", 1));
    CONN_ERR4("data_idle_stream", H2_PROTOCOL_ERROR, data(3, 0, "x", 1));
    CONN_ERR4("priority_bad_length", H2_FRAME_SIZE_ERROR, frame(H2_PRIORITY, 0, 1, "abcd", 4));
    CONN_ERR4("priority_stream0", H2_PROTOCOL_ERROR, frame(H2_PRIORITY, 0, 0, "abcde", 5));
    CONN_ERR4("settings_on_stream", H2_PROTOCOL_ERROR, frame(H2_SETTINGS, 0, 1, NULL, 0));
    CONN_ERR4("settings_bad_length", H2_FRAME_SIZE_ERROR, frame(H2_SETTINGS, 0, 0, "abcde", 5));
    CONN_ERR4("settings_ack_payload", H2_FRAME_SIZE_ERROR, frame(H2_SETTINGS, H2_F_ACK, 0, "abcdef", 6));
    CONN_ERR4("settings_unexpected_ack", H2_PROTOCOL_ERROR,
              frame(H2_SETTINGS, H2_F_ACK, 0, NULL, 0); frame(H2_SETTINGS, H2_F_ACK, 0, NULL, 0));
    { static const uint16_t i_[] = { H2_SET_ENABLE_PUSH }; static const uint32_t v_[] = { 1 };
      CONN_ERR4("settings_enable_push_1", H2_PROTOCOL_ERROR, settings(1, i_, v_)); }
    { static const uint16_t i_[] = { H2_SET_MAX_FRAME_SIZE }; static const uint32_t v_[] = { 16383 };
      CONN_ERR4("settings_max_frame_small", H2_PROTOCOL_ERROR, settings(1, i_, v_)); }
    { static const uint16_t i_[] = { H2_SET_MAX_FRAME_SIZE }; static const uint32_t v_[] = { 0x1000000 };
      CONN_ERR4("settings_max_frame_big", H2_PROTOCOL_ERROR, settings(1, i_, v_)); }
    { static const uint16_t i_[] = { H2_SET_ENABLE_CONNECT_PROTOCOL, H2_SET_ENABLE_CONNECT_PROTOCOL };
      static const uint32_t v_[] = { 1, 0 };
      CONN_ERR4("settings_connect_protocol_back_to_0", H2_PROTOCOL_ERROR, settings(2, i_, v_)); }
    /* HPACK failures are COMPRESSION_ERROR. */
    CONN_ERR4("hpack_dynamic_reference", H2_COMPRESSION_ERROR,
              frame(H2_HEADERS, H2_F_END_HEADERS, 1, "\xbe", 1));
    CONN_ERR4("hpack_size_update_above_0", H2_COMPRESSION_ERROR,
              frame(H2_HEADERS, H2_F_END_HEADERS, 1, "\x21\x88", 2));
    CONN_ERR4("hpack_block_cut", H2_COMPRESSION_ERROR,
              frame(H2_HEADERS, H2_F_END_HEADERS, 1, "\x00\x05" "ab", 4));
    /* ...also on a stream we no longer track (the table must stay in sync). */
    CONN_ERR4("hpack_error_on_closed_stream", H2_COMPRESSION_ERROR,
              frame_u32(H2_RST_STREAM, 1, 0); frame(H2_HEADERS, H2_F_END_HEADERS, 1, "\x80", 1));

    /* Not errors: unknown frame type, unknown setting, PRIORITY. */
    client_with_request(kHello, 5);
    srv_reset();
    frame(0xfa, 0xff, 1, "whatever", 8);
    frame(0x0b, 0, 0, NULL, 0);
    { static const uint16_t i_[] = { 0x4242 }; static const uint32_t v_[] = { 9 }; settings(1, i_, v_); }
    frame(H2_PRIORITY, 0, 7, "abcde", 5);
    headers(1, H2_F_END_STREAM, nv200, 1);
    int rc = feed(1);
    check("unknown_frames_settings_ignored", rc == H2C_OK && s_h.s.closed && s_h.s.close_err == 0);

    /* A send failing mid-feed. */
    client_with_request(kHello, 5);
    s_io.fail_send = s_io.sends + 1;
    srv_reset();
    frame(H2_PING, 0, 0, "abcdefgh", 8);
    rc = feed(0);
    check("send_failure_reported", rc == H2C_ERR_IO && s_h.dead);
}

/* ---- fuzz ------------------------------------------------------------------- */

/* ---- the side stream (round 1.3.7, B1) ------------------------------------ */

static const h2_field_t kPushHdrs[] = {
    { ":method", "POST" }, { ":scheme", "https" }, { ":path", "/machine/map" },
    { ":authority", "controlplane.tailscale.com" },
    { "content-type", "application/json" }, { "content-length", "4" },
};
static const h2_field_t kMapHdrs[] = {
    { ":method", "POST" }, { ":scheme", "https" }, { ":path", "/machine/map" },
    { ":authority", "controlplane.tailscale.com" },
    { "content-type", "application/json" }, { "content-length", "5" },
};

/* A started client with the push (stream 1, "push") opened ahead of the
 * map stream (stream 3, "hello") in one burst. */
static int client_with_pair(void)
{
    io_reset();
    h2c_init(&s_h, &s_io);
    (void)h2c_start(&s_h);
    s_io.out_len = 0;
    s_io.sends = 0;
    const h2_req_t side = { kPushHdrs, 6, (const uint8_t *)"push", 4 };
    const h2_req_t req = { kMapHdrs, 6, kHello, 5 };
    return h2c_request_pair(&s_h, &side, &req);
}

static void test_side_stream(void)
{
    /* The burst: one send, side first on the lower ID, both bodies whole. */
    int rc = client_with_pair();
    frm_t f[8];
    int n = out_frames(f, 8);
    check("pair_one_record_four_frames", rc == H2C_OK && s_io.sends == 1 && n == 4);
    check("pair_side_first_stream1",
          f[0].type == H2_HEADERS && f[0].sid == 1 && f[0].p[0] == 0x20 &&
          f[1].type == H2_DATA && f[1].sid == 1 && f[1].flags == H2_F_END_STREAM &&
          f[1].len == 4 && memcmp(f[1].p, "push", 4) == 0);
    check("pair_main_second_stream3_no_size_update",
          f[2].type == H2_HEADERS && f[2].sid == 3 && f[2].p[0] == 0x02 &&
          f[3].type == H2_DATA && f[3].sid == 3 && f[3].flags == H2_F_END_STREAM &&
          f[3].len == 5 && memcmp(f[3].p, "hello", 5) == 0);
    check("pair_state", s_h.side.open && s_h.side.local_end && s_h.s.open &&
          s_h.s.local_end && s_h.next_id == 5 && s_h.last_id == 3);
    check("pair_refused_while_side_open",
          h2c_request_pair(&s_h, &(h2_req_t){ kPushHdrs, 6, NULL, 0 },
                           &(h2_req_t){ kMapHdrs, 6, NULL, 0 }) == H2C_ERR_STATE);

    /* Side answered first (429 + Retry-After, a body), then the stream:
     * the hooks see the main stream only, at every split. */
    for (int mode = 0; mode < 3; mode++) {
        (void)client_with_pair();
        srv_reset();
        static const char *const s429[] = { ":status", "429", "retry-after", "60",
                                            "content-length", "11" };
        headers(1, 0, s429, 3);
        data(1, H2_F_END_STREAM, "slow down\r\n", 11);
        static const char *const ok[] = { ":status", "200", "x-main", "1" };
        headers(3, 0, ok, 2);
        data(3, 0, "abc", 3);
        const int r = feed(mode);
        char nm[64];
        snprintf(nm, sizeof(nm), "side_first_hooks_main_only_mode%d", mode);
        check(nm, r == H2C_OK && s_io.n_status == 1 && s_io.status == 200 &&
                  strcmp(s_io.hdrs, "x-main: 1\n") == 0 && s_io.data_len == 3 &&
                  memcmp(s_io.data, "abc", 3) == 0 && s_h.s.open && !s_h.s.closed);
        snprintf(nm, sizeof(nm), "side_first_status_kept_mode%d", mode);
        check(nm, s_h.side.closed && !s_h.side.open && s_h.side.final &&
                  s_h.side.status == 429 && s_h.side.close_err == 0 &&
                  s_h.side.recv_len == 11);
    }

    /* Interleaved: the stream's DATA before, around and after the side's
     * answer; the side's DATA never reaches on_data. */
    for (int mode = 0; mode < 3; mode++) {
        (void)client_with_pair();
        srv_reset();
        static const char *const ok[] = { ":status", "200" };
        headers(3, 0, ok, 1);
        data(3, 0, "one-", 4);
        headers(1, 0, ok, 1);
        data(3, 0, "two-", 4);
        data(1, 0, "{}", 2);
        data(3, 0, "three", 5);
        data(1, H2_F_END_STREAM, NULL, 0);
        data(3, 0, "-four", 5);
        const int r = feed(mode);
        char nm[64];
        snprintf(nm, sizeof(nm), "interleaved_main_bytes_exact_mode%d", mode);
        check(nm, r == H2C_OK && s_io.data_len == 18 &&
                  memcmp(s_io.data, "one-two-three-four", 18) == 0 && s_io.n_status == 1);
        snprintf(nm, sizeof(nm), "interleaved_side_closed_200_mode%d", mode);
        check(nm, s_h.side.closed && s_h.side.status == 200 && s_h.side.recv_len == 2 &&
                  s_h.s.open && s_io.tx_buf_in_feed == 0);
    }

    /* Stream ends first, side still open; then its late answer. */
    (void)client_with_pair();
    srv_reset();
    static const char *const ok1[] = { ":status", "200" };
    headers(3, H2_F_END_STREAM, ok1, 1);
    rc = feed(0);
    check("main_closes_side_stays_open", rc == H2C_OK && s_h.s.closed && s_h.side.open &&
          !s_h.side.closed);
    srv_reset();
    headers(1, H2_F_END_STREAM, ok1, 1);
    rc = feed(1);
    check("side_late_answer_after_main", rc == H2C_OK && s_h.side.closed &&
          s_h.side.status == 200 && s_io.n_status == 1);

    /* RST_STREAM on the side: closed with the code, main untouched. */
    (void)client_with_pair();
    srv_reset();
    frame_u32(H2_RST_STREAM, 1, H2_REFUSED_STREAM);
    headers(3, 0, ok1, 1);
    rc = feed(2);
    check("side_rst_closed_with_code", rc == H2C_OK && s_h.side.closed && !s_h.side.final &&
          s_h.side.close_err == H2_REFUSED_STREAM && s_h.s.open && s_io.status == 200);

    /* A malformed side answer (DATA before HEADERS) is a stream error on
     * the side's ID only. */
    (void)client_with_pair();
    srv_reset();
    data(1, 0, "x", 1);
    headers(3, 0, ok1, 1);
    data(3, 0, "ok", 2);
    rc = feed(1);
    check("side_malformed_rst_side_only",
          rc == H2C_OK && sent_rst(1) == H2_PROTOCOL_ERROR && sent_rst(3) == -1 &&
          s_h.side.closed && s_h.side.close_err == H2_PROTOCOL_ERROR &&
          s_h.s.open && s_io.data_len == 2 && memcmp(s_io.data, "ok", 2) == 0);
    /* … and a content-length the side's body overruns. */
    (void)client_with_pair();
    srv_reset();
    static const char *const cl1[] = { ":status", "200", "content-length", "1" };
    headers(1, 0, cl1, 2);
    data(1, H2_F_END_STREAM, "xy", 2);
    rc = feed(0);
    check("side_content_length_overrun", rc == H2C_OK && sent_rst(1) == H2_PROTOCOL_ERROR &&
          s_h.side.closed && s_h.s.open && s_io.data_len == 0 && s_io.n_status == 0);

    /* GOAWAY: last 1 refuses the main stream only, last 0 both. */
    (void)client_with_pair();
    srv_reset();
    uint8_t ga[8] = { 0, 0, 0, 1, 0, 0, 0, 0 };
    frame(H2_GOAWAY, 0, 0, ga, 8);
    rc = feed(0);
    check("goaway_last1_refuses_main_keeps_side",
          rc == H2C_OK && s_h.s.closed && s_h.s.close_err == H2_REFUSED_STREAM &&
          s_h.side.open);
    (void)client_with_pair();
    srv_reset();
    ga[3] = 0;
    frame(H2_GOAWAY, 0, 0, ga, 8);
    rc = feed(0);
    check("goaway_last0_refuses_both",
          rc == H2C_OK && s_h.s.close_err == H2_REFUSED_STREAM &&
          s_h.side.closed && s_h.side.close_err == H2_REFUSED_STREAM);

    /* INITIAL_WINDOW_SIZE moves both send windows; WINDOW_UPDATE on the
     * side's ID reaches the side; the connection window counts both. */
    (void)client_with_pair();
    srv_reset();
    static const uint16_t iw[] = { H2_SET_INITIAL_WINDOW_SIZE };
    static const uint32_t iv[] = { 1000 };
    settings(1, iw, iv);
    frame_u32(H2_WINDOW_UPDATE, 1, 7);
    rc = feed(0);
    check("settings_window_both_streams",
          rc == H2C_OK && s_h.s.send_win == 1000 - 5 && s_h.side.send_win == 1000 - 4 + 7 &&
          s_h.conn_send_win == 65535 - 9);
    (void)client_with_pair();
    srv_reset();
    headers(1, 0, ok1, 1);
    static uint8_t big[12000];
    for (int i = 0; i < 3; i++) data(1, 0, big, sizeof(big));
    headers(3, 0, ok1, 1);
    data(3, 0, big, 1000);
    rc = feed(0);
    check("receive_window_counts_side_data",
          rc == H2C_OK && wu_sum(0) == 36000 && wu_sum(1) == 36000 && wu_sum(3) == 0 &&
          s_h.conn_consumed == 1000 && s_io.data_len == 1000);

    /* The side does not fit: nothing but the staged control frames goes
     * out, no ID spent, and a plain request still works on stream 1. */
    io_reset();
    h2c_init(&s_h, &s_io);
    (void)h2c_start(&s_h);
    srv_reset();
    static const uint32_t tiny[] = { 3 };
    settings(1, iw, tiny);
    s_io.in_feed = true;
    rc = h2c_feed_staged(&s_h, s_srv, s_srv_len);   /* its ACK stays staged */
    s_io.in_feed = false;
    s_io.out_len = 0;
    s_io.sends = 0;
    const h2_req_t side = { kPushHdrs, 6, (const uint8_t *)"push", 4 };
    const h2_req_t req = { kMapHdrs, 6, kHello, 5 };
    rc = h2c_request_pair(&s_h, &side, &req);
    n = out_frames(f, 8);
    check("side_not_whole_nothing_sent",
          rc == H2C_ERR_SIZE && n == 1 && f[0].type == H2_SETTINGS &&
          (f[0].flags & H2_F_ACK) && s_h.next_id == 1 && s_h.last_id == 0 &&
          !s_h.sent_size_update && !s_h.side.open && !s_h.s.open &&
          s_h.conn_send_win == 65535);
    s_io.out_len = 0;
    rc = h2c_request(&s_h, kMapHdrs, 6, kHello, 5);
    n = out_frames(f, 8);
    check("after_side_refusal_plain_request_stream1",
          rc == H2C_OK && f[0].type == H2_HEADERS && f[0].sid == 1 && f[0].p[0] == 0x20 &&
          f[1].type == H2_DATA && f[1].len == 3);
    /* … and a side body larger than the lent buffer. */
    io_reset();
    h2c_init(&s_h, &s_io);
    (void)h2c_start(&s_h);
    s_io.tx_cap = 512;
    static uint8_t sbody[600];
    rc = h2c_request_pair(&s_h, &(h2_req_t){ kPushHdrs, 6, sbody, sizeof(sbody) }, &req);
    check("side_over_buffer_refused", rc == H2C_ERR_SIZE && s_h.next_id == 1 &&
          !s_h.side.open && !s_h.s.open);

    /* The next pair after both closed: streams 5 and 7. */
    (void)client_with_pair();
    srv_reset();
    headers(1, H2_F_END_STREAM, ok1, 1);
    headers(3, H2_F_END_STREAM, ok1, 1);
    rc = feed(0);
    s_io.out_len = 0;
    rc |= h2c_request_pair(&s_h, &side, &req);
    n = out_frames(f, 8);
    check("second_pair_streams_5_7", rc == H2C_OK && n == 4 && f[0].sid == 5 && f[2].sid == 7);

    /* Fuzz: the two answers' frames interleaved at random, fed at random
     * splits — the main body exact, the side's status kept, nothing of
     * the side in the hooks. */
    static uint8_t mb[20000];
    int bad = 0;
    for (int t = 0; t < 300; t++) {
        (void)client_with_pair();
        srv_reset();
        const size_t mlen = rnd() % sizeof(mb);
        for (size_t i = 0; i < mlen; i++) mb[i] = (uint8_t)rnd();
        const int sst = 200 + (int)(rnd() % 3) * 100;   /* 200 / 300 / 400 */
        char sbuf[4];
        snprintf(sbuf, sizeof(sbuf), "%d", sst);
        const char *sh[] = { ":status", sbuf, "retry-after", "5" };
        static const char *const mh[] = { ":status", "200" };
        bool side_hdr = false, side_end = false, main_hdr = false;
        size_t moff = 0, sdat = 0;
        while (!side_end || moff < mlen || !main_hdr) {
            if (rnd() & 1) {
                if (!side_hdr) { headers(1, 0, sh, 2); side_hdr = true; }
                else if (!side_end && rnd() % 3) { data(1, 0, "zz", 2); sdat += 2; }
                else if (!side_end) { data(1, H2_F_END_STREAM, NULL, 0); side_end = true; }
            } else {
                if (!main_hdr) { headers(3, 0, mh, 1); main_hdr = true; }
                else if (moff < mlen) {
                    size_t k = 1 + rnd() % 2500;
                    if (k > mlen - moff) k = mlen - moff;
                    data(3, 0, mb + moff, k);
                    moff += k;
                }
            }
        }
        rc = feed(2);
        if (rc != H2C_OK || s_io.n_status != 1 || s_io.status != 200 || s_io.data_len != mlen ||
            memcmp(s_io.data, mb, mlen) != 0 || s_io.hdrs[0] != 0 || !s_h.side.closed ||
            s_h.side.status != sst || s_h.side.recv_len != (int64_t)sdat || !s_h.s.open ||
            s_io.tx_buf_in_feed != 0) bad++;
    }
    check("side_interleave_fuzz_300", bad == 0);
}

/* Random but well-formed server transcripts: SETTINGS, PINGs, unknown
 * frames, response HEADERS (padded / prioritised /
 * split over CONTINUATIONs, random fields), DATA with random padding and
 * an exact content-length half the time, trailers sometimes; the
 * transcript is fed at random splits and the body must come out exact. */
static void test_structured_fuzz(void)
{
    static uint8_t body[200000];
    int bad = 0, runs = 0;
    for (int t = 0; t < 400; t++, runs++) {
        client_with_request(kHello, 5);
        srv_reset();
        size_t blen = rnd() % (t < 20 ? sizeof(body) : 3000);
        for (size_t i = 0; i < blen; i++) body[i] = (uint8_t)rnd();
        if (rnd() % 2) {
            static const uint16_t ids[] = { H2_SET_MAX_CONCURRENT_STREAMS, H2_SET_HEADER_TABLE_SIZE };
            static const uint32_t vals[] = { 100, 4096 };
            settings(2, ids, vals);
        }
        if (rnd() % 2) frame(H2_SETTINGS, H2_F_ACK, 0, NULL, 0);
        char clen[16];
        snprintf(clen, sizeof(clen), "%zu", blen);
        const char *nv[12] = { ":status", "200", "content-type", "application/json",
                               "x-r", "abcdefghijklmnopqrstuvwxyz0123456789" };
        int nf = 3;
        if (rnd() % 2) { nv[2 * nf] = "content-length"; nv[2 * nf + 1] = clen; nf++; }
        uint8_t blk[512];
        size_t bl = block(blk, nv, nf);
        /* HEADERS, maybe padded / prioritised, maybe split */
        size_t first = (rnd() % 2) ? bl : rnd() % (bl + 1);
        uint8_t pl[600];
        size_t o = 0;
        uint8_t fl = 0;
        uint8_t pad = (uint8_t)(rnd() % 3 == 0 ? rnd() % 40 : 0);
        if (pad) { fl |= H2_F_PADDED; pl[o++] = pad; }
        if (rnd() % 3 == 0) { fl |= H2_F_PRIORITY; memset(pl + o, 0, 5); o += 5; }
        memcpy(pl + o, blk, first);
        o += first;
        memset(pl + o, 0, pad);
        o += pad;
        frame(H2_HEADERS, fl | (first == bl ? H2_F_END_HEADERS : 0), 1, pl, o);
        for (size_t rest = bl - first, pieces = 0; rest > 0; pieces++) {
            const size_t n = pieces == 6 ? rest : 1 + rnd() % rest;
            frame(H2_CONTINUATION, n == rest ? H2_F_END_HEADERS : 0, 1, blk + (bl - rest), n);
            rest -= n;
        }
        size_t off = 0;
        while (off < blen) {
            if (rnd() % 8 == 0) frame(H2_PING, 0, 0, "fuzzping", 8);
            if (rnd() % 10 == 0) frame(0x42, 0, 1, "x", 1);
            size_t n = 1 + rnd() % 3000;
            if (n > blen - off) n = blen - off;
            uint8_t pd = (uint8_t)(rnd() % 4 == 0 ? rnd() % 64 : 0);
            if (pd) data_padded(1, 0, body + off, n, pd);
            else data(1, 0, body + off, n);
            off += n;
        }
        static const char *const tr[] = { "x-trailer", "1" };
        if (rnd() % 3 == 0) headers(1, H2_F_END_STREAM, tr, 1);
        else data(1, H2_F_END_STREAM, NULL, 0);
        int rc = feed(2);
        if (rc != H2C_OK || s_io.status != 200 || s_io.data_len != blen ||
            memcmp(s_io.data, body, blen) != 0 || !s_h.s.closed || s_h.s.close_err != 0 ||
            s_io.tx_buf_in_feed != 0) {
            if (bad < 3) printf("  run %d: rc %d status %d data %zu/%zu err %u\n", t, rc,
                                s_io.status, s_io.data_len, blen, (unsigned)s_h.s.close_err);
            bad++;
        }
    }
    char nm[64];
    snprintf(nm, sizeof(nm), "structured_fuzz_%d_transcripts", runs);
    check(nm, bad == 0);
}

/* Garbage after a valid start: the parser must neither crash nor leave
 * its invariants; every run ends as OK or a connection error. */
static void test_garbage_fuzz(void)
{
    int outcomes[5] = { 0 };
    for (int t = 0; t < 20000; t++) {
        client_with_request(kHello, 5);
        srv_reset();
        int nframes = 1 + (int)(rnd() % 6);
        for (int i = 0; i < nframes; i++) {
            uint8_t p[200];
            size_t n = rnd() % sizeof(p);
            for (size_t k = 0; k < n; k++) p[k] = (uint8_t)rnd();
            uint8_t type = (uint8_t)(rnd() % 12);
            uint8_t flags = (uint8_t)rnd();
            uint32_t sid = rnd() % 4;
            if (type == H2_HEADERS && (rnd() & 1)) { p[0] = 0x88; flags = H2_F_END_HEADERS; n = n ? n : 1; }
            frame(type, flags, sid, p, n);
        }
        /* and sometimes raw bytes */
        if (rnd() % 4 == 0) {
            size_t n = rnd() % 64;
            for (size_t k = 0; k < n; k++) s_srv[s_srv_len++] = (uint8_t)rnd();
        }
        int rc = feed((int)(rnd() % 3));
        if (rc == H2C_OK) outcomes[0]++;
        else if (rc == H2C_ERR_PROTO) outcomes[1]++;
        else outcomes[2]++;
        if (s_h.s.open && s_h.s.closed) outcomes[3]++;
        if (s_io.tx_buf_in_feed) outcomes[4]++;
    }
    printf("  garbage: %d ok, %d connection errors, %d other\n", outcomes[0], outcomes[1], outcomes[2]);
    check("garbage_fuzz_20000", outcomes[2] == 0 && outcomes[3] == 0 && outcomes[4] == 0 &&
          outcomes[0] > 0 && outcomes[1] > 0);
}

int main(void)
{
    test_preface_and_request_bytes();
    test_response_paths();
    test_padding_priority_continuation();
    test_flow_control_receive();
    test_flow_control_send();
    test_ping_goaway_rst();
    test_response_checks();
    test_connection_errors();
    test_side_stream();
    test_structured_fuzz();
    test_garbage_fuzz();
    if (s_fails == 0) printf("\nALL OK\n");
    return s_fails ? 1 : 0;
}
