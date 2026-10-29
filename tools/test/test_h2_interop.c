// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// HTTP/2 interop (round 1.3.4, D1): tinylink's control-plane requests
// against an independent HTTP/2 server — nghttp2's server side, in
// memory — in the shapes tinylink sends them: POST JSON → 200 + body,
// 429 / 503 + Retry-After, an oversized body (the overflow latch), the
// long-poll stream (MapResponses in many DATA frames, past the 64 KiB
// windows, so WINDOW_UPDATEs must flow), a server PING mid-stream,
// GOAWAY mid-stream and GOAWAY refusing the stream, RST_STREAM before /
// after the headers, register → push → stream on one connection, a tiny
// server window for the request body, padding, a CONTINUATION-sized
// header, trailers, a 1xx, the server closing mid-stream, the stream
// callback stopping, and the server's first bytes left over from the
// connect (D5).
//
// Built twice from this file:
//  - test_h2_interop: the firmware stack — h2_client.c on h2_core.c /
//    hpack.c on ts2021_client.c, records sealed with Noise over a fake
//    esp_tls, the server's output cut into records of random sizes;
//  - test_h2_ref (-DH2_REF): the 1.3.4 nghttp2-based client
//    (ref/h2_134/), over a plaintext ts2021 stand-in.
// Both check the same expectations, so the table below is what nghttp2's
// client did; the two deliberate differences are marked H2_REF (the
// final status after a 1xx; no stream callback after it said stop).
//
// TL_H2_WIRE=1 prints every client record (the wire comparison).

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nghttp2/nghttp2.h>

#include "h2_client.h"
#include "ts2021_client.h"

#ifdef H2_REF
#define PFX "ref_"
#else
#define PFX "interop_"
#endif

static int s_fails;

static void check(const char *name, int ok)
{
    printf("[" PFX "%s] %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) s_fails++;
}

static uint32_t s_rng = 0x5eed1234u;
static uint32_t rnd(void)
{
    s_rng ^= s_rng << 13; s_rng ^= s_rng >> 17; s_rng ^= s_rng << 5;
    return s_rng;
}

bool tl_time_synced(void) { return false; }

static bool s_wire;
static int  s_rec_no;

static void wire(const char *dir, const uint8_t *p, size_t n)
{
    if (!s_wire) return;
    printf("  %s record %d (%zu B): ", dir, s_rec_no++, n);
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

/* ---- the nghttp2 server ------------------------------------------------- */

enum {
    SC_OK, SC_429, SC_503_DATE, SC_BIG, SC_STREAM, SC_PING, SC_GOAWAY_MID,
    SC_GOAWAY_REFUSE, SC_RST_AFTER_HEADERS, SC_RST_BEFORE, SC_PADDING,
    SC_BIG_HEADER, SC_TRAILERS, SC_1XX, SC_EOF_MID, SC_HEADERS_ONLY,
};

typedef struct {
    nghttp2_session *ng;
    int      sc;                 /* response scenario for the next request */
    int      nreq;
    int32_t  sid[8];
    char     path[8][48];
    char     hdrs[8][512];
    uint8_t  body[8][4096];
    size_t   body_len[8];
    uint8_t  resp[400 * 1024];
    size_t   resp_len, resp_off;
    size_t   chunk;              /* max DATA chunk (random 1..chunk), 0 = any */
    size_t   pause_at;           /* data provider defers here once */
    bool     paused, acted;
    bool     hold;               /* data provider defers forever */
    bool     eof;
    int      ping_acks;
    int      data_frames;
    int      padded_frames;
    int32_t  cur;
    int      bad;                /* server-side protocol trouble */
} srv_t;

static srv_t S;

static int on_begin_headers(nghttp2_session *s, const nghttp2_frame *f, void *ud)
{
    (void)s; (void)ud;
    if (f->hd.type == NGHTTP2_HEADERS && S.nreq < 8) S.sid[S.nreq] = f->hd.stream_id;
    return 0;
}

static int on_header(nghttp2_session *s, const nghttp2_frame *f, const uint8_t *n, size_t nl,
                     const uint8_t *v, size_t vl, uint8_t fl, void *ud)
{
    (void)s; (void)f; (void)fl; (void)ud;
    if (S.nreq >= 8) return 0;
    size_t l = strlen(S.hdrs[S.nreq]);
    snprintf(S.hdrs[S.nreq] + l, sizeof(S.hdrs[0]) - l, "%.*s: %.*s\n", (int)nl, n, (int)vl, v);
    if (nl == 5 && memcmp(n, ":path", 5) == 0)
        snprintf(S.path[S.nreq], sizeof(S.path[0]), "%.*s", (int)vl, v);
    return 0;
}

static int on_data(nghttp2_session *s, uint8_t fl, int32_t sid, const uint8_t *d, size_t n, void *ud)
{
    (void)s; (void)fl; (void)sid; (void)ud;
    if (S.nreq < 8 && S.body_len[S.nreq] + n <= sizeof(S.body[0])) {
        memcpy(S.body[S.nreq] + S.body_len[S.nreq], d, n);
        S.body_len[S.nreq] += n;
    }
    return 0;
}

static nghttp2_ssize srv_read(nghttp2_session *s, int32_t sid, uint8_t *buf, size_t len,
                              uint32_t *flags, nghttp2_data_source *src, void *ud)
{
    (void)src; (void)ud;
    if (S.hold) return NGHTTP2_ERR_DEFERRED;
    if (S.pause_at && S.resp_off == S.pause_at && !S.paused && !S.acted) {
        S.paused = true;
        return NGHTTP2_ERR_DEFERRED;
    }
    size_t n = S.resp_len - S.resp_off;
    if (S.chunk) {
        const size_t c = 1 + rnd() % S.chunk;
        if (n > c) n = c;
    }
    if (n > len) n = len;
    if (S.pause_at && !S.acted && S.resp_off < S.pause_at && S.resp_off + n > S.pause_at)
        n = S.pause_at - S.resp_off;
    memcpy(buf, S.resp + S.resp_off, n);
    S.resp_off += n;
    if (S.resp_off == S.resp_len) {
        *flags |= NGHTTP2_DATA_FLAG_EOF;
        if (S.sc == SC_TRAILERS) {
            *flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
            static const nghttp2_nv tr[] = { { (uint8_t *)"x-trailer", (uint8_t *)"done", 9, 4, 0 } };
            nghttp2_submit_trailer(s, sid, tr, 1);
        }
    }
    return (nghttp2_ssize)n;
}

static nghttp2_ssize srv_padding(nghttp2_session *s, const nghttp2_frame *f, size_t max, void *ud)
{
    (void)s; (void)ud;
    if (S.sc != SC_PADDING) return (nghttp2_ssize)f->hd.length;
    size_t want = f->hd.length + 1 + rnd() % 200;
    if (want > max) want = max;
    return (nghttp2_ssize)want;
}

static int on_frame_send(nghttp2_session *s, const nghttp2_frame *f, void *ud)
{
    (void)s; (void)ud;
    if (f->hd.type == NGHTTP2_DATA) {
        S.data_frames++;
        if (f->hd.flags & NGHTTP2_FLAG_PADDED) S.padded_frames++;
    }
    if (f->hd.type == NGHTTP2_HEADERS && (f->hd.flags & NGHTTP2_FLAG_PADDED)) S.padded_frames++;
    if (f->hd.type == NGHTTP2_HEADERS && S.sc == SC_RST_AFTER_HEADERS)
        nghttp2_submit_rst_stream(s, NGHTTP2_FLAG_NONE, f->hd.stream_id, NGHTTP2_INTERNAL_ERROR);
    return 0;
}

#define NV(n, v) { (uint8_t *)(n), (uint8_t *)(v), sizeof(n) - 1, sizeof(v) - 1, 0 }

static char s_big_value[40001];

static void respond(int32_t sid)
{
    nghttp2_data_provider2 dp = { .read_callback = srv_read };
    static char clen[16];
    snprintf(clen, sizeof(clen), "%zu", S.resp_len);
    nghttp2_nv base[] = {
        NV(":status", "200"), NV("content-type", "application/json"),
        { (uint8_t *)"content-length", (uint8_t *)clen, 14, strlen(clen), 0 },
    };
    S.resp_off = 0;
    S.cur = sid;
    switch (S.sc) {
    case SC_429: {
        nghttp2_nv h[] = { NV(":status", "429"), NV("retry-after", "7"),
                           NV("content-type", "text/plain; charset=utf-8") };
        nghttp2_submit_response2(S.ng, sid, h, 3, NULL);
        return;
    }
    case SC_503_DATE: {
        nghttp2_nv h[] = { NV(":status", "503"), NV("retry-after", "Wed, 21 Oct 2026 07:28:00 GMT") };
        nghttp2_submit_response2(S.ng, sid, h, 2, NULL);
        return;
    }
    case SC_HEADERS_ONLY: {
        nghttp2_nv h[] = { NV(":status", "200") };
        nghttp2_submit_response2(S.ng, sid, h, 1, NULL);
        return;
    }
    case SC_GOAWAY_REFUSE:
        nghttp2_submit_goaway(S.ng, NGHTTP2_FLAG_NONE, 0, NGHTTP2_NO_ERROR, NULL, 0);
        return;
    case SC_RST_BEFORE:
        nghttp2_submit_rst_stream(S.ng, NGHTTP2_FLAG_NONE, sid, NGHTTP2_INTERNAL_ERROR);
        return;
    case SC_RST_AFTER_HEADERS:
        /* body deferred; RST_STREAM once the HEADERS are out (on_frame_send) */
        S.hold = true;
        nghttp2_submit_response2(S.ng, sid, base, 2, &dp);
        return;
    case SC_BIG_HEADER: {
        nghttp2_nv h[] = { NV(":status", "200"),
                           { (uint8_t *)"x-big", (uint8_t *)s_big_value, 5, 40000, NGHTTP2_NV_FLAG_NO_INDEX },
                           base[2] };
        nghttp2_submit_response2(S.ng, sid, h, 3, &dp);
        return;
    }
    case SC_1XX: {
        nghttp2_nv i[] = { NV(":status", "103"), NV("link", "</style.css>; rel=preload"),
                           NV("retry-after", "9") };
        nghttp2_submit_headers(S.ng, NGHTTP2_FLAG_NONE, sid, NULL, i, 3, NULL);
        nghttp2_submit_response2(S.ng, sid, base, 3, &dp);
        return;
    }
    case SC_STREAM:
    case SC_PING:
    case SC_GOAWAY_MID:
    case SC_EOF_MID:
    case SC_TRAILERS: {
        /* streaming: no content-length, as Go's server answers the map poll */
        nghttp2_submit_response2(S.ng, sid, base, 2, &dp);
        return;
    }
    default:
        nghttp2_submit_response2(S.ng, sid, base, 3, &dp);
        return;
    }
}

static int on_frame_recv(nghttp2_session *s, const nghttp2_frame *f, void *ud)
{
    (void)s; (void)ud;
    if (f->hd.type == NGHTTP2_PING && (f->hd.flags & NGHTTP2_FLAG_ACK)) S.ping_acks++;
    if ((f->hd.type == NGHTTP2_DATA || f->hd.type == NGHTTP2_HEADERS) &&
        (f->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
        respond(f->hd.stream_id);
        S.nreq++;
    }
    return 0;
}

static int on_invalid_frame(nghttp2_session *s, const nghttp2_frame *f, int err, void *ud)
{
    (void)s; (void)f; (void)ud;
    fprintf(stderr, "server: invalid frame from the client: %s\n", nghttp2_strerror(err));
    S.bad++;
    return 0;
}

static int on_stream_close(nghttp2_session *s, int32_t sid, uint32_t err, void *ud)
{
    (void)s; (void)sid; (void)ud;
    /* PROTOCOL_ERROR from the server's side = our request was malformed */
    if (err == NGHTTP2_PROTOCOL_ERROR || err == NGHTTP2_FLOW_CONTROL_ERROR ||
        err == NGHTTP2_COMPRESSION_ERROR) S.bad++;
    return 0;
}

/* Go's x/net http2.Server opens with these (and a 1 GiB connection
 * window); window = 0 keeps nghttp2's defaults instead. */
static void srv_new(uint32_t stream_window)
{
    memset(&S, 0, sizeof(S));
    nghttp2_session_callbacks *cb;
    nghttp2_session_callbacks_new(&cb);
    nghttp2_session_callbacks_set_on_begin_headers_callback(cb, on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(cb, on_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, on_data);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cb, on_frame_recv);
    nghttp2_session_callbacks_set_on_frame_send_callback(cb, on_frame_send);
    nghttp2_session_callbacks_set_on_invalid_frame_recv_callback(cb, on_invalid_frame);
    nghttp2_session_callbacks_set_on_stream_close_callback(cb, on_stream_close);
    nghttp2_session_callbacks_set_select_padding_callback2(cb, srv_padding);
    nghttp2_session_server_new(&S.ng, cb, NULL);
    nghttp2_session_callbacks_del(cb);
    nghttp2_settings_entry se[] = {
        { NGHTTP2_SETTINGS_MAX_FRAME_SIZE, 1048576 },
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 250 },
        { NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, 1048896 },
        { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, stream_window ? stream_window : 4194304 },
    };
    nghttp2_submit_settings(S.ng, NGHTTP2_FLAG_NONE, se, 4);
    nghttp2_submit_window_update(S.ng, NGHTTP2_FLAG_NONE, 0, 1073741824 - 65535);
}

static void srv_del(void)
{
    nghttp2_session_del(S.ng);
    S.ng = NULL;
}

/* Bytes the client sent → the server. */
static void srv_input(const uint8_t *p, size_t n)
{
    wire("C>", p, n);
    nghttp2_ssize r = nghttp2_session_mem_recv2(S.ng, p, n);
    if (r < 0) {
        fprintf(stderr, "server mem_recv: %s\n", nghttp2_strerror((int)r));
        S.bad++;
    }
}

static uint8_t s_s2c[600 * 1024];

/* Whatever the server has to send now; runs a deferred scenario action
 * when the data provider paused. */
static size_t srv_output(void)
{
    if (S.eof) return 0;
    for (int round = 0; round < 3; round++) {
        size_t n = 0;
        for (;;) {
            const uint8_t *d;
            nghttp2_ssize r = nghttp2_session_mem_send2(S.ng, &d);
            if (r <= 0) break;
            if (n + (size_t)r > sizeof(s_s2c)) break;
            memcpy(s_s2c + n, d, (size_t)r);
            n += (size_t)r;
        }
        if (n > 0) return n;
        if (S.paused && !S.acted) {
            S.acted = true;
            S.paused = false;
            if (S.sc == SC_PING) {
                nghttp2_submit_ping(S.ng, NGHTTP2_FLAG_NONE, (const uint8_t *)"keepaliv");
                nghttp2_session_resume_data(S.ng, S.cur);
            } else if (S.sc == SC_GOAWAY_MID) {
                /* graceful: our stream is the last one the server keeps */
                nghttp2_submit_goaway(S.ng, NGHTTP2_FLAG_NONE, S.cur, NGHTTP2_NO_ERROR,
                                      (const uint8_t *)"shutdown", 8);
            } else if (S.sc == SC_EOF_MID) {
                S.eof = true;
                return 0;
            }
            continue;
        }
        break;
    }
    return 0;
}

/* ---- client transport ---------------------------------------------------- */

static ts2021_conn_t s_conn;

#ifdef H2_REF

/* Plaintext stand-in for the ts2021 record layer: one ts2021_send = one
 * record to the server, one ts2021_recv = at most one record back. */
static size_t s_out_len, s_out_off;

esp_err_t ts2021_send(ts2021_conn_t *c, const uint8_t *data, size_t len)
{
    (void)c;
    srv_input(data, len);
    return ESP_OK;
}

esp_err_t ts2021_recv(ts2021_conn_t *c, uint8_t *out, size_t max, size_t *len)
{
    (void)c;
    if (s_out_off == s_out_len) {
        s_out_off = 0;
        s_out_len = srv_output();
        if (s_out_len == 0) return ESP_FAIL;          /* EOF */
    }
    size_t n = s_out_len - s_out_off;
    size_t rec = 1 + rnd() % TS2021_RECORD_PLAINTEXT_MAX;
    if (n > rec) n = rec;
    if (n > max) n = max;
    memcpy(out, s_s2c + s_out_off, n);
    s_out_off += n;
    *len = n;
    return ESP_OK;
}

static void transport_reset(void) { s_out_len = s_out_off = 0; }

#else  /* the firmware stack */

void esp_fill_random(void *buf, size_t len) { memset(buf, 0x5a, len); }
esp_err_t tl_crt_bundle_attach(void *conf) { (void)conf; return ESP_OK; }

struct esp_tls {
    uint8_t c2s[64 * 1024];      /* client bytes not yet cut into records */
    size_t  c2s_len;
    uint8_t s2c[700 * 1024];     /* sealed records for the client */
    size_t  s2c_len, s2c_off;
};
static struct esp_tls s_tls;
static noise_ik_state_t s_peer;
static const uint8_t kK1[32] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                                 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
static const uint8_t kK2[32] = { 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa,
                                 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4,
                                 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee,
                                 0xef, 0xd0 };
static int s_c2s_records;
static size_t s_c2s_max_record;

esp_tls_t *esp_tls_init(void) { return &s_tls; }
int esp_tls_conn_http_new_sync(const char *u, const esp_tls_cfg_t *c, esp_tls_t *t)
{
    (void)u; (void)c; (void)t;
    return -1;
}
int esp_tls_conn_destroy(esp_tls_t *t) { (void)t; return 0; }
esp_err_t esp_tls_get_conn_sockfd(esp_tls_t *t, int *fd) { (void)t; *fd = -1; return ESP_FAIL; }

/* Seal the server's plaintext into records of random sizes (empty ones
 * now and then). */
static void seal_records(const uint8_t *p, size_t n)
{
    size_t off = 0;
    while (off < n) {
        size_t r = rnd() % 10 == 0 ? 0 : 1 + rnd() % TS2021_RECORD_PLAINTEXT_MAX;
        if (r > n - off) r = n - off;
        uint8_t *o = s_tls.s2c + s_tls.s2c_len;
        size_t ct = 0;
        if (noise_ik_encrypt(&s_peer, o + 3, sizeof(s_tls.s2c) - s_tls.s2c_len - 3,
                             p + off, r, &ct) != ESP_OK) {
            S.bad++;
            return;
        }
        o[0] = TS2021_MSG_RECORD;
        o[1] = (uint8_t)(ct >> 8);
        o[2] = (uint8_t)ct;
        s_tls.s2c_len += 3 + ct;
        off += r;
    }
}

ssize_t esp_tls_conn_read(esp_tls_t *t, void *data, size_t len)
{
    if (t->s2c_off == t->s2c_len) {
        t->s2c_off = t->s2c_len = 0;
        size_t n = srv_output();
        if (n == 0) return 0;                 /* EOF: nothing more will come */
        seal_records(s_s2c, n);
    }
    size_t n = t->s2c_len - t->s2c_off;
    if (n > len) n = len;
    memcpy(data, t->s2c + t->s2c_off, n);
    t->s2c_off += n;
    return (ssize_t)n;
}

ssize_t esp_tls_conn_write(esp_tls_t *t, const void *data, size_t len)
{
    if (t->c2s_len + len > sizeof(t->c2s)) return -1;
    memcpy(t->c2s + t->c2s_len, data, len);
    t->c2s_len += len;
    /* complete records → open → server */
    size_t off = 0;
    while (t->c2s_len - off >= 3) {
        const uint8_t *r = t->c2s + off;
        size_t rl = ((size_t)r[1] << 8) | r[2];
        if (t->c2s_len - off < 3 + rl) break;
        uint8_t pt[4096];
        size_t pl = 0;
        if (r[0] != TS2021_MSG_RECORD ||
            noise_ik_decrypt(&s_peer, pt, sizeof(pt), r + 3, rl, &pl) != ESP_OK) {
            S.bad++;
        } else {
            s_c2s_records++;
            if (3 + rl > s_c2s_max_record) s_c2s_max_record = 3 + rl;
            srv_input(pt, pl);
        }
        off += 3 + rl;
    }
    memmove(t->c2s, t->c2s + off, t->c2s_len - off);
    t->c2s_len -= off;
    return (ssize_t)len;
}

static void transport_reset(void)
{
    memset(&s_tls, 0, sizeof(s_tls));
    memset(&s_peer, 0, sizeof(s_peer));
    s_peer.transport_ready = true;
    memcpy(s_peer.k_recv, kK1, 32);
    memcpy(s_peer.k_send, kK2, 32);
    s_c2s_records = 0;
    s_c2s_max_record = 0;
}

#endif

/* A connected conn with a started session. leftover: the server's first
 * bytes (its SETTINGS + WINDOW_UPDATE) already sit in h2_rx, as
 * consume_early_payload leaves them (D5). */
static void conn_up(bool leftover)
{
    transport_reset();
    memset(&s_conn, 0, sizeof(s_conn));
    s_conn.connected = true;
#ifndef H2_REF
    s_conn.tls = &s_tls;
    s_conn.noise.transport_ready = true;
    memcpy(s_conn.noise.k_send, kK1, 32);
    memcpy(s_conn.noise.k_recv, kK2, 32);
#endif
    if (leftover) {
        size_t n = srv_output();
        memcpy(s_conn.h2_rx, s_s2c, n);
        s_conn.h2_rx_len = n;
        s_conn.h2_rx_off = 0;
    }
    s_rec_no = 0;
    if (h2_session_init(&s_conn) != ESP_OK) S.bad++;
}

static void conn_down(void)
{
#ifdef H2_REF
    h2_session_destroy(&s_conn);
#else
    ts2021_close(&s_conn);
#endif
    srv_del();
}

/* ---- request helpers ------------------------------------------------------- */

#define AUTH "controlplane.tailscale.com"

static const char kRegBody[] =
    "{\"Version\":148,\"NodeKey\":\"nodekey:0123456789abcdef0123456789abcdef0123456789abcdef"
    "0123456789abcdef\",\"Hostinfo\":{\"OS\":\"esp32\",\"Hostname\":\"tinylink\"}}";

static uint8_t s_resp[8192];

typedef struct {
    esp_err_t err;
    int       status;
    size_t    len;
} res_t;

static res_t post(const char *path, const void *body, size_t blen, size_t cap)
{
    res_t r;
    memset(&r, 0, sizeof(r));
    r.err = h2_post_json(&s_conn, path, AUTH, (const uint8_t *)body, blen,
                         &r.status, s_resp, cap, &r.len);
    return r;
}

static uint8_t s_sbuf[400 * 1024];
static size_t  s_slen;
static int     s_scalls, s_sstop;

static int stream_cb(const uint8_t *buf, size_t len, void *ctx)
{
    (void)ctx;
    s_scalls++;
    if (s_slen + len <= sizeof(s_sbuf)) {
        memcpy(s_sbuf + s_slen, buf, len);
        s_slen += len;
    }
    return (s_sstop && s_scalls >= s_sstop) ? -1 : 0;
}

static res_t stream(const void *body, size_t blen)
{
    res_t r;
    memset(&r, 0, sizeof(r));
    s_slen = 0;
    s_scalls = 0;
    r.err = h2_post_json_stream(&s_conn, "/machine/map", AUTH, (const uint8_t *)body, blen,
                                &r.status, stream_cb, NULL);
    r.len = s_slen;
    return r;
}

/* LE32 length-prefixed MapResponses, as the map stream carries them. */
static void fill_mapresponses(int n, size_t each)
{
    S.resp_len = 0;
    for (int i = 0; i < n; i++) {
        size_t sz = each + rnd() % 64;
        uint8_t *p = S.resp + S.resp_len;
        p[0] = (uint8_t)sz; p[1] = (uint8_t)(sz >> 8); p[2] = (uint8_t)(sz >> 16); p[3] = 0;
        for (size_t k = 0; k < sz; k++) p[4 + k] = (uint8_t)(' ' + (rnd() % 90));
        S.resp_len += 4 + sz;
    }
}

static const char kOkBody[] = "{\"MachineAuthorized\":true,\"User\":{\"ID\":1}}";

/* ---- scenarios -------------------------------------------------------------- */

static void sc_register_ok(bool leftover)
{
    srv_new(0);
    conn_up(leftover);
    S.sc = SC_OK;
    memcpy(S.resp, kOkBody, sizeof(kOkBody) - 1);
    S.resp_len = sizeof(kOkBody) - 1;
    res_t r = post("/machine/register", kRegBody, sizeof(kRegBody) - 1, 4095);
    char nm[64];
    snprintf(nm, sizeof(nm), "register_200%s", leftover ? "_leftover_preface" : "");
    check(nm, r.err == ESP_OK && r.status == 200 && r.len == S.resp_len &&
              memcmp(s_resp, S.resp, r.len) == 0 && !s_conn.h2_resp_overflow &&
              s_conn.h2_stream_error == 0 && !s_conn.h2_retry_after_present);
    snprintf(nm, sizeof(nm), "register_request_seen%s", leftover ? "_leftover_preface" : "");
    char want[512];
    snprintf(want, sizeof(want), ":method: POST\n:scheme: https\n:path: /machine/register\n"
             ":authority: " AUTH "\ncontent-type: application/json\ncontent-length: %zu\n",
             sizeof(kRegBody) - 1);
    check(nm, S.bad == 0 && S.nreq == 1 && S.sid[0] == 1 && strcmp(S.hdrs[0], want) == 0 &&
              S.body_len[0] == sizeof(kRegBody) - 1 &&
              memcmp(S.body[0], kRegBody, S.body_len[0]) == 0);
    conn_down();
}

static void sc_rate_limits(void)
{
    srv_new(0);
    conn_up(false);
    S.sc = SC_429;
    res_t r = post("/machine/register", kRegBody, sizeof(kRegBody) - 1, 4095);
    check("429_retry_after_7", r.err == ESP_OK && r.status == 429 && r.len == 0 &&
          s_conn.h2_retry_after_present && s_conn.h2_retry_after_s == 7 && S.bad == 0);
    conn_down();

    srv_new(0);
    conn_up(false);
    S.sc = SC_503_DATE;
    r = post("/machine/map", kRegBody, sizeof(kRegBody) - 1, 256);
    /* an HTTP-date before NTP sync: present, no usable delay */
    check("503_retry_after_date_unsynced", r.err == ESP_OK && r.status == 503 &&
          s_conn.h2_retry_after_present && s_conn.h2_retry_after_s == 0);
    conn_down();
}

static void sc_overflow(void)
{
    srv_new(0);
    conn_up(false);
    S.sc = SC_BIG;
    S.resp_len = 6000;
    for (size_t i = 0; i < S.resp_len; i++) S.resp[i] = (uint8_t)('a' + i % 26);
    S.chunk = 700;
    res_t r = post("/machine/register", kRegBody, sizeof(kRegBody) - 1, 4095);
    check("overflow_latched", r.err == ESP_OK && r.status == 200 && r.len == 4095 &&
          s_conn.h2_resp_overflow && memcmp(s_resp, S.resp, 4095) == 0 &&
          s_conn.h2_stream_error == 0);
    /* the conn is still good after a consumed oversized body */
    S.sc = SC_HEADERS_ONLY;
    r = post("/machine/map", kRegBody, 10, 256);
    check("overflow_conn_reusable", r.err == ESP_OK && r.status == 200 && r.len == 0 &&
          !s_conn.h2_resp_overflow && S.sid[1] == 3);
    conn_down();
}

static void sc_stream(int sc, const char *name)
{
    srv_new(0);
    conn_up(true);
    S.sc = sc;
    /* three 25 KB netmaps and keepalive-sized ones: > 64 KiB, so the
     * connection and stream windows must be re-opened by the client */
    fill_mapresponses(3, 25800);
    size_t big = S.resp_len;
    for (int i = 0; i < 40; i++) {
        uint8_t *p = S.resp + S.resp_len;
        p[0] = 17; p[1] = p[2] = p[3] = 0;
        memcpy(p + 4, "{\"KeepAlive\":true}", 17);
        S.resp_len += 21;
    }
    (void)big;
    S.chunk = sc == SC_STREAM ? 3000 : 16384;
    if (sc == SC_PING || sc == SC_GOAWAY_MID || sc == SC_EOF_MID) S.pause_at = 30000;
    res_t r = stream(kRegBody, 120);
    char nm[64];
    switch (sc) {
    case SC_STREAM:
        snprintf(nm, sizeof(nm), "%s_all_bytes_in_order", name);
        check(nm, r.err == ESP_OK && r.status == 200 && r.len == S.resp_len &&
                  memcmp(s_sbuf, S.resp, S.resp_len) == 0 && s_conn.h2_stream_error == 0);
        snprintf(nm, sizeof(nm), "%s_many_data_frames", name);
        check(nm, S.data_frames > 40 && s_scalls > 40 && S.bad == 0);
        break;
    case SC_PING:
        snprintf(nm, sizeof(nm), "%s_acked_stream_intact", name);
        check(nm, r.err == ESP_OK && r.status == 200 && r.len == S.resp_len &&
                  memcmp(s_sbuf, S.resp, S.resp_len) == 0 && S.ping_acks == 1 && S.bad == 0);
        break;
    case SC_GOAWAY_MID:
        snprintf(nm, sizeof(nm), "%s_invalid_state", name);
        check(nm, r.err == ESP_ERR_INVALID_STATE && r.status == 200 && s_conn.h2_goaway &&
                  r.len == 30000 && memcmp(s_sbuf, S.resp, 30000) == 0);
        {
            res_t r2 = post("/machine/map", kRegBody, 10, 256);
            snprintf(nm, sizeof(nm), "%s_next_request_refused", name);
            check(nm, r2.err == ESP_ERR_INVALID_STATE);
        }
        break;
    case SC_EOF_MID:
        snprintf(nm, sizeof(nm), "%s_fails", name);
        check(nm, r.err == ESP_FAIL && r.status == 200 && r.len == 30000);
        break;
    }
    conn_down();
}

static void sc_goaway_refuse_and_rst(void)
{
    srv_new(0);
    conn_up(false);
    S.sc = SC_GOAWAY_REFUSE;
    res_t r = post("/machine/register", kRegBody, sizeof(kRegBody) - 1, 4095);
    check("goaway_refuses_stream", r.err == ESP_OK && r.status == 0 &&
          s_conn.h2_stream_error == NGHTTP2_REFUSED_STREAM && s_conn.h2_goaway);
    conn_down();

    srv_new(0);
    conn_up(false);
    S.sc = SC_RST_BEFORE;
    r = post("/machine/register", kRegBody, sizeof(kRegBody) - 1, 4095);
    check("rst_before_headers", r.err == ESP_OK && r.status == 0 &&
          s_conn.h2_stream_error == NGHTTP2_INTERNAL_ERROR);
    /* the connection survives a stream reset */
    S.sc = SC_OK;
    memcpy(S.resp, kOkBody, sizeof(kOkBody) - 1);
    S.resp_len = sizeof(kOkBody) - 1;
    r = post("/machine/register", kRegBody, sizeof(kRegBody) - 1, 4095);
    check("rst_conn_reusable", r.err == ESP_OK && r.status == 200 && s_conn.h2_stream_error == 0 &&
          S.sid[1] == 3);
    conn_down();

    srv_new(0);
    conn_up(false);
    S.sc = SC_RST_AFTER_HEADERS;
    r = stream(kRegBody, 100);
    check("rst_after_headers", r.err == ESP_OK && r.status == 200 && r.len == 0 &&
          s_conn.h2_stream_error == NGHTTP2_INTERNAL_ERROR);
    conn_down();
}

static void sc_sequence(void)
{
    /* the boot sequence: register, endpoint push, map stream — one conn */
    srv_new(0);
    conn_up(true);
    S.sc = SC_OK;
    memcpy(S.resp, kOkBody, sizeof(kOkBody) - 1);
    S.resp_len = sizeof(kOkBody) - 1;
    res_t r1 = post("/machine/register", kRegBody, sizeof(kRegBody) - 1, 4095);
    S.sc = SC_OK;
    S.resp_len = 2;
    memcpy(S.resp, "{}", 2);
    res_t r2 = post("/machine/map", kRegBody, sizeof(kRegBody) - 1, 256);
    S.sc = SC_STREAM;
    fill_mapresponses(2, 9000);
    S.chunk = 5000;
    res_t r3 = stream(kRegBody, sizeof(kRegBody) - 1);
    check("sequence_register_push_stream",
          r1.err == ESP_OK && r1.status == 200 && r2.err == ESP_OK && r2.status == 200 &&
          r2.len == 2 && r3.err == ESP_OK && r3.status == 200 && r3.len == S.resp_len &&
          memcmp(s_sbuf, S.resp, S.resp_len) == 0);
    check("sequence_stream_ids_1_3_5", S.nreq == 3 && S.sid[0] == 1 && S.sid[1] == 3 &&
          S.sid[2] == 5 && strcmp(S.path[1], "/machine/map") == 0 && S.bad == 0);
#ifndef H2_REF
    /* new client: HEADERS + DATA of a request share one record, and no
     * record is over 2 048 B — one TLS record each (D4) */
    check("sequence_records", s_c2s_records <= 1 + 3 + 3 && s_c2s_max_record <= 2048);
#endif
    conn_down();
}

static void sc_small_server_window(void)
{
    /* The server lets us send 100 bytes per stream: the 2-KiB body of the
     * second request must go out in pieces as its WINDOW_UPDATEs come. */
    static char body[2000];
    for (size_t i = 0; i < sizeof(body); i++) body[i] = (char)('A' + i % 26);
    srv_new(100);
    conn_up(true);
    S.sc = SC_HEADERS_ONLY;
    res_t r1 = post("/machine/map", body, 50, 256);
    S.sc = SC_HEADERS_ONLY;
    res_t r2 = post("/machine/register", body, sizeof(body), 256);
    check("small_server_window_body_complete",
          r1.err == ESP_OK && r1.status == 200 && r2.err == ESP_OK && r2.status == 200 &&
          S.body_len[1] == sizeof(body) && memcmp(S.body[1], body, sizeof(body)) == 0 &&
          S.bad == 0);
    conn_down();
}

static void sc_large_body(void)
{
    /* A body bigger than one record: the request goes out in ≤ 2 048-B
     * records cut from the ring (D4), in order, whatever the frames. */
    static char body[4000];
    for (size_t i = 0; i < sizeof(body); i++) body[i] = (char)('a' + i % 23);
    srv_new(0);
    conn_up(true);
    S.sc = SC_HEADERS_ONLY;
    res_t r = post("/machine/register", body, sizeof(body), 256);
    check("large_body_complete",
          r.err == ESP_OK && r.status == 200 && S.body_len[0] == sizeof(body) &&
          memcmp(S.body[0], body, sizeof(body)) == 0 && S.bad == 0);
#ifndef H2_REF
    check("large_body_2k_records", s_c2s_records >= 1 + 2 && s_c2s_max_record <= 2048);
#endif
    conn_down();
}

static void sc_misc(void)
{
    /* padded DATA (and HEADERS) from the server */
    srv_new(0);
    conn_up(false);
    S.sc = SC_PADDING;
    S.resp_len = 9000;
    for (size_t i = 0; i < S.resp_len; i++) S.resp[i] = (uint8_t)rnd();
    S.chunk = 900;
    res_t r = post("/machine/register", kRegBody, 20, 8192);
    check("padding", r.err == ESP_OK && r.status == 200 && r.len == 8192 &&
          memcmp(s_resp, S.resp, 8192) == 0 && S.padded_frames > 5 && s_conn.h2_resp_overflow);
    conn_down();

    /* a 40 000-char header (~35 KB coded): HEADERS + CONTINUATIONs */
    for (int i = 0; i < 40000; i++) s_big_value[i] = (char)(i % 7 ? 'x' : '#');
    srv_new(0);
    conn_up(false);
    S.sc = SC_BIG_HEADER;
    memcpy(S.resp, kOkBody, sizeof(kOkBody) - 1);
    S.resp_len = sizeof(kOkBody) - 1;
    r = post("/machine/register", kRegBody, 20, 4095);
    check("continuation_big_header", r.err == ESP_OK && r.status == 200 && r.len == S.resp_len &&
          s_conn.h2_stream_error == 0);
    conn_down();

    /* trailers after a streamed body */
    srv_new(0);
    conn_up(false);
    S.sc = SC_TRAILERS;
    fill_mapresponses(1, 3000);
    r = stream(kRegBody, 20);
    check("trailers", r.err == ESP_OK && r.status == 200 && r.len == S.resp_len &&
          s_conn.h2_stream_error == 0);
    conn_down();

    /* 103 Early Hints, then the final response */
    srv_new(0);
    conn_up(false);
    S.sc = SC_1XX;
    memcpy(S.resp, kOkBody, sizeof(kOkBody) - 1);
    S.resp_len = sizeof(kOkBody) - 1;
    r = post("/machine/register", kRegBody, 20, 4095);
#ifdef H2_REF
    /* The deliberate difference: the 1.3.4 glue read :status only from
     * blocks nghttp2 labels HCAT_RESPONSE, and nghttp2 labels the final
     * response after a 1xx HCAT_HEADERS — so it reported the 103. */
    check("informational_103", r.err == ESP_OK && r.status == 103 && r.len == S.resp_len);
#else
    /* The final status, as HTTP requires (RFC 9110 §15.2), and none of
     * the 103's fields: its Retry-After is not the final response's. */
    check("informational_103", r.err == ESP_OK && r.status == 200 && r.len == S.resp_len &&
          !s_conn.h2_retry_after_present && s_conn.h2_retry_after_s == 0);
#endif
    conn_down();

    /* The stream callback stops after the first chunk; DATA frames of
     * ≤ 100 B, so the record it came in carries more of them. */
    srv_new(0);
    conn_up(false);
    S.sc = SC_STREAM;
    fill_mapresponses(4, 10000);
    S.chunk = 100;
    s_sstop = 1;
    r = stream(kRegBody, 20);
    s_sstop = 0;
#ifdef H2_REF
    /* Difference 2: nghttp2 went on parsing the record and the glue kept
     * calling the callback for every further DATA frame in it. */
    check("callback_stop", r.err == ESP_OK && r.status == 200 && s_scalls > 1);
#else
    /* No DATA after the callback said stop. */
    check("callback_stop", r.err == ESP_OK && r.status == 200 && s_scalls == 1);
#endif
    conn_down();
}

int main(void)
{
    s_wire = getenv("TL_H2_WIRE") != NULL;
    if (s_wire) {
        printf("== wire: register + push on one connection, server preface left over\n");
        srv_new(0);
        conn_up(true);
        S.sc = SC_OK;
        memcpy(S.resp, kOkBody, sizeof(kOkBody) - 1);
        S.resp_len = sizeof(kOkBody) - 1;
        post("/machine/register", kRegBody, sizeof(kRegBody) - 1, 4095);
        S.sc = SC_HEADERS_ONLY;
        post("/machine/map", kRegBody, sizeof(kRegBody) - 1, 256);
        conn_down();
        s_wire = false;
        printf("== end wire\n");
    }
    sc_register_ok(false);
    sc_register_ok(true);
    sc_rate_limits();
    sc_overflow();
    sc_stream(SC_STREAM, "stream_100k");
    sc_stream(SC_PING, "server_ping_mid_stream");
    sc_stream(SC_GOAWAY_MID, "goaway_mid_stream");
    sc_stream(SC_EOF_MID, "eof_mid_stream");
    sc_goaway_refuse_and_rst();
    sc_sequence();
    sc_small_server_window();
    sc_large_body();
    sc_misc();
    if (s_fails == 0) printf("\nALL OK\n");
    return s_fails ? 1 : 0;
}
