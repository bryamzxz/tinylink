// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// In-tree HTTP/2 client engine (round 1.3.4, D1). Design and scope in
// h2_core.h. Where nghttp2's observable behaviour matters (what the
// callers see, what goes on the wire), the comments name the nghttp2
// rule being mirrored; tools/test/test_h2_interop.c runs the same
// scenarios against the 1.3.4 nghttp2 client as a reference.

#include "h2_core.h"

#include <string.h>

enum { PH_PADLEN, PH_PRIO, PH_BODY, PH_PAD, PH_FIXED, PH_SKIP };

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static void put_fh(uint8_t *b, uint32_t len, uint8_t type, uint8_t flags,
                   uint32_t sid)
{
    b[0] = (uint8_t)(len >> 16);
    b[1] = (uint8_t)(len >> 8);
    b[2] = (uint8_t)len;
    b[3] = type;
    b[4] = flags;
    put32(b + 5, sid);
}

/* ---- control frames -------------------------------------------------- */

static int ctl_flush(h2_core_t *h)
{
    if (h->ctl_len == 0) return H2C_OK;
    const int rc = h2_io_send(h->io, h->ctl, h->ctl_len);
    h->ctl_len = 0;
    if (rc != 0) {
        h->dead = true;
        return H2C_ERR_IO;
    }
    return H2C_OK;
}

static int ctl_frame(h2_core_t *h, uint8_t type, uint8_t flags, uint32_t sid,
                     const uint8_t *payload, uint32_t n)
{
    if (h->ctl_len + H2_FRAME_HDR_LEN + n > H2_CTL_CAP) {
        const int rc = ctl_flush(h);
        if (rc != H2C_OK) return rc;
    }
    put_fh(h->ctl + h->ctl_len, n, type, flags, sid);
    if (n) memcpy(h->ctl + h->ctl_len + H2_FRAME_HDR_LEN, payload, n);
    h->ctl_len = (uint8_t)(h->ctl_len + H2_FRAME_HDR_LEN + n);
    return H2C_OK;
}

static int ctl_u32(h2_core_t *h, uint8_t type, uint32_t sid, uint32_t v)
{
    uint8_t p[4];
    put32(p, v);
    return ctl_frame(h, type, 0, sid, p, 4);
}

/* Connection error (§5.4.1): GOAWAY(last stream 0 — we never accept a
 * server stream, as nghttp2's client sends), then nothing more. */
static int conn_error(h2_core_t *h, uint32_t code)
{
    if (!h->dead) {
        uint8_t p[8];
        put32(p, 0);
        put32(p + 4, code);
        if (ctl_frame(h, H2_GOAWAY, 0, 0, p, 8) == H2C_OK) (void)ctl_flush(h);
        h->dead = true;
    }
    return H2C_ERR_PROTO;
}

static void close_stream(h2_stream_t *s, uint32_t code)
{
    s->open = false;
    s->closed = true;
    s->close_err = code;
}

/* The open stream `sid` names: the main one or the side one (round
 * 1.3.7, B1); NULL for any other — closed, never ours, or 0. */
static h2_stream_t *stream_of(h2_core_t *h, uint32_t sid)
{
    if (h->s.open && sid == h->s.id) return &h->s;
    if (h->side.open && sid == h->side.id) return &h->side;
    return NULL;
}

/* Stream error (§5.4.2) on the stream of the frame being parsed:
 * RST_STREAM, closed with that code — what nghttp2's stream_close_cb
 * reported. The rest of the frame / header block is parsed and ignored. */
static int stream_error(h2_core_t *h, uint32_t code)
{
    int rc = H2C_OK;
    h2_stream_t *s = stream_of(h, h->f_sid);
    if (s != NULL) {
        rc = ctl_u32(h, H2_RST_STREAM, s->id, code);
        close_stream(s, code);
    }
    h->f_ignore = true;
    h->blk_error = true;
    return rc;
}

/* Server-initiated (even) streams are never opened (push is off), and
 * odd ones above the last we opened are idle: a frame on either is a
 * PROTOCOL_ERROR (nghttp2: "stream in idle"). */
static bool idle_stream(const h2_core_t *h, uint32_t sid)
{
    return sid != 0 && ((sid & 1u) == 0 || sid > h->last_id);
}

/* ---- received DATA: flow control + delivery ------------------------- */

/* nghttp2's automatic WINDOW_UPDATE: once half of the 65 535 window is
 * consumed, give it back — for the stream only while more of it can
 * come (not on a frame carrying END_STREAM). */
#define H2_WU_THRESHOLD (H2_DEFAULT_WINDOW / 2)

static int data_consumed(h2_core_t *h, uint32_t n)
{
    int rc = H2C_OK;
    h->conn_consumed += (int32_t)n;
    if (h->conn_consumed >= H2_WU_THRESHOLD) {
        rc = ctl_u32(h, H2_WINDOW_UPDATE, 0, (uint32_t)h->conn_consumed);
        h->conn_recv_win += h->conn_consumed;
        h->conn_consumed = 0;
        if (rc != H2C_OK) return rc;
    }
    h2_stream_t *s = h->f_ignore ? NULL : stream_of(h, h->f_sid);
    if (s != NULL) {
        s->consumed += (int32_t)n;
        if (s->consumed >= H2_WU_THRESHOLD && !(h->f_flags & H2_F_END_STREAM)) {
            rc = ctl_u32(h, H2_WINDOW_UPDATE, s->id, (uint32_t)s->consumed);
            s->recv_win += s->consumed;
            s->consumed = 0;
        }
    }
    return rc;
}

static int data_bytes(h2_core_t *h, const uint8_t *p, uint32_t n)
{
    h2_stream_t *s = h->f_ignore ? NULL : stream_of(h, h->f_sid);
    if (s == NULL) return H2C_OK;
    s->recv_len += n;
    /* nghttp2_http_on_data_chunk: DATA before the final response, or
     * past content-length, is a stream error — and is not delivered. */
    if (!s->final || (s->content_length >= 0 && s->recv_len > s->content_length))
        return stream_error(h, H2_PROTOCOL_ERROR);
    /* The side stream's body is counted (flow control, content-length)
     * and dropped: only its status matters (h2_core.h). */
    if (s == &h->s && !s->stop && n > 0 && h2_io_on_data(h->io, p, n) < 0) s->stop = true;
    return H2C_OK;
}

/* The server ended stream s (END_STREAM on DATA or HEADERS). */
static int remote_end(h2_core_t *h, h2_stream_t *s)
{
    /* nghttp2_http_on_remote_end_stream */
    if (!s->final ||
        (s->content_length >= 0 && s->content_length != s->recv_len))
        return stream_error(h, H2_PROTOCOL_ERROR);
    s->remote_end = true;
    if (s->local_end) {
        close_stream(s, H2_NO_ERROR);
        return H2C_OK;
    }
    /* Complete response before our body was out (only with a tiny server
     * window): stop sending and release the stream (§8.1). */
    const int rc = ctl_u32(h, H2_RST_STREAM, s->id, H2_CANCEL);
    close_stream(s, H2_NO_ERROR);
    return rc;
}

/* ---- response header fields ------------------------------------------ */

static bool name_is(const hpack_field_t *f, const char *n, size_t len)
{
    return f->name_total == len && memcmp(f->name, n, len) == 0;
}

static bool value_ieq(const hpack_field_t *f, const char *v, size_t len)
{
    if (f->value_total != len) return false;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = f->value[i];
        if (c >= 'A' && c <= 'Z') c = (uint8_t)(c + 32);
        if (c != (uint8_t)v[i]) return false;
    }
    return true;
}

/* nghttp2's parse_uint: one or more digits, no overflow; else -1. */
static int64_t parse_uint(const hpack_field_t *f)
{
    if (f->value_total == 0 || (f->flags & HPACK_F_VALUE_CUT)) return -1;
    int64_t v = 0;
    for (uint32_t i = 0; i < f->value_len; i++) {
        const uint8_t c = f->value[i];
        if (c < '0' || c > '9' || v > (INT64_MAX - 9) / 10) return -1;
        v = v * 10 + (c - '0');
    }
    return v;
}

/* nghttp2_http_on_header + http_response_on_header for a client: a bad
 * pseudo field, an uppercase name, a second :status / content-length,
 * a connection-specific field or a pseudo field after a regular one is
 * a stream error; an otherwise invalid regular field is dropped. */
static int field_cb(void *ctx, const hpack_field_t *f)
{
    h2_core_t *h = ctx;
    if (h->blk_ignore || h->blk_error) return 0;
    h2_stream_t *s = stream_of(h, h->f_sid);
    if (s == NULL) return 0;   /* not reached: blk_ignore / blk_error cover it */
    const bool is_main = s == &h->s;
    const bool pseudo = f->name_len > 0 && f->name[0] == ':';

    if (f->flags & (HPACK_F_NAME_BAD | HPACK_F_NAME_UPPER)) {
        if (pseudo || (f->flags & HPACK_F_NAME_UPPER)) goto bad;
        s->pseudo_done = true;
        return 0;
    }
    if (f->flags & HPACK_F_VALUE_BAD) {
        if (pseudo) goto bad;
        s->pseudo_done = true;
        return 0;
    }
    if (pseudo) {
        if (h->blk_trailer || s->pseudo_done || !name_is(f, ":status", 7) || s->have_status)
            goto bad;
        if (f->value_total != 3) goto bad;
        const int64_t st = parse_uint(f);
        if (st < 0 || st == 101) goto bad;
        s->have_status = true;
        s->status = (int)st;
        if (is_main) h2_io_on_status(h->io, s->status);
        return 0;
    }
    s->pseudo_done = true;
    if (name_is(f, "content-length", 14)) {
        if (s->status == 204) {
            /* RFC 9110 forbids it; nghttp2 tolerates "0" and drops it. */
            if (s->content_length != -1 || !value_ieq(f, "0", 1)) goto bad;
            s->content_length = 0;
            return 0;
        }
        if (s->status / 100 == 1 || s->content_length != -1) goto bad;
        s->content_length = parse_uint(f);
        if (s->content_length < 0) goto bad;
    } else if (name_is(f, "connection", 10) || name_is(f, "keep-alive", 10) ||
               name_is(f, "proxy-connection", 16) ||
               name_is(f, "transfer-encoding", 17) || name_is(f, "upgrade", 7)) {
        goto bad;
    } else if (name_is(f, "te", 2) && !value_ieq(f, "trailers", 8)) {
        goto bad;
    }
    if (!h->blk_trailer && is_main) h2_io_on_header(h->io, f);
    return 0;
bad:
    (void)stream_error(h, H2_PROTOCOL_ERROR);
    return 0;
}

/* END_HEADERS: the block is complete. */
static int block_end(h2_core_t *h)
{
    if (hpack_dec_end(&h->hpack) != HPACK_OK) return conn_error(h, H2_COMPRESSION_ERROR);
    h->cont_sid = 0;
    h2_stream_t *s = stream_of(h, h->f_sid);
    if (h->blk_ignore || h->blk_error || s == NULL) return H2C_OK;
    if (!h->blk_trailer) {
        /* nghttp2_http_on_response_headers */
        if (!s->have_status) return stream_error(h, H2_PROTOCOL_ERROR);
        if (s->status / 100 == 1) {          /* informational: a final one follows */
            s->have_status = false;
            s->pseudo_done = false;
            s->content_length = -1;
            if (h->blk_end_stream) return stream_error(h, H2_PROTOCOL_ERROR);
            return H2C_OK;
        }
        s->final = true;
        if (s->status == 204 || s->status == 304) s->content_length = 0;
    } else if (!h->blk_end_stream) {
        return stream_error(h, H2_PROTOCOL_ERROR);   /* trailers must end it */
    }
    return h->blk_end_stream ? remote_end(h, s) : H2C_OK;
}

static int block_bytes(h2_core_t *h, const uint8_t *p, uint32_t n)
{
    const int rc = hpack_dec_feed(&h->hpack, p, n, field_cb, h);
    if (rc != HPACK_OK) return conn_error(h, H2_COMPRESSION_ERROR);
    return h->dead ? H2C_ERR_IO : H2C_OK;
}

/* ---- SETTINGS / fixed-size frames ------------------------------------- */

static int setting(h2_core_t *h, uint16_t id, uint32_t v)
{
    switch (id) {
    case H2_SET_ENABLE_PUSH:
        /* §6.5.2: a server must not enable it (nghttp2: PROTOCOL_ERROR). */
        if (v != 0) return conn_error(h, H2_PROTOCOL_ERROR);
        break;
    case H2_SET_INITIAL_WINDOW_SIZE: {
        if (v > H2_MAX_WINDOW) return conn_error(h, H2_FLOW_CONTROL_ERROR);
        const int64_t delta = (int64_t)v - (int64_t)h->peer_initial_win;
        h2_stream_t *const both[2] = { &h->s, &h->side };
        for (int i = 0; i < 2; i++) {
            if (!both[i]->open) continue;
            const int64_t w = (int64_t)both[i]->send_win + delta;
            if (w > H2_MAX_WINDOW) return conn_error(h, H2_FLOW_CONTROL_ERROR);
            both[i]->send_win = (int32_t)w;   /* may go negative (§6.9.2) */
        }
        h->peer_initial_win = v;
        break;
    }
    case H2_SET_MAX_FRAME_SIZE:
        if (v < 16384u || v > 0xffffffu) return conn_error(h, H2_PROTOCOL_ERROR);
        h->peer_max_frame = v;
        break;
    case H2_SET_ENABLE_CONNECT_PROTOCOL:
        /* nghttp2: 0/1 only, and never back from 1 to 0. */
        if (v > 1 || (h->peer_enable_connect && v == 0))
            return conn_error(h, H2_PROTOCOL_ERROR);
        h->peer_enable_connect = v;
        break;
    case H2_SET_NO_RFC7540_PRIORITIES:
        if (v > 1) return conn_error(h, H2_PROTOCOL_ERROR);
        break;
    case H2_SET_MAX_CONCURRENT_STREAMS:
        /* One stream needs no check (a server allowing none refuses it
         * whatever we do); a pair needs two (h2c_request_pair). A value
         * that drops under the streams already open closes none
         * (§5.1.2): the server refuses what is over it. */
        h->peer_max_streams = v;
        break;
    default:
        /* HEADER_TABLE_SIZE: our encoder never indexes, and the size
         * update in our first header block already took the server's
         * decoder table to 0. MAX_HEADER_LIST_SIZE: our blocks are
         * ~130 B. Unknown: ignored (§6.5.2). */
        break;
    }
    return H2C_OK;
}

static uint32_t fixed_len(uint8_t type)
{
    switch (type) {
    case H2_SETTINGS:      return 6;
    case H2_PING:
    case H2_GOAWAY:        return 8;
    default:               return 4;   /* RST_STREAM, WINDOW_UPDATE */
    }
}

static int fixed_done(h2_core_t *h)
{
    const uint8_t *p = h->f_fix;
    switch (h->f_type) {
    case H2_SETTINGS:
        return setting(h, (uint16_t)((p[0] << 8) | p[1]), get32(p + 2));
    case H2_PING:
        if (h->f_flags & H2_F_ACK) return H2C_OK;      /* we never ping */
        return ctl_frame(h, H2_PING, H2_F_ACK, 0, p, 8);
    case H2_GOAWAY: {
        const uint32_t last = get32(p) & 0x7fffffffu;
        const uint32_t err = get32(p + 4);
        /* nghttp2: last_stream_id must name one of our (odd) streams and
         * may only go down across GOAWAYs. */
        if ((last != 0 && (last & 1u) == 0) || last > h->goaway_last)
            return conn_error(h, H2_PROTOCOL_ERROR);
        h->goaway = true;
        h->goaway_last = last;
        h2_io_on_goaway(h->io, last, err);
        /* Streams above it were never processed: closed REFUSED_STREAM,
         * as nghttp2's session_close_stream_on_goaway does (no RST). */
        if (h->s.open && h->s.id > last) close_stream(&h->s, H2_REFUSED_STREAM);
        if (h->side.open && h->side.id > last) close_stream(&h->side, H2_REFUSED_STREAM);
        return H2C_OK;
    }
    case H2_RST_STREAM: {
        h2_stream_t *s = stream_of(h, h->f_sid);
        if (s != NULL) close_stream(s, get32(p));
        return H2C_OK;
    }
    case H2_WINDOW_UPDATE: {
        const uint32_t inc = get32(p) & 0x7fffffffu;
        if (h->f_sid == 0) {
            if (inc == 0) return conn_error(h, H2_PROTOCOL_ERROR);
            if ((int64_t)h->conn_send_win + inc > H2_MAX_WINDOW)
                return conn_error(h, H2_FLOW_CONTROL_ERROR);
            h->conn_send_win += (int32_t)inc;
        } else {
            h2_stream_t *s = stream_of(h, h->f_sid);
            if (s == NULL) return H2C_OK;
            if (inc == 0) return stream_error(h, H2_PROTOCOL_ERROR);
            if ((int64_t)s->send_win + inc > H2_MAX_WINDOW)
                return stream_error(h, H2_FLOW_CONTROL_ERROR);
            s->send_win += (int32_t)inc;
        }
        return H2C_OK;
    }
    default:
        return H2C_OK;
    }
}

/* ---- frame boundaries ------------------------------------------------- */

static int begin_data(h2_core_t *h)
{
    if (h->f_sid == 0 || idle_stream(h, h->f_sid)) return conn_error(h, H2_PROTOCOL_ERROR);
    if ((h->f_flags & H2_F_PADDED) && h->f_len < 1) return conn_error(h, H2_FRAME_SIZE_ERROR);
    /* A stream the server ended is closed at once (remote_end), so a
     * later frame on it is one for a stream we no longer track. */
    h2_stream_t *s = stream_of(h, h->f_sid);
    /* Flow control counts the whole payload, padding included (§6.9.1),
     * also for streams we no longer track. */
    h->conn_recv_win -= (int32_t)h->f_len;
    if (h->conn_recv_win < 0) return conn_error(h, H2_FLOW_CONTROL_ERROR);
    h->f_ignore = s == NULL;
    if (s != NULL) {
        s->recv_win -= (int32_t)h->f_len;
        if (s->recv_win < 0) {
            const int rc = stream_error(h, H2_FLOW_CONTROL_ERROR);
            if (rc != H2C_OK) return rc;
        }
    }
    h->f_body_left = h->f_len;
    h->f_phase = (h->f_flags & H2_F_PADDED) ? PH_PADLEN : PH_BODY;
    return H2C_OK;
}

static int begin_headers(h2_core_t *h)
{
    if (h->f_sid == 0 || idle_stream(h, h->f_sid)) return conn_error(h, H2_PROTOCOL_ERROR);
    const uint32_t min = ((h->f_flags & H2_F_PADDED) ? 1u : 0u) +
                         ((h->f_flags & H2_F_PRIORITY) ? 5u : 0u);
    if (h->f_len < min) return conn_error(h, H2_FRAME_SIZE_ERROR);
    const h2_stream_t *s = stream_of(h, h->f_sid);
    hpack_dec_begin(&h->hpack);
    h->blk_ignore = s == NULL;
    h->blk_error = false;
    h->blk_trailer = s != NULL && s->final;
    h->blk_end_stream = (h->f_flags & H2_F_END_STREAM) != 0;
    h->cont_sid = (h->f_flags & H2_F_END_HEADERS) ? 0 : h->f_sid;
    h->cont_count = 0;
    h->f_body_left = h->f_len - ((h->f_flags & H2_F_PRIORITY) ? 5u : 0u);
    h->f_phase = (h->f_flags & H2_F_PADDED) ? PH_PADLEN
               : (h->f_flags & H2_F_PRIORITY) ? PH_PRIO : PH_BODY;
    return H2C_OK;
}

static int frame_begin(h2_core_t *h)
{
    const uint8_t *b = h->fh;
    h->f_len = ((uint32_t)b[0] << 16) | ((uint32_t)b[1] << 8) | b[2];
    h->f_type = b[3];
    h->f_flags = b[4];
    h->f_sid = get32(b + 5) & 0x7fffffffu;
    h->f_left = h->f_len;
    h->f_fix_have = 0;
    h->f_pad = 0;
    h->f_ignore = false;
    h->f_phase = PH_SKIP;

    if (h->f_len > H2_MAX_FRAME) return conn_error(h, H2_FRAME_SIZE_ERROR);
    /* §6.10: nothing but CONTINUATION on the same stream may interrupt a
     * header block. */
    if (h->cont_sid != 0 && (h->f_type != H2_CONTINUATION || h->f_sid != h->cont_sid))
        return conn_error(h, H2_PROTOCOL_ERROR);

    switch (h->f_type) {
    case H2_DATA:
        return begin_data(h);
    case H2_HEADERS:
        return begin_headers(h);
    case H2_CONTINUATION:
        if (h->cont_sid == 0) return conn_error(h, H2_PROTOCOL_ERROR);
        if (++h->cont_count > H2_MAX_CONTINUATIONS) return conn_error(h, H2_ENHANCE_YOUR_CALM);
        if (h->f_flags & H2_F_END_HEADERS) h->cont_sid = 0;
        h->f_body_left = h->f_len;
        h->f_phase = PH_BODY;
        return H2C_OK;
    case H2_PRIORITY:
        if (h->f_sid == 0) return conn_error(h, H2_PROTOCOL_ERROR);
        if (h->f_len != 5) return conn_error(h, H2_FRAME_SIZE_ERROR);
        return H2C_OK;                         /* deprecated; ignored */
    case H2_RST_STREAM:
        if (h->f_sid == 0 || idle_stream(h, h->f_sid)) return conn_error(h, H2_PROTOCOL_ERROR);
        if (h->f_len != 4) return conn_error(h, H2_FRAME_SIZE_ERROR);
        h->f_phase = PH_FIXED;
        return H2C_OK;
    case H2_SETTINGS:
        if (h->f_sid != 0) return conn_error(h, H2_PROTOCOL_ERROR);
        if ((h->f_flags & H2_F_ACK) ? h->f_len != 0 : (h->f_len % 6) != 0)
            return conn_error(h, H2_FRAME_SIZE_ERROR);
        h->f_phase = PH_FIXED;
        return H2C_OK;
    case H2_PUSH_PROMISE:                      /* we sent ENABLE_PUSH 0 */
        return conn_error(h, H2_PROTOCOL_ERROR);
    case H2_PING:
        if (h->f_sid != 0) return conn_error(h, H2_PROTOCOL_ERROR);
        if (h->f_len != 8) return conn_error(h, H2_FRAME_SIZE_ERROR);
        h->f_phase = PH_FIXED;
        return H2C_OK;
    case H2_GOAWAY:
        if (h->f_sid != 0) return conn_error(h, H2_PROTOCOL_ERROR);
        if (h->f_len < 8) return conn_error(h, H2_FRAME_SIZE_ERROR);
        h->f_phase = PH_FIXED;                 /* then the debug data, skipped */
        return H2C_OK;
    case H2_WINDOW_UPDATE:
        if (h->f_len != 4) return conn_error(h, H2_FRAME_SIZE_ERROR);
        if (idle_stream(h, h->f_sid)) return conn_error(h, H2_PROTOCOL_ERROR);
        h->f_phase = PH_FIXED;
        return H2C_OK;
    default:
        return H2C_OK;                         /* extension frame: skipped (§5.5) */
    }
}

static int frame_end(h2_core_t *h)
{
    switch (h->f_type) {
    case H2_DATA: {
        h2_stream_t *s = h->f_ignore ? NULL : stream_of(h, h->f_sid);
        if (s != NULL && (h->f_flags & H2_F_END_STREAM)) return remote_end(h, s);
        return H2C_OK;
    }
    case H2_HEADERS:
    case H2_CONTINUATION:
        if (h->f_flags & H2_F_END_HEADERS) return block_end(h);
        return H2C_OK;
    case H2_SETTINGS:
        if (h->f_flags & H2_F_ACK) {
            /* nghttp2: an ACK for SETTINGS we never sent. */
            if (h->settings_unacked == 0) return conn_error(h, H2_PROTOCOL_ERROR);
            h->settings_unacked--;
            return H2C_OK;
        }
        return ctl_frame(h, H2_SETTINGS, H2_F_ACK, 0, NULL, 0);
    case H2_PING:
    case H2_GOAWAY:
    case H2_RST_STREAM:
    case H2_WINDOW_UPDATE:
        return fixed_done(h);
    default:
        return H2C_OK;
    }
}

/* Payload bytes of the current frame: n ≤ h->f_left. */
static int frame_payload(h2_core_t *h, const uint8_t *p, uint32_t n)
{
    const bool is_data = h->f_type == H2_DATA;
    while (n > 0) {
        uint32_t take = n;
        int rc = H2C_OK;
        switch (h->f_phase) {
        case PH_PADLEN: {
            take = 1;
            h->f_pad = p[0];
            const uint32_t prio = (h->f_flags & H2_F_PRIORITY) && !is_data ? 5u : 0u;
            /* §6.1 / §6.2: padding ≥ the rest of the payload. */
            if ((uint32_t)h->f_pad + prio > h->f_left - 1u)
                return conn_error(h, H2_PROTOCOL_ERROR);
            h->f_body_left = h->f_left - 1u - prio - h->f_pad;
            h->f_phase = prio ? PH_PRIO : PH_BODY;
            break;
        }
        case PH_PRIO:
            if (take > 5u - h->f_fix_have) take = 5u - h->f_fix_have;
            h->f_fix_have = (uint8_t)(h->f_fix_have + take);
            if (h->f_fix_have == 5) {
                h->f_fix_have = 0;
                h->f_phase = PH_BODY;
            }
            break;
        case PH_BODY:
            if (take > h->f_body_left) take = h->f_body_left;
            if (take > 0) {
                rc = is_data ? data_bytes(h, p, take) : block_bytes(h, p, take);
                h->f_body_left -= take;
            }
            if (h->f_body_left == 0) h->f_phase = PH_PAD;
            break;
        case PH_FIXED: {
            const uint32_t fl = fixed_len(h->f_type);
            if (take > fl - h->f_fix_have) take = fl - h->f_fix_have;
            memcpy(h->f_fix + h->f_fix_have, p, take);
            h->f_fix_have = (uint8_t)(h->f_fix_have + take);
            if (h->f_fix_have == fl) {
                if (h->f_type == H2_SETTINGS) {        /* one entry at a time */
                    rc = fixed_done(h);
                    h->f_fix_have = 0;
                } else {
                    h->f_phase = PH_SKIP;              /* frame_end processes it */
                }
            }
            break;
        }
        default:   /* PH_PAD, PH_SKIP: nothing to look at */
            break;
        }
        if (rc == H2C_OK && is_data) rc = data_consumed(h, take);
        if (rc != H2C_OK) return rc;
        h->f_left -= take;
        p += take;
        n -= take;
    }
    return H2C_OK;
}

static int feed(h2_core_t *h, const uint8_t *p, size_t len)
{
    if (h->dead) return H2C_ERR_STATE;
    int rc = H2C_OK;
    while (len > 0 && rc == H2C_OK) {
        if (h->fh_have < H2_FRAME_HDR_LEN) {
            size_t n = H2_FRAME_HDR_LEN - h->fh_have;
            if (n > len) n = len;
            memcpy(h->fh + h->fh_have, p, n);
            h->fh_have = (uint8_t)(h->fh_have + n);
            p += n;
            len -= n;
            if (h->fh_have < H2_FRAME_HDR_LEN) break;
            rc = frame_begin(h);
        } else {
            const uint32_t n = len < h->f_left ? (uint32_t)len : h->f_left;
            rc = frame_payload(h, p, n);
            p += n;
            len -= n;
        }
        if (rc == H2C_OK && h->fh_have == H2_FRAME_HDR_LEN && h->f_left == 0) {
            rc = frame_end(h);
            h->fh_have = 0;
        }
    }
    return h->dead && rc == H2C_OK ? H2C_ERR_IO : rc;
}

int h2c_feed(h2_core_t *h, const uint8_t *p, size_t len)
{
    int rc = feed(h, p, len);
    if (rc == H2C_OK) rc = ctl_flush(h);
    return rc;
}

int h2c_feed_staged(h2_core_t *h, const uint8_t *p, size_t len)
{
    return feed(h, p, len);
}

/* ---- sending ------------------------------------------------------------ */

/* As many DATA frames of stream s's body as the windows and the buffer
 * allow; the last one carries END_STREAM (an empty one for an empty
 * body, as nghttp2's data provider sends). Returns the new fill. */
static size_t put_data(h2_core_t *h, h2_stream_t *s, uint8_t *b, size_t cap, size_t off)
{
    while (s->open && !s->local_end && cap - off >= H2_FRAME_HDR_LEN) {
        const size_t rem = s->body_len - s->body_off;
        const int32_t win = h->conn_send_win < s->send_win ? h->conn_send_win : s->send_win;
        if (rem > 0 && win <= 0) break;            /* windows can be negative */
        size_t n = rem;
        if (rem > 0 && n > (size_t)win) n = (size_t)win;
        if (n > h->peer_max_frame) n = h->peer_max_frame;
        if (n > cap - off - H2_FRAME_HDR_LEN) n = cap - off - H2_FRAME_HDR_LEN;
        if (rem > 0 && n == 0) break;
        const bool last = n == rem;
        put_fh(b + off, (uint32_t)n, H2_DATA, last ? H2_F_END_STREAM : 0, s->id);
        if (n) memcpy(b + off + H2_FRAME_HDR_LEN, s->body + s->body_off, n);
        off += H2_FRAME_HDR_LEN + n;
        s->body_off += n;
        h->conn_send_win -= (int32_t)n;
        s->send_win -= (int32_t)n;
        if (last) s->local_end = true;
    }
    return off;
}

/* Lend the embedder's buffer, starting with any control frames still
 * staged (one record for both). */
static uint8_t *tx_begin(h2_core_t *h, size_t *cap, size_t *off)
{
    uint8_t *b = h2_io_tx_buf(h->io, cap);
    if (b == NULL || *cap < H2_CTL_CAP + H2_FRAME_HDR_LEN + 1) return NULL;
    memcpy(b, h->ctl, h->ctl_len);
    *off = h->ctl_len;
    h->ctl_len = 0;
    return b;
}

static int tx_end(h2_core_t *h, size_t off)
{
    if (off == 0) return H2C_OK;
    if (h2_io_tx_send(h->io, off) != 0) {
        h->dead = true;
        return H2C_ERR_IO;
    }
    return H2C_OK;
}

/* Only the main stream can have body left: a side request goes out
 * whole in its opening burst (h2c_request_pair). */
int h2c_pump(h2_core_t *h)
{
    h2_stream_t *s = &h->s;
    if (h->dead) return H2C_ERR_STATE;
    while (s->open && !s->local_end) {
        const size_t rem = s->body_len - s->body_off;
        const int32_t win = h->conn_send_win < s->send_win ? h->conn_send_win : s->send_win;
        if (rem > 0 && win <= 0) break;            /* wait for WINDOW_UPDATE */
        size_t cap, off;
        uint8_t *b = tx_begin(h, &cap, &off);
        if (b == NULL) return H2C_ERR_IO;
        off = put_data(h, s, b, cap, off);
        const int rc = tx_end(h, off);
        if (rc != H2C_OK) return rc;
    }
    return H2C_OK;
}

/* HEADERS opening stream s on the next ID at b[*off], then as much of
 * its body as fits (put_data). H2C_ERR_SIZE when the header block does
 * not fit the buffer or one frame; the caller rolls back. */
static int open_stream(h2_core_t *h, h2_stream_t *s, const h2_req_t *r,
                       uint8_t *b, size_t cap, size_t *off)
{
    size_t o = *off;
    if (cap - o < H2_FRAME_HDR_LEN + 1) return H2C_ERR_SIZE;
    const size_t fh_at = o;
    o += H2_FRAME_HDR_LEN;
    const size_t blk_at = o;
    /* nghttp2 (max_deflate_dynamic_table_size 0) opened its first block
     * with a table size update to 0: the server's decoder table is 0
     * from then on, so no SETTINGS_HEADER_TABLE_SIZE it may send later
     * can require another update from us. Same bytes here. */
    if (!h->sent_size_update) b[o++] = 0x20;
    for (size_t i = 0; i < r->n_fields; i++) {
        const size_t n = hpack_put_field(b + o, cap - o,
                                         r->fields[i].name, strlen(r->fields[i].name),
                                         r->fields[i].value, strlen(r->fields[i].value));
        if (n == 0) return H2C_ERR_SIZE;
        o += n;
    }
    const size_t blk_len = o - blk_at;
    if (blk_len > h->peer_max_frame) return H2C_ERR_SIZE;
    const uint32_t sid = h->next_id;
    h->next_id += 2;
    h->last_id = sid;
    h->sent_size_update = true;
    put_fh(b + fh_at, (uint32_t)blk_len, H2_HEADERS, H2_F_END_HEADERS, sid);

    memset(s, 0, sizeof(*s));
    s->id = sid;
    s->open = true;
    s->send_win = (int32_t)h->peer_initial_win;
    s->recv_win = H2_DEFAULT_WINDOW;
    s->content_length = -1;
    s->body = r->body;
    s->body_len = r->body != NULL ? r->body_len : 0;
    *off = put_data(h, s, b, cap, o);
    return H2C_OK;
}

int h2c_request_pair(h2_core_t *h, const h2_req_t *side, const h2_req_t *req)
{
    if (!h->started || h->dead || h->goaway || h->s.open ||
        (side != NULL && h->side.open)) return H2C_ERR_STATE;
    /* IDs exhausted */
    if (h->next_id > (side != NULL ? 0x7ffffffdu : 0x7fffffffu)) return H2C_ERR_STATE;
    /* Two streams at once only where the server allows two: one that
     * advertised 1 refuses the second — the map stream (§5.1.2). The
     * caller sends them one after the other instead. */
    if (side != NULL && h->peer_max_streams < 2u) return H2C_ERR_STREAMS;

    size_t cap, off;
    uint8_t *b = tx_begin(h, &cap, &off);
    if (b == NULL) return H2C_ERR_IO;
    /* All or nothing: on a size failure only the staged control frames
     * go out, and no ID, window or size update is spent. */
    const size_t ctl_at = off;
    const uint32_t next_id = h->next_id, last_id = h->last_id;
    const bool sent_size_update = h->sent_size_update;
    const int32_t conn_send_win = h->conn_send_win;
    int rc = H2C_OK;
    if (side != NULL) {
        rc = open_stream(h, &h->side, side, b, cap, &off);
        if (rc == H2C_OK && !h->side.local_end) rc = H2C_ERR_SIZE;   /* not whole */
    }
    if (rc == H2C_OK) rc = open_stream(h, &h->s, req, b, cap, &off);
    if (rc != H2C_OK) {
        if (side != NULL) memset(&h->side, 0, sizeof(h->side));
        h->s.open = false;
        h->next_id = next_id;
        h->last_id = last_id;
        h->sent_size_update = sent_size_update;
        h->conn_send_win = conn_send_win;
        /* The control frames still go; if they cannot, the session is
         * dead and that is the answer — not "nothing sent, intact". */
        const int frc = tx_end(h, ctl_at);
        return frc != H2C_OK ? frc : rc;
    }
    rc = tx_end(h, off);
    if (rc != H2C_OK) return rc;
    return h2c_pump(h);
}

int h2c_request(h2_core_t *h, const h2_field_t *fields, size_t n_fields,
                const uint8_t *body, size_t body_len)
{
    const h2_req_t r = { fields, n_fields, body, body_len };
    return h2c_request_pair(h, NULL, &r);
}

int h2c_start(h2_core_t *h)
{
    if (h->started) return H2C_ERR_STATE;
    /* Client preface + SETTINGS {HEADER_TABLE_SIZE 0, ENABLE_PUSH 0} —
     * the same 45 bytes nghttp2 sent (it wrote them as two records). */
    memcpy(h->ctl, H2_PREFACE, H2_PREFACE_LEN);
    h->ctl_len = H2_PREFACE_LEN;
    uint8_t p[12] = { 0, H2_SET_HEADER_TABLE_SIZE, 0, 0, 0, 0,
                      0, H2_SET_ENABLE_PUSH, 0, 0, 0, 0 };
    int rc = ctl_frame(h, H2_SETTINGS, 0, 0, p, sizeof(p));
    if (rc == H2C_OK) rc = ctl_flush(h);
    if (rc != H2C_OK) return rc;
    h->settings_unacked = 1;
    h->started = true;
    return H2C_OK;
}

void h2c_init(h2_core_t *h, void *io)
{
    memset(h, 0, sizeof(*h));
    h->io = io;
    h->next_id = 1;
    h->goaway_last = 0x7fffffffu;
    h->conn_send_win = H2_DEFAULT_WINDOW;
    h->conn_recv_win = H2_DEFAULT_WINDOW;
    h->peer_initial_win = H2_DEFAULT_WINDOW;
    h->peer_max_frame = H2_MAX_FRAME;
    h->peer_max_streams = 0xffffffffu;   /* unlimited until SETTINGS say (§6.5.2) */
    /* SETTINGS_HEADER_TABLE_SIZE 0 is what we advertise: the decoder's
     * table is bounded by it (no storage at all). */
    hpack_dec_init(&h->hpack, NULL, 0, 0);
}
