// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// In-tree HTTP/2 client engine (RFC 9113) — round 1.3.4, D1, replacing
// nghttp2 (71 KB of flash with its 16 KB Huffman table; a 10–14 KiB
// session and a 16 KiB send chunk on the heap per connect). Platform-
// independent (host-tested in tools/test); h2_client.c binds it to the
// ts2021 Noise channel.
//
// Scope — exactly what tinylink's control plane needs:
//  - client only, one connection, one stream at a time on increasing
//    odd IDs (register, then the long-poll map stream) — plus, since
//    round 1.3.7 (B1), one side stream opened in the same burst ahead
//    of it (the endpoint push with the map stream), answered inside the
//    engine: only its :status is kept;
//  - preface + SETTINGS {HEADER_TABLE_SIZE 0, ENABLE_PUSH 0}, sent
//    without waiting for the server's (B9); the server's SETTINGS are
//    applied and ACKed;
//  - HEADERS (+CONTINUATION, ≤ H2_MAX_CONTINUATIONS) decoded by the
//    streaming HPACK decoder (hpack.h) straight from the record bytes —
//    no header-block buffer; DATA delivered in place, padding allowed;
//  - flow control: our receive windows stay at the 65 535 default and
//    are re-opened with WINDOW_UPDATE once half is consumed (nghttp2's
//    automatic rule), so a long map stream never stalls; request bodies
//    respect the server's connection and stream windows (and a later
//    SETTINGS_INITIAL_WINDOW_SIZE, which can make a window negative);
//  - PING → ACK, GOAWAY (last-stream refusal), RST_STREAM, response
//    :status / content-length / trailers checked the way nghttp2's HTTP
//    messaging layer checks them (a malformed response is a stream
//    error: RST_STREAM PROTOCOL_ERROR, as nghttp2 did).
//
// Buffers: none of its own beyond H2_CTL_CAP bytes of control-frame
// staging. Received bytes are parsed where they lie (h2c_feed); a
// request is built in a buffer the embedder lends (h2_io_tx_buf), only
// while it holds no unparsed received bytes — the record buffer on the
// device.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hpack.h"

#ifdef __cplusplus
extern "C" {
#endif

#define H2_PREFACE          "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_PREFACE_LEN      24u
#define H2_FRAME_HDR_LEN    9u
#define H2_DEFAULT_WINDOW   65535
#define H2_MAX_WINDOW       0x7fffffff
/* Our SETTINGS_MAX_FRAME_SIZE: the default, never raised. */
#define H2_MAX_FRAME        16384u
/* nghttp2's default bound (the 2024 CONTINUATION-flood fixes). */
#define H2_MAX_CONTINUATIONS 8u
#define H2_CTL_CAP          64u

/* Frame types (RFC 9113 §6) */
enum {
    H2_DATA = 0x0, H2_HEADERS = 0x1, H2_PRIORITY = 0x2, H2_RST_STREAM = 0x3,
    H2_SETTINGS = 0x4, H2_PUSH_PROMISE = 0x5, H2_PING = 0x6, H2_GOAWAY = 0x7,
    H2_WINDOW_UPDATE = 0x8, H2_CONTINUATION = 0x9,
};
/* Flags */
#define H2_F_END_STREAM  0x01u
#define H2_F_ACK         0x01u
#define H2_F_END_HEADERS 0x04u
#define H2_F_PADDED      0x08u
#define H2_F_PRIORITY    0x20u
/* Error codes (§7) */
enum {
    H2_NO_ERROR = 0x0, H2_PROTOCOL_ERROR = 0x1, H2_INTERNAL_ERROR = 0x2,
    H2_FLOW_CONTROL_ERROR = 0x3, H2_SETTINGS_TIMEOUT = 0x4,
    H2_STREAM_CLOSED = 0x5, H2_FRAME_SIZE_ERROR = 0x6,
    H2_REFUSED_STREAM = 0x7, H2_CANCEL = 0x8, H2_COMPRESSION_ERROR = 0x9,
    H2_ENHANCE_YOUR_CALM = 0xb,
};
/* SETTINGS identifiers */
enum {
    H2_SET_HEADER_TABLE_SIZE = 0x1, H2_SET_ENABLE_PUSH = 0x2,
    H2_SET_MAX_CONCURRENT_STREAMS = 0x3, H2_SET_INITIAL_WINDOW_SIZE = 0x4,
    H2_SET_MAX_FRAME_SIZE = 0x5, H2_SET_MAX_HEADER_LIST_SIZE = 0x6,
    H2_SET_ENABLE_CONNECT_PROTOCOL = 0x8, H2_SET_NO_RFC7540_PRIORITIES = 0x9,
};

/* h2c_* return codes */
enum {
    H2C_OK        = 0,
    H2C_ERR_IO    = -1,  /* an h2_io_* send failed                   */
    H2C_ERR_PROTO = -2,  /* connection error: GOAWAY sent, conn dead */
    H2C_ERR_STATE = -3,  /* not now: GOAWAY received, dead, busy     */
    H2C_ERR_SIZE  = -4,  /* request headers do not fit one frame     */
    H2C_ERR_STREAMS = -5,  /* a pair over the server's stream limit  */
};

typedef struct {
    const char *name;
    const char *value;
} h2_field_t;

typedef struct {
    uint32_t id;            /* 0 = none yet                           */
    bool     open;          /* HEADERS sent, not closed               */
    bool     local_end;     /* our END_STREAM sent                    */
    bool     remote_end;    /* server's END_STREAM received           */
    bool     closed;
    bool     stop;          /* h2_io_on_data asked to stop            */
    bool     have_status;   /* :status of the current response block  */
    bool     final;         /* a final (non-1xx) response was seen    */
    bool     pseudo_done;   /* a regular field was seen (no more pseudo) */
    uint32_t close_err;     /* HTTP/2 error code it closed with       */
    int      status;
    int32_t  send_win;      /* server's window for our DATA           */
    int32_t  recv_win;      /* our window as the server sees it       */
    int32_t  consumed;      /* DATA bytes since our last WINDOW_UPDATE */
    int64_t  content_length;  /* -1 = none                            */
    int64_t  recv_len;
    const uint8_t *body;
    size_t   body_len;
    size_t   body_off;
} h2_stream_t;

typedef struct {
    void    *io;            /* handed back to the h2_io_* hooks       */
    bool     started;       /* preface sent                           */
    bool     dead;          /* connection error, or a send failed     */
    bool     goaway;        /* GOAWAY received                        */
    bool     sent_size_update;
    uint32_t goaway_last;
    uint32_t next_id;
    uint32_t last_id;       /* highest stream ID we opened            */
    uint8_t  settings_unacked;  /* our SETTINGS frames without an ACK */
    int32_t  conn_send_win;
    int32_t  conn_recv_win;
    int32_t  conn_consumed;
    uint32_t peer_initial_win;
    uint32_t peer_max_frame;
    uint32_t peer_enable_connect;
    uint32_t peer_max_streams;  /* SETTINGS_MAX_CONCURRENT_STREAMS; ~0 = none yet */

    /* frame parser */
    uint8_t  fh[H2_FRAME_HDR_LEN];
    uint8_t  fh_have;
    uint8_t  f_type, f_flags;
    uint8_t  f_phase;
    uint8_t  f_pad;
    uint8_t  f_fix_have;
    bool     f_ignore;      /* payload is for a closed stream / errored */
    uint32_t f_len, f_sid, f_left;
    uint32_t f_body_left;   /* DATA / header-block bytes before padding */
    uint8_t  f_fix[8];      /* fixed-size payload pieces              */

    /* header block in progress */
    uint32_t cont_sid;      /* != 0: CONTINUATION expected on it      */
    uint8_t  cont_count;
    bool     blk_end_stream;
    bool     blk_ignore;
    bool     blk_trailer;
    bool     blk_error;     /* a stream error was raised in this block */
    hpack_dec_t hpack;

    h2_stream_t s;          /* the request the hooks report on          */
    /* The side request (h2c_request_pair): its frames are parsed and
     * checked like the main stream's, but nothing of it reaches the
     * h2_io_on_* hooks — status lands here, DATA is counted (flow
     * control, content-length) and dropped. side.closed with
     * side.final: answered (side.status); without: reset or refused
     * (side.close_err). */
    h2_stream_t side;

    uint8_t  ctl[H2_CTL_CAP];
    uint8_t  ctl_len;
} h2_core_t;

/* ---- hooks: implemented by the embedder (h2_client.c on the device) ----
 * Plain functions rather than pointers: one embedder per image, and the
 * static stack analysis (tools/stack_worst.py) follows direct calls. */

/* Send control frames; called at any time, also while parsing. */
int h2_io_send(void *io, const uint8_t *buf, size_t len);
/* Lend a buffer to build a request burst in; only called from
 * h2c_request / h2c_pump, i.e. when the embedder holds no unparsed
 * received bytes. */
uint8_t *h2_io_tx_buf(void *io, size_t *cap);
/* Send the first `len` bytes of that buffer. */
int h2_io_tx_send(void *io, size_t len);
/* Response events for the stream in flight. */
void h2_io_on_status(void *io, int status);
void h2_io_on_header(void *io, const hpack_field_t *f);   /* regular, validated */
int  h2_io_on_data(void *io, const uint8_t *buf, size_t len);  /* < 0: stop */
void h2_io_on_goaway(void *io, uint32_t last_stream_id, uint32_t error_code);

/* ---- engine ---- */

void h2c_init(h2_core_t *h, void *io);
/* Client preface + our SETTINGS. */
int  h2c_start(h2_core_t *h);
/* Open the next stream: HEADERS (fields in order, :pseudo first) and
 * as much of the body as the windows allow; the rest goes out from
 * h2c_pump as WINDOW_UPDATEs arrive. body may be NULL when body_len 0. */
int  h2c_request(h2_core_t *h, const h2_field_t *fields, size_t n_fields,
                 const uint8_t *body, size_t body_len);

typedef struct {
    const h2_field_t *fields;
    size_t            n_fields;
    const uint8_t    *body;
    size_t            body_len;
} h2_req_t;

/* h2c_request with a side request ahead of it in the same burst (round
 * 1.3.7, B1): the side's HEADERS and its whole body first, on the lower
 * ID, then req as h2c_request sends it — usually one record for both.
 * The side request must go out whole now (windows, the lent buffer;
 * side->body need not outlive the call): if it cannot, nothing is sent
 * but the staged control frames and H2C_ERR_SIZE comes back with no ID
 * spent. Nothing at all is sent, H2C_ERR_STREAMS, when the server's
 * SETTINGS_MAX_CONCURRENT_STREAMS is known to be under 2 (RFC 9113
 * §5.1.2). A failed send of the staged frames is H2C_ERR_IO, the
 * session then dead. side NULL = h2c_request. H2C_ERR_STATE also while
 * the previous side stream is still open. */
int  h2c_request_pair(h2_core_t *h, const h2_req_t *side, const h2_req_t *req);
/* Parse received bytes (any split). Consumes all of them; returns
 * H2C_ERR_PROTO on a connection error (GOAWAY already sent). */
int  h2c_feed(h2_core_t *h, const uint8_t *buf, size_t len);
/* The same, but the control frames it produces (SETTINGS ACK, ...) stay
 * staged for the h2c_request that the caller sends next, in one record
 * with it. */
int  h2c_feed_staged(h2_core_t *h, const uint8_t *buf, size_t len);
/* After a feed: send more of the request body if the windows opened. */
int  h2c_pump(h2_core_t *h);

#ifdef __cplusplus
}
#endif
