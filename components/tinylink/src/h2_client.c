// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Persistent HTTP/2 client over a ts2021 Noise channel. Since round
// 1.3.4 (D1) it runs on the in-tree engine (h2_core.c + hpack.c) instead
// of nghttp2: no heap at all (nghttp2 took a 10–14 KiB session plus a
// 16 KiB send chunk per connect), 0 B of Huffman tables to speak of
// (nghttp2: 16 KB), and every received record is parsed where it lies in
// conn->h2_rx, the buffer it is decrypted in (D4). The engine state lives
// in ts2021_conn_t (BSS). This file binds the engine's hooks to the conn,
// and keeps the request loop and the error mapping callers rely on (see
// h2_drive_request).

#include "h2_client.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_log.h"
#include "esp_timer.h"

#include "h2_core.h"
#include "h2_retry_after.h"
#include "tl_time.h"
#include "ts2021_client.h"

static const char *TAG = "h2";

/* Reset per-request fields on conn before a new request. Keeps
 * session-wide state (the engine, h2_goaway) intact. */
static void h2_request_reset(ts2021_conn_t *conn)
{
    conn->h2_req_body      = NULL;
    conn->h2_req_body_len  = 0;
    conn->h2_status        = 0;
    conn->h2_stream_id     = -1;
    conn->h2_stream_error  = 0;
    conn->h2_retry_after_s = 0;
    conn->h2_retry_after_present = false;
    conn->h2_resp_buf      = NULL;
    conn->h2_resp_cap      = 0;
    conn->h2_resp_len      = 0;
    conn->h2_resp_overflow = false;
    conn->h2_cb            = NULL;
    conn->h2_cb_ctx        = NULL;
    conn->h2_cb_stop       = false;
    /* h2_rx carries over: it may hold the start of the server's stream
     * (ts2021_connect) — parsed before the next request goes out. */
}

/* The one-shot deadline in force — see h2_post_json. Defined here for
 * the side request's share of it (h2_drive_request). */
static uint32_t s_req_ms = TS2021_REQ_TIMEOUT_MS;

/* The streaming request's first-response deadline in force (round 1.3.8,
 * C1, ts2021_client.h): TS2021_RESP_TIMEOUT_MS; doubled after a stream
 * that ran out of it, up to TS2021_RESP_TIMEOUT_MAX_MS; after an answer,
 * twice the time that answer took, within the same bounds. s_resp_streak:
 * expiries without an answer in between — from the second on, the conn
 * counts as failed (h2_post_json_stream). s_resp_since_us: when the
 * streaming request in flight went out. s_repoll: the hook took a
 * deadline off the conn, whose socket polls go back to the stream's once
 * the record that brought the answer is parsed. One streaming request at
 * a time (the long-poll task's); word-sized, no lock. */
static uint32_t s_resp_ms = TS2021_RESP_TIMEOUT_MS;
static uint8_t  s_resp_streak;
static int64_t  s_resp_since_us;
static bool     s_repoll;

static uint32_t resp_ms_after(int64_t took_us)
{
    const int64_t twice_ms = took_us > 0 ? took_us / 500 : 0;
    if (twice_ms <= (int64_t)TS2021_RESP_TIMEOUT_MS) return TS2021_RESP_TIMEOUT_MS;
    if (twice_ms >= (int64_t)TS2021_RESP_TIMEOUT_MAX_MS) return TS2021_RESP_TIMEOUT_MAX_MS;
    return (uint32_t)twice_ms;
}

/* A side request riding with a stream (h2_post_json_stream_side). */
typedef struct {
    const uint8_t *body;
    size_t         len;
    h2_side_fn_t   cb;
    void          *ctx;
    uint32_t       ms;       /* its deadline: s_req_ms when it went out */
    uint32_t       resp_ms;  /* the stream's first-response deadline then */
    bool           armed;    /* sent, not closed yet */
    /* The stream's final response came first: the conn is alive, and
     * the side's deadline is its own from then on (deadline_us: the
     * burst + ms), no longer the conn's — past it the side is cancelled,
     * the stream goes on (round 1.3.7 review). */
    bool           detached;
    bool           expired;  /* cancelled by us at its deadline */
    int64_t        deadline_us;
    h2_side_result_t res;    /* its Retry-After as it arrives */
} h2_side_t;

/* The side request in flight, for the hooks: one request at a time runs
 * on the control conn (the long-poll task's). */
static h2_side_t *s_side;

/* A server that allows one stream at a time (SETTINGS_MAX_CONCURRENT_
 * STREAMS < 2), seen on any conn: the side request then goes before its
 * stream, alone (ESP_ERR_INVALID_SIZE to the caller), on every later
 * conn too — a limit that arrives after a pair went out is only learned
 * from the refusal of its second stream. Servers do not change it per
 * conn; a reboot forgets it. */
static bool s_one_stream;

/* ---- h2_core hooks ---------------------------------------------------- */

/* Control frames (preface, SETTINGS / ACK, PING ACK, WINDOW_UPDATE,
 * RST_STREAM, GOAWAY): one Noise record, sealed off the ring (they can
 * be sent mid-record). */
int h2_io_send(void *io, const uint8_t *buf, size_t len)
{
    _Static_assert(H2_CTL_CAP <= TS2021_SMALL_PLAINTEXT_MAX,
                   "a control-frame flush must stay one record");
    return ts2021_send((ts2021_conn_t *)io, buf, len) == ESP_OK ? 0 : -1;
}

/* A request (pending control frames, HEADERS, DATA) is built in the
 * record ring and sealed where it lies, ≤ 2 KiB per record (round 1.3.4,
 * D4): the engine only asks between records, when every byte in the
 * ring has been parsed. */
uint8_t *h2_io_tx_buf(void *io, size_t *cap)
{
    return ts2021_tx_buf((ts2021_conn_t *)io, cap);
}

int h2_io_tx_send(void *io, size_t len)
{
    return ts2021_tx_send((ts2021_conn_t *)io, len) == ESP_OK ? 0 : -1;
}

void h2_io_on_status(void *io, int status)
{
    ts2021_conn_t *conn = (ts2021_conn_t *)io;
    /* Every response header block — a 1xx, then the final one — opens
     * with :status, and a Retry-After belongs to the block it came in:
     * one on a 103 must not make the final 200 look rate-limited. */
    conn->h2_status = status;
    conn->h2_retry_after_s = 0;
    conn->h2_retry_after_present = false;
    if (status < 200 || conn->h2_cb == NULL) return;   /* a 1xx; a one-shot */
    /* The streaming request's final response proves the conn alive: its
     * first-response deadline ends (round 1.3.8, C1), and a side request
     * still unanswered keeps its deadline, but as its own (h2_drive_
     * request cancels it there). Here, before any DATA of this response
     * reaches the stream callback — the map stream's handler can run for
     * a while (the first netmap's data-plane start, the relay wait) — and
     * before the flush that ends this feed: no read or write fails on
     * either deadline any more. */
    const int64_t took_us = esp_timer_get_time() - s_resp_since_us;
    s_resp_ms = resp_ms_after(took_us);
    s_resp_streak = 0;
    ESP_LOGI(TAG, "map stream answered: HTTP %d in %u ms", status,
             (unsigned)(took_us > 0 ? took_us / 1000 : 0));
    h2_side_t *side = s_side;
    bool off = conn->resp_wait;
    if (side != NULL && side->armed && !side->detached) {
        side->detached = true;
        off = true;
    }
    if (off && conn->req_deadline_us != 0) {
        conn->req_deadline_us = 0;
        conn->resp_wait = false;
        s_repoll = true;
    }
}

/* The side stream's response: only its Retry-After is kept — per
 * header block, as for the stream's. */
void h2_io_on_side_status(void *io, int status)
{
    (void)io;
    (void)status;
    if (s_side != NULL) {
        s_side->res.retry_after_present = false;
        s_side->res.retry_after_s = 0;
    }
}

void h2_io_on_side_header(void *io, const hpack_field_t *f)
{
    (void)io;
    if (s_side == NULL) return;
    if (f->name_total == 11 && memcmp(f->name, "retry-after", 11) == 0) {
        s_side->res.retry_after_present = f->value_total > 0;
        s_side->res.retry_after_s = (f->flags & HPACK_F_VALUE_CUT) ? 0
            : h2_parse_retry_after_seconds(f->value, f->value_len,
                                           tl_time_synced() ? (int64_t)time(NULL) : 0);
    }
}

void h2_io_on_header(void *io, const hpack_field_t *f)
{
    ts2021_conn_t *conn = (ts2021_conn_t *)io;
    /* HTTP/2 field names are lowercase (RFC 9113 §8.2.1; the engine
     * resets the stream on an uppercase one), so an exact match is
     * enough. Captured unconditionally; h2_rate_limit_wait_ms decides
     * whether the status makes it a rate limit. An HTTP-date needs a
     * real clock, so `now` is only passed once SNTP has synced. A value
     * longer than the decoder's capture (64 B, more than any valid
     * Retry-After) counts as present but invalid. */
    if (f->name_total == 11 && memcmp(f->name, "retry-after", 11) == 0) {
        conn->h2_retry_after_present = f->value_total > 0;
        conn->h2_retry_after_s = (f->flags & HPACK_F_VALUE_CUT) ? 0
            : h2_parse_retry_after_seconds(f->value, f->value_len,
                                           tl_time_synced() ? (int64_t)time(NULL) : 0);
    }
}

int h2_io_on_data(void *io, const uint8_t *data, size_t len)
{
    ts2021_conn_t *conn = (ts2021_conn_t *)io;

    if (conn->h2_cb != NULL) {
        /* A negative return stops the stream: the engine delivers no
         * more DATA and h2_drive_request returns. */
        if (conn->h2_cb(data, len, conn->h2_cb_ctx) < 0) {
            conn->h2_cb_stop = true;
            return -1;
        }
        return 0;
    }

    /* One-shot: collect up to the cap, latch the overflow and keep
     * consuming (register.c refuses to parse a truncated body). */
    if (conn->h2_resp_len + len > conn->h2_resp_cap) {
        size_t take = conn->h2_resp_cap - conn->h2_resp_len;
        if (take > 0) {
            memcpy(conn->h2_resp_buf + conn->h2_resp_len, data, take);
            conn->h2_resp_len += take;
        }
        conn->h2_resp_overflow = true;
        return 0;
    }
    memcpy(conn->h2_resp_buf + conn->h2_resp_len, data, len);
    conn->h2_resp_len += len;
    return 0;
}

/* GOAWAY: the server is done with the conn; we must reconnect after the
 * current stream finishes. */
void h2_io_on_goaway(void *io, uint32_t last_stream_id, uint32_t error_code)
{
    ts2021_conn_t *conn = (ts2021_conn_t *)io;
    conn->h2_goaway = true;
    ESP_LOGW(TAG, "received GOAWAY (last_stream=%d, error=0x%x)",
             (int)last_stream_id, (unsigned)error_code);
}

/* ---- session ----------------------------------------------------------- */

esp_err_t h2_session_init(ts2021_conn_t *conn)
{
    if (conn == NULL) return ESP_ERR_INVALID_ARG;

    /* Idempotent: a second call starts a fresh session on the conn. */
    conn->h2_goaway = false;
    /* h2_rx is NOT reset: ts2021_connect's consume_early_payload left
     * the first HTTP/2 bytes there (round 1.3.4, D5); the first request
     * parses them before it goes out. */
    h2c_init(&conn->h2, conn);

    /* Send the client preface + our SETTINGS now (one record), and
     * return WITHOUT waiting for the server's SETTINGS or its ACK of
     * ours (round 1.3.2, B9 — the old pump spent one full RTT here on
     * every control connect). RFC 9113 §3.4 lets a client send requests
     * right after its preface, and the upstream client does exactly that
     * (x/net http2.Transport writes preface, SETTINGS, WINDOW_UPDATE and
     * then the first request; it only waits for the server's SETTINGS
     * for extended CONNECT). Nothing tinylink sends depends on the
     * server's values: our bodies (< 2 KiB) fit the default 64 KiB
     * windows and 16 KiB frames, and the engine applies whatever the
     * server announces as soon as the first request's loop reads it (and
     * ACKs it from the same loop). HEADER_TABLE_SIZE 0 holds for every
     * response: the server reads our SETTINGS before our HEADERS on the
     * same byte stream, so each of its response header blocks is encoded
     * for a 0-byte table (opening with the size update to 0); the decoder
     * enforces 0 from the start (h2_core.c). Holds for both control
     * planes: tailscale.com (x/net http2.Server.ServeConn) and headscale's
     * net/http h2c front end (62714564), which waits for the client
     * preface, then processes frames in order. */
    if (h2c_start(&conn->h2) != H2C_OK) {
        ESP_LOGE(TAG, "preface + SETTINGS send failed");
        return ESP_FAIL;
    }
    return ESP_OK;
}

void h2_session_destroy(ts2021_conn_t *conn)
{
    if (conn == NULL) return;
    /* Nothing to free and nothing sent: the conn is closed under it. */
    conn->h2.started   = false;
    conn->h2_goaway    = false;
    conn->h2_rx_len    = 0;
    conn->h2_rx_off    = 0;
}

/* Parse what h2_rx still holds (the connect's leftover HTTP/2 bytes).
 * Its SETTINGS ACK rides in the request's record. */
static int feed_pending(ts2021_conn_t *conn)
{
    if (conn->h2_rx_off >= conn->h2_rx_len) return H2C_OK;
    const int rc = h2c_feed_staged(&conn->h2, conn->h2_rx + conn->h2_rx_off,
                                   conn->h2_rx_len - conn->h2_rx_off);
    conn->h2_rx_off = conn->h2_rx_len;
    return rc;
}

/* The side stream closed: its deadline ends (the stream polls at the
 * stream budget from here), and the caller hears how — at once, not
 * when the stream ends hours later. */
static esp_err_t side_closed(ts2021_conn_t *conn, h2_side_t *side)
{
    const h2_stream_t *ss = &conn->h2.side;
    side->armed = false;
    /* Answered or reset: the conn is alive and the next one-shot request
     * gets the base deadline. Cancelled unanswered: twice this one's, as
     * after an expiry (h2_post_json). */
    s_req_ms = !side->expired ? TS2021_REQ_TIMEOUT_MS
             : side->ms < TS2021_REQ_TIMEOUT_MAX_MS / 2 ? 2 * side->ms
                                                        : TS2021_REQ_TIMEOUT_MAX_MS;
    /* Closed before the stream answered: the conn waits for that answer
     * under the stream's own first-response deadline from here, counted
     * from the burst (round 1.3.8, C1) — no longer the side's. */
    const esp_err_t err = side->detached ? ESP_OK
        : ts2021_response_deadline(conn, side->resp_ms, s_resp_since_us);
    side->res.status = ss->final ? ss->status : 0;
    side->res.stream_error = (int)ss->close_err;
    side->res.expired = side->expired;
    side->res.goaway = !ss->final && conn->h2_goaway &&
                       ss->close_err == H2_REFUSED_STREAM;
    side->cb(&side->res, side->ctx);
    return err;
}

/* One HTTP/2 request on the persistent session bound to `conn`. Caller
 * pre-fills h2_req_body / h2_resp_buf / h2_cb on conn; `side` (NULL for
 * none) goes out ahead of it in the same burst.
 *
 * Return mapping (the callers' contract, kept from the nghttp2 client):
 *  - ESP_OK: the stream closed — normally, or reset by the server or by
 *    us for a malformed response (h2_stream_error = the HTTP/2 code; no
 *    final response means h2_status 0), or refused by a GOAWAY below its
 *    ID (REFUSED_STREAM) — or the stream callback asked to stop;
 *  - ESP_ERR_INVALID_STATE: no session, a GOAWAY arrived earlier, or one
 *    arrived while the stream was still open (the caller reconnects);
 *  - ESP_FAIL: the record layer failed (TLS error, EOF, the 120-s idle
 *    budget, a deadline, ts2021_abort_reads), or a connection-level protocol error
 *    (GOAWAY sent). nghttp2 returned ESP_OK with whatever status it had
 *    for the latter; every caller treats both as a failed exchange and
 *    drops the conn. */
static esp_err_t h2_drive_request(ts2021_conn_t *conn,
                                  const char *path, const char *authority,
                                  size_t body_len, h2_side_t *side)
{
    h2_core_t *h = &conn->h2;
    if (!h->started || h->dead) {
        ESP_LOGE(TAG, "drive_request without active session");
        return ESP_ERR_INVALID_STATE;
    }
    if (conn->h2_goaway) {
        /* Server already told us to reconnect — refuse new streams on
         * this session. Caller (long-poll/register) will close + reopen. */
        return ESP_ERR_INVALID_STATE;
    }
    /* The server's first bytes (SETTINGS, maybe a GOAWAY) may already be
     * here: apply them before the request goes out. */
    if (feed_pending(conn) != H2C_OK) {
        ESP_LOGE(TAG, "connection error in the server preface");
        return ESP_FAIL;
    }
    if (conn->h2_goaway) return ESP_ERR_INVALID_STATE;

    char content_length[16];
    snprintf(content_length, sizeof(content_length), "%u", (unsigned)body_len);
    /* Same fields, same order as the nghttp2 client sent. */
    const h2_field_t hdrs[] = {
        { ":method",        "POST" },
        { ":scheme",        "https" },
        { ":path",          path },
        { ":authority",     authority },
        { "content-type",   "application/json" },
        { "content-length", content_length },
    };
    const h2_req_t req = { hdrs, sizeof(hdrs) / sizeof(hdrs[0]),
                           conn->h2_req_body, body_len };
    /* The side request: the same path and fields, its own length. */
    char side_length[16];
    h2_field_t side_hdrs[sizeof(hdrs) / sizeof(hdrs[0])];
    h2_req_t side_req;
    if (side != NULL) {
        snprintf(side_length, sizeof(side_length), "%u", (unsigned)side->len);
        memcpy(side_hdrs, hdrs, sizeof(hdrs));
        side_hdrs[5].value = side_length;
        side_req = (h2_req_t){ side_hdrs, sizeof(hdrs) / sizeof(hdrs[0]),
                               side->body, side->len };
    }
    int rc = h2c_request_pair(h, side != NULL ? &side_req : NULL, &req);
    if ((rc == H2C_ERR_SIZE || rc == H2C_ERR_STREAMS) && side != NULL) {
        /* Nothing of either request went out; the session is intact. */
        if (rc == H2C_ERR_STREAMS) {
            s_one_stream = true;
            ESP_LOGW(TAG, "server allows %u stream(s) at a time — the side "
                          "request goes alone, first", (unsigned)h->peer_max_streams);
        } else {
            ESP_LOGW(TAG, "side request does not fit the opening burst");
        }
        return ESP_ERR_INVALID_SIZE;
    }
    if (rc != H2C_OK) {
        if (conn->req_expired || conn->resp_expired) {
            ESP_LOGD(TAG, "request send left: deadline");
        } else {
            ESP_LOGE(TAG, "request send failed: %d", rc);
        }
        return ESP_FAIL;
    }
    conn->h2_stream_id = (int32_t)h->s.id;
    if (side != NULL) side->armed = true;

    /* One Noise record per iteration: parse it, flush what it asked for
     * (ACKs, WINDOW_UPDATEs — h2c_feed sends them before returning), then
     * push more of the request body if the server opened its window. */
    while (!h->s.closed && !h->s.stop) {
        size_t got = 0;
        if (ts2021_recv_record(conn, &got) != ESP_OK) {
            /* A requested recycle (ts2021_abort_reads), a one-shot
             * request past its deadline or a stream unanswered past its
             * first-response deadline already has its one line in ts2021
             * (I / W); only a real read failure is an error here. */
            if (conn->aborted || conn->req_expired || conn->resp_expired) {
                ESP_LOGD(TAG, "stream %d left: %s", (int)conn->h2_stream_id,
                         conn->aborted ? "recycle requested" : "deadline");
            } else {
                ESP_LOGE(TAG, "stream read failed (stream %d)", (int)conn->h2_stream_id);
            }
            return ESP_FAIL;
        }
        rc = h2c_feed(h, conn->h2_rx, got);
        conn->h2_rx_off = got;
        if (rc == H2C_OK) rc = h2c_pump(h);
        if (rc != H2C_OK) {
            if (rc != H2C_ERR_PROTO && (conn->req_expired || conn->resp_expired)) {
                /* an ACK / WINDOW_UPDATE past the deadline: ts2021 has
                 * the line */
                ESP_LOGD(TAG, "stream %d left: deadline", (int)conn->h2_stream_id);
            } else {
                ESP_LOGE(TAG, "%s (stream %d)", rc == H2C_ERR_PROTO
                             ? "protocol error from the server — GOAWAY sent"
                             : "send failed", (int)conn->h2_stream_id);
            }
            return ESP_FAIL;
        }
        if (s_repoll) {
            /* The stream answered (h2_io_on_status): its own budget and
             * 30-s polls from here. */
            s_repoll = false;
            if (ts2021_request_deadline(conn, 0) != ESP_OK) return ESP_FAIL;
        }
        if (side != NULL && side->armed) {
            /* Unanswered past its deadline: cancelled — checked as records
             * arrive, so on a quiet stream at its next KeepAlive. Not
             * while received bytes wait unread (the stream callback can
             * hold this loop past the deadline with the answer already
             * in): those records first. Answered — its final :status in,
             * the body still coming — is not late: it closes on its own. */
            if (side->detached && h->side.open && !h->side.final &&
                esp_timer_get_time() > side->deadline_us && !ts2021_rx_ready(conn)) {
                ESP_LOGW(TAG, "side request: no answer within %u ms — "
                              "cancelled, the stream goes on", (unsigned)side->ms);
                side->expired = true;
                if (h2c_cancel_side(h) != H2C_OK) return ESP_FAIL;
            }
            if (!h->side.open && side_closed(conn, side) != ESP_OK) return ESP_FAIL;
        }
        if (conn->h2_goaway && !h->s.closed) {
            /* GOAWAY with the stream still open: bail to the caller for
             * reconnection (as with nghttp2). */
            ESP_LOGW(TAG, "GOAWAY during in-flight stream %d",
                     (int)conn->h2_stream_id);
            return ESP_ERR_INVALID_STATE;
        }
    }
    conn->h2_stream_error = (int)h->s.close_err;

    if (conn->h2_resp_overflow) {
        ESP_LOGW(TAG, "response truncated (status=%d)", conn->h2_status);
    }
    if (conn->h2_stream_error != 0) {
        ESP_LOGW(TAG, "stream closed with error 0x%x", conn->h2_stream_error);
    }
    return ESP_OK;
}

/* The one-shot deadline in force (round 1.3.5, s_req_ms above):
 * TS2021_REQ_TIMEOUT_MS, doubled after each request that ran out of it,
 * up to TS2021_REQ_TIMEOUT_MAX_MS — the budget a one-shot request had
 * before — and back to TS2021_REQ_TIMEOUT_MS once a request is
 * answered. A dead conn is still cut after 10 s; a control plane that is
 * slow for a while rather than gone (a push answered after 52 s, say)
 * still gets an answer within four tries, where a fixed 10 s would fail
 * every retry of the register loop and of the long-poll's push. Register
 * and the pushes run one at a time on the one control conn; a
 * word-sized value, so no lock. */

esp_err_t h2_post_json(ts2021_conn_t *conn,
                       const char *path,
                       const char *authority,
                       const uint8_t *body, size_t body_len,
                       int *status_out,
                       uint8_t *response_buf, size_t response_buf_size,
                       size_t *response_len)
{
    if (conn == NULL || path == NULL || authority == NULL ||
        response_buf == NULL || response_len == NULL ||
        status_out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    h2_request_reset(conn);
    conn->h2_req_body     = body;
    conn->h2_req_body_len = body_len;
    conn->h2_resp_buf     = response_buf;
    conn->h2_resp_cap     = response_buf_size;

    /* A one-shot request has s_req_ms from here to its last response
     * byte (round 1.3.5), not the map stream's 120-s budget: on expiry it
     * fails like a dropped conn — the callers (register, endpoint push)
     * drop the conn and the next dial is fresh. */
    const uint32_t ms = s_req_ms;
    esp_err_t err = ts2021_request_deadline(conn, ms);
    if (err == ESP_OK) err = h2_drive_request(conn, path, authority, body_len, NULL);
    const esp_err_t derr = ts2021_request_deadline(conn, 0);
    if (err == ESP_OK) err = derr;   /* not usable for a stream at 2-s polls */
    if (conn->req_expired) {
        s_req_ms = ms < TS2021_REQ_TIMEOUT_MAX_MS / 2 ? 2 * ms : TS2021_REQ_TIMEOUT_MAX_MS;
    } else if (err == ESP_OK) {
        s_req_ms = TS2021_REQ_TIMEOUT_MS;
    }

    *status_out   = conn->h2_status;
    *response_len = conn->h2_resp_len;

    /* Clear the borrowed pointers so the conn doesn't outlive its
     * caller's buffer. The session itself stays. */
    conn->h2_req_body = NULL;
    conn->h2_resp_buf = NULL;
    conn->h2.s.body   = NULL;
    return err;
}

/* A streaming request is over: its first-response deadline off if it is
 * still on (or its socket polls still short), and on an expiry the next
 * one doubled — the second expiry in a row on, the conn counts as failed
 * like any young conn that dies (ts2021_close: a :80 one sends the next
 * dial to :443, one at the cached address re-resolves the name), so a
 * stall that persists also tries the other port and a fresh address. */
static esp_err_t resp_deadline_done(ts2021_conn_t *conn, uint32_t ms, esp_err_t err)
{
    if (conn->req_idle != 0) {
        const esp_err_t derr = ts2021_request_deadline(conn, 0);
        if (err == ESP_OK) err = derr;   /* not usable for a stream at 2-s polls */
    }
    s_repoll = false;
    if (conn->resp_expired) {
        s_resp_ms = ms < TS2021_RESP_TIMEOUT_MAX_MS / 2 ? 2 * ms : TS2021_RESP_TIMEOUT_MAX_MS;
        if (s_resp_streak < UINT8_MAX) s_resp_streak++;
        if (s_resp_streak >= 2) conn->io_failed = true;
    }
    return err;
}

esp_err_t h2_post_json_stream(ts2021_conn_t *conn,
                              const char *path,
                              const char *authority,
                              const uint8_t *body, size_t body_len,
                              int *status_out,
                              h2_data_callback cb, void *cb_ctx)
{
    if (conn == NULL || path == NULL || authority == NULL ||
        cb == NULL || status_out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    h2_request_reset(conn);
    conn->h2_req_body     = body;
    conn->h2_req_body_len = body_len;
    conn->h2_cb           = cb;
    conn->h2_cb_ctx       = cb_ctx;

    /* Its response headers within s_resp_ms of the request, or the conn
     * is recycled (round 1.3.8, C1); from them on the stream budget only
     * (h2_io_on_status ends the deadline), as upstream's watchdog. */
    const uint32_t ms = s_resp_ms;
    s_resp_since_us = esp_timer_get_time();
    s_repoll = false;
    esp_err_t err = ts2021_response_deadline(conn, ms, s_resp_since_us);
    if (err == ESP_OK) err = h2_drive_request(conn, path, authority, body_len, NULL);
    err = resp_deadline_done(conn, ms, err);

    *status_out = conn->h2_status;

    conn->h2_req_body = NULL;
    conn->h2_cb       = NULL;
    conn->h2_cb_ctx   = NULL;
    conn->h2.s.body   = NULL;
    return err;
}

#ifndef ESP_PLATFORM
void h2_client_forget_limits(void)
{
    s_one_stream = false;
}
#endif

esp_err_t h2_post_json_stream_side(ts2021_conn_t *conn,
                                   const char *path,
                                   const char *authority,
                                   const uint8_t *side_body, size_t side_len,
                                   h2_side_fn_t side_cb, void *side_ctx,
                                   const uint8_t *body, size_t body_len,
                                   int *status_out,
                                   h2_data_callback cb, void *cb_ctx)
{
    if (conn == NULL || path == NULL || authority == NULL || side_body == NULL ||
        side_cb == NULL || cb == NULL || status_out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_one_stream) return ESP_ERR_INVALID_SIZE;   /* nothing sent */

    h2_request_reset(conn);
    conn->h2_req_body     = body;
    conn->h2_req_body_len = body_len;
    conn->h2_cb           = cb;
    conn->h2_cb_ctx       = cb_ctx;

    /* The side request is a one-shot: s_req_ms from the burst to its
     * answer, as h2_post_json gives one (a conn that answers nothing is
     * cut after 10 s, not after the stream's 120-s budget). The conn is
     * under that deadline until the stream's final response proves it
     * alive (h2_io_on_status); after that a late side request is only
     * cancelled — a push answered after 52 s once cost the sensor three
     * reconnects of a working map stream. A side request that closes
     * before the stream has answered hands the conn to the stream's own
     * first-response deadline, counted from the burst (round 1.3.8, C1;
     * side_closed). */
    const uint32_t ms = s_req_ms;
    const uint32_t resp_ms = s_resp_ms;
    s_resp_since_us = esp_timer_get_time();
    s_repoll = false;
    h2_side_t side = { .body = side_body, .len = side_len,
                       .cb = side_cb, .ctx = side_ctx, .ms = ms, .resp_ms = resp_ms };
    esp_err_t err = ts2021_request_deadline(conn, ms);
    side.deadline_us = conn->req_deadline_us;   /* its own, once detached */
    s_side = &side;
    if (err == ESP_OK) err = h2_drive_request(conn, path, authority, body_len, &side);
    s_side = NULL;
    if (side.armed || err == ESP_ERR_INVALID_SIZE) {
        /* Left with the side request unanswered (or never sent). */
        if (conn->req_expired) {
            s_req_ms = ms < TS2021_REQ_TIMEOUT_MAX_MS / 2 ? 2 * ms : TS2021_REQ_TIMEOUT_MAX_MS;
        }
    }
    /* Either deadline off; a stream unanswered past its own counted as
     * in h2_post_json_stream. */
    err = resp_deadline_done(conn, resp_ms, err);
    if (!s_one_stream && conn->h2.peer_max_streams < 2u) {
        s_one_stream = true;   /* the limit came after the burst */
        ESP_LOGW(TAG, "server allows %u stream(s) at a time — side requests "
                      "go alone from now on", (unsigned)conn->h2.peer_max_streams);
    }

    *status_out = conn->h2_status;

    conn->h2_req_body = NULL;
    conn->h2_cb       = NULL;
    conn->h2_cb_ctx   = NULL;
    conn->h2.s.body   = NULL;
    conn->h2.side.body = NULL;
    return err;
}
