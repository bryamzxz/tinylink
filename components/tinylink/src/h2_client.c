// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Persistent HTTP/2 client over a ts2021 Noise channel. The session is
// owned by ts2021_conn_t and lives across multiple requests so the
// ~10-14 KiB nghttp2 session alloc happens exactly once when the
// long-poll TLS conn is fresh and the heap is unfragmented.

#include "h2_client.h"

#include <string.h>

#include "esp_log.h"
#include "nghttp2/nghttp2.h"

#include "ts2021_client.h"

static const char *TAG = "h2";

/* Reset per-request fields on conn before a new submit_request. Keeps
 * session-wide flags (h2, h2_goaway, h2_settings_acked) intact. */
static void h2_request_reset(ts2021_conn_t *conn)
{
    conn->h2_req_body      = NULL;
    conn->h2_req_body_len  = 0;
    conn->h2_req_body_off  = 0;
    conn->h2_status        = 0;
    conn->h2_stream_id     = -1;
    conn->h2_stream_closed = false;
    conn->h2_stream_error  = 0;
    conn->h2_resp_buf      = NULL;
    conn->h2_resp_cap      = 0;
    conn->h2_resp_len      = 0;
    conn->h2_resp_overflow = false;
    conn->h2_cb            = NULL;
    conn->h2_cb_ctx        = NULL;
    conn->h2_cb_stop       = false;
    /* h2_rx and h2_may_refill carry over: the recv ring may legitimately
     * hold bytes from the previous request's tail that belong to a new
     * SETTINGS update or PING from the server. */
}

/* nghttp2 -> network. nghttp2 hands us framed HTTP/2 bytes; we wrap them
 * in a Noise transport record and send through ts2021. */
static ssize_t send_cb(nghttp2_session *session, const uint8_t *data,
                       size_t length, int flags, void *user_data)
{
    (void)session; (void)flags;
    ts2021_conn_t *conn = (ts2021_conn_t *)user_data;

    /* ts2021_send caps at TS2021_RECORD_PLAINTEXT_MAX per record. Chunk. */
    size_t off = 0;
    while (off < length) {
        size_t take = length - off;
        if (take > TS2021_RECORD_PLAINTEXT_MAX) {
            take = TS2021_RECORD_PLAINTEXT_MAX;
        }
        if (ts2021_send(conn, data + off, take) != ESP_OK) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        off += take;
    }
    return (ssize_t)length;
}

/* Network -> nghttp2. Cooperative non-blocking: refilling from the
 * network is gated on conn->h2_may_refill so session_recv unwinds when
 * we've already pulled one record this iteration, letting queued
 * outbound (e.g. SETTINGS_ACK) flush via session_send. */
static ssize_t recv_cb(nghttp2_session *session, uint8_t *buf,
                       size_t length, int flags, void *user_data)
{
    (void)session; (void)flags;
    ts2021_conn_t *conn = (ts2021_conn_t *)user_data;

    /* Drain any plaintext already buffered from a prior refill. */
    if (conn->h2_rx_off < conn->h2_rx_len) {
        size_t avail = conn->h2_rx_len - conn->h2_rx_off;
        size_t take = (length < avail) ? length : avail;
        memcpy(buf, conn->h2_rx + conn->h2_rx_off, take);
        conn->h2_rx_off += take;
        return (ssize_t)take;
    }

    if (!conn->h2_may_refill) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    conn->h2_may_refill = false;

    size_t got = 0;
    if (ts2021_recv(conn, conn->h2_rx, sizeof(conn->h2_rx), &got) != ESP_OK) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    conn->h2_rx_len = got;
    conn->h2_rx_off = 0;
    if (got == 0) {
        return NGHTTP2_ERR_WOULDBLOCK;
    }
    size_t take = (length < got) ? length : got;
    memcpy(buf, conn->h2_rx, take);
    conn->h2_rx_off = take;
    return (ssize_t)take;
}

/* Body provider for the outgoing POST. */
static ssize_t data_provider_read(nghttp2_session *session, int32_t stream_id,
                                  uint8_t *buf, size_t length,
                                  uint32_t *data_flags,
                                  nghttp2_data_source *source, void *user_data)
{
    (void)session; (void)stream_id; (void)source;
    ts2021_conn_t *conn = (ts2021_conn_t *)user_data;

    size_t remaining = conn->h2_req_body_len - conn->h2_req_body_off;
    size_t take = (length < remaining) ? length : remaining;
    if (take > 0) {
        memcpy(buf, conn->h2_req_body + conn->h2_req_body_off, take);
        conn->h2_req_body_off += take;
    }
    if (conn->h2_req_body_off >= conn->h2_req_body_len) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return (ssize_t)take;
}

static int header_cb(nghttp2_session *session, const nghttp2_frame *frame,
                     const uint8_t *name, size_t namelen,
                     const uint8_t *value, size_t valuelen,
                     uint8_t flags, void *user_data)
{
    (void)session; (void)flags;
    ts2021_conn_t *conn = (ts2021_conn_t *)user_data;

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_RESPONSE) {
        return 0;
    }
    if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
        char status_str[8] = {0};
        size_t copy = (valuelen < sizeof(status_str) - 1)
                       ? valuelen : sizeof(status_str) - 1;
        memcpy(status_str, value, copy);
        conn->h2_status = atoi(status_str);
    }
    return 0;
}

static int data_chunk_cb(nghttp2_session *session, uint8_t flags,
                         int32_t stream_id, const uint8_t *data,
                         size_t len, void *user_data)
{
    (void)session; (void)flags; (void)stream_id;
    ts2021_conn_t *conn = (ts2021_conn_t *)user_data;

    if (conn->h2_cb != NULL) {
        int rc = conn->h2_cb(data, len, conn->h2_cb_ctx);
        if (rc < 0) {
            conn->h2_cb_stop = true;
        }
        return 0;
    }

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

static int stream_close_cb(nghttp2_session *session, int32_t stream_id,
                           uint32_t error_code, void *user_data)
{
    (void)session;
    ts2021_conn_t *conn = (ts2021_conn_t *)user_data;
    if (stream_id == conn->h2_stream_id) {
        conn->h2_stream_closed = true;
        conn->h2_stream_error = (int)error_code;
    }
    return 0;
}

/* Frame-level recv hook: catches GOAWAY (server is done with the conn,
 * we must reconnect after the current stream finishes) and SETTINGS
 * with the ACK flag (the server confirmed our initial SETTINGS — only
 * relevant during h2_session_init's pump). */
static int frame_recv_cb(nghttp2_session *session,
                         const nghttp2_frame *frame, void *user_data)
{
    (void)session;
    ts2021_conn_t *conn = (ts2021_conn_t *)user_data;

    switch (frame->hd.type) {
        case NGHTTP2_GOAWAY:
            conn->h2_goaway = true;
            ESP_LOGW(TAG, "received GOAWAY (last_stream=%d, error=0x%x)",
                     frame->goaway.last_stream_id,
                     (unsigned)frame->goaway.error_code);
            break;
        case NGHTTP2_SETTINGS:
            if (frame->hd.flags & NGHTTP2_FLAG_ACK) {
                conn->h2_settings_acked = true;
            }
            break;
        default:
            break;
    }
    return 0;
}

static nghttp2_nv mknv(const char *name, const char *value)
{
    nghttp2_nv nv = {
        .name      = (uint8_t *)name,
        .value     = (uint8_t *)value,
        .namelen   = strlen(name),
        .valuelen  = strlen(value),
        .flags     = NGHTTP2_NV_FLAG_NO_INDEX,
    };
    return nv;
}

esp_err_t h2_session_init(ts2021_conn_t *conn)
{
    if (conn == NULL) return ESP_ERR_INVALID_ARG;

    /* Idempotent: if a prior session is still around, free it first. */
    if (conn->h2 != NULL) {
        nghttp2_session_del(conn->h2);
        conn->h2 = NULL;
    }
    conn->h2_goaway          = false;
    conn->h2_settings_acked  = false;
    conn->h2_rx_len          = 0;
    conn->h2_rx_off          = 0;
    conn->h2_may_refill      = false;

    nghttp2_session_callbacks *cbs = NULL;
    if (nghttp2_session_callbacks_new(&cbs) != 0) return ESP_ERR_NO_MEM;
    nghttp2_session_callbacks_set_send_callback(cbs, send_cb);
    nghttp2_session_callbacks_set_recv_callback(cbs, recv_cb);
    nghttp2_session_callbacks_set_on_header_callback(cbs, header_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, data_chunk_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, stream_close_cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, frame_recv_cb);

    /* Drop the HPACK encoder's dynamic table to zero: nghttp2 default
     * is 4 KiB per side. We're a small client; header indexing buys
     * nothing and saves ~4 KiB heap permanently. The peer is hinted via
     * SETTINGS_HEADER_TABLE_SIZE=0 below. */
    nghttp2_option *opt = NULL;
    if (nghttp2_option_new(&opt) != 0) {
        nghttp2_session_callbacks_del(cbs);
        return ESP_ERR_NO_MEM;
    }
    nghttp2_option_set_max_deflate_dynamic_table_size(opt, 0);

    int rc = nghttp2_session_client_new2(&conn->h2, cbs, conn, opt);
    nghttp2_option_del(opt);
    nghttp2_session_callbacks_del(cbs);
    if (rc != 0) {
        ESP_LOGE(TAG, "session_client_new: %d", rc);
        conn->h2 = NULL;
        return ESP_FAIL;
    }

    /* Tell the peer we won't index headers either: it can stop holding
     * its 4 KiB encoder dynamic table. ENABLE_PUSH=0 disables server
     * push (we never PUSH_PROMISE-handle). */
    const nghttp2_settings_entry settings[] = {
        { NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 0 },
        { NGHTTP2_SETTINGS_ENABLE_PUSH, 0 },
    };
    rc = nghttp2_submit_settings(conn->h2, NGHTTP2_FLAG_NONE, settings,
                                 sizeof(settings) / sizeof(settings[0]));
    if (rc != 0) {
        ESP_LOGE(TAG, "submit_settings: %d", rc);
        nghttp2_session_del(conn->h2);
        conn->h2 = NULL;
        return ESP_FAIL;
    }

    /* Pump the initial SETTINGS exchange so the first request lands on
     * a synchronized session (client SETTINGS sent → server SETTINGS
     * received → server's SETTINGS acked by us → our SETTINGS acked by
     * server). Without this pump the first request would race with the
     * SETTINGS handshake, which on Tailscale's Go server can result in
     * the server using HPACK dynamic table for our headers (since it
     * hasn't processed our HEADER_TABLE_SIZE=0 yet). */
    for (int i = 0; i < H2_SETTINGS_PUMP_MAX; i++) {
        if (nghttp2_session_want_write(conn->h2)) {
            int prc = nghttp2_session_send(conn->h2);
            if (prc != 0) {
                ESP_LOGE(TAG, "session_send during init: %d", prc);
                nghttp2_session_del(conn->h2);
                conn->h2 = NULL;
                return ESP_FAIL;
            }
        }
        if (conn->h2_settings_acked &&
            !nghttp2_session_want_write(conn->h2)) {
            return ESP_OK;
        }
        conn->h2_may_refill = true;
        int prc = nghttp2_session_recv(conn->h2);
        if (prc != 0) {
            ESP_LOGE(TAG, "session_recv during init: %d", prc);
            nghttp2_session_del(conn->h2);
            conn->h2 = NULL;
            return ESP_FAIL;
        }
    }

    ESP_LOGW(TAG, "settings handshake did not complete in %d iters",
             H2_SETTINGS_PUMP_MAX);
    /* Don't fail outright — best-effort. The first request might still
     * succeed; if not, the caller will reconnect. */
    return ESP_OK;
}

void h2_session_destroy(ts2021_conn_t *conn)
{
    if (conn == NULL) return;
    if (conn->h2 != NULL) {
        nghttp2_session_del(conn->h2);
        conn->h2 = NULL;
    }
    conn->h2_goaway          = false;
    conn->h2_settings_acked  = false;
    conn->h2_rx_len          = 0;
    conn->h2_rx_off          = 0;
}

/* Submit + drive one HTTP/2 request on the persistent session bound to
 * `conn`. Caller pre-fills h2_req_body / h2_resp_buf / h2_cb on conn. */
static esp_err_t h2_drive_request(ts2021_conn_t *conn,
                                  const char *path, const char *authority,
                                  size_t body_len)
{
    if (conn->h2 == NULL) {
        ESP_LOGE(TAG, "drive_request without active session");
        return ESP_ERR_INVALID_STATE;
    }
    if (conn->h2_goaway) {
        /* Server already told us to reconnect — refuse new streams on
         * this session. Caller (long-poll/register) will close + reopen. */
        return ESP_ERR_INVALID_STATE;
    }

    char content_length[16];
    snprintf(content_length, sizeof(content_length), "%u", (unsigned)body_len);

    nghttp2_nv hdrs[] = {
        mknv(":method",      "POST"),
        mknv(":scheme",      "https"),
        mknv(":path",        path),
        mknv(":authority",   authority),
        mknv("content-type", "application/json"),
        mknv("content-length", content_length),
    };
    nghttp2_data_provider dp = {
        .source.ptr   = NULL,
        .read_callback = data_provider_read,
    };
    int32_t stream_id = nghttp2_submit_request(conn->h2, NULL,
                                               hdrs,
                                               sizeof(hdrs) / sizeof(hdrs[0]),
                                               &dp, conn);
    if (stream_id < 0) {
        ESP_LOGE(TAG, "submit_request: %d", stream_id);
        return ESP_FAIL;
    }
    conn->h2_stream_id = stream_id;

    while (!conn->h2_stream_closed && !conn->h2_cb_stop) {
        if (nghttp2_session_want_write(conn->h2)) {
            int rc = nghttp2_session_send(conn->h2);
            if (rc != 0) {
                ESP_LOGE(TAG, "session_send: %d", rc);
                return ESP_FAIL;
            }
        }
        if (!conn->h2_stream_closed && nghttp2_session_want_read(conn->h2)) {
            conn->h2_may_refill = true;
            int rc = nghttp2_session_recv(conn->h2);
            if (rc != 0) {
                ESP_LOGE(TAG, "session_recv: %d", rc);
                return ESP_FAIL;
            }
        }
        if (conn->h2_goaway) {
            /* GOAWAY detected mid-stream. Let the current stream finish
             * if it's already closing, otherwise bail to caller for
             * reconnection. */
            if (!conn->h2_stream_closed) {
                ESP_LOGW(TAG, "GOAWAY during in-flight stream %d",
                         (int)conn->h2_stream_id);
                return ESP_ERR_INVALID_STATE;
            }
        }
        if (!nghttp2_session_want_read(conn->h2) &&
            !nghttp2_session_want_write(conn->h2)) {
            break;
        }
    }

    if (conn->h2_resp_overflow) {
        ESP_LOGW(TAG, "response truncated (status=%d)", conn->h2_status);
    }
    if (conn->h2_stream_error != 0) {
        ESP_LOGW(TAG, "stream closed with error 0x%x", conn->h2_stream_error);
    }
    return ESP_OK;
}

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

    esp_err_t err = h2_drive_request(conn, path, authority, body_len);

    *status_out   = conn->h2_status;
    *response_len = conn->h2_resp_len;

    /* Clear the borrowed pointers so the conn doesn't outlive its
     * caller's buffer. The session itself stays. */
    conn->h2_req_body = NULL;
    conn->h2_resp_buf = NULL;
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

    esp_err_t err = h2_drive_request(conn, path, authority, body_len);

    *status_out = conn->h2_status;

    conn->h2_req_body = NULL;
    conn->h2_cb       = NULL;
    conn->h2_cb_ctx   = NULL;
    return err;
}
