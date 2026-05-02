// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "h2_client.h"

#include <string.h>

#include "esp_log.h"
#include "nghttp2/nghttp2.h"

#include "ts2021_client.h"

static const char *TAG = "h2";

#define RECV_BUF_LEN  TS2021_RECORD_PLAINTEXT_MAX

/* Per-request state passed via session user_data. Either response
 * accumulation (`resp_buf`) is used, or a streaming callback (`cb`),
 * not both. */
typedef struct {
    ts2021_conn_t *ts2021;

    /* Request body cursor for data_provider. */
    const uint8_t *req_body;
    size_t         req_body_len;
    size_t         req_body_off;

    /* Response collection (one-shot mode). */
    int      status;
    uint8_t *resp_buf;
    size_t   resp_cap;
    size_t   resp_len;
    bool     resp_overflow;

    /* Streaming mode. */
    h2_data_callback cb;
    void            *cb_ctx;
    bool             cb_stop;     /* set if cb returned <0 */

    /* Plaintext receive buffer (decrypted Noise record byte stream). */
    uint8_t  recv_buf[RECV_BUF_LEN];
    size_t   recv_buf_len;
    size_t   recv_buf_off;

    int32_t  stream_id;
    bool     stream_closed;
    int      stream_error;
} h2_req_t;

/* nghttp2 -> network. nghttp2 hands us framed HTTP/2 bytes; we wrap them
 * in a Noise transport record and send through ts2021. */
static ssize_t send_cb(nghttp2_session *session, const uint8_t *data,
                       size_t length, int flags, void *user_data)
{
    (void)session; (void)flags;
    h2_req_t *r = (h2_req_t *)user_data;

    /* ts2021_send caps at TS2021_RECORD_PLAINTEXT_MAX per record. Chunk. */
    size_t off = 0;
    while (off < length) {
        size_t take = length - off;
        if (take > TS2021_RECORD_PLAINTEXT_MAX) {
            take = TS2021_RECORD_PLAINTEXT_MAX;
        }
        if (ts2021_send(r->ts2021, data + off, take) != ESP_OK) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        off += take;
    }
    return (ssize_t)length;
}

/* Network -> nghttp2. nghttp2 wants up to `length` bytes; we keep a
 * small ring of decrypted Noise plaintext and refill it on demand. */
static ssize_t recv_cb(nghttp2_session *session, uint8_t *buf,
                       size_t length, int flags, void *user_data)
{
    (void)session; (void)flags;
    h2_req_t *r = (h2_req_t *)user_data;

    if (r->recv_buf_off >= r->recv_buf_len) {
        size_t got = 0;
        if (ts2021_recv(r->ts2021, r->recv_buf, sizeof(r->recv_buf),
                        &got) != ESP_OK) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        r->recv_buf_len = got;
        r->recv_buf_off = 0;
    }
    size_t avail = r->recv_buf_len - r->recv_buf_off;
    size_t take = (length < avail) ? length : avail;
    memcpy(buf, r->recv_buf + r->recv_buf_off, take);
    r->recv_buf_off += take;
    return (ssize_t)take;
}

/* Body provider for the outgoing POST: copies from req_body[req_body_off]
 * into the buffer nghttp2 hands us, marking END_STREAM when drained. */
static ssize_t data_provider_read(nghttp2_session *session, int32_t stream_id,
                                  uint8_t *buf, size_t length,
                                  uint32_t *data_flags,
                                  nghttp2_data_source *source, void *user_data)
{
    (void)session; (void)stream_id; (void)source;
    h2_req_t *r = (h2_req_t *)user_data;

    size_t remaining = r->req_body_len - r->req_body_off;
    size_t take = (length < remaining) ? length : remaining;
    if (take > 0) {
        memcpy(buf, r->req_body + r->req_body_off, take);
        r->req_body_off += take;
    }
    if (r->req_body_off >= r->req_body_len) {
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
    h2_req_t *r = (h2_req_t *)user_data;

    if (frame->hd.type != NGHTTP2_HEADERS ||
        frame->headers.cat != NGHTTP2_HCAT_RESPONSE) {
        return 0;
    }
    if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
        char status_str[8] = {0};
        size_t copy = (valuelen < sizeof(status_str) - 1)
                       ? valuelen : sizeof(status_str) - 1;
        memcpy(status_str, value, copy);
        r->status = atoi(status_str);
    }
    return 0;
}

static int data_chunk_cb(nghttp2_session *session, uint8_t flags,
                         int32_t stream_id, const uint8_t *data,
                         size_t len, void *user_data)
{
    (void)session; (void)flags; (void)stream_id;
    h2_req_t *r = (h2_req_t *)user_data;

    if (r->cb != NULL) {
        int rc = r->cb(data, len, r->cb_ctx);
        if (rc < 0) {
            r->cb_stop = true;
        }
        return 0;
    }

    if (r->resp_len + len > r->resp_cap) {
        size_t take = r->resp_cap - r->resp_len;
        if (take > 0) {
            memcpy(r->resp_buf + r->resp_len, data, take);
            r->resp_len += take;
        }
        r->resp_overflow = true;
        return 0;
    }
    memcpy(r->resp_buf + r->resp_len, data, len);
    r->resp_len += len;
    return 0;
}

static int stream_close_cb(nghttp2_session *session, int32_t stream_id,
                           uint32_t error_code, void *user_data)
{
    (void)session;
    h2_req_t *r = (h2_req_t *)user_data;
    if (stream_id == r->stream_id) {
        r->stream_closed = true;
        r->stream_error = (int)error_code;
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

/* Shared driver: build the session, fire the request, pump send/recv
 * until either the stream closes or the streaming callback signaled
 * stop. Caller fills `r->resp_buf` (one-shot) or `r->cb`/`r->cb_ctx`
 * (streaming) ahead of the call. */
static esp_err_t h2_drive_request(h2_req_t *r,
                                  const char *path, const char *authority,
                                  size_t body_len)
{
    nghttp2_session_callbacks *cbs = NULL;
    if (nghttp2_session_callbacks_new(&cbs) != 0) return ESP_ERR_NO_MEM;
    nghttp2_session_callbacks_set_send_callback(cbs, send_cb);
    nghttp2_session_callbacks_set_recv_callback(cbs, recv_cb);
    nghttp2_session_callbacks_set_on_header_callback(cbs, header_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, data_chunk_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, stream_close_cb);

    nghttp2_session *session = NULL;
    int rc = nghttp2_session_client_new(&session, cbs, r);
    nghttp2_session_callbacks_del(cbs);
    if (rc != 0) {
        ESP_LOGE(TAG, "session_client_new: %d", rc);
        return ESP_FAIL;
    }

    /* Disable HPACK dynamic table indexing on our side: we never benefit
     * from it for one-shot requests. The server may still index its own
     * responses; nghttp2 handles that transparently on receive. */
    const nghttp2_settings_entry settings[] = {
        { NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, 0 },
        { NGHTTP2_SETTINGS_ENABLE_PUSH, 0 },
    };
    rc = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, settings,
                                 sizeof(settings) / sizeof(settings[0]));
    if (rc != 0) {
        ESP_LOGE(TAG, "submit_settings: %d", rc);
        nghttp2_session_del(session);
        return ESP_FAIL;
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
    int32_t stream_id = nghttp2_submit_request(session, NULL,
                                               hdrs,
                                               sizeof(hdrs) / sizeof(hdrs[0]),
                                               &dp, r);
    if (stream_id < 0) {
        ESP_LOGE(TAG, "submit_request: %d", stream_id);
        nghttp2_session_del(session);
        return ESP_FAIL;
    }
    r->stream_id = stream_id;

    /* Drive send/recv until the stream closes or the streaming callback
     * asks us to stop. nghttp2_session_send drains the outbound queue
     * (via send_cb); _recv pulls one frame in (via recv_cb). */
    while (!r->stream_closed && !r->cb_stop) {
        if (nghttp2_session_want_write(session)) {
            rc = nghttp2_session_send(session);
            if (rc != 0) {
                ESP_LOGE(TAG, "session_send: %d", rc);
                nghttp2_session_del(session);
                return ESP_FAIL;
            }
        }
        if (!r->stream_closed && nghttp2_session_want_read(session)) {
            rc = nghttp2_session_recv(session);
            if (rc != 0) {
                ESP_LOGE(TAG, "session_recv: %d", rc);
                nghttp2_session_del(session);
                return ESP_FAIL;
            }
        }
        if (!nghttp2_session_want_read(session) &&
            !nghttp2_session_want_write(session)) {
            break;
        }
    }

    nghttp2_session_del(session);

    if (r->resp_overflow) {
        ESP_LOGW(TAG, "response truncated (status=%d)", r->status);
    }
    if (r->stream_error != 0) {
        ESP_LOGW(TAG, "stream closed with error 0x%x", r->stream_error);
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

    h2_req_t r = {
        .ts2021       = conn,
        .req_body     = body,
        .req_body_len = body_len,
        .resp_buf     = response_buf,
        .resp_cap     = response_buf_size,
        .stream_id    = -1,
    };

    esp_err_t err = h2_drive_request(&r, path, authority, body_len);
    if (err != ESP_OK) return err;

    *status_out   = r.status;
    *response_len = r.resp_len;
    return ESP_OK;
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

    h2_req_t r = {
        .ts2021       = conn,
        .req_body     = body,
        .req_body_len = body_len,
        .cb           = cb,
        .cb_ctx       = cb_ctx,
        .stream_id    = -1,
    };

    esp_err_t err = h2_drive_request(&r, path, authority, body_len);
    if (err != ESP_OK) return err;

    *status_out = r.status;
    return ESP_OK;
}
