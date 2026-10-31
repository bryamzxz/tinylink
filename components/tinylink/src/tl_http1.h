// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Minimal HTTP/1.1 response parser for the one plain-HTTPS request
// tinylink makes: the TOFU `GET /key` (control_key.c). Round 1.3.2 (B1)
// replaced esp_http_client (~33 KB of flash for this single GET) with
// esp_tls + this parser.
//
// The caller sends `Connection: close` and accumulates the whole
// response in one buffer; tl_http1_parse() is re-run on the bytes so far
// after every read, and says whether the response is complete. It
// understands every framing a Go net/http server (or a proxy in front of
// it) can produce for a response:
//   * Content-Length,
//   * Transfer-Encoding: chunked (de-chunked in place, trailers skipped),
//   * neither → the body runs to EOF (close-delimited),
// plus interim 1xx responses (skipped), 204/304 (no body) and bare-LF
// line endings. Transfer-Encoding wins over Content-Length (RFC 9112
// §6.3); conflicting Content-Length values are rejected.
//
// Pure, header-only, no allocation; host-tested by tools/test/test_http1.c.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TL_HTTP1_OK             0   /* complete response in the buffer        */
#define TL_HTTP1_MORE           1   /* need more bytes (and !eof)             */
#define TL_HTTP1_ERR_MALFORMED (-1)
#define TL_HTTP1_ERR_TOO_LARGE (-2) /* body > body_max; `status` is valid     */
#define TL_HTTP1_ERR_TRUNCATED (-3) /* EOF before the framed body / headers ended */

typedef struct {
    int    status;     /* final status code (0 until the headers are in) */
    size_t body_off;   /* body = buf[body_off .. body_off + body_len)     */
    size_t body_len;
} tl_http1_resp_t;

/* Find the end of the line starting at `pos`: returns the index of its
 * '\n' and sets *end to where the content stops (before an optional
 * '\r'). Returns `len` when no '\n' is buffered yet. */
static inline size_t tl_http1_line(const uint8_t *b, size_t len, size_t pos,
                                   size_t *end)
{
    const uint8_t *nl = (pos < len) ? memchr(b + pos, '\n', len - pos) : NULL;
    if (nl == NULL) return len;
    size_t i = (size_t)(nl - b);
    *end = (i > pos && b[i - 1] == '\r') ? i - 1 : i;
    return i;
}

static inline uint8_t tl_http1_lc(uint8_t c)
{
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 32) : c;
}

/* Case-insensitive compare of b[s..e) with the lowercase literal `lit`. */
static inline bool tl_http1_ieq(const uint8_t *b, size_t s, size_t e,
                                const char *lit)
{
    const size_t n = strlen(lit);
    if (e - s != n) return false;
    for (size_t i = 0; i < n; i++) {
        if (tl_http1_lc(b[s + i]) != (uint8_t)lit[i]) return false;
    }
    return true;
}

static inline bool tl_http1_ows(uint8_t c) { return c == ' ' || c == '\t'; }

/* Parse buf[0..len). `eof` = the peer has closed the connection (it
 * completes a close-delimited body and turns "need more" into
 * TRUNCATED). The body may not exceed `body_max` bytes.
 *
 * Non-destructive until it returns TL_HTTP1_OK for a chunked body: then
 * the chunks are compacted in place to buf[body_off..). Do not parse the
 * same buffer again after an OK. */
static inline int tl_http1_parse(uint8_t *buf, size_t len, bool eof,
                                 size_t body_max, tl_http1_resp_t *out)
{
    const int need_more = eof ? TL_HTTP1_ERR_TRUNCATED : TL_HTTP1_MORE;
    size_t pos = 0;
    out->status = 0;
    out->body_off = 0;
    out->body_len = 0;

    for (;;) {   /* one iteration per response head; 1xx heads loop */
        /* Status line: HTTP/1.x SP 3DIGIT [SP reason] */
        size_t end = 0;
        size_t nl = tl_http1_line(buf, len, pos, &end);
        if (nl == len) return need_more;
        if (end - pos < 12 || memcmp(buf + pos, "HTTP/1.", 7) != 0 ||
            buf[pos + 7] < '0' || buf[pos + 7] > '9' || buf[pos + 8] != ' ') {
            return TL_HTTP1_ERR_MALFORMED;
        }
        int status = 0;
        for (size_t i = pos + 9; i < pos + 12; i++) {
            if (buf[i] < '0' || buf[i] > '9') return TL_HTTP1_ERR_MALFORMED;
            status = status * 10 + (buf[i] - '0');
        }
        if (end - pos > 12 && buf[pos + 12] != ' ') return TL_HTTP1_ERR_MALFORMED;
        if (status < 100) return TL_HTTP1_ERR_MALFORMED;

        /* Header fields up to the empty line. */
        bool   te = false, chunked = false, have_cl = false;
        size_t cl = 0;
        pos = nl + 1;
        for (;;) {
            nl = tl_http1_line(buf, len, pos, &end);
            if (nl == len) return need_more;
            if (end == pos) { pos = nl + 1; break; }          /* end of head */
            size_t colon = pos;
            while (colon < end && buf[colon] != ':') colon++;
            if (colon == end || colon == pos) return TL_HTTP1_ERR_MALFORMED;
            for (size_t i = pos; i < colon; i++) {            /* token chars */
                if (buf[i] <= ' ' || buf[i] >= 0x7f) return TL_HTTP1_ERR_MALFORMED;
            }
            size_t vs = colon + 1, ve = end;
            while (vs < ve && tl_http1_ows(buf[vs])) vs++;
            while (ve > vs && tl_http1_ows(buf[ve - 1])) ve--;

            if (tl_http1_ieq(buf, pos, colon, "content-length")) {
                if (vs == ve) return TL_HTTP1_ERR_MALFORMED;
                size_t v = 0;
                for (size_t i = vs; i < ve; i++) {
                    if (buf[i] < '0' || buf[i] > '9') return TL_HTTP1_ERR_MALFORMED;
                    if (v > (SIZE_MAX - 9) / 10) return TL_HTTP1_ERR_MALFORMED;
                    v = v * 10 + (size_t)(buf[i] - '0');
                }
                if (have_cl && v != cl) return TL_HTTP1_ERR_MALFORMED;
                have_cl = true;
                cl = v;
            } else if (tl_http1_ieq(buf, pos, colon, "transfer-encoding")) {
                /* Chunked iff it is the LAST coding of the last field. */
                te = true;
                size_t ts = ve;
                while (ts > vs && buf[ts - 1] != ',') ts--;
                while (ts < ve && tl_http1_ows(buf[ts])) ts++;
                chunked = tl_http1_ieq(buf, ts, ve, "chunked");
            }
            pos = nl + 1;
        }

        if (status == 101) return TL_HTTP1_ERR_MALFORMED;  /* never asked */
        if (status < 200) continue;                        /* interim 1xx */

        out->status   = status;
        out->body_off = pos;
        if (status == 204 || status == 304) return TL_HTTP1_OK;

        if (te && chunked) {
            /* Pass 1 (read-only): validate the framing, find the end. */
            size_t p = pos, total = 0;
            for (;;) {
                nl = tl_http1_line(buf, len, p, &end);
                if (nl == len) return need_more;
                size_t i = p, sz = 0;
                for (; i < end; i++) {
                    const uint8_t c = tl_http1_lc(buf[i]);
                    int d = (c >= '0' && c <= '9') ? c - '0'
                          : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
                    if (d < 0) break;
                    if (i - p >= 8) return TL_HTTP1_ERR_TOO_LARGE;
                    sz = (sz << 4) | (size_t)d;
                }
                if (i == p) return TL_HTTP1_ERR_MALFORMED;
                while (i < end && tl_http1_ows(buf[i])) i++;
                if (i < end && buf[i] != ';') return TL_HTTP1_ERR_MALFORMED;
                p = nl + 1;
                if (sz == 0) {
                    /* Trailer fields (ignored) up to the empty line. */
                    for (;;) {
                        nl = tl_http1_line(buf, len, p, &end);
                        if (nl == len) return need_more;
                        if (end == p) break;
                        p = nl + 1;
                    }
                    break;
                }
                if (sz > body_max - total) return TL_HTTP1_ERR_TOO_LARGE;
                total += sz;
                if (len - p < sz) return need_more;
                p += sz;
                if (p < len && buf[p] == '\r') p++;
                if (p >= len) return need_more;
                if (buf[p] != '\n') return TL_HTTP1_ERR_MALFORMED;
                p++;
            }
            /* Pass 2: compact the chunk data to body_off (moves only
             * leftwards; framing was validated above). */
            size_t w = pos;
            p = pos;
            for (;;) {
                nl = tl_http1_line(buf, len, p, &end);
                size_t sz = 0;
                for (size_t i = p; i < end; i++) {
                    const uint8_t c = tl_http1_lc(buf[i]);
                    int d = (c >= '0' && c <= '9') ? c - '0'
                          : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
                    if (d < 0) break;
                    sz = (sz << 4) | (size_t)d;
                }
                p = nl + 1;
                if (sz == 0) break;
                memmove(buf + w, buf + p, sz);
                w += sz;
                p += sz;
                if (buf[p] == '\r') p++;
                p++;   /* '\n' */
            }
            out->body_len = total;
            return TL_HTTP1_OK;
        }

        if (!te && have_cl) {
            if (cl > body_max) return TL_HTTP1_ERR_TOO_LARGE;
            if (len - pos < cl) return need_more;
            out->body_len = cl;   /* bytes past it are ignored */
            return TL_HTTP1_OK;
        }

        /* Close-delimited (no framing, or a non-chunked coding). */
        if (len - pos > body_max) return TL_HTTP1_ERR_TOO_LARGE;
        if (!eof) return TL_HTTP1_MORE;
        out->body_len = len - pos;
        return TL_HTTP1_OK;
    }
}

#ifdef __cplusplus
}
#endif
