// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// KATs for tl_http1.h — the HTTP/1.1 response parser behind the TOFU
// GET /key (control_key.c). Covers every framing a Go net/http server
// can answer with (Content-Length, chunked, close-delimited), interim
// 1xx, the size caps, and malformed input. Every complete response is
// also replayed byte by byte: each strict prefix must say "more" (or
// "truncated" at EOF), never a premature OK or an error.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tl_http1.h"

static int g_fail;
#define CHECK(name, cond) do { \
    if (cond) printf("[%s] OK\n", name); \
    else { printf("[%s] FAIL\n", name); g_fail = 1; } } while (0)

static uint8_t g_buf[8192];

/* Parse a copy (OK compacts chunked bodies in place). */
static int parse(const char *resp, size_t len, int eof, size_t body_max,
                 tl_http1_resp_t *out)
{
    memcpy(g_buf, resp, len);
    return tl_http1_parse(g_buf, len, eof != 0, body_max, out);
}

static int body_is(const tl_http1_resp_t *r, const char *want)
{
    return r->body_len == strlen(want) &&
           memcmp(g_buf + r->body_off, want, r->body_len) == 0;
}

/* Every strict prefix of a framed response: MORE without EOF, TRUNCATED
 * with it. */
static int prefixes_need_more(const char *resp)
{
    const size_t len = strlen(resp);
    tl_http1_resp_t r;
    for (size_t n = 0; n < len; n++) {
        if (parse(resp, n, 0, 512, &r) != TL_HTTP1_MORE) return 0;
        if (parse(resp, n, 1, 512, &r) != TL_HTTP1_ERR_TRUNCATED) return 0;
    }
    return 1;
}

int main(void)
{
    tl_http1_resp_t r;

    /* A real Go net/http answer to GET /key?v=148 (headers as Go writes
     * them for a small handler response). */
    static const char go_key[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Date: Tue, 28 Oct 2026 12:00:00 GMT\r\n"
        "Content-Length: 175\r\n"
        "Connection: close\r\n"
        "\r\n"
        "{\"legacyPublicKey\":\"mkey:0000000000000000000000000000000000000000000000000000000000000000\","
        "\"publicKey\":\"mkey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}";
    {
        const char *body = strstr(go_key, "\r\n\r\n") + 4;
        int rc = parse(go_key, strlen(go_key), 0, 511, &r);
        CHECK("cl/go-key", rc == TL_HTTP1_OK && r.status == 200 && body_is(&r, body)
                           && r.body_len == 175);
        CHECK("cl/go-key-prefixes", prefixes_need_more(go_key));
        rc = parse(go_key, strlen(go_key), 1, 511, &r);
        CHECK("cl/complete-at-eof", rc == TL_HTTP1_OK && body_is(&r, body));
    }
    {
        const char *s = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhiEXTRA";
        int rc = parse(s, strlen(s), 0, 511, &r);
        CHECK("cl/bytes-past-body-ignored", rc == TL_HTTP1_OK && body_is(&r, "hi"));
    }
    {
        const char *s = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        int rc = parse(s, strlen(s), 0, 511, &r);
        CHECK("cl/zero", rc == TL_HTTP1_OK && r.body_len == 0);
    }
    {
        const char *s = "HTTP/1.1 200 OK\r\ncontent-LENGTH:5\r\n\r\nhello";
        int rc = parse(s, strlen(s), 0, 511, &r);
        CHECK("cl/name-case-and-no-ows", rc == TL_HTTP1_OK && body_is(&r, "hello"));
    }
    {
        const char *s = "HTTP/1.1 200 OK\r\nContent-Length: 5 \t\r\nContent-Length: 5\r\n\r\nhello";
        int rc = parse(s, strlen(s), 0, 511, &r);
        CHECK("cl/duplicate-equal", rc == TL_HTTP1_OK && body_is(&r, "hello"));
    }
    {
        const char *s = "HTTP/1.1 200 OK\nContent-Length: 2\n\nhi";
        int rc = parse(s, strlen(s), 0, 511, &r);
        CHECK("cl/bare-lf", rc == TL_HTTP1_OK && body_is(&r, "hi"));
    }
    {
        const char *s = "HTTP/1.0 200\r\nContent-Length: 2\r\n\r\nhi";
        int rc = parse(s, strlen(s), 0, 511, &r);
        CHECK("cl/http10-no-reason", rc == TL_HTTP1_OK && r.status == 200 && body_is(&r, "hi"));
    }

    /* --- chunked -------------------------------------------------- */
    static const char go_chunked[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/json\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "a\r\n{\"publicKe\r\n"
        "1A;name=val\r\ny\":\"mkey:0123456789abcdef\"\r\n"
        "1\r\n}\r\n"
        "0\r\n"
        "X-Trailer: t\r\n"
        "\r\n";
    {
        int rc = parse(go_chunked, strlen(go_chunked), 0, 511, &r);
        CHECK("chunked/dechunked", rc == TL_HTTP1_OK && r.status == 200 &&
              body_is(&r, "{\"publicKey\":\"mkey:0123456789abcdef\"}"));
        CHECK("chunked/prefixes", prefixes_need_more(go_chunked));
    }
    {
        const char *s = "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n2\nhi\n0\n\n";
        int rc = parse(s, strlen(s), 0, 511, &r);
        CHECK("chunked/bare-lf", rc == TL_HTTP1_OK && body_is(&r, "hi"));
    }
    {
        const char *s = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        int rc = parse(s, strlen(s), 0, 511, &r);
        CHECK("chunked/empty", rc == TL_HTTP1_OK && r.body_len == 0);
    }
    {
        /* Transfer-Encoding wins over Content-Length (RFC 9112 §6.3). */
        const char *s = "HTTP/1.1 200 OK\r\nContent-Length: 99\r\nTransfer-Encoding: Chunked\r\n\r\n"
                        "3\r\nabc\r\n0\r\n\r\n";
        int rc = parse(s, strlen(s), 0, 511, &r);
        CHECK("chunked/te-beats-cl", rc == TL_HTTP1_OK && body_is(&r, "abc"));
    }
    {
        /* Exactly at the cap is fine, one byte more is not. */
        char s[700];
        int n = snprintf(s, sizeof(s), "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                       "100\r\n%0256d\r\nff\r\n%0255d\r\n0\r\n\r\n", 0, 0);
        int rc = parse(s, (size_t)n, 0, 511, &r);
        CHECK("chunked/at-cap", rc == TL_HTTP1_OK && r.body_len == 511);
        rc = parse(s, (size_t)n, 0, 510, &r);
        CHECK("chunked/over-cap", rc == TL_HTTP1_ERR_TOO_LARGE && r.status == 200);
    }
    {
        const char *s = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n123456789\r\n";
        int rc = parse(s, strlen(s), 0, 511, &r);
        CHECK("chunked/size-overflow", rc == TL_HTTP1_ERR_TOO_LARGE);
    }
    {
        const char *s = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n";
        CHECK("chunked/bad-size", parse(s, strlen(s), 0, 511, &r) == TL_HTTP1_ERR_MALFORMED);
        s = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2 x\r\nhi\r\n0\r\n\r\n";
        CHECK("chunked/junk-after-size", parse(s, strlen(s), 0, 511, &r) == TL_HTTP1_ERR_MALFORMED);
        s = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhiX\r\n0\r\n\r\n";
        CHECK("chunked/missing-crlf", parse(s, strlen(s), 0, 511, &r) == TL_HTTP1_ERR_MALFORMED);
    }

    /* --- close-delimited ------------------------------------------ */
    {
        const char *s = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"a\":1}";
        int rc = parse(s, strlen(s), 0, 511, &r);
        CHECK("close/needs-eof", rc == TL_HTTP1_MORE);
        rc = parse(s, strlen(s), 1, 511, &r);
        CHECK("close/eof-completes", rc == TL_HTTP1_OK && body_is(&r, "{\"a\":1}"));
        rc = parse(s, strlen(s), 0, 3, &r);
        CHECK("close/over-cap", rc == TL_HTTP1_ERR_TOO_LARGE && r.status == 200);
    }
    {
        /* chunked not the final coding → close-delimited (RFC 9112 §6.3). */
        const char *s = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\nraw";
        int rc = parse(s, strlen(s), 1, 511, &r);
        CHECK("close/te-not-chunked", rc == TL_HTTP1_OK && body_is(&r, "raw"));
    }

    /* --- status handling ------------------------------------------ */
    {
        const char *s = "HTTP/1.1 100 Continue\r\n\r\n"
                        "HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n"
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        int rc = parse(s, strlen(s), 0, 511, &r);
        CHECK("status/interim-1xx-skipped", rc == TL_HTTP1_OK && r.status == 200 && body_is(&r, "ok"));
        CHECK("status/interim-prefixes", prefixes_need_more(s));
    }
    {
        const char *s = "HTTP/1.1 204 No Content\r\n\r\n";
        int rc = parse(s, strlen(s), 0, 511, &r);
        CHECK("status/204-no-body", rc == TL_HTTP1_OK && r.status == 204 && r.body_len == 0);
    }
    {
        const char *s = "HTTP/1.1 400 Bad Request\r\nContent-Length: 27\r\n\r\nunsupported client version\n";
        int rc = parse(s, strlen(s), 0, 511, &r);
        CHECK("status/400-with-body", rc == TL_HTTP1_OK && r.status == 400);
    }
    {
        const char *s = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 4096\r\n\r\n";
        int rc = parse(s, strlen(s), 0, 511, &r);
        CHECK("status/known-when-body-too-large", rc == TL_HTTP1_ERR_TOO_LARGE && r.status == 502);
    }
    {
        const char *s = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n";
        CHECK("status/101-rejected", parse(s, strlen(s), 0, 511, &r) == TL_HTTP1_ERR_MALFORMED);
    }

    /* --- malformed ------------------------------------------------ */
    {
        static const char *bad[] = {
            "HTTP/2 200 OK\r\n\r\n",
            "HTTP/1.1 20 OK\r\n\r\n",
            "HTTP/1.1 2000 OK\r\n\r\n",
            "HTTP/1.1 2x0 OK\r\n\r\n",
            "HTTP/1.1 099 Low\r\n\r\n",
            "SSH-2.0-OpenSSH_9.6\r\n\r\n",
            "HTTP/1.1 200 OK\r\nNoColonHere\r\n\r\n",
            "HTTP/1.1 200 OK\r\n: empty-name\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent Length: 2\r\n\r\nhi",
            "HTTP/1.1 200 OK\r\n folded: x\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nhi",
            "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 1,1\r\n\r\nh",
            "HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n",
        };
        int ok = 1;
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            int rc = parse(bad[i], strlen(bad[i]), 0, 511, &r);
            if (rc != TL_HTTP1_ERR_MALFORMED) {
                printf("  bad[%u] -> %d\n", (unsigned)i, rc);
                ok = 0;
            }
        }
        CHECK("malformed/all-rejected", ok);
    }
    {
        const char *s = "HTTP/1.1 200 OK\r\nContent-Length: 600\r\n\r\n";
        CHECK("cl/over-cap", parse(s, strlen(s), 0, 511, &r) == TL_HTTP1_ERR_TOO_LARGE
                             && r.status == 200);
    }
    {
        const char *s = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort";
        CHECK("cl/truncated-at-eof", parse(s, strlen(s), 1, 511, &r) == TL_HTTP1_ERR_TRUNCATED);
        CHECK("empty/more", parse("", 0, 0, 511, &r) == TL_HTTP1_MORE);
        CHECK("empty/eof-truncated", parse("", 0, 1, 511, &r) == TL_HTTP1_ERR_TRUNCATED);
    }

    /* Adversarial fuzz: random bytes after a valid head must never crash
     * or read past the buffer (ASan run), whatever the verdict. */
    {
        srand(1234);
        int ok = 1;
        for (int t = 0; t < 2000; t++) {
            char s[256];
            int n = snprintf(s, sizeof(s), "HTTP/1.1 200 OK\r\n%s\r\n",
                             (t & 1) ? "Transfer-Encoding: chunked\r\n" : "");
            size_t len = (size_t)n + (size_t)(rand() % 64);
            for (size_t i = (size_t)n; i < len; i++) {
                static const char alpha[] = "0123456789abcdefXZ;\r\n \t:";
                s[i] = alpha[rand() % (int)(sizeof(alpha) - 1)];
            }
            int rc = parse(s, len, rand() & 1, 64, &r);
            if (rc == TL_HTTP1_OK && r.body_off + r.body_len > len) ok = 0;
        }
        CHECK("fuzz/no-overrun", ok);
    }

    return g_fail ? 1 : 0;
}
