// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "ts2021_client.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "esp_crt_bundle.h"
#include "esp_timer.h"
#include "tl_time.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include "mbedtls/ssl.h"

#include "h2_client.h"
#include "tls_io.h"
#include "tls_resume.h"
#include "crypto/secure_zero.h"

static const char *TAG = "ts2021";

#define UPGRADE_TOKEN  "tailscale-control-protocol"
#define HANDSHAKE_HDR  "X-Tailscale-Handshake"

#define TLS_TIMEOUT_MS 30000

/* Liveness budget for every blocking read/write on the control conn:
 * consecutive WANT_READ/WANT_WRITE polls (one SO_RCVTIMEO period =
 * TLS_TIMEOUT_MS each) tolerated before the stream is declared dead.
 * The server emits a KeepAlive on the map stream every ~60 s
 * (direct.go:1051 "we should be receiving a keep alive ping every
 * minute"), and the upstream client kills the poll after 120 s of
 * read inactivity (direct.go:1054 `watchdogTimeout = 120s`, re-armed
 * per read-loop iteration). The default 120 s budget (4 polls) mirrors
 * that: two missed KeepAlives. Without this bound a half-open TCP conn
 * — control plane instance replaced without FIN/RST, NAT flow expired
 * — parks the long-poll task in the retry loop FOREVER and the node
 * never reconnects until a manual power cycle (the "device stops
 * reconnecting after a control-plane change" failure observed in
 * production, 2026-07). */
#define TS2021_MAX_IDLE_POLLS \
    ((uint32_t)((CONFIG_TINYLINK_STREAM_IDLE_TIMEOUT_S * 1000 \
                 + TLS_TIMEOUT_MS - 1) / TLS_TIMEOUT_MS))

/* ts2021 over plain HTTP :80 (round 1.3.5, D10a). Upstream
 * (control/controlhttp/client.go dialHostOpt) dials http://host:80/ts2021
 * first and races https://host:443 after httpsFallbackDelay = 500 ms; the
 * Noise IK handshake authenticates the server by its known public key,
 * so TLS adds nothing but a second cipher — and, here, the largest piece
 * of the boot: on the 1.3.4 sensor (2026-10-29) DNS + TCP + TLS took
 * 2.4–3 s (cert validated 7.50 s, Noise init sent 8.21 s, 101 8.38 s,
 * Noise done 8.41 s), the chain verify and the ECDHE most of it; over :80
 * the same exchange is TCP + one RTT. Like upstream for an https:// URL
 * without a port, only with the default control port 443 (a custom
 * HTTPS port says nothing about a :80 server). */
#if defined(CONFIG_TINYLINK_CONTROL_PLAIN_HTTP) && CONFIG_TINYLINK_CONTROL_PORT == 443
#define TS2021_PLAIN 1
#else
#define TS2021_PLAIN 0
#endif
#define TS2021_PLAIN_PORT 80

/* One sequential attempt instead of upstream's race (one TLS-capable
 * heap, one socket at a time), so :80 has a hard budget instead of a
 * head start: TS2021_PLAIN_TIMEOUT_MS for the TCP connect (esp-tls's
 * select), as SO_RCVTIMEO / SO_SNDTIMEO, and as the deadline for the
 * whole unauthenticated exchange after it (request → 101 → Noise msg2).
 * 3 s: the 1.3.4 sensor log has 0.17 s from "Noise init sent" to "101"
 * (one RTT to controlplane) and the TCP connect is one RTT more; lwIP
 * retransmits a lost SYN after CONFIG_LWIP_TCP_RTO_TIME = 1.5 s, so 3 s
 * still connects through one lost SYN or SYN-ACK at RTTs up to ~1.5 s
 * and leaves the 101 the same margin for one retransmission. A network
 * that drops :80 silently pays this once per boot (then :80 is off,
 * below); one that refuses it or answers with a redirect, ~1 RTT. The
 * deadline also stops a middlebox from trickling a 101 header one byte
 * per SO_RCVTIMEO (4 095 bytes × 3 s) — over TLS only the authenticated
 * server could. */
#ifndef TS2021_PLAIN_TIMEOUT_MS
#define TS2021_PLAIN_TIMEOUT_MS 3000
#endif

/* Upstream's "LastNoiseDialWasRecent" (health.go: < 2 min since the last
 * dial → force :443) works around networks that pass the :80 upgrade and
 * then cut the connection (tailscale#13597). Here: a :80 conn that died
 * of a transport failure within this long of its Noise handshake sends
 * the next dial — only that one — to :443. A deliberate recycle
 * (ts2021_abort_reads) or a clean end does not count. */
#define TS2021_PLAIN_EARLY_DROP_S 120

/* :80 state for this boot (RAM only): off once a :80 attempt failed and
 * :443 answered right after it (the server is fine, :80 is not — a
 * firewall, a proxy, a redirect); one-dial :443 after an early drop. */
static bool s_plain_off;
static bool s_tls_next;

/* TLS session of the last :443 conn, for the next :443 connect (D9). */
static tls_resume_slot_t s_resume;

/* base64 encoder used for the X-Tailscale-Handshake header. */
static int b64_encode(const uint8_t *in, size_t in_len,
                      char *out, size_t out_size)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t needed = ((in_len + 2) / 3) * 4 + 1;
    if (needed > out_size) return -1;

    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in_len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < in_len) v |= (uint32_t)in[i + 2];
        out[o++] = alphabet[(v >> 18) & 0x3F];
        out[o++] = alphabet[(v >> 12) & 0x3F];
        out[o++] = (i + 1 < in_len) ? alphabet[(v >> 6) & 0x3F] : '=';
        out[o++] = (i + 2 < in_len) ? alphabet[v & 0x3F]        : '=';
    }
    out[o] = '\0';
    return 0;
}

/* Cooperative stream abort. Set from ANY task (tinylink.c's endpoint
 * push) to make the long-poll's blocking record read fail at its next
 * poll — esp_tls_conn_read returns WANT_READ every SO_RCVTIMEO (30 s),
 * so the abort lands within one poll without touching the socket from
 * a foreign task. Cleared by ts2021_connect, i.e. it only ever kills
 * the conn that was open when it was raised. One flag for the single
 * control conn this firmware keeps. */
static volatile bool s_abort_reads;

void ts2021_abort_reads(void)
{
    s_abort_reads = true;
}

/* Transport shims for tls_io_*: esp_tls on :443, the socket on :80
 * (tls_io_sock_*: same return contract). The cast on the TLS write side
 * hides esp_tls_conn_write's `void *` (non-const) second parameter — we
 * never mutate it. */
static ssize_t ts2021_conn_read(void *ctx, uint8_t *buf, size_t len)
{
    ts2021_conn_t *c = (ts2021_conn_t *)ctx;
    if (s_abort_reads) return TS2021_ERR_READ_ABORTED;
    if (!c->plain) return esp_tls_conn_read(c->tls, buf, len);
    if (c->hs_deadline_us != 0 && esp_timer_get_time() > c->hs_deadline_us) {
        return TS2021_ERR_HS_DEADLINE;
    }
    return tls_io_sock_read(c->sock, buf, len);
}
static ssize_t ts2021_conn_write(void *ctx, const uint8_t *buf, size_t len)
{
    ts2021_conn_t *c = (ts2021_conn_t *)ctx;
    return c->plain ? tls_io_sock_write(c->sock, buf, len)
                    : esp_tls_conn_write(c->tls, (void *)buf, len);
}

/* Consecutive silent socket polls a read / write may sit out: the stream
 * budget, or one poll during the unauthenticated part of a :80 handshake. */
static uint32_t idle_budget(const ts2021_conn_t *c)
{
    return c->hs_idle != 0 ? c->hs_idle : TS2021_MAX_IDLE_POLLS;
}

/* The socket timeout behind one such poll. */
static uint32_t poll_ms(const ts2021_conn_t *c)
{
    return c->hs_idle != 0 ? TS2021_PLAIN_TIMEOUT_MS : TLS_TIMEOUT_MS;
}

static esp_err_t tls_read_full(ts2021_conn_t *c, uint8_t *buf, size_t need)
{
    int rc = tls_io_read_full(ts2021_conn_read, c, buf, need, idle_budget(c));
    if (rc != 0) {
        if (rc == TS2021_ERR_READ_ABORTED) {
            ESP_LOGI(TAG, "control stream read aborted on request (recycle)");
            return ESP_FAIL;
        }
        c->io_failed = true;
        if (rc == TS2021_ERR_HS_DEADLINE ||
            (rc == TLS_IO_ERR_IDLE_TIMEOUT && c->hs_idle != 0)) {
            ESP_LOGW(TAG, ":80 handshake: no answer within %d ms",
                     TS2021_PLAIN_TIMEOUT_MS);
        } else if (rc == TLS_IO_ERR_IDLE_TIMEOUT) {
            ESP_LOGW(TAG, "control stream silent past %d s — declaring dead",
                     CONFIG_TINYLINK_STREAM_IDLE_TIMEOUT_S);
        } else {
            ESP_LOGE(TAG, "tls_read_full failed: %d", rc);
        }
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t tls_write_full(ts2021_conn_t *c, const uint8_t *buf, size_t len)
{
    int rc = tls_io_write_full(ts2021_conn_write, c, buf, len, idle_budget(c));
    if (rc != 0) {
        c->io_failed = true;
        ESP_LOGE(TAG, "tls_write_full failed: %d", rc);
        return ESP_FAIL;
    }
    return ESP_OK;
}

/* TCP_NODELAY on the control conn (round 1.3.2, B8). Every write here is
 * a complete message — one HTTP request, one Noise record — and the next
 * step waits for the server's answer, so Nagle only ever cost us: a
 * small record behind an unacknowledged one sat out the server's delayed
 * ACK (~1 RTT, up to 200 ms) on the upgrade, the Noise handshake and the
 * h2 request bursts. Set right after the TLS handshake (esp-tls has no
 * hook before it) or the :80 TCP connect; a failure only costs latency,
 * so it is logged and ignored. */
static void set_tcp_nodelay(int fd)
{
    int one = 1;
    if (fd < 0 || setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0) {
        ESP_LOGW(TAG, "TCP_NODELAY not set (fd=%d)", fd);
    }
}

static esp_err_t read_upgrade_response(ts2021_conn_t *c,
                                       uint8_t *buf, size_t buf_size)
{
    size_t   total = 0;
    uint32_t idle  = 0;
    while (total < buf_size - 1) {
        ssize_t r = ts2021_conn_read(c, buf + total, 1);
        if (r == MBEDTLS_ERR_SSL_WANT_READ ||
            r == MBEDTLS_ERR_SSL_WANT_WRITE) {
            /* Same transient-timeout class as tls_io_read_full handles
             * — but here we read one byte at a time scanning for
             * "\r\n\r\n", so we open-code the retry instead of
             * pulling the helper. Same liveness budget as the record
             * reader: a server that accepts the connection but never
             * answers the upgrade must not park the caller forever. */
            if (++idle >= idle_budget(c)) {
                ESP_LOGE(TAG, "no 101 response within %u ms — giving up",
                         (unsigned)(idle_budget(c) * poll_ms(c)));
                return ESP_FAIL;
            }
            continue;
        }
        idle = 0;
        if (r == TS2021_ERR_HS_DEADLINE) {
            ESP_LOGW(TAG, ":80 handshake: no 101 within %d ms", TS2021_PLAIN_TIMEOUT_MS);
            return ESP_FAIL;
        }
        if (r <= 0) {
            ESP_LOGE(TAG, "read while waiting for 101: %d", (int)r);
            return ESP_FAIL;
        }
        total += (size_t)r;
        buf[total] = '\0';
        if (total >= 4 && memcmp(buf + total - 4, "\r\n\r\n", 4) == 0) {
            break;
        }
    }
    if (total >= buf_size - 1) return ESP_ERR_INVALID_SIZE;

    if (strncmp((const char *)buf, "HTTP/1.1 101 ", 13) != 0 &&
        strncmp((const char *)buf, "HTTP/1.0 101 ", 13) != 0) {
        ESP_LOGE(TAG, "control plane did not return 101: '%.*s'",
                 (int)(total > 60 ? 60 : total), (const char *)buf);
        return ESP_FAIL;
    }
    return ESP_OK;
}

/* Reads one controlbase frame header (3 bytes: type || BE16 length) and
 * up to len bytes of payload. Caller-supplied buf must be ≥ len bytes. */
static esp_err_t read_record_frame(ts2021_conn_t *c, uint8_t *type_out,
                                   uint8_t *payload, size_t payload_max,
                                   size_t *payload_len)
{
    uint8_t hdr[TS2021_HEADER_LEN];
    if (tls_read_full(c, hdr, sizeof(hdr)) != ESP_OK) return ESP_FAIL;
    size_t len = ((size_t)hdr[1] << 8) | (size_t)hdr[2];
    if (len > payload_max) {
        ESP_LOGE(TAG, "record too large: %u > %u",
                 (unsigned)len, (unsigned)payload_max);
        c->io_failed = true;
        return ESP_ERR_INVALID_SIZE;
    }
    if (len > 0) {
        if (tls_read_full(c, payload, len) != ESP_OK) return ESP_FAIL;
    }
    *type_out = hdr[0];
    *payload_len = len;
    return ESP_OK;
}

/* Read the next transport record into the conn's record ring and
 * decrypt it there (round 1.3.4, D4): the ciphertext goes straight into
 * h2_rx and is opened in place, where it used to land in a 4 096-B `ct`
 * stack array on every task that reads the control conn (the deepest
 * frame of the long-poll). The plaintext is h2_rx[0..*len); a failed
 * tag leaves ciphertext only, never plaintext. Every caller has drained
 * the ring before it asks for the next record. */
static esp_err_t recv_record(ts2021_conn_t *c, size_t *len)
{
    uint8_t  type;
    size_t   ct_len = 0;
    c->h2_rx_off = 0;
    c->h2_rx_len = 0;
    if (read_record_frame(c, &type, c->h2_rx, sizeof(c->h2_rx), &ct_len) != ESP_OK) {
        return ESP_FAIL;
    }
    if (type == TS2021_MSG_ERROR) {
        ESP_LOGE(TAG, "control plane error: %.*s",
                 (int)(ct_len > 200 ? 200 : ct_len), (const char *)c->h2_rx);
        return ESP_FAIL;
    }
    if (type != TS2021_MSG_RECORD) {
        ESP_LOGE(TAG, "unexpected post-handshake frame type 0x%02x", type);
        c->io_failed = true;
        return ESP_FAIL;
    }
    if (noise_ik_decrypt(&c->noise, c->h2_rx, sizeof(c->h2_rx), c->h2_rx, ct_len,
                         len) != ESP_OK) {
        c->io_failed = true;   /* not from the server: tampering */
        return ESP_FAIL;
    }
    c->h2_rx_len = *len;
    return ESP_OK;
}

/* After the Noise handshake the server may send an optional
 * tailcfg.EarlyNoise payload before the HTTP/2 session begins:
 *     magic[5] || BE32 length || JSON[length]
 * followed by the HTTP/2 stream. The early payload is optional; some
 * servers (and pre-capver-113 clients) never receive one.
 *
 * CRITICAL: the control plane does NOT pack this header into a single
 * Noise record. Observed in vivo against tailscale.com for a capver>=113
 * client, the 5-byte magic arrives as its OWN record, with the BE32
 * length and the JSON in later records. So the 9-byte header must be read
 * as a byte STREAM that can span record boundaries — exactly like upstream
 * control/ts2021/conn.go readHeader (which does io.ReadFull(conn, hdr[:9])
 * over the decrypted stream). The earlier record-aligned version assumed
 * the whole 9-byte header fit in the first record and mis-stashed a short
 * 5-byte magic record as HTTP/2 data, desyncing the stream so the server
 * closed the connection (h2_session_init -> EOF).
 *
 * Records are read into the conn's h2_rx ring and consumed byte-wise.
 * Whatever is left once the header (and any JSON) is dealt with stays
 * there as the window [h2_rx_off, h2_rx_len) — the first HTTP/2 bytes,
 * which the HTTP/2 layer parses before it reads another record. Until
 * round 1.3.4 (D5) that tail was copied into a second 4 077-B buffer,
 * `rx_residual`. */

/* The stream turned out to start with HTTP/2 at rec[off] (the first byte
 * that differs from the magic), after `matched` bytes that equal the
 * magic's first `matched` bytes. Those may have come from earlier
 * records (a record boundary inside the magic), so they are not
 * necessarily in front of rec[off]; but their value is known — the magic
 * itself — so put them back in front of the tail: the window becomes
 * magic[0..matched) || rec[off..len). matched ≤ 4 and len ≤ 4 080 (the
 * plaintext of the largest record read_record_frame accepts), so the
 * result fits the 4 096-B ring. */
static void keep_http2_start(ts2021_conn_t *c, size_t off, size_t len,
                             size_t matched)
{
    _Static_assert(sizeof(c->h2_rx) >= TS2021_MAX_MESSAGE - NOISE_TAGLEN +
                                       TS2021_EARLY_PAYLOAD_MAGIC_LEN - 1,
                   "h2_rx must hold a record plus a put-back magic prefix");
    uint8_t *rec = c->h2_rx;
    memmove(rec + matched, rec + off, len - off);
    memcpy(rec, TS2021_EARLY_PAYLOAD_MAGIC, matched);
    c->h2_rx_off = 0;
    c->h2_rx_len = matched + (len - off);
}

static esp_err_t consume_early_payload(ts2021_conn_t *c)
{
    /* Record scratch: the conn's h2_rx ring, where recv_record reads
     * and decrypts each record. It is idle until h2_session_init runs at
     * the very end of ts2021_connect. Saves 4 077 B of stack on the
     * connect path (this function is inlined into ts2021_connect). */
    uint8_t *rec = c->h2_rx;
    size_t  rec_len = 0, rec_off = 0;

    /* 1) Read up to the 9-byte early-payload header from the record stream.
     *    Bail to the "no early payload" path at the first of the 5 magic
     *    bytes that does not match — from there on the bytes are HTTP/2
     *    (a frame header's first byte is 0x00 for any frame we accept, so
     *    in practice that is the very first byte). */
    uint8_t hdr[TS2021_EARLY_PAYLOAD_HDR_LEN];
    size_t  hdr_have = 0;

    while (hdr_have < TS2021_EARLY_PAYLOAD_HDR_LEN) {
        if (rec_off == rec_len) {
            if (recv_record(c, &rec_len) != ESP_OK) return ESP_FAIL;
            rec_off = 0;
            if (rec_len == 0) continue;  /* empty record: pull the next one */
        }
        const uint8_t b = rec[rec_off];
        if (hdr_have < TS2021_EARLY_PAYLOAD_MAGIC_LEN &&
            b != (uint8_t)TS2021_EARLY_PAYLOAD_MAGIC[hdr_have]) {
            /* No early payload: the bytes taken so far (a magic prefix)
             * plus the rest of this record are the first HTTP/2 bytes,
             * in order. */
            keep_http2_start(c, rec_off, rec_len, hdr_have);
            return ESP_OK;
        }
        hdr[hdr_have++] = b;
        rec_off++;
    }

    /* 2) Magic matched and we have all 9 header bytes — parse the BE32 JSON
     *    length and skip that many bytes (which may span further records),
     *    leaving anything after the JSON as the start of HTTP/2. */
    uint32_t ep_len = ((uint32_t)hdr[5] << 24) | ((uint32_t)hdr[6] << 16) |
                      ((uint32_t)hdr[7] <<  8) |  (uint32_t)hdr[8];
    if (ep_len > 64 * 1024) {
        ESP_LOGE(TAG, "EarlyPayload too large: %u", (unsigned)ep_len);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "EarlyPayload sentinel found, %u bytes JSON (skipping)",
             (unsigned)ep_len);

    size_t to_skip = ep_len;
    while (to_skip > 0) {
        if (rec_off == rec_len) {
            if (recv_record(c, &rec_len) != ESP_OK) return ESP_FAIL;
            rec_off = 0;
            if (rec_len == 0) continue;
        }
        size_t avail = rec_len - rec_off;
        if (avail <= to_skip) {
            to_skip -= avail;
            rec_off  = rec_len;
        } else {
            rec_off += to_skip;
            to_skip  = 0;
        }
    }

    /* Whatever is left in the current record after the JSON — served by
     * offset, no copy. */
    c->h2_rx_off = rec_off;
    c->h2_rx_len = rec_len;
    return ESP_OK;
}

/* Open the :443 transport: TLS, offering the session the previous :443
 * conn left (round 1.3.5, D9; tls_resume.h). */
static esp_err_t open_tls(ts2021_conn_t *c, tls_resume_result_t *res)
{
    char url[160];
    snprintf(url, sizeof(url), "https://%s:%d",
             CONFIG_TINYLINK_CONTROL_HOST, CONFIG_TINYLINK_CONTROL_PORT);

    esp_tls_cfg_t tls_cfg = {
        .crt_bundle_attach = tl_crt_bundle_attach,
        .timeout_ms = TLS_TIMEOUT_MS,
    };
    tls_resume_entry_t *offered = tls_resume_take(&s_resume, CONFIG_TINYLINK_CONTROL_HOST,
                                                  CONFIG_TINYLINK_CONTROL_PORT);
    tls_resume_offer(&tls_cfg, offered);

    c->tls = esp_tls_init();
    const int rc = (c->tls != NULL) ? esp_tls_conn_http_new_sync(url, &tls_cfg, c->tls) : -1;
    *res = tls_resume_keep(&s_resume, offered, rc == 1 ? c->tls : NULL,
                           CONFIG_TINYLINK_CONTROL_HOST, CONFIG_TINYLINK_CONTROL_PORT);
    if (rc != 1) {
        ESP_LOGE(TAG, "TLS connect failed");
        return ESP_FAIL;
    }
    int fd = -1;
    (void)esp_tls_get_conn_sockfd(c->tls, &fd);
    set_tcp_nodelay(fd);
    return ESP_OK;
}

/* Open the :80 transport: a plain TCP socket through esp-tls's resolver
 * and connect-with-timeout (no TLS context is allocated). Until Noise IK
 * authenticates the server, every read and write gets one
 * TS2021_PLAIN_TIMEOUT_MS poll and the whole exchange one deadline. */
static esp_err_t open_plain(ts2021_conn_t *c)
{
    esp_tls_cfg_t cfg = { .timeout_ms = TS2021_PLAIN_TIMEOUT_MS };
    esp_tls_last_error_t terr = { 0 };
    int fd = -1;
    const esp_err_t err = esp_tls_plain_tcp_connect(CONFIG_TINYLINK_CONTROL_HOST,
                                                    (int)strlen(CONFIG_TINYLINK_CONTROL_HOST),
                                                    TS2021_PLAIN_PORT, &cfg, &terr, &fd);
    if (err != ESP_OK || fd < 0) {
        ESP_LOGW(TAG, ":80 connect failed: 0x%x", err);
        return ESP_FAIL;
    }
    c->plain = true;
    c->sock = fd;
    c->hs_idle = 1;
    c->hs_deadline_us = esp_timer_get_time() + (int64_t)TS2021_PLAIN_TIMEOUT_MS * 1000;
    set_tcp_nodelay(fd);
    return ESP_OK;
}

/* Noise IK completed on :80, so the peer holds the pinned key's private
 * half: from here the conn is a stream like the TLS one — TLS_TIMEOUT_MS
 * socket polls under the stream idle budget. A socket left at 3-s polls
 * would declare the long-poll dead after 12 s of silence between
 * KeepAlives, so failing to switch fails the attempt. */
static esp_err_t plain_to_stream(ts2021_conn_t *c)
{
    struct timeval tv = { .tv_sec = TLS_TIMEOUT_MS / 1000, .tv_usec = 0 };
    if (setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0 ||
        setsockopt(c->sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        ESP_LOGE(TAG, ":80 stream timeouts not set");
        return ESP_FAIL;
    }
    c->hs_idle = 0;
    c->hs_deadline_us = 0;
    return ESP_OK;
}

/* Drop the transport and scrub the conn (ts2021_close adds the :80
 * early-drop accounting on top). */
static void conn_teardown(ts2021_conn_t *c)
{
    /* Drop the H2 session before the transport (it sends nothing on the
     * way out; the order is kept so it never could touch a destroyed
     * TLS context). */
    h2_session_destroy(c);
    if (c->tls != NULL) {
        esp_tls_conn_destroy(c->tls);
        c->tls = NULL;
    }
    if (c->plain) {
        close(c->sock);
        c->plain = false;
        c->sock = -1;
    }
    c->connected = false;
    /* The Noise state keeps a copy of the machine private key (s_priv),
     * the ephemeral private key and both transport keys. The 2026-06
     * secure_zero sweep (df7b6bd) scrubbed the WG side but left this
     * struct live in BSS between control-plane reconnects; scrub it the
     * moment the conn is gone so a later memory disclosure (coredump,
     * heap-overread elsewhere) cannot recover a session key. */
    tl_secure_zero(&c->noise, sizeof(c->noise));
}

/* Upgrade, Noise IK, EarlyPayload, HTTP/2 start on an open transport —
 * the same bytes on :80 and :443. */
static esp_err_t handshake(ts2021_conn_t *out,
                           const uint8_t machine_priv[NOISE_DHLEN],
                           const uint8_t machine_pub[NOISE_DHLEN],
                           const uint8_t control_pub[NOISE_DHLEN])
{
    /* Noise IK with prologue = "Tailscale Control Protocol v<CAPVER>"
     * (TS2021_PROTOCOL_VERSION = TINYLINK_CAPVER). The same version is
     * also placed in the cleartext BE16 header of the initiation frame;
     * mixing it into the prologue binds the encrypted handshake to the
     * advertised version. The server reconstructs this prologue from the
     * version we claim in the header, so the two must match. */
    char prologue[40];
    int plen = snprintf(prologue, sizeof(prologue), "%s%d",
                        TS2021_PROLOGUE_PREFIX, TS2021_PROTOCOL_VERSION);
    if (plen <= 0 || plen >= (int)sizeof(prologue)) {
        return ESP_FAIL;
    }
    if (noise_ik_init(&out->noise, machine_priv, machine_pub, control_pub,
                      TS2021_PROTOCOL_NAME,
                      (const uint8_t *)prologue, (size_t)plen) != ESP_OK) {
        return ESP_FAIL;
    }

    /* Build the 101-byte initiation frame: 5-byte header + 96-byte Noise. */
    uint8_t init[TS2021_INIT_HEADER_LEN + NOISE_IK_MSG1_LEN];
    init[0] = (uint8_t)((TS2021_PROTOCOL_VERSION >> 8) & 0xFF);
    init[1] = (uint8_t)( TS2021_PROTOCOL_VERSION       & 0xFF);
    init[2] = TS2021_MSG_INITIATION;
    init[3] = (uint8_t)((NOISE_IK_MSG1_LEN >> 8) & 0xFF);
    init[4] = (uint8_t)( NOISE_IK_MSG1_LEN       & 0xFF);
    if (noise_ik_write_msg1(&out->noise,
                            init + TS2021_INIT_HEADER_LEN) != ESP_OK) {
        return ESP_FAIL;
    }

    /* base64-encode the init frame for the X-Tailscale-Handshake header. */
    char init_b64[((sizeof(init) + 2) / 3) * 4 + 1];
    if (b64_encode(init, sizeof(init), init_b64, sizeof(init_b64)) != 0) {
        return ESP_ERR_INVALID_SIZE;
    }

    /* Build the upgrade request in the (still idle) h2_rx ring instead of
     * a 1 KiB stack buffer: nothing reads the ring before the 101 below,
     * which overwrites it. −1 KiB on the connect frame (main and
     * long-poll tasks). */
    char *req = (char *)out->h2_rx;
    int n = snprintf(req, sizeof(out->h2_rx),
        "POST /ts2021 HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: %s\r\n"
        "Connection: upgrade\r\n"
        "%s: %s\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        CONFIG_TINYLINK_CONTROL_HOST, UPGRADE_TOKEN,
        HANDSHAKE_HDR, init_b64);
    if (n <= 0 || n >= (int)sizeof(out->h2_rx)) {
        return ESP_ERR_INVALID_SIZE;
    }
    if (tls_write_full(out, (const uint8_t *)req, (size_t)n) != ESP_OK) {
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "ts2021: sent init in X-Tailscale-Handshake (%u bytes), waiting for 101",
             (unsigned)sizeof(init));

    /* Read 101 + headers into the (still idle) h2_rx ring instead of a
     * 4 KiB stack buffer — the response is a few hundred bytes and the
     * ring is one full record (4 077 B). Another 4 KiB off the connect
     * path frame; consume_early_payload reuses the same ring after us. */
    _Static_assert(sizeof(out->h2_rx) >= 1024, "h2_rx must hold the 101 response");
    if (read_upgrade_response(out, out->h2_rx, sizeof(out->h2_rx)) != ESP_OK) {
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "ts2021: got 101 Switching Protocols");

    /* Read response message: 3-byte header (type + BE16 length) + 48 byte
     * Noise msg2. */
    uint8_t  type;
    uint8_t  msg2[NOISE_IK_MSG2_LEN];
    size_t   msg2_len = 0;
    if (read_record_frame(out, &type, msg2, sizeof(msg2),
                          &msg2_len) != ESP_OK) {
        return ESP_FAIL;
    }
    if (type == TS2021_MSG_ERROR) {
        ESP_LOGE(TAG, "control plane handshake error: %.*s",
                 (int)(msg2_len > 200 ? 200 : msg2_len), (const char *)msg2);
        return ESP_FAIL;
    }
    if (type != TS2021_MSG_RESPONSE || msg2_len != NOISE_IK_MSG2_LEN) {
        ESP_LOGE(TAG, "unexpected msg2: type=0x%02x len=%u",
                 type, (unsigned)msg2_len);
        return ESP_FAIL;
    }
    if (noise_ik_read_msg2(&out->noise, msg2) != ESP_OK) {
        ESP_LOGE(TAG, "Noise IK msg2 refused — not from the pinned control key");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "ts2021: Noise IK handshake complete");
    out->up_us = esp_timer_get_time();
    if (out->plain && plain_to_stream(out) != ESP_OK) return ESP_FAIL;

    /* Skip optional EarlyPayload, leaving the h2_rx window primed with
     * the first 0..N HTTP/2 plaintext bytes. */
    if (consume_early_payload(out) != ESP_OK) {
        return ESP_FAIL;
    }

    /* Mark connected BEFORE h2_session_init so its preface + SETTINGS
     * flush can ride ts2021_send (which guards on c->connected). */
    out->connected = true;

    /* Start the HTTP/2 session: client preface + SETTINGS (no heap since
     * round 1.3.4, D1 — the nghttp2 session it replaced needed a
     * 10–14 KiB block, which is why this runs at connect time). */
    if (h2_session_init(out) != ESP_OK) {
        ESP_LOGE(TAG, "h2_session_init failed");
        return ESP_FAIL;
    }
    return ESP_OK;
}

/* One attempt on one transport. */
static esp_err_t connect_on(ts2021_conn_t *out, bool plain,
                            const uint8_t machine_priv[NOISE_DHLEN],
                            const uint8_t machine_pub[NOISE_DHLEN],
                            const uint8_t control_pub[NOISE_DHLEN],
                            tls_resume_result_t *res)
{
    memset(out, 0, sizeof(*out));
    out->sock = -1;
    esp_err_t err = plain ? open_plain(out) : open_tls(out, res);
    if (err == ESP_OK) err = handshake(out, machine_priv, machine_pub, control_pub);
    if (err != ESP_OK) conn_teardown(out);
    return err;
}

/* :80 is tried only with a key pinned before this boot: without TLS the
 * server's identity rests on Noise IK alone — msg2's tag is keyed by
 * DH(e, rs) and DH(s, rs), so only the holder of the pinned key's private
 * half can produce it, and `connected` also waits for the first
 * transport record (consume_early_payload), AEAD-opened under keys from
 * the same chain. A fake 101, garbage, a redirect, an error frame or a
 * msg2 from any other key fails the attempt before that, and the
 * fallback below takes :443 — the control key is never re-fetched here
 * (control_key.c fetches it once, over TLS, when nothing is pinned). A
 * genuine control-key rotation therefore fails on both ports, as it
 * failed on :443 before: the conn is refused, the caller backs off, the
 * pin stays. */
esp_err_t ts2021_connect(ts2021_conn_t *out,
                         const uint8_t machine_priv[NOISE_DHLEN],
                         const uint8_t machine_pub[NOISE_DHLEN],
                         const uint8_t control_pub[NOISE_DHLEN],
                         bool key_pinned)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    s_abort_reads = false;   /* a pending abort targets the OLD conn only */

    const int64_t t0 = esp_timer_get_time();
    tls_resume_result_t res = TLS_RESUME_NONE;
    bool plain = TS2021_PLAIN && key_pinned && !s_plain_off;
    if (plain && s_tls_next) {
        ESP_LOGW(TAG, "last :80 conn dropped early — this dial on :%d",
                 CONFIG_TINYLINK_CONTROL_PORT);
        plain = false;
    }
    s_tls_next = false;

    esp_err_t err = ESP_FAIL;
    bool fallback = !plain;
    if (plain) {
        err = connect_on(out, true, machine_priv, machine_pub, control_pub, &res);
        /* An abort raised meanwhile (endpoint push) is for this dial too. */
        if (err != ESP_OK && !s_abort_reads) {
            ESP_LOGW(TAG, ":80 attempt failed (0x%x) — falling back to :%d",
                     err, CONFIG_TINYLINK_CONTROL_PORT);
            fallback = true;
        }
    }
    if (fallback) {
        err = connect_on(out, false, machine_priv, machine_pub, control_pub, &res);
        if (err == ESP_OK && plain) {
            s_plain_off = true;
            ESP_LOGW(TAG, ":%d answered after :80 failed — :80 off for the rest of this boot",
                     CONFIG_TINYLINK_CONTROL_PORT);
        }
    }
    if (err == ESP_OK) {
        /* One line per connect, for the soak: which port, and on :443
         * whether the TLS session resumed. */
        ESP_LOGI(TAG, "ts2021: control conn up on :%d (%s) in %u ms",
                 out->plain ? TS2021_PLAIN_PORT : CONFIG_TINYLINK_CONTROL_PORT,
                 out->plain ? "plain HTTP, Noise IK" :
                 res == TLS_RESUME_RESUMED ? "TLS, session resumed" : "TLS, full handshake",
                 (unsigned)((esp_timer_get_time() - t0) / 1000));
    }
    return err;
}

/* Seal rec[4..4 + len) in place (the tag lands right behind it) and
 * write rec[1..4) header + ciphertext in ONE esp_tls write (round 1.3.2,
 * B8; one send() on :80): one TLS record per Noise record, since both
 * senders below keep a record ≤ MBEDTLS_SSL_OUT_CONTENT_LEN
 * (TS2021_TX_RECORD_MAX, round 1.3.4, D4). The separate 3-byte header write used to be a TLS record
 * and a TCP segment of its own, held by Nagle until the previous one was
 * ACKed. rec + 4 is word-aligned when rec is: the AEAD's aligned path. */
#ifdef CONFIG_MBEDTLS_SSL_OUT_CONTENT_LEN
_Static_assert(TS2021_TX_RECORD_MAX <= CONFIG_MBEDTLS_SSL_OUT_CONTENT_LEN,
               "a sent Noise record must fit one TLS record");
#endif

static esp_err_t seal_and_write(ts2021_conn_t *c, uint8_t *rec, size_t len)
{
    size_t ct_len = 0;
    if (noise_ik_encrypt(&c->noise, rec + 4, len + NOISE_TAGLEN, rec + 4, len,
                         &ct_len) != ESP_OK) {
        return ESP_FAIL;
    }
    rec[1] = TS2021_MSG_RECORD;
    rec[2] = (uint8_t)((ct_len >> 8) & 0xFF);
    rec[3] = (uint8_t)( ct_len       & 0xFF);
    return tls_write_full(c, rec + 1, TS2021_HEADER_LEN + ct_len);
}

esp_err_t ts2021_send(ts2021_conn_t *c,
                      const uint8_t *data, size_t data_len)
{
    if (c == NULL || !c->connected) return ESP_ERR_INVALID_STATE;
    if (data == NULL && data_len != 0) return ESP_ERR_INVALID_ARG;
    /* The HTTP/2 control frames (≤ H2_CTL_CAP = 64 B) go through this
     * small stack record, so they can go out while the ring still holds
     * a record being parsed; a longer write is split. Until round 1.3.4
     * (D4) every write was sealed into a 4 096-B stack array; requests
     * now take ts2021_tx_buf / ts2021_tx_send. */
    uint8_t rec[4 + TS2021_SMALL_PLAINTEXT_MAX + NOISE_TAGLEN] __attribute__((aligned(4)));
    size_t off = 0;
    do {
        size_t n = data_len - off;
        if (n > TS2021_SMALL_PLAINTEXT_MAX) n = TS2021_SMALL_PLAINTEXT_MAX;
        if (n) memcpy(rec + 4, data + off, n);
        const esp_err_t err = seal_and_write(c, rec, n);
        if (err != ESP_OK) return err;
        off += n;
    } while (off < data_len);
    return ESP_OK;
}

uint8_t *ts2021_tx_buf(ts2021_conn_t *c, size_t *cap)
{
    _Static_assert(sizeof(c->h2_rx) >= 1 + TS2021_TX_RECORD_MAX,
                   "h2_rx must hold a TX record at offset 1");
    c->h2_rx_off = 0;
    c->h2_rx_len = 0;
    *cap = TS2021_TX_PLAINTEXT_MAX;
    return c->h2_rx + 4;
}

esp_err_t ts2021_tx_send(ts2021_conn_t *c, size_t len)
{
    if (c == NULL || !c->connected) return ESP_ERR_INVALID_STATE;
    if (len > TS2021_TX_PLAINTEXT_MAX) return ESP_ERR_INVALID_SIZE;
    return seal_and_write(c, c->h2_rx, len);
}

esp_err_t ts2021_recv_record(ts2021_conn_t *c, size_t *len)
{
    if (c == NULL || !c->connected) return ESP_ERR_INVALID_STATE;
    if (len == NULL) return ESP_ERR_INVALID_ARG;
    return recv_record(c, len);
}

void ts2021_close(ts2021_conn_t *c)
{
    if (c == NULL) return;
    if (c->plain && c->connected && c->io_failed) {
        const int64_t up_s = (esp_timer_get_time() - c->up_us) / 1000000;
        if (up_s < TS2021_PLAIN_EARLY_DROP_S) {
            s_tls_next = true;
            ESP_LOGW(TAG, ":80 conn failed %d s after its handshake — next dial on :%d",
                     (int)up_s, CONFIG_TINYLINK_CONTROL_PORT);
        }
    }
    conn_teardown(c);
}
