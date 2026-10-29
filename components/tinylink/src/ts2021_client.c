// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "ts2021_client.h"

#include <stdio.h>
#include <string.h>

#include "esp_crt_bundle.h"
#include "tl_time.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include "mbedtls/ssl.h"

#include "h2_client.h"
#include "tls_io.h"
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

/* Adapter shims so tls_io_* can call esp_tls_conn_{read,write}. The
 * cast on the write side hides esp_tls_conn_write's `void *` (non-const)
 * second parameter — we never mutate it. */
static ssize_t ts2021_tls_read(void *ctx, uint8_t *buf, size_t len) {
    if (s_abort_reads) return TS2021_ERR_READ_ABORTED;
    return esp_tls_conn_read((esp_tls_t *)ctx, buf, len);
}
static ssize_t ts2021_tls_write(void *ctx, const uint8_t *buf, size_t len) {
    return esp_tls_conn_write((esp_tls_t *)ctx, (void *)buf, len);
}

static esp_err_t tls_read_full(esp_tls_t *tls, uint8_t *buf, size_t need)
{
    int rc = tls_io_read_full(ts2021_tls_read, tls, buf, need,
                              TS2021_MAX_IDLE_POLLS);
    if (rc != 0) {
        if (rc == TLS_IO_ERR_IDLE_TIMEOUT) {
            ESP_LOGW(TAG, "control stream silent past %d s — declaring dead",
                     CONFIG_TINYLINK_STREAM_IDLE_TIMEOUT_S);
        } else if (rc == TS2021_ERR_READ_ABORTED) {
            ESP_LOGI(TAG, "control stream read aborted on request (recycle)");
        } else {
            ESP_LOGE(TAG, "tls_read_full failed: %d", rc);
        }
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t tls_write_full(esp_tls_t *tls, const uint8_t *buf, size_t len)
{
    int rc = tls_io_write_full(ts2021_tls_write, tls, buf, len,
                               TS2021_MAX_IDLE_POLLS);
    if (rc != 0) {
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
 * hook before it); a failure only costs latency, so it is logged and
 * ignored. */
static void set_tcp_nodelay(esp_tls_t *tls)
{
    int fd = -1;
    int one = 1;
    if (esp_tls_get_conn_sockfd(tls, &fd) != ESP_OK || fd < 0 ||
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0) {
        ESP_LOGW(TAG, "TCP_NODELAY not set (fd=%d)", fd);
    }
}

static esp_err_t read_upgrade_response(esp_tls_t *tls,
                                       uint8_t *buf, size_t buf_size)
{
    size_t   total = 0;
    uint32_t idle  = 0;
    while (total < buf_size - 1) {
        ssize_t r = esp_tls_conn_read(tls, buf + total, 1);
        if (r == MBEDTLS_ERR_SSL_WANT_READ ||
            r == MBEDTLS_ERR_SSL_WANT_WRITE) {
            /* Same transient-timeout class as tls_io_read_full handles
             * — but here we read one byte at a time scanning for
             * "\r\n\r\n", so we open-code the retry instead of
             * pulling the helper. Same liveness budget as the record
             * reader: a server that accepts TLS but never answers the
             * upgrade must not park the caller forever. */
            if (++idle >= TS2021_MAX_IDLE_POLLS) {
                ESP_LOGE(TAG, "no 101 response within %d s — giving up",
                         CONFIG_TINYLINK_STREAM_IDLE_TIMEOUT_S);
                return ESP_FAIL;
            }
            continue;
        }
        idle = 0;
        if (r <= 0) {
            ESP_LOGE(TAG, "tls read while waiting for 101: %d", (int)r);
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
static esp_err_t read_record_frame(esp_tls_t *tls, uint8_t *type_out,
                                   uint8_t *payload, size_t payload_max,
                                   size_t *payload_len)
{
    uint8_t hdr[TS2021_HEADER_LEN];
    if (tls_read_full(tls, hdr, sizeof(hdr)) != ESP_OK) return ESP_FAIL;
    size_t len = ((size_t)hdr[1] << 8) | (size_t)hdr[2];
    if (len > payload_max) {
        ESP_LOGE(TAG, "record too large: %u > %u",
                 (unsigned)len, (unsigned)payload_max);
        return ESP_ERR_INVALID_SIZE;
    }
    if (len > 0) {
        if (tls_read_full(tls, payload, len) != ESP_OK) return ESP_FAIL;
    }
    *type_out = hdr[0];
    *payload_len = len;
    return ESP_OK;
}

/* Decrypt one record into a caller buffer. */
static esp_err_t recv_record_plaintext(ts2021_conn_t *c,
                                       uint8_t *out, size_t out_max,
                                       size_t *out_len)
{
    uint8_t  type;
    uint8_t  ct[TS2021_MAX_MESSAGE];
    size_t   ct_len = 0;
    if (read_record_frame(c->tls, &type, ct, sizeof(ct), &ct_len) != ESP_OK) {
        return ESP_FAIL;
    }
    if (type == TS2021_MSG_ERROR) {
        ESP_LOGE(TAG, "control plane error: %.*s",
                 (int)(ct_len > 200 ? 200 : ct_len), (const char *)ct);
        return ESP_FAIL;
    }
    if (type != TS2021_MSG_RECORD) {
        ESP_LOGE(TAG, "unexpected post-handshake frame type 0x%02x", type);
        return ESP_FAIL;
    }
    return noise_ik_decrypt(&c->noise, out, out_max, ct, ct_len, out_len);
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
 * which recv_cb hands to nghttp2 before it reads another record. Until
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
    /* Record scratch: the conn's h2_rx ring. It is idle until
     * h2_session_init runs at the very end of ts2021_connect, and it is
     * one record long. Saves 4 077 B of stack on the connect path (this
     * function is inlined into ts2021_connect, whose frame was 9 888 B). */
    uint8_t *rec = c->h2_rx;
    const size_t rec_cap = sizeof(c->h2_rx);
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
            if (recv_record_plaintext(c, rec, rec_cap, &rec_len) != ESP_OK)
                return ESP_FAIL;
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
            if (recv_record_plaintext(c, rec, rec_cap, &rec_len) != ESP_OK)
                return ESP_FAIL;
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

esp_err_t ts2021_connect(ts2021_conn_t *out,
                         const uint8_t machine_priv[NOISE_DHLEN],
                         const uint8_t machine_pub[NOISE_DHLEN],
                         const uint8_t control_pub[NOISE_DHLEN])
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    s_abort_reads = false;   /* a pending abort targets the OLD conn only */

    char host_with_port[160];
    snprintf(host_with_port, sizeof(host_with_port), "https://%s:%d",
             CONFIG_TINYLINK_CONTROL_HOST, CONFIG_TINYLINK_CONTROL_PORT);

    esp_tls_cfg_t tls_cfg = {
        .crt_bundle_attach = tl_crt_bundle_attach,
        .timeout_ms = TLS_TIMEOUT_MS,
    };

    out->tls = esp_tls_init();
    if (out->tls == NULL) return ESP_FAIL;
    int rc = esp_tls_conn_http_new_sync(host_with_port, &tls_cfg, out->tls);
    if (rc != 1) {
        ESP_LOGE(TAG, "TLS connect failed");
        ts2021_close(out);
        return ESP_FAIL;
    }
    set_tcp_nodelay(out->tls);

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
        ts2021_close(out);
        return ESP_FAIL;
    }
    if (noise_ik_init(&out->noise, machine_priv, machine_pub, control_pub,
                      TS2021_PROTOCOL_NAME,
                      (const uint8_t *)prologue, (size_t)plen) != ESP_OK) {
        ts2021_close(out);
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
        ts2021_close(out);
        return ESP_FAIL;
    }

    /* base64-encode the init frame for the X-Tailscale-Handshake header. */
    char init_b64[((sizeof(init) + 2) / 3) * 4 + 1];
    if (b64_encode(init, sizeof(init), init_b64, sizeof(init_b64)) != 0) {
        ts2021_close(out);
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
        ts2021_close(out);
        return ESP_ERR_INVALID_SIZE;
    }
    if (tls_write_full(out->tls, (const uint8_t *)req, (size_t)n) != ESP_OK) {
        ts2021_close(out);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "ts2021: sent init in X-Tailscale-Handshake (%u bytes), waiting for 101",
             (unsigned)sizeof(init));

    /* Read 101 + headers into the (still idle) h2_rx ring instead of a
     * 4 KiB stack buffer — the response is a few hundred bytes and the
     * ring is one full record (4 077 B). Another 4 KiB off the connect
     * path frame; consume_early_payload reuses the same ring after us. */
    _Static_assert(sizeof(out->h2_rx) >= 1024, "h2_rx must hold the 101 response");
    if (read_upgrade_response(out->tls, out->h2_rx, sizeof(out->h2_rx)) != ESP_OK) {
        ts2021_close(out);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "ts2021: got 101 Switching Protocols");

    /* Read response message: 3-byte header (type + BE16 length) + 48 byte
     * Noise msg2. */
    uint8_t  type;
    uint8_t  msg2[NOISE_IK_MSG2_LEN];
    size_t   msg2_len = 0;
    if (read_record_frame(out->tls, &type, msg2, sizeof(msg2),
                          &msg2_len) != ESP_OK) {
        ts2021_close(out);
        return ESP_FAIL;
    }
    if (type == TS2021_MSG_ERROR) {
        ESP_LOGE(TAG, "control plane handshake error: %.*s",
                 (int)(msg2_len > 200 ? 200 : msg2_len), (const char *)msg2);
        ts2021_close(out);
        return ESP_FAIL;
    }
    if (type != TS2021_MSG_RESPONSE || msg2_len != NOISE_IK_MSG2_LEN) {
        ESP_LOGE(TAG, "unexpected msg2: type=0x%02x len=%u",
                 type, (unsigned)msg2_len);
        ts2021_close(out);
        return ESP_FAIL;
    }
    if (noise_ik_read_msg2(&out->noise, msg2) != ESP_OK) {
        ts2021_close(out);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "ts2021: Noise IK handshake complete");

    /* Skip optional EarlyPayload, leaving the h2_rx window primed with
     * the first 0..N HTTP/2 plaintext bytes. */
    if (consume_early_payload(out) != ESP_OK) {
        ts2021_close(out);
        return ESP_FAIL;
    }

    /* Mark connected BEFORE h2_session_init so its preface + SETTINGS
     * flush can ride ts2021_send (which guards on c->connected). */
    out->connected = true;

    /* Allocate the persistent nghttp2 session NOW, while only this
     * (long-poll) TLS conn is alive and the heap still has a single
     * contiguous ~24 KiB block. nghttp2_session_client_new2 wants
     * ~10–14 KiB in one malloc; if we deferred this until first
     * request, a second TLS conn (DERP supervisor) could already
     * have fragmented the heap and the call would return -901
     * NGHTTP2_ERR_NOMEM. */
    if (h2_session_init(out) != ESP_OK) {
        ESP_LOGE(TAG, "h2_session_init failed");
        ts2021_close(out);
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t ts2021_send(ts2021_conn_t *c,
                      const uint8_t *data, size_t data_len)
{
    if (c == NULL || !c->connected) return ESP_ERR_INVALID_STATE;
    if (data_len > TS2021_RECORD_PLAINTEXT_MAX) return ESP_ERR_INVALID_SIZE;

    /* Header + ciphertext built back to back and written ONCE (round
     * 1.3.2, B8): one esp_tls write = one TLS record per Noise record
     * (two only for a > 2 KiB record — MBEDTLS_SSL_OUT_CONTENT_LEN),
     * where the separate 3-byte header write used to be a TLS record and
     * a TCP segment of its own, held by Nagle until the previous one was
     * ACKed. Same stack array as before plus the 3 header bytes. */
    uint8_t  rec[TS2021_HEADER_LEN + TS2021_RECORD_PLAINTEXT_MAX + NOISE_TAGLEN];
    size_t   ct_len = 0;
    if (noise_ik_encrypt(&c->noise, rec + TS2021_HEADER_LEN,
                         sizeof(rec) - TS2021_HEADER_LEN,
                         data, data_len, &ct_len) != ESP_OK) {
        return ESP_FAIL;
    }
    if (ct_len > 0xFFFF) return ESP_ERR_INVALID_SIZE;

    rec[0] = TS2021_MSG_RECORD;
    rec[1] = (uint8_t)((ct_len >> 8) & 0xFF);
    rec[2] = (uint8_t)( ct_len       & 0xFF);
    return tls_write_full(c->tls, rec, TS2021_HEADER_LEN + ct_len);
}

esp_err_t ts2021_recv(ts2021_conn_t *c,
                      uint8_t *out, size_t out_max, size_t *out_len)
{
    if (c == NULL || !c->connected) return ESP_ERR_INVALID_STATE;
    if (out == NULL || out_len == NULL) return ESP_ERR_INVALID_ARG;
    return recv_record_plaintext(c, out, out_max, out_len);
}

void ts2021_close(ts2021_conn_t *c)
{
    if (c == NULL) return;
    /* Free the persistent H2 session BEFORE the TLS context: nghttp2
     * may call into our send_cb during shutdown (RST_STREAM/GOAWAY
     * frames it had queued), and that path dereferences c->tls. */
    h2_session_destroy(c);
    if (c->tls != NULL) {
        esp_tls_conn_destroy(c->tls);
        c->tls = NULL;
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
