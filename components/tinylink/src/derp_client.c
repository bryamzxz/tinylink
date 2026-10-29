// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#ifdef ESP_PLATFORM

#include "derp_client.h"

#include <string.h>
#include <stdio.h>

#include "esp_crt_bundle.h"
#include "tl_time.h"
#include "esp_log.h"
#include "esp_random.h"
#include "lwip/sockets.h"
#include "mbedtls/ssl.h"

#include "esp_timer.h"
#include "tl_addr.h"
#include "tls_io.h"
#include "tls_resume.h"

static const char *TAG = "derp_client";

/* TLS session of the last DERP connect (round 1.3.5, D9; tls_resume.h),
 * for a reconnect to the same relay: one per firmware — the supervisor
 * (or, with SUPERVISED=n, the boot smoke) is the only DERP client. A
 * different host (home region change) is a full handshake. derp16b
 * resumed 5/5 from the host (one address, TTL 600 s). */
static tls_resume_slot_t s_resume;

/* Same budget as ts2021 — covers cert chain verify + ECDSA. */
#define DERP_TLS_TIMEOUT_MS 30000

/* A dial by the DERP map's address (round 1.3.5, tl_addr.h): esp-tls
 * applies timeout_ms to the TCP connect and to every handshake read, and
 * the socket stays at it through the login, one poll per read, so the
 * attempt gets 3 s per step — one lost SYN at lwIP's 1.5-s RTO, as
 * ts2021's :80 budget — and a stale address costs at most that per step
 * before the name is resolved. Once logged in, the socket goes to the
 * stream's DERP_TLS_TIMEOUT_MS polls. */
#define DERP_ADDR_TIMEOUT_MS 3000

/* Liveness budget, same shape as ts2021_client.c: consecutive silent
 * SO_RCVTIMEO polls tolerated before the DERP stream is declared dead.
 * The DERP server keepalives roughly every minute; the shared default
 * (120 s = 4 polls) is two missed keepalives. Without it a half-open
 * TCP conn parks derp_client_run forever and the supervisor never
 * reconnects — the relay fallback silently dies for the rest of the
 * session. */
#define DERP_MAX_IDLE_POLLS \
    ((uint32_t)((CONFIG_TINYLINK_STREAM_IDLE_TIMEOUT_S * 1000 \
                 + DERP_TLS_TIMEOUT_MS - 1) / DERP_TLS_TIMEOUT_MS))

/* Largest single read for either the upgrade response or any login
 * frame. ServerKey ≈ 40 B, ServerInfo box typically ≤ 100 B. 256 B
 * leaves comfortable headroom and stays small enough for the stack. */
#define DERP_LOGIN_BUF_LEN  256

/* esp-tls callback adapters for tls_io_*.
 *
 * Two flavours: the *_raw versions take an esp_tls_t* directly (used
 * by the login handshake where derp_client_t is half-initialised),
 * while the bare derp_tls_read/_write expect a derp_client_t* and
 * are wired into the recv-loop side, where derp_run_loop hands
 * io_ctx = derp_client_t* through. Mixing them up at call sites
 * caused an InstrFetchProhibited at PC=0 (esp_tls_conn_read deref'd
 * a derp_client_t cast to esp_tls_t — its first field happens to be
 * tls, so reads partially succeed before veering into garbage). */
static ssize_t derp_tls_read_raw(void *ctx, uint8_t *buf, size_t len) {
    return esp_tls_conn_read((esp_tls_t *)ctx, buf, len);
}
static ssize_t derp_tls_write_raw(void *ctx, const uint8_t *buf, size_t len) {
    return esp_tls_conn_write((esp_tls_t *)ctx, (void *)buf, len);
}
static ssize_t derp_tls_read(void *ctx, uint8_t *buf, size_t len) {
    derp_client_t *c = (derp_client_t *)ctx;
    if (c->abort_reads) return DERP_ERR_READ_ABORTED;
    return esp_tls_conn_read(c->tls, buf, len);
}

/* The login's reads and writes: `idle` silent socket polls each at most
 * (1 at the DERP map's address, DERP_MAX_IDLE_POLLS by name). */
static esp_err_t tls_read_full(esp_tls_t *tls, uint8_t *buf, size_t need, uint32_t idle)
{
    int rc = tls_io_read_full(derp_tls_read_raw, tls, buf, need, idle);
    if (rc != 0) {
        if (rc == TLS_IO_ERR_IDLE_TIMEOUT) {
            ESP_LOGW(TAG, "DERP stream silent past %d s — declaring dead",
                     CONFIG_TINYLINK_STREAM_IDLE_TIMEOUT_S);
        } else {
            ESP_LOGE(TAG, "tls_read_full failed: %d", rc);
        }
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t tls_write_full(esp_tls_t *tls, const uint8_t *buf, size_t len,
                                uint32_t idle)
{
    int rc = tls_io_write_full(derp_tls_write_raw, tls, buf, len, idle);
    if (rc != 0) {
        ESP_LOGE(TAG, "tls_write_full failed: %d", rc);
        return ESP_FAIL;
    }
    return ESP_OK;
}

/* TCP_NODELAY on the DERP conn (round 1.3.2, B8), same reasoning as
 * ts2021_client.c: every write is a whole frame and relayed packets are
 * latency-bound, so Nagle (holding a frame until the previous segment is
 * ACKed) only ever added an RTT. Set after the TLS handshake; a failure
 * only costs latency. */
static void set_tcp_nodelay(esp_tls_t *tls)
{
    int fd = -1;
    int one = 1;
    if (esp_tls_get_conn_sockfd(tls, &fd) != ESP_OK || fd < 0 ||
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0) {
        ESP_LOGW(TAG, "TCP_NODELAY not set (fd=%d)", fd);
    }
}

/* SO_RCVTIMEO / SO_SNDTIMEO back to the stream's 30-s polls after a
 * login made with DERP_ADDR_TIMEOUT_MS: left at 3 s, the idle budget
 * (DERP_MAX_IDLE_POLLS polls) would declare the stream dead after 12 s
 * between server keepalives. */
static bool set_stream_timeouts(esp_tls_t *tls)
{
    int fd = -1;
    struct timeval tv = { .tv_sec = DERP_TLS_TIMEOUT_MS / 1000, .tv_usec = 0 };
    return esp_tls_get_conn_sockfd(tls, &fd) == ESP_OK && fd >= 0 &&
           setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0 &&
           setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == 0;
}

/* One TLS connect into out->tls: to `ip` with the certificate checked
 * against `host` — esp-tls hands cfg.common_name to
 * mbedtls_ssl_set_hostname, i.e. the SNI and the name verification
 * (esp_tls_mbedtls.c set_client_config), and an IP literal never reaches
 * lwIP's resolver (dns_gethostbyname_addrtype returns it as is) — or to
 * `host` through esp-tls's resolver (ip NULL). The TLS session is offered
 * and kept by host:port either way: it belongs to the name the
 * certificate proved, and a server at another address that does not
 * hold its ticket key answers with a full, verified handshake. On false
 * the caller closes `out`. */
static bool open_tls(derp_client_t *out, const char *host, uint16_t port,
                     const uint8_t *ip, tls_resume_result_t *res)
{
    esp_tls_cfg_t cfg = {
        .crt_bundle_attach = tl_crt_bundle_attach,
        .timeout_ms        = ip != NULL ? DERP_ADDR_TIMEOUT_MS : DERP_TLS_TIMEOUT_MS,
        .common_name       = host,
    };
    tls_resume_entry_t *offered = tls_resume_take(&s_resume, host, port);
    tls_resume_offer(&cfg, offered);

    out->tls = esp_tls_init();
    int rc = -1;
    if (out->tls == NULL) {
        ESP_LOGE(TAG, "esp_tls_init failed");
    } else if (ip != NULL) {
        char a[TL_IPV4_STRLEN];
        tl_ipv4_str(ip, a);
        rc = esp_tls_conn_new_sync(a, (int)strlen(a), port, &cfg, out->tls);
    } else {
        char url[160];
        snprintf(url, sizeof(url), "https://%s:%u", host, (unsigned)port);
        rc = esp_tls_conn_http_new_sync(url, &cfg, out->tls);
    }
    *res = tls_resume_keep(&s_resume, offered, rc == 1 ? out->tls : NULL, host, port);
    return rc == 1;
}

/* Read the HTTP/1.1 upgrade response one byte at a time until the
 * "\r\n\r\n" terminator. Same shape as ts2021_client.c's
 * read_upgrade_response — DERP servers return a real 101 (no fast-
 * start path on this code path), so we wait for full headers. */
static esp_err_t read_upgrade_response(esp_tls_t *tls,
                                       uint8_t *buf, size_t buf_size, uint32_t max_idle)
{
    size_t   total = 0;
    uint32_t idle  = 0;
    while (total < buf_size - 1) {
        ssize_t r = esp_tls_conn_read(tls, buf + total, 1);
        if (r == MBEDTLS_ERR_SSL_WANT_READ ||
            r == MBEDTLS_ERR_SSL_WANT_WRITE) {
            /* Bounded like the frame reader — a server that accepts
             * TLS but never answers the upgrade must not hang us. */
            if (++idle >= max_idle) {
                ESP_LOGE(TAG, "no 101 response within %u polls — giving up",
                         (unsigned)max_idle);
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
        ESP_LOGE(TAG, "DERP server did not return 101: '%.*s'",
                 (int)(total > 80 ? 80 : total), (const char *)buf);
        return ESP_FAIL;
    }
    return ESP_OK;
}

/* Read one frame header + payload into `payload` (capped at pcap).
 * Returns the actual payload length, or 0 on failure. The frame type
 * is returned via *type. */
static esp_err_t read_one_frame(esp_tls_t *tls,
                                derp_frame_type_t *type,
                                uint8_t *payload, size_t pcap,
                                size_t *plen_out, uint32_t idle)
{
    uint8_t hdr[DERP_FRAME_HDR_LEN];
    if (tls_read_full(tls, hdr, sizeof(hdr), idle) != ESP_OK) return ESP_FAIL;

    uint32_t plen;
    if (derp_read_frame_header(hdr, sizeof(hdr), type, &plen) != 0) {
        ESP_LOGE(TAG, "frame header parse failed");
        return ESP_FAIL;
    }
    if (plen > pcap) {
        ESP_LOGE(TAG, "frame payload %u > cap %u", (unsigned)plen, (unsigned)pcap);
        return ESP_ERR_INVALID_SIZE;
    }
    if (plen > 0) {
        if (tls_read_full(tls, payload, plen, idle) != ESP_OK) return ESP_FAIL;
    }
    *plen_out = plen;
    return ESP_OK;
}

/* The DERP login on an open TLS conn: HTTP upgrade, ServerKey,
 * ClientInfo, ServerInfo. On failure the caller closes `out`. */
static esp_err_t login(derp_client_t *out, const char *server_host, uint32_t idle,
                       const uint8_t client_priv[DERP_KEY_LEN],
                       const uint8_t client_pub[DERP_KEY_LEN])
{
    /* Build and send: GET /derp HTTP/1.1 + Upgrade: DERP. The Host
     * header MUST match the SNI / cert host we just dialed. */
    char req[256];
    int n = snprintf(req, sizeof(req),
        "GET /derp HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: DERP\r\n"
        "Connection: Upgrade\r\n"
        "User-Agent: tinylink/0.1\r\n"
        "\r\n",
        server_host);
    if (n <= 0 || n >= (int)sizeof(req)) return ESP_ERR_INVALID_SIZE;
    if (tls_write_full(out->tls, (const uint8_t *)req, (size_t)n, idle) != ESP_OK) {
        return ESP_FAIL;
    }

    /* Read the 101 response. */
    uint8_t up_resp[DERP_LOGIN_BUF_LEN];
    if (read_upgrade_response(out->tls, up_resp, sizeof(up_resp), idle) != ESP_OK) {
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "got HTTP 101, entering DERP frame mode");

    /* Frame 1: server → client FrameServerKey. */
    derp_frame_type_t ftype;
    uint8_t  payload[DERP_LOGIN_BUF_LEN];
    size_t   plen = 0;
    if (read_one_frame(out->tls, &ftype, payload, sizeof(payload), &plen, idle) != ESP_OK) {
        return ESP_FAIL;
    }
    if (ftype != DERP_FRAME_SERVER_KEY) {
        ESP_LOGE(TAG, "expected ServerKey, got 0x%02x", (unsigned)ftype);
        return ESP_FAIL;
    }
    if (derp_parse_server_key(payload, plen, out->server_pub) != 0) {
        ESP_LOGE(TAG, "ServerKey parse failed (plen=%u)", (unsigned)plen);
        return ESP_FAIL;
    }

    /* Frame 2: client → server FrameClientInfo. */
    uint8_t nonce[DERP_NONCE_LEN];
    esp_fill_random(nonce, sizeof(nonce));

    /* Header(5) + payload(32+24+16+32) = 5 + 104 = 109 B. */
    uint8_t ci_buf[5 + 32 + 24 + 16 + 64];
    size_t ci_payload_len = derp_build_client_info(
        ci_buf + DERP_FRAME_HDR_LEN, sizeof(ci_buf) - DERP_FRAME_HDR_LEN,
        client_pub, client_priv, out->server_pub, nonce);
    if (ci_payload_len == 0) {
        ESP_LOGE(TAG, "client_info build failed");
        return ESP_FAIL;
    }
    derp_write_frame_header(ci_buf, DERP_FRAME_CLIENT_INFO,
                            (uint32_t)ci_payload_len);
    if (tls_write_full(out->tls, ci_buf,
                       DERP_FRAME_HDR_LEN + ci_payload_len, idle) != ESP_OK) {
        return ESP_FAIL;
    }

    /* Frame 3: server → client FrameServerInfo. */
    if (read_one_frame(out->tls, &ftype, payload, sizeof(payload), &plen, idle) != ESP_OK) {
        return ESP_FAIL;
    }
    if (ftype != DERP_FRAME_SERVER_INFO) {
        ESP_LOGE(TAG, "expected ServerInfo, got 0x%02x", (unsigned)ftype);
        return ESP_FAIL;
    }
    if (derp_parse_server_info(payload, plen, client_priv, out->server_pub,
                               &out->server_version) != 0) {
        ESP_LOGE(TAG, "ServerInfo decrypt/parse failed");
        return ESP_FAIL;
    }
    return ESP_OK;
}

/* One attempt, at `ip` or by name (NULL): TLS, then the login. On
 * failure `out` is closed. */
static esp_err_t connect_on(derp_client_t *out, const char *server_host, uint16_t port,
                            const uint8_t *ip, int64_t t0,
                            const uint8_t client_priv[DERP_KEY_LEN],
                            const uint8_t client_pub[DERP_KEY_LEN])
{
    tls_resume_result_t res = TLS_RESUME_NONE;
    char via[TL_IPV4_STRLEN + 3] = "by name";
    if (ip != NULL) {
        char a[TL_IPV4_STRLEN];
        tl_ipv4_str(ip, a);
        snprintf(via, sizeof(via), "at %s", a);
    }
    if (!open_tls(out, server_host, port, ip, &res)) {
        if (ip == NULL) {
            ESP_LOGE(TAG, "TLS connect to %s:%u failed", server_host, (unsigned)port);
        }
        derp_client_close(out);
        return ESP_FAIL;
    }
    set_tcp_nodelay(out->tls);
    ESP_LOGI(TAG, "TLS up to %s:%u %s (%s handshake, %u ms), sending HTTP upgrade",
             server_host, (unsigned)port, via,
             res == TLS_RESUME_RESUMED ? "resumed" : "full",
             (unsigned)((esp_timer_get_time() - t0) / 1000));
    esp_err_t err = login(out, server_host, ip != NULL ? 1 : DERP_MAX_IDLE_POLLS,
                          client_priv, client_pub);
    if (err == ESP_OK && ip != NULL && !set_stream_timeouts(out->tls)) {
        ESP_LOGW(TAG, "stream socket timeouts not set");
        err = ESP_FAIL;
    }
    if (err != ESP_OK) {
        derp_client_close(out);
        return err;
    }
    out->connected = true;
    ESP_LOGI(TAG, "DERP login OK: server version=%d", out->server_version);
    return ESP_OK;
}

esp_err_t derp_client_connect_login(derp_client_t *out,
                                    const char *server_host, uint16_t port,
                                    const uint8_t server_v4[4],
                                    const uint8_t client_priv[DERP_KEY_LEN],
                                    const uint8_t client_pub[DERP_KEY_LEN])
{
    if (out == NULL || server_host == NULL ||
        client_priv == NULL || client_pub == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    /* DERPNode.DERPPort is json:",omitempty" (tailcfg/derpmap.go) — it is
     * on the wire only when non-default; mapreq.c parses it into
     * tl_derp_node_t.port, leaving it 0 when absent. Treat 0 as "use the
     * DERP default" so callers can pass dn->port unchanged. */
    if (port == 0) port = 443;
    /* The write lock outlives individual connections: it is created on
     * the first connect of a (zero-initialised) derp_client_t and never
     * deleted (see derp_client_close), so a concurrent sender blocked on
     * it can never wake up on a freed semaphore. Preserve it across the
     * per-connect reset. Callers must zero the struct before the first
     * connect (static storage or `= {0}`). */
    SemaphoreHandle_t lock = out->write_lock;
    memset(out, 0, sizeof(*out));
    out->write_lock = lock;

    if (out->write_lock == NULL) {
        out->write_lock = xSemaphoreCreateMutex();
    }
    if (out->write_lock == NULL) {
        ESP_LOGE(TAG, "write_lock create failed");
        return ESP_ERR_NO_MEM;
    }

    /* The DERP map's address first (round 1.3.5): no DNS on the boot
     * path, where 1.3.5's lookups lost answers and the connect took
     * 1.79–6.36 s. Any failure there — refused, the 3-s budget, a
     * certificate that is not server_host's, a server there that does
     * not complete the DERP login — falls back to the name in this same
     * call, so a stale address costs one short attempt. */
    const int64_t t0 = esp_timer_get_time();
    esp_err_t err = ESP_FAIL;
    if (server_v4 != NULL && tl_ipv4_usable(server_v4)) {
        err = connect_on(out, server_host, port, server_v4, t0, client_priv, client_pub);
        if (err != ESP_OK) {
            char a[TL_IPV4_STRLEN];
            tl_ipv4_str(server_v4, a);
            ESP_LOGW(TAG, "DERP to %s at %s:%u failed (0x%x) — resolving the name",
                     server_host, a, (unsigned)port, err);
        }
    }
    if (err != ESP_OK) {
        err = connect_on(out, server_host, port, NULL, t0, client_priv, client_pub);
    }
    return err;
}

void derp_client_close(derp_client_t *c)
{
    if (c == NULL) return;
    /* Teardown ordering vs the wg_tx relay (tinylink_relay_via_derp →
     * derp_client_send_packet), which runs on ANOTHER task and used to
     * race this function: the old code destroyed the TLS context and
     * deleted the mutex while a sender could be inside
     * esp_tls_conn_write or blocked on xSemaphoreTake — a use-after-free
     * of c->tls and a wait on a deleted semaphore. Now:
     *   1. drop `connected` first, so the relay's unlocked fast-path
     *      check stops admitting new sends;
     *   2. take the write lock, so a sender already past its check
     *      finishes (or fails) its frame before the TLS context goes;
     *   3. destroy TLS under the lock and NULL it, so a sender that
     *      wins the lock afterwards sees c->tls == NULL and bails;
     *   4. never delete the lock — it is created once per client. */
    c->connected = false;
    if (c->write_lock != NULL) {
        xSemaphoreTake(c->write_lock, portMAX_DELAY);
    }
    if (c->tls != NULL) {
        esp_tls_conn_destroy(c->tls);
        c->tls = NULL;
    }
    if (c->write_lock != NULL) {
        xSemaphoreGive(c->write_lock);
    }
}

/* Write one frame: header, then `key` (DERP_KEY_LEN bytes, NULL = none),
 * then `payload`. Caller holds c->write_lock and has re-checked c->tls.
 * Up to DERP_TX_STAGE_MAX of key + payload the frame is assembled in
 * c->tx_stage and leaves as one write (one TLS record); anything bigger
 * — nothing tinylink sends today — as separate writes, still atomic on
 * the wire because the lock is held. */
static int write_frame_locked(derp_client_t *c, derp_frame_type_t type,
                              const uint8_t *key,
                              const uint8_t *payload, size_t plen)
{
    const size_t klen = (key != NULL) ? DERP_KEY_LEN : 0;
    const size_t body = klen + plen;
    if (body <= DERP_TX_STAGE_MAX) {
        uint8_t *f = c->tx_stage;
        derp_write_frame_header(f, type, (uint32_t)body);
        if (klen > 0) memcpy(f + DERP_FRAME_HDR_LEN, key, klen);
        if (plen > 0) memcpy(f + DERP_FRAME_HDR_LEN + klen, payload, plen);
        return tls_io_write_full(derp_tls_write_raw, c->tls, f,
                                 DERP_FRAME_HDR_LEN + body,
                                 DERP_MAX_IDLE_POLLS);
    }
    uint8_t hdr[DERP_FRAME_HDR_LEN];
    derp_write_frame_header(hdr, type, (uint32_t)body);
    int rc = tls_io_write_full(derp_tls_write_raw, c->tls, hdr, sizeof(hdr),
                               DERP_MAX_IDLE_POLLS);
    if (rc == 0 && klen > 0) {
        rc = tls_io_write_full(derp_tls_write_raw, c->tls, key, klen,
                               DERP_MAX_IDLE_POLLS);
    }
    if (rc == 0 && plen > 0) {
        rc = tls_io_write_full(derp_tls_write_raw, c->tls, payload, plen,
                               DERP_MAX_IDLE_POLLS);
    }
    return rc;
}

/* Atomic-frame writer used by the recv loop's pongs (via derp_run_loop).
 * Holds c->write_lock across the whole frame so concurrent senders
 * (derp_client_send_packet) cannot interleave and corrupt the framing. */
static int derp_send_frame_locked(void *ctx, derp_frame_type_t type,
                                  const uint8_t *payload, size_t plen)
{
    derp_client_t *c = (derp_client_t *)ctx;
    if (c == NULL || c->tls == NULL) return -1;
    if (plen > 0xffffffffU) return -1;

    xSemaphoreTake(c->write_lock, portMAX_DELAY);
    if (c->tls == NULL) {           /* closed while we waited for the lock */
        xSemaphoreGive(c->write_lock);
        return -1;
    }
    int rc = write_frame_locked(c, type, NULL, payload, plen);
    xSemaphoreGive(c->write_lock);
    return rc;
}

esp_err_t derp_client_run(derp_client_t *c,
                          uint8_t *frame_buf, size_t frame_cap,
                          derp_event_cb_t cb, void *cb_ctx)
{
    if (c == NULL || c->tls == NULL || !c->connected || frame_buf == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    int rc = derp_run_loop(derp_tls_read, derp_send_frame_locked, c,
                           frame_buf, frame_cap, cb, cb_ctx,
                           DERP_MAX_IDLE_POLLS);
    switch (rc) {
        case  0: return ESP_OK;                          /* cb stop */
        case -2: return ESP_ERR_INVALID_RESPONSE;        /* RESTARTING */
        default: return ESP_FAIL;
    }
}

/* True when the conn's socket can take a frame without blocking: lwIP's
 * select() marks a TCP socket writable only above TCP_SNDLOWAT free
 * send-buffer bytes (≈ 2.9 KB here), more than one DERP frame + TLS
 * record (≤ ~1.6 KB). Caller holds c->write_lock. */
static bool socket_writable_now(derp_client_t *c)
{
    int fd = -1;
    if (esp_tls_get_conn_sockfd(c->tls, &fd) != ESP_OK || fd < 0) return false;
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);
    struct timeval tv = { 0, 0 };
    return select(fd + 1, NULL, &wfds, NULL, &tv) == 1;
}

static esp_err_t send_packet(derp_client_t *c,
                             const uint8_t dst_pub[DERP_KEY_LEN],
                             const uint8_t *packet, size_t plen,
                             bool no_wait)
{
    if (c == NULL || c->tls == NULL || !c->connected || c->write_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (dst_pub == NULL || (plen > 0 && packet == NULL)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (plen > DERP_MAX_PACKET) return ESP_ERR_INVALID_SIZE;

    /* FrameSendPacket payload = dstPub[32] || packet[plen], one frame
     * written under the write lock so the recv loop's pongs cannot land
     * inside it. */
    if (xSemaphoreTake(c->write_lock, no_wait ? 0 : portMAX_DELAY) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    /* Re-validate under the lock: derp_client_close may have torn the
     * connection down between the unlocked pre-check above and here. */
    if (c->tls == NULL || !c->connected) {
        xSemaphoreGive(c->write_lock);
        return ESP_ERR_INVALID_STATE;
    }
    if (no_wait && !socket_writable_now(c)) {
        xSemaphoreGive(c->write_lock);
        return ESP_ERR_TIMEOUT;
    }
    int rc = write_frame_locked(c, DERP_FRAME_SEND_PACKET, dst_pub,
                                packet, plen);
    xSemaphoreGive(c->write_lock);
    return (rc == 0) ? ESP_OK : ESP_FAIL;
}

esp_err_t derp_client_send_packet(derp_client_t *c,
                                  const uint8_t dst_pub[DERP_KEY_LEN],
                                  const uint8_t *packet, size_t plen)
{
    return send_packet(c, dst_pub, packet, plen, false);
}

esp_err_t derp_client_try_send_packet(derp_client_t *c,
                                      const uint8_t dst_pub[DERP_KEY_LEN],
                                      const uint8_t *packet, size_t plen)
{
    return send_packet(c, dst_pub, packet, plen, true);
}

#endif /* ESP_PLATFORM */
