// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#ifdef ESP_PLATFORM

#include "derp_client.h"

#include <string.h>
#include <stdio.h>

#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/ssl.h"

#include "tls_io.h"

static const char *TAG = "derp_client";

/* Same budget as ts2021 — covers cert chain verify + ECDSA. */
#define DERP_TLS_TIMEOUT_MS 30000

/* Largest single read for either the upgrade response or any login
 * frame. ServerKey ≈ 40 B, ServerInfo box typically ≤ 100 B. 256 B
 * leaves comfortable headroom and stays small enough for the stack. */
#define DERP_LOGIN_BUF_LEN  256

/* esp-tls callback adapters for tls_io_*. */
static ssize_t derp_tls_read(void *ctx, uint8_t *buf, size_t len) {
    return esp_tls_conn_read((esp_tls_t *)ctx, buf, len);
}
static ssize_t derp_tls_write(void *ctx, const uint8_t *buf, size_t len) {
    return esp_tls_conn_write((esp_tls_t *)ctx, (void *)buf, len);
}

static esp_err_t tls_read_full(esp_tls_t *tls, uint8_t *buf, size_t need)
{
    int rc = tls_io_read_full(derp_tls_read, tls, buf, need);
    if (rc != 0) {
        ESP_LOGE(TAG, "tls_read_full failed: %d", rc);
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t tls_write_full(esp_tls_t *tls, const uint8_t *buf, size_t len)
{
    int rc = tls_io_write_full(derp_tls_write, tls, buf, len);
    if (rc != 0) {
        ESP_LOGE(TAG, "tls_write_full failed: %d", rc);
        return ESP_FAIL;
    }
    return ESP_OK;
}

/* Read the HTTP/1.1 upgrade response one byte at a time until the
 * "\r\n\r\n" terminator. Same shape as ts2021_client.c's
 * read_upgrade_response — DERP servers return a real 101 (no fast-
 * start path on this code path), so we wait for full headers. */
static esp_err_t read_upgrade_response(esp_tls_t *tls,
                                       uint8_t *buf, size_t buf_size)
{
    size_t total = 0;
    while (total < buf_size - 1) {
        ssize_t r = esp_tls_conn_read(tls, buf + total, 1);
        if (r == MBEDTLS_ERR_SSL_WANT_READ ||
            r == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
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
                                size_t *plen_out)
{
    uint8_t hdr[DERP_FRAME_HDR_LEN];
    if (tls_read_full(tls, hdr, sizeof(hdr)) != ESP_OK) return ESP_FAIL;

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
        if (tls_read_full(tls, payload, plen) != ESP_OK) return ESP_FAIL;
    }
    *plen_out = plen;
    return ESP_OK;
}

esp_err_t derp_client_connect_login(derp_client_t *out,
                                    const char *server_host, uint16_t port,
                                    const uint8_t client_priv[DERP_KEY_LEN],
                                    const uint8_t client_pub[DERP_KEY_LEN])
{
    if (out == NULL || server_host == NULL || port == 0 ||
        client_priv == NULL || client_pub == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(out, 0, sizeof(*out));

    char url[160];
    snprintf(url, sizeof(url), "https://%s:%u", server_host, (unsigned)port);

    esp_tls_cfg_t cfg = {
        .crt_bundle_attach = esp_crt_bundle_attach,
        .timeout_ms        = DERP_TLS_TIMEOUT_MS,
    };

    out->tls = esp_tls_init();
    if (out->tls == NULL) {
        ESP_LOGE(TAG, "esp_tls_init failed");
        return ESP_FAIL;
    }

    int rc = esp_tls_conn_http_new_sync(url, &cfg, out->tls);
    if (rc != 1) {
        ESP_LOGE(TAG, "TLS connect to %s:%u failed", server_host, (unsigned)port);
        derp_client_close(out);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "TLS up to %s:%u, sending HTTP upgrade", server_host, (unsigned)port);

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
    if (n <= 0 || n >= (int)sizeof(req)) {
        derp_client_close(out);
        return ESP_ERR_INVALID_SIZE;
    }
    if (tls_write_full(out->tls, (const uint8_t *)req, (size_t)n) != ESP_OK) {
        derp_client_close(out);
        return ESP_FAIL;
    }

    /* Read the 101 response. */
    uint8_t up_resp[DERP_LOGIN_BUF_LEN];
    if (read_upgrade_response(out->tls, up_resp, sizeof(up_resp)) != ESP_OK) {
        derp_client_close(out);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "got HTTP 101, entering DERP frame mode");

    /* Frame 1: server → client FrameServerKey. */
    derp_frame_type_t ftype;
    uint8_t  payload[DERP_LOGIN_BUF_LEN];
    size_t   plen = 0;
    if (read_one_frame(out->tls, &ftype, payload, sizeof(payload), &plen) != ESP_OK) {
        derp_client_close(out);
        return ESP_FAIL;
    }
    if (ftype != DERP_FRAME_SERVER_KEY) {
        ESP_LOGE(TAG, "expected ServerKey, got 0x%02x", (unsigned)ftype);
        derp_client_close(out);
        return ESP_FAIL;
    }
    if (derp_parse_server_key(payload, plen, out->server_pub) != 0) {
        ESP_LOGE(TAG, "ServerKey parse failed (plen=%u)", (unsigned)plen);
        derp_client_close(out);
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
        derp_client_close(out);
        return ESP_FAIL;
    }
    derp_write_frame_header(ci_buf, DERP_FRAME_CLIENT_INFO,
                            (uint32_t)ci_payload_len);
    if (tls_write_full(out->tls, ci_buf,
                       DERP_FRAME_HDR_LEN + ci_payload_len) != ESP_OK) {
        derp_client_close(out);
        return ESP_FAIL;
    }

    /* Frame 3: server → client FrameServerInfo. */
    if (read_one_frame(out->tls, &ftype, payload, sizeof(payload), &plen) != ESP_OK) {
        derp_client_close(out);
        return ESP_FAIL;
    }
    if (ftype != DERP_FRAME_SERVER_INFO) {
        ESP_LOGE(TAG, "expected ServerInfo, got 0x%02x", (unsigned)ftype);
        derp_client_close(out);
        return ESP_FAIL;
    }
    if (derp_parse_server_info(payload, plen, client_priv, out->server_pub,
                               &out->server_version) != 0) {
        ESP_LOGE(TAG, "ServerInfo decrypt/parse failed");
        derp_client_close(out);
        return ESP_FAIL;
    }

    out->connected = true;
    ESP_LOGI(TAG, "DERP login OK: server version=%d", out->server_version);
    return ESP_OK;
}

void derp_client_close(derp_client_t *c)
{
    if (c == NULL) return;
    if (c->tls != NULL) {
        esp_tls_conn_destroy(c->tls);
        c->tls = NULL;
    }
    c->connected = false;
}

#endif /* ESP_PLATFORM */
