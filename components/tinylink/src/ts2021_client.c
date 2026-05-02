// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "ts2021_client.h"

#include <stdio.h>
#include <string.h>

#include "esp_crt_bundle.h"
#include "esp_log.h"

static const char *TAG = "ts2021";

#define UPGRADE_TOKEN  "tailscale-control-protocol"
#define HANDSHAKE_HDR  "X-Tailscale-Handshake"

#define TLS_TIMEOUT_MS 30000
#define HTTP_RESPONSE_BUF 4096

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

static esp_err_t tls_read_full(esp_tls_t *tls, uint8_t *buf, size_t need)
{
    size_t got = 0;
    while (got < need) {
        ssize_t r = esp_tls_conn_read(tls, buf + got, need - got);
        if (r < 0) {
            ESP_LOGE(TAG, "esp_tls_conn_read failed: %d", (int)r);
            return ESP_FAIL;
        }
        if (r == 0) return ESP_FAIL;
        got += (size_t)r;
    }
    return ESP_OK;
}

static esp_err_t tls_write_full(esp_tls_t *tls, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t w = esp_tls_conn_write(tls, buf + sent, len - sent);
        if (w < 0) {
            ESP_LOGE(TAG, "esp_tls_conn_write failed: %d", (int)w);
            return ESP_FAIL;
        }
        sent += (size_t)w;
    }
    return ESP_OK;
}

static esp_err_t read_upgrade_response(esp_tls_t *tls,
                                       uint8_t *buf, size_t buf_size)
{
    size_t total = 0;
    while (total < buf_size - 1) {
        ssize_t r = esp_tls_conn_read(tls, buf + total, 1);
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

/* After the Noise handshake, the very first 9 plaintext bytes are
 * either the EarlyPayload sentinel or the start of HTTP/2 SETTINGS.
 *  - On magic: skip the JSON of declared length, residual = anything past it.
 *  - Otherwise: residual = those 9 bytes (HTTP/2 begins there). */
static esp_err_t consume_early_payload(ts2021_conn_t *c)
{
    uint8_t pt[TS2021_RECORD_PLAINTEXT_MAX];
    size_t  pt_len = 0;
    if (recv_record_plaintext(c, pt, sizeof(pt), &pt_len) != ESP_OK) {
        return ESP_FAIL;
    }
    if (pt_len < TS2021_EARLY_PAYLOAD_HDR_LEN) {
        /* Pathologically small first record. Stash whatever we have. */
        memcpy(c->rx_residual, pt, pt_len);
        c->rx_residual_len = pt_len;
        c->rx_residual_off = 0;
        return ESP_OK;
    }

    if (memcmp(pt, TS2021_EARLY_PAYLOAD_MAGIC,
               TS2021_EARLY_PAYLOAD_MAGIC_LEN) != 0) {
        /* No early payload: those 9 bytes are HTTP/2 SETTINGS. */
        memcpy(c->rx_residual, pt, pt_len);
        c->rx_residual_len = pt_len;
        c->rx_residual_off = 0;
        return ESP_OK;
    }

    uint32_t ep_len = ((uint32_t)pt[5] << 24) | ((uint32_t)pt[6] << 16) |
                     ((uint32_t)pt[7] <<  8) |  (uint32_t)pt[8];
    if (ep_len > 64 * 1024) {
        ESP_LOGE(TAG, "EarlyPayload too large: %u", (unsigned)ep_len);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "EarlyPayload sentinel found, %u bytes JSON (skipping)",
             (unsigned)ep_len);

    /* Bytes already consumed past the 9-byte sentinel header. */
    size_t already = pt_len - TS2021_EARLY_PAYLOAD_HDR_LEN;
    if (already >= ep_len) {
        /* JSON fully fits in this record. Residual starts after. */
        size_t residual = already - ep_len;
        if (residual > 0) {
            memcpy(c->rx_residual,
                   pt + TS2021_EARLY_PAYLOAD_HDR_LEN + ep_len, residual);
        }
        c->rx_residual_len = residual;
        c->rx_residual_off = 0;
        return ESP_OK;
    }
    /* Need more records to drain ep_len bytes. */
    size_t to_skip = ep_len - already;
    while (to_skip > 0) {
        size_t got = 0;
        if (recv_record_plaintext(c, pt, sizeof(pt), &got) != ESP_OK) {
            return ESP_FAIL;
        }
        if (got <= to_skip) {
            to_skip -= got;
        } else {
            size_t residual = got - to_skip;
            memcpy(c->rx_residual, pt + to_skip, residual);
            c->rx_residual_len = residual;
            c->rx_residual_off = 0;
            return ESP_OK;
        }
    }
    c->rx_residual_len = 0;
    c->rx_residual_off = 0;
    return ESP_OK;
}

esp_err_t ts2021_connect(ts2021_conn_t *out,
                         const uint8_t machine_priv[NOISE_DHLEN],
                         const uint8_t machine_pub[NOISE_DHLEN],
                         const uint8_t control_pub[NOISE_DHLEN])
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    char host_with_port[160];
    snprintf(host_with_port, sizeof(host_with_port), "https://%s:%d",
             CONFIG_TINYLINK_CONTROL_HOST, CONFIG_TINYLINK_CONTROL_PORT);

    esp_tls_cfg_t tls_cfg = {
        .crt_bundle_attach = esp_crt_bundle_attach,
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

    /* Noise IK with prologue = "Tailscale Control Protocol v1". The
     * version is also placed in the cleartext header of the initiation
     * frame; mixing it into the prologue binds the encrypted handshake
     * to the advertised version. */
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

    char req[1024];
    int n = snprintf(req, sizeof(req),
        "POST /ts2021 HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: %s\r\n"
        "Connection: upgrade\r\n"
        "%s: %s\r\n"
        "Content-Length: 0\r\n"
        "\r\n",
        CONFIG_TINYLINK_CONTROL_HOST, UPGRADE_TOKEN,
        HANDSHAKE_HDR, init_b64);
    if (n <= 0 || n >= (int)sizeof(req)) {
        ts2021_close(out);
        return ESP_ERR_INVALID_SIZE;
    }
    if (tls_write_full(out->tls, (const uint8_t *)req, (size_t)n) != ESP_OK) {
        ts2021_close(out);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "ts2021: sent init in X-Tailscale-Handshake (%u bytes), waiting for 101",
             (unsigned)sizeof(init));

    /* Read 101 + headers. */
    uint8_t resp_buf[HTTP_RESPONSE_BUF];
    if (read_upgrade_response(out->tls, resp_buf, sizeof(resp_buf)) != ESP_OK) {
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

    /* Skip optional EarlyPayload, leaving rx_residual primed with the
     * first 0..N HTTP/2 plaintext bytes. */
    if (consume_early_payload(out) != ESP_OK) {
        ts2021_close(out);
        return ESP_FAIL;
    }

    out->connected = true;
    return ESP_OK;
}

esp_err_t ts2021_send(ts2021_conn_t *c,
                      const uint8_t *data, size_t data_len)
{
    if (c == NULL || !c->connected) return ESP_ERR_INVALID_STATE;
    if (data_len > TS2021_RECORD_PLAINTEXT_MAX) return ESP_ERR_INVALID_SIZE;

    uint8_t  ct[TS2021_RECORD_PLAINTEXT_MAX + NOISE_TAGLEN];
    size_t   ct_len = 0;
    if (noise_ik_encrypt(&c->noise, ct, sizeof(ct),
                         data, data_len, &ct_len) != ESP_OK) {
        return ESP_FAIL;
    }
    if (ct_len > 0xFFFF) return ESP_ERR_INVALID_SIZE;

    uint8_t hdr[TS2021_HEADER_LEN] = {
        TS2021_MSG_RECORD,
        (uint8_t)((ct_len >> 8) & 0xFF),
        (uint8_t)( ct_len       & 0xFF),
    };
    if (tls_write_full(c->tls, hdr, sizeof(hdr)) != ESP_OK) return ESP_FAIL;
    return tls_write_full(c->tls, ct, ct_len);
}

esp_err_t ts2021_recv(ts2021_conn_t *c,
                      uint8_t *out, size_t out_max, size_t *out_len)
{
    if (c == NULL || !c->connected) return ESP_ERR_INVALID_STATE;
    if (out == NULL || out_len == NULL) return ESP_ERR_INVALID_ARG;

    /* Drain residual first. */
    if (c->rx_residual_off < c->rx_residual_len) {
        size_t avail = c->rx_residual_len - c->rx_residual_off;
        size_t take  = (out_max < avail) ? out_max : avail;
        memcpy(out, c->rx_residual + c->rx_residual_off, take);
        c->rx_residual_off += take;
        *out_len = take;
        return ESP_OK;
    }

    return recv_record_plaintext(c, out, out_max, out_len);
}

void ts2021_close(ts2021_conn_t *c)
{
    if (c == NULL) return;
    if (c->tls != NULL) {
        esp_tls_conn_destroy(c->tls);
        c->tls = NULL;
    }
    c->connected = false;
}
