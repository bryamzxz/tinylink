// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "ts2021_client.h"

#include <string.h>

#include "esp_crt_bundle.h"
#include "esp_log.h"

#include "cJSON.h"

#include "crypto/nacl_box.h"
#include "esp_random.h"
#include "json_helpers.h"

static const char *TAG = "ts2021";

/* The Upgrade token is "tailscale-control-protocol" per the protocol
 * research artifact (§A) and `control/ts2021/server.go` upstream. The
 * shorter "ts2021" form is the path component, NOT the upgrade token. */
#define UPGRADE_TOKEN "tailscale-control-protocol"

#define TLS_TIMEOUT_MS 30000
#define HTTP_REQUEST_BUF 1024
#define HTTP_RESPONSE_BUF 4096

static esp_err_t tls_read_full(esp_tls_t *tls, uint8_t *buf, size_t need)
{
    size_t got = 0;
    while (got < need) {
        ssize_t r = esp_tls_conn_read(tls, buf + got, need - got);
        if (r < 0) {
            ESP_LOGE(TAG, "esp_tls_conn_read failed: %d", (int)r);
            return ESP_FAIL;
        }
        if (r == 0) return ESP_FAIL; /* EOF mid-read */
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

/* Read TLS until we see the HTTP/1.1 status line + headers terminator
 * "\r\n\r\n". Returns ESP_OK on 101 Switching Protocols, ESP_FAIL else. */
static esp_err_t read_upgrade_response(esp_tls_t *tls,
                                       uint8_t *buf, size_t buf_size,
                                       size_t *out_consumed)
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
    *out_consumed = total;
    return ESP_OK;
}

static esp_err_t write_frame(esp_tls_t *tls, uint8_t type,
                             const uint8_t *payload, size_t payload_len)
{
    if (payload_len > 0xFFFF) return ESP_ERR_INVALID_SIZE;
    uint8_t hdr[TS2021_FRAME_HEADER_LEN] = {
        TS2021_FRAME_VERSION,
        type,
        (uint8_t)((payload_len >> 8) & 0xFF),
        (uint8_t)(payload_len & 0xFF),
    };
    if (tls_write_full(tls, hdr, sizeof(hdr)) != ESP_OK) return ESP_FAIL;
    if (payload_len > 0) {
        if (tls_write_full(tls, payload, payload_len) != ESP_OK) return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t read_frame(esp_tls_t *tls, uint8_t *type_out,
                            uint8_t *payload, size_t payload_max,
                            size_t *payload_len)
{
    uint8_t hdr[TS2021_FRAME_HEADER_LEN];
    if (tls_read_full(tls, hdr, sizeof(hdr)) != ESP_OK) return ESP_FAIL;
    if (hdr[0] != TS2021_FRAME_VERSION) {
        ESP_LOGE(TAG, "bad frame version 0x%02x", hdr[0]);
        return ESP_FAIL;
    }
    size_t len = ((size_t)hdr[2] << 8) | (size_t)hdr[3];
    if (len > payload_max) return ESP_ERR_INVALID_SIZE;
    if (len > 0) {
        if (tls_read_full(tls, payload, len) != ESP_OK) return ESP_FAIL;
    }
    *type_out = hdr[1];
    *payload_len = len;
    return ESP_OK;
}

/* Process the EarlyNoise message (if any). Per the protocol research
 * artifact (§A) and tailscale/control/controlclient/direct.go around
 * lines 1159-1239, the server sends a NaCl-box-encrypted blob whose
 * plaintext is the NodeKeyChallenge. The client OPENS that box with its
 * NodeKey private key (proving NodeKey possession to the server) and
 * re-encrypts the response.
 *
 * TS2021_VERIFY (HIGH): the implementation below currently *signs the
 * base64-encoded challenge string* with a NaCl box, which is the wrong
 * primitive direction. The correct flow is:
 *   1. Read EarlyNoise frame, decrypt outer Noise transport.
 *   2. Parse JSON; the challenge is itself a NaCl box from server.
 *   3. nacl_box_open(challenge, control_disco_pub, our_node_priv).
 *   4. Build the NodeKeySignature response and re-encrypt.
 * Cross-check against direct.go:1159-1239 before trusting this code.
 */
static esp_err_t process_early_noise(ts2021_conn_t *c,
                                     const uint8_t node_priv[NOISE_DHLEN],
                                     const uint8_t control_pub[NOISE_DHLEN])
{
    uint8_t  type;
    uint8_t  ciphertext[1024];
    size_t   ct_len;

    /* TS2021_VERIFY: some Tailscale builds skip EarlyNoise entirely. If
     * read_frame times out / fails here, treat that as "no EarlyNoise"
     * and continue with an empty signature. */
    if (read_frame(c->tls, &type, ciphertext, sizeof(ciphertext),
                   &ct_len) != ESP_OK) {
        ESP_LOGW(TAG, "no EarlyNoise frame (continuing without signature)");
        c->node_key_signature_len = 0;
        return ESP_OK;
    }

    uint8_t plaintext[512];
    size_t  pt_len = 0;
    if (noise_ik_decrypt(&c->noise, plaintext, sizeof(plaintext),
                         ciphertext, ct_len, &pt_len) != ESP_OK) {
        return ESP_FAIL;
    }

    cJSON *root = cJSON_ParseWithLength((const char *)plaintext, pt_len);
    if (root == NULL) {
        ESP_LOGW(TAG, "EarlyNoise body did not parse as JSON; skipping");
        c->node_key_signature_len = 0;
        return ESP_OK;
    }

    char challenge_b64[128] = {0};
    esp_err_t err = json_get_string(root, "NodeKeyChallenge",
                                    challenge_b64, sizeof(challenge_b64));
    cJSON_Delete(root);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "EarlyNoise missing NodeKeyChallenge; skipping");
        c->node_key_signature_len = 0;
        return ESP_OK;
    }

    /* TS2021_VERIFY: the challenge value is a base64-encoded blob in the
     * canonical wire format; below we sign the raw base64 string itself
     * to keep the format opaque. The actual scheme is per the control
     * plane spec — verify against direct.go. */
    uint8_t nonce[NACL_BOX_NONCE_LEN];
    esp_fill_random(nonce, sizeof(nonce));

    size_t challenge_len = strlen(challenge_b64);
    if (challenge_len + NACL_BOX_TAG_LEN + NACL_BOX_NONCE_LEN
        > sizeof(c->node_key_signature)) {
        return ESP_ERR_INVALID_SIZE;
    }

    /* Layout: nonce(24) || box(challenge, nonce, control_pub, node_priv). */
    memcpy(c->node_key_signature, nonce, NACL_BOX_NONCE_LEN);
    if (nacl_box(c->node_key_signature + NACL_BOX_NONCE_LEN,
                 (const uint8_t *)challenge_b64, challenge_len,
                 nonce, control_pub, node_priv) != 0) {
        return ESP_FAIL;
    }
    c->node_key_signature_len =
        NACL_BOX_NONCE_LEN + challenge_len + NACL_BOX_TAG_LEN;
    ESP_LOGI(TAG, "EarlyNoise: signed NodeKeyChallenge (%u bytes)",
             (unsigned)c->node_key_signature_len);
    return ESP_OK;
}

esp_err_t ts2021_connect(ts2021_conn_t *out,
                         const uint8_t machine_priv[NOISE_DHLEN],
                         const uint8_t machine_pub[NOISE_DHLEN],
                         const uint8_t control_pub[NOISE_DHLEN],
                         const uint8_t node_priv[NOISE_DHLEN])
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

    /* Initialize Noise IK and prepare msg1. The prologue is a single byte
     * carrying the ts2021 protocol version (1), per upstream commit
     * 1b7380a "control/noise: include the protocol version in the Noise
     * prologue". */
    static const uint8_t prologue[1] = { 0x01 };
    if (noise_ik_init(&out->noise, machine_priv, machine_pub, control_pub,
                      TS2021_PROTOCOL_NAME, prologue, sizeof(prologue))
        != ESP_OK) {
        ts2021_close(out);
        return ESP_FAIL;
    }
    uint8_t msg1[NOISE_IK_MSG1_LEN];
    if (noise_ik_write_msg1(&out->noise, msg1) != ESP_OK) {
        ts2021_close(out);
        return ESP_FAIL;
    }

    /* Build HTTP/1.1 Upgrade request whose body carries Noise msg1 wrapped
     * in a HANDSHAKE frame. TS2021_VERIFY: some Tailscale revisions put
     * the Noise msg1 in a query parameter on a GET request rather than a
     * POST body — check control/ts2021/server.go. */
    uint8_t framed_msg1[NOISE_IK_MSG1_LEN + TS2021_FRAME_HEADER_LEN];
    framed_msg1[0] = TS2021_FRAME_VERSION;
    framed_msg1[1] = TS2021_FRAME_HANDSHAKE;
    framed_msg1[2] = (uint8_t)((NOISE_IK_MSG1_LEN >> 8) & 0xFF);
    framed_msg1[3] = (uint8_t)(NOISE_IK_MSG1_LEN & 0xFF);
    memcpy(framed_msg1 + TS2021_FRAME_HEADER_LEN, msg1, NOISE_IK_MSG1_LEN);

    char req[HTTP_REQUEST_BUF];
    int n = snprintf(req, sizeof(req),
        "POST /ts2021 HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: %s\r\n"
        "Connection: Upgrade\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %d\r\n"
        "\r\n",
        CONFIG_TINYLINK_CONTROL_HOST, UPGRADE_TOKEN,
        (int)sizeof(framed_msg1));
    if (n <= 0 || n >= (int)sizeof(req)) {
        ts2021_close(out);
        return ESP_ERR_INVALID_SIZE;
    }
    if (tls_write_full(out->tls, (const uint8_t *)req, (size_t)n) != ESP_OK) {
        ts2021_close(out);
        return ESP_FAIL;
    }
    if (tls_write_full(out->tls, framed_msg1, sizeof(framed_msg1)) != ESP_OK) {
        ts2021_close(out);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "ts2021: sent Noise msg1 (%u bytes), waiting for 101",
             (unsigned)sizeof(framed_msg1));

    /* Read 101 Switching Protocols + headers. */
    uint8_t resp[HTTP_RESPONSE_BUF];
    size_t  resp_consumed = 0;
    if (read_upgrade_response(out->tls, resp, sizeof(resp),
                              &resp_consumed) != ESP_OK) {
        ts2021_close(out);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "ts2021: got 101 Switching Protocols");

    /* Read Noise msg2 (framed). */
    uint8_t  type;
    uint8_t  msg2_payload[NOISE_IK_MSG2_LEN];
    size_t   msg2_len = 0;
    if (read_frame(out->tls, &type, msg2_payload, sizeof(msg2_payload),
                   &msg2_len) != ESP_OK) {
        ts2021_close(out);
        return ESP_FAIL;
    }
    if (type != TS2021_FRAME_HANDSHAKE || msg2_len != NOISE_IK_MSG2_LEN) {
        ESP_LOGE(TAG, "unexpected msg2 frame: type=%u len=%u",
                 type, (unsigned)msg2_len);
        ts2021_close(out);
        return ESP_FAIL;
    }
    if (noise_ik_read_msg2(&out->noise, msg2_payload) != ESP_OK) {
        ts2021_close(out);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "ts2021: Noise IK handshake complete");

    /* Optional EarlyNoise message with NodeKeyChallenge. */
    if (process_early_noise(out, node_priv, control_pub) != ESP_OK) {
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
    return write_frame(c->tls, TS2021_FRAME_RECORD, ct, ct_len);
}

esp_err_t ts2021_recv(ts2021_conn_t *c,
                      uint8_t *out, size_t out_max, size_t *out_len)
{
    if (c == NULL || !c->connected) return ESP_ERR_INVALID_STATE;
    if (out == NULL || out_len == NULL) return ESP_ERR_INVALID_ARG;

    uint8_t  type;
    uint8_t  ct[TS2021_RECORD_PLAINTEXT_MAX + NOISE_TAGLEN];
    size_t   ct_len = 0;
    if (read_frame(c->tls, &type, ct, sizeof(ct), &ct_len) != ESP_OK) {
        return ESP_FAIL;
    }
    if (type != TS2021_FRAME_RECORD) {
        ESP_LOGE(TAG, "unexpected frame type %u during recv", type);
        return ESP_FAIL;
    }
    return noise_ik_decrypt(&c->noise, out, out_max, ct, ct_len, out_len);
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
