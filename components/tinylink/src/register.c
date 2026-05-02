// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "register.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_log.h"

#include "cJSON.h"

#include "json_helpers.h"
#include "ts2021_client.h"

static const char *TAG = "register";

#define REQUEST_BUF  2048
#define RESPONSE_BUF 4096

static void hex_encode(const uint8_t *in, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hex[in[i] >> 4];
        out[2 * i + 1] = hex[in[i] & 0x0F];
    }
    out[2 * len] = '\0';
}

/* Tailscale's JSON convention encodes 32-byte keys as "<prefix>:<hex>". */
static void format_keyed_hex(char *out, const char *prefix,
                             const uint8_t key[32])
{
    size_t plen = strlen(prefix);
    memcpy(out, prefix, plen);
    hex_encode(key, 32, out + plen);
}

static int base64_encode(const uint8_t *in, size_t in_len,
                         char *out, size_t out_size)
{
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t needed = ((in_len + 2) / 3) * 4 + 1;
    if (needed > out_size) return -1;

    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in_len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < in_len) v |= (uint32_t)in[i + 2];
        out[o++] = b64[(v >> 18) & 0x3F];
        out[o++] = b64[(v >> 12) & 0x3F];
        out[o++] = (i + 1 < in_len) ? b64[(v >> 6) & 0x3F] : '=';
        out[o++] = (i + 2 < in_len) ? b64[v & 0x3F]        : '=';
    }
    out[o] = '\0';
    return 0;
}

static esp_err_t build_request_body(const tinylink_keys_t *keys,
                                    const char *auth_key,
                                    const uint8_t *node_key_signature,
                                    size_t node_key_signature_len,
                                    char *out, size_t out_size,
                                    int *out_len)
{
    char node_key_hex[8 + 64 + 1];
    char old_node_key[8 + 64 + 1];
    char node_key_sig_b64[512] = {0};

    format_keyed_hex(node_key_hex, "nodekey:", keys->node_pub);
    /* OldNodeKey is all zeros on first registration. */
    memcpy(old_node_key, "nodekey:", 8);
    memset(old_node_key + 8, '0', 64);
    old_node_key[8 + 64] = '\0';

    if (node_key_signature_len > 0) {
        if (base64_encode(node_key_signature, node_key_signature_len,
                          node_key_sig_b64, sizeof(node_key_sig_b64)) != 0) {
            return ESP_ERR_INVALID_SIZE;
        }
    }

    /* RFC3339 timestamp from the current wall clock. If time isn't synced
     * we still send something monotonic-ish; the control plane will reject
     * if the skew is too large. */
    char ts[40];
    time_t now = time(NULL);
    struct tm tm_utc;
    gmtime_r(&now, &tm_utc);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);

    cJSON *root = cJSON_CreateObject();
    cJSON *hostinfo = cJSON_CreateObject();
    cJSON *auth = cJSON_CreateObject();
    if (root == NULL || hostinfo == NULL || auth == NULL) {
        cJSON_Delete(root); cJSON_Delete(hostinfo); cJSON_Delete(auth);
        return ESP_ERR_NO_MEM;
    }

    cJSON_AddNumberToObject(root, "Version", 100);
    cJSON_AddStringToObject(root, "NodeKey", node_key_hex);
    cJSON_AddStringToObject(root, "OldNodeKey", old_node_key);
    cJSON_AddStringToObject(root, "Followup", "");
    cJSON_AddStringToObject(root, "Timestamp", ts);
    cJSON_AddStringToObject(root, "Expiry", "0001-01-01T00:00:00Z");
    cJSON_AddBoolToObject(root, "Ephemeral", false);
    if (node_key_signature_len > 0) {
        cJSON_AddStringToObject(root, "NodeKeySignature", node_key_sig_b64);
    }

    cJSON_AddStringToObject(hostinfo, "OS", "esp32");
    cJSON_AddStringToObject(hostinfo, "Hostname", CONFIG_TINYLINK_DEVICE_HOSTNAME);
    cJSON_AddStringToObject(hostinfo, "IPNVersion", "0.1.0-tinylink");
    cJSON_AddItemToObject(root, "Hostinfo", hostinfo);

    cJSON_AddStringToObject(auth, "AuthKey", auth_key);
    cJSON_AddItemToObject(root, "Auth", auth);

    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (body == NULL) return ESP_ERR_NO_MEM;

    size_t body_len = strlen(body);
    if (body_len + 1 > out_size) {
        cJSON_free(body);
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(out, body, body_len + 1);
    *out_len = (int)body_len;
    cJSON_free(body);
    return ESP_OK;
}

esp_err_t register_emit(ts2021_conn_t *conn,
                        const tinylink_keys_t *keys,
                        const char *auth_key)
{
    if (conn == NULL || keys == NULL || auth_key == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    char  body[REQUEST_BUF];
    int   body_len = 0;
    esp_err_t err = build_request_body(keys, auth_key,
                                       conn->node_key_signature,
                                       conn->node_key_signature_len,
                                       body, sizeof(body), &body_len);
    if (err != ESP_OK) return err;

    /* HTTP/1.1 request line + headers + body, as one Noise record. M2 will
     * upgrade the inner protocol to HTTP/2 (see ts2021_client.h). */
    char req[REQUEST_BUF + 256];
    int n = snprintf(req, sizeof(req),
        "POST /machine/register HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "\r\n%s",
        CONFIG_TINYLINK_CONTROL_HOST, body_len, body);
    if (n <= 0 || n >= (int)sizeof(req)) return ESP_ERR_INVALID_SIZE;

    if (ts2021_send(conn, (const uint8_t *)req, (size_t)n) != ESP_OK) {
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "/machine/register sent (%d bytes JSON)", body_len);

    uint8_t resp[RESPONSE_BUF];
    size_t  resp_len = 0;
    if (ts2021_recv(conn, resp, sizeof(resp) - 1, &resp_len) != ESP_OK) {
        return ESP_FAIL;
    }
    resp[resp_len] = '\0';

    /* Find body after CRLFCRLF. */
    const char *body_start = strstr((const char *)resp, "\r\n\r\n");
    if (body_start == NULL) {
        ESP_LOGE(TAG, "register response missing CRLFCRLF");
        return ESP_FAIL;
    }
    body_start += 4;

    cJSON *root = cJSON_Parse(body_start);
    if (root == NULL) {
        ESP_LOGE(TAG, "register response did not parse as JSON");
        return ESP_ERR_INVALID_RESPONSE;
    }
    bool authorized = false;
    err = json_get_bool(root, "MachineAuthorized", &authorized);
    if (err == ESP_ERR_NOT_FOUND) {
        char err_msg[160] = {0};
        if (json_get_string(root, "Error", err_msg, sizeof(err_msg)) == ESP_OK
            && err_msg[0] != '\0') {
            ESP_LOGE(TAG, "control plane error: %s", err_msg);
        }
        cJSON_Delete(root);
        return ESP_FAIL;
    }
    cJSON_Delete(root);
    if (err != ESP_OK) return err;

    if (!authorized) {
        ESP_LOGW(TAG, "MachineAuthorized=false — waiting for operator approval");
        return ESP_ERR_NOT_FINISHED;
    }
    ESP_LOGI(TAG, "MachineAuthorized=true — node registered");
    return ESP_OK;
}
