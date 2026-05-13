// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "register.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_log.h"

#include "cJSON.h"

#include "h2_client.h"
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

static esp_err_t build_request_body(const tinylink_keys_t *keys,
                                    const char *auth_key,
                                    char *out, size_t out_size,
                                    int *out_len)
{
    char node_key_hex[8 + 64 + 1];
    char old_node_key[8 + 64 + 1];
    char nl_key_zero[6 + 64 + 1];

    format_keyed_hex(node_key_hex, "nodekey:", keys->node_pub);
    /* OldNodeKey is all zeros on first registration. */
    memcpy(old_node_key, "nodekey:", 8);
    memset(old_node_key + 8, '0', 64);
    old_node_key[8 + 64] = '\0';

    /* NLKey is required (no `omitempty` upstream). M1 has no TKA, so an
     * all-zero Ed25519 public key is tolerated. Real NLPrivate generation
     * lands in M7 hardening. */
    memcpy(nl_key_zero, "nlpub:", 6);
    memset(nl_key_zero + 6, '0', 64);
    nl_key_zero[6 + 64] = '\0';

    cJSON *root = cJSON_CreateObject();
    cJSON *hostinfo = cJSON_CreateObject();
    cJSON *auth = cJSON_CreateObject();
    if (root == NULL || hostinfo == NULL || auth == NULL) {
        cJSON_Delete(root); cJSON_Delete(hostinfo); cJSON_Delete(auth);
        return ESP_ERR_NO_MEM;
    }

    /* Version here is the Tailscale CapabilityVersion. Production
     * clients use tailcfg.CurrentCapabilityVersion (= 138 as of
     * 2026-05-02 per /home/bryam/dev/tailscale/tailcfg/tailcfg.go).
     * M1 had hardcoded 1 — the server treated our request as a
     * legacy client and silently dropped the connection after
     * sending SETTINGS, observed as a 31s TLS-read timeout on
     * first hardware boot. */
    cJSON_AddNumberToObject(root, "Version", 138);
    cJSON_AddStringToObject(root, "NodeKey", node_key_hex);
    cJSON_AddStringToObject(root, "OldNodeKey", old_node_key);
    cJSON_AddStringToObject(root, "NLKey", nl_key_zero);
    cJSON_AddStringToObject(root, "Followup", "");
    cJSON_AddStringToObject(root, "Expiry", "0001-01-01T00:00:00Z");
    /* Notes per upstream tailcfg.go::RegisterRequest:
     *   - Timestamp / SignatureType / Signature / DeviceCert all carry
     *     `json:",omitempty"` and are only populated for SignatureV1
     *     (machine identity certificates). M1 uses SignatureNone, so
     *     none of these fields should appear in the JSON.
     *   - Ephemeral is `bool, omitempty`: omitted when false. We are
     *     not ephemeral. */

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
                                       body, sizeof(body), &body_len);
    if (err != ESP_OK) return err;

    /* HTTP/2 POST over the Noise channel. The control plane runs
     * http2.Server.ServeConn after the Upgrade and rejects HTTP/1.1
     * inside Noise with PROTOCOL_ERROR. */
    static uint8_t resp[RESPONSE_BUF];
    size_t  resp_len = 0;
    int     status   = 0;
    err = h2_post_json(conn, "/machine/register",
                       CONFIG_TINYLINK_CONTROL_HOST,
                       (const uint8_t *)body, (size_t)body_len,
                       &status, resp, sizeof(resp) - 1, &resp_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "h2_post_json failed: 0x%x", err);
        return err;
    }
    resp[resp_len] = '\0';
    ESP_LOGI(TAG, "/machine/register status=%d body=%u bytes",
             status, (unsigned)resp_len);
    if (status != 200) {
        if (status == 429 || status == 503) {
            ESP_LOGW(TAG, "control plane throttled register: HTTP %d "
                          "(Retry-After=%d s)",
                     status, conn->h2_retry_after_s);
        } else {
            ESP_LOGE(TAG, "control plane returned HTTP %d", status);
        }
        return ESP_FAIL;
    }
    /* h2_drive_request consumes the full body even past resp_len, but
     * silently latches h2_resp_overflow=true (h2_client.c:163-171) when
     * the response exceeds RESPONSE_BUF-1. Parsing a truncated JSON could
     * succeed against attacker-shaped truncation and yield a misleading
     * MachineAuthorized verdict. Refuse rather than risk it — Noise IK
     * authenticates the control plane upstream, but defense-in-depth
     * costs nothing here. */
    if (conn->h2_resp_overflow) {
        ESP_LOGE(TAG, "register response exceeded %u-byte buffer — refusing to parse",
                 (unsigned)(sizeof(resp) - 1));
        return ESP_ERR_INVALID_RESPONSE;
    }

    cJSON *root = cJSON_Parse((const char *)resp);
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
