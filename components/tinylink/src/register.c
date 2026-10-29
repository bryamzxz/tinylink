// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "register.h"

#include <string.h>

#include "esp_log.h"
#include "sdkconfig.h"

#include "crypto/secure_zero.h"
#include "ctrl_buf.h"
#include "h2_client.h"
#include "register_json.h"
#include "tinylink.h"        /* TINYLINK_CAPVER / TINYLINK_IPN_VERSION */
#include "ts2021_client.h"

static const char *TAG = "register";

/* Both live in the shared control buffer (ctrl_buf.h, round 1.3.2): the
 * request at offset 0, the response right behind it. Same sizes as the
 * old stack request / static response. */
#define REQUEST_BUF  2048
#define RESPONSE_BUF 4096
_Static_assert(REQUEST_BUF + RESPONSE_BUF <= TL_CTRL_BUF_SZ,
               "register request + response must fit the control buffer");

static esp_err_t register_emit_in(ts2021_conn_t *conn,
                                  const tinylink_keys_t *keys,
                                  const char *auth_key, uint8_t *buf,
                                  int *http_status)
{
    /* Version is the Tailscale CapabilityVersion (TINYLINK_CAPVER,
     * single source of truth). Production clients use
     * tailcfg.CurrentCapabilityVersion. M1 had hardcoded 1 — the server
     * treated our request as a legacy client and silently dropped the
     * connection after sending SETTINGS, observed as a 31s TLS-read
     * timeout on first hardware boot. Field set and escaping: see
     * register_build_body. */
    char  *body     = (char *)buf;
    size_t body_len = 0;
    esp_err_t err = register_build_body(TINYLINK_CAPVER, keys->node_pub,
                                        CONFIG_TINYLINK_DEVICE_HOSTNAME,
                                        TINYLINK_IPN_VERSION, auth_key,
                                        body, REQUEST_BUF, &body_len);
    if (err != ESP_OK) return err;

    /* HTTP/2 POST over the Noise channel. The control plane runs
     * http2.Server.ServeConn after the Upgrade and rejects HTTP/1.1
     * inside Noise with PROTOCOL_ERROR. */
    uint8_t *resp     = buf + REQUEST_BUF;
    size_t   resp_len = 0;
    int      status   = 0;
    err = h2_post_json(conn, "/machine/register",
                       CONFIG_TINYLINK_CONTROL_HOST,
                       (const uint8_t *)body, body_len,
                       &status, resp, RESPONSE_BUF - 1, &resp_len);
    /* The request may carry the auth key: scrub it the moment it is sent
     * (it used to sit in a dead stack frame; the buffer is long-lived). */
    tl_secure_zero(body, body_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "h2_post_json failed: 0x%x", err);
        return err;
    }
    /* Only an answered request reports a status (register_retry_with_auth
     * reads 0 as "no answer"). */
    *http_status = status;
    resp[resp_len] = '\0';
    ESP_LOGI(TAG, "/machine/register status=%d body=%u bytes%s",
             status, (unsigned)resp_len,
             auth_key != NULL ? "" : " (known node, no auth)");
    if (status != 200) {
        if (status == 429 || status == 503) {
            ESP_LOGW(TAG, "control plane throttled register: HTTP %d "
                          "(Retry-After %s, %d s valid)",
                     status, conn->h2_retry_after_present ? "set" : "absent",
                     conn->h2_retry_after_s);
        } else {
            ESP_LOGE(TAG, "control plane returned HTTP %d", status);
        }
        return ESP_FAIL;
    }
    /* h2_drive_request consumes the full body even past resp_len, but
     * silently latches h2_resp_overflow=true (h2_client.c data_chunk_cb)
     * when the response exceeds RESPONSE_BUF-1. Parsing a truncated JSON
     * could succeed against attacker-shaped truncation and yield a
     * misleading MachineAuthorized verdict. Refuse rather than risk it —
     * Noise IK authenticates the control plane upstream, but
     * defense-in-depth costs nothing here. */
    if (conn->h2_resp_overflow) {
        ESP_LOGE(TAG, "register response exceeded %u-byte buffer — refusing to parse",
                 (unsigned)(RESPONSE_BUF - 1));
        return ESP_ERR_INVALID_RESPONSE;
    }

    const char *js = (const char *)resp;
    if (json_check_object(js, resp_len) != ESP_OK) {
        ESP_LOGE(TAG, "register response did not parse as JSON");
        return ESP_ERR_INVALID_RESPONSE;
    }
    char err_msg[160];
    err = register_parse_response(js, resp_len, err_msg, sizeof(err_msg));
    switch (err) {
    case ESP_OK:
        ESP_LOGI(TAG, "MachineAuthorized=true — node registered");
        break;
    case ESP_ERR_NOT_FINISHED:
        ESP_LOGW(TAG, "MachineAuthorized=false — waiting for operator approval");
        break;
    case ESP_ERR_INVALID_STATE:
        /* RegisterResponse.NodeKeyExpired: control accepted the machine
         * but the NodeKey we keep re-sending is expired. Upstream rotates
         * the node key here (direct.go); tinylink does not (yet), so this
         * is a failure — otherwise an expired node "registers" OK and the
         * next stream is expired again, every cycle. Recovery: disable
         * key expiry for the node (tailscale.com) or re-auth with a valid
         * key (headscale clears it). */
        ESP_LOGE(TAG, "register: NodeKeyExpired=true — node key expired on "
                      "the control plane (disable key expiry or re-auth)");
        break;
    case ESP_FAIL:
        /* No MachineAuthorized at all: an error answer. */
        if (err_msg[0] != '\0') {
            ESP_LOGE(TAG, "control plane error: %s", err_msg);
        }
        break;
    default:
        break;   /* MachineAuthorized not a bool */
    }
    return err;
}

esp_err_t register_emit(ts2021_conn_t *conn,
                        const tinylink_keys_t *keys,
                        const char *auth_key, int *http_status)
{
    if (http_status != NULL) *http_status = 0;
    if (conn == NULL || keys == NULL || http_status == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    uint8_t *buf = tl_ctrl_buf_claim("register");
    if (buf == NULL) return ESP_ERR_INVALID_STATE;
    esp_err_t err = register_emit_in(conn, keys, auth_key, buf, http_status);
    tl_ctrl_buf_release();
    return err;
}
