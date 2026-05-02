// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "app_wireguard.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_wireguard.h"

#include "app_nvs.h"

static const char *TAG = "app_wg";

#define WG_PRIV_KEY_KEY      "wg_priv_key"
#define WG_PEER_PUB_KEY      "wg_peer_pub"
#define WG_PEER_ENDPOINT_KEY "wg_peer_endpoint"
#define WG_PEER_ALLOWED_KEY  "wg_peer_allowed_ip"
#define WG_LOCAL_IP_KEY      "wg_local_ip"

#define WG_KEY_BIN_LEN       32
#define WG_KEY_B64_LEN       45  /* base64(32) + NUL */
#define WG_ENDPOINT_MAX      64  /* "host:port" */
#define WG_LOCAL_IP_MAX      16  /* "100.x.y.z\0"   */

static wireguard_config_t s_wg_cfg;
static wireguard_ctx_t    s_wg_ctx;
static char s_priv_b64[WG_KEY_B64_LEN];
static char s_peer_pub_b64[WG_KEY_B64_LEN];
static char s_endpoint_host[WG_ENDPOINT_MAX];
static char s_allowed_ip[APP_WG_ALLOWED_IP_MAX];
static char s_local_ip[WG_LOCAL_IP_MAX];
static int  s_endpoint_port;
static bool s_started;

static esp_err_t bin_to_base64(const uint8_t *in, size_t in_len,
                               char *out, size_t out_size);
static esp_err_t parse_endpoint(const char *raw, char *host, size_t host_size,
                                int *port);

esp_err_t app_wireguard_start(void)
{
    uint8_t priv_bin[WG_KEY_BIN_LEN];
    uint8_t peer_pub_bin[WG_KEY_BIN_LEN];
    char    raw_endpoint[WG_ENDPOINT_MAX];

    esp_err_t err;
    err = app_nvs_read_blob(WG_PRIV_KEY_KEY, priv_bin, sizeof(priv_bin));
    if (err != ESP_OK) return err;
    err = app_nvs_read_blob(WG_PEER_PUB_KEY, peer_pub_bin, sizeof(peer_pub_bin));
    if (err != ESP_OK) return err;
    err = app_nvs_read_str(WG_PEER_ENDPOINT_KEY, raw_endpoint, sizeof(raw_endpoint));
    if (err != ESP_OK) return err;
    err = app_nvs_read_str(WG_PEER_ALLOWED_KEY, s_allowed_ip, sizeof(s_allowed_ip));
    if (err != ESP_OK) return err;
    err = app_nvs_read_str(WG_LOCAL_IP_KEY, s_local_ip, sizeof(s_local_ip));
    if (err != ESP_OK) return err;

    err = bin_to_base64(priv_bin, sizeof(priv_bin), s_priv_b64, sizeof(s_priv_b64));
    if (err != ESP_OK) return err;
    err = bin_to_base64(peer_pub_bin, sizeof(peer_pub_bin),
                        s_peer_pub_b64, sizeof(s_peer_pub_b64));
    if (err != ESP_OK) return err;

    err = parse_endpoint(raw_endpoint, s_endpoint_host, sizeof(s_endpoint_host),
                         &s_endpoint_port);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "invalid wg_peer_endpoint '%s'", raw_endpoint);
        return err;
    }

    s_wg_cfg = (wireguard_config_t) ESP_WIREGUARD_CONFIG_DEFAULT();
    s_wg_cfg.private_key = s_priv_b64;
    s_wg_cfg.public_key  = s_peer_pub_b64;
    s_wg_cfg.endpoint    = s_endpoint_host;
    s_wg_cfg.port        = s_endpoint_port;
    s_wg_cfg.address     = s_local_ip;
    s_wg_cfg.netmask     = "255.255.255.255";
    s_wg_cfg.allowed_ip  = s_allowed_ip;
    s_wg_cfg.allowed_ip_mask = "255.255.255.255";
    s_wg_cfg.persistent_keepalive = 25;

    err = esp_wireguard_init(&s_wg_cfg, &s_wg_ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_init failed: 0x%x", err);
        return err;
    }
    err = esp_wireguard_connect(&s_wg_ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_connect failed: 0x%x", err);
        return err;
    }

    ESP_LOGI(TAG, "wg connect requested: local=%s peer=%s allowed=%s endpoint=%s:%d",
             s_local_ip, s_peer_pub_b64, s_allowed_ip,
             s_endpoint_host, s_endpoint_port);
    s_started = true;
    return ESP_OK;
}

esp_err_t app_wireguard_wait_up(uint32_t timeout_ms)
{
    if (!s_started) return ESP_ERR_INVALID_STATE;

    const TickType_t step = pdMS_TO_TICKS(500);
    TickType_t waited = 0;
    const TickType_t deadline = pdMS_TO_TICKS(timeout_ms);

    while (waited < deadline) {
        esp_err_t err = esp_wireguardif_peer_is_up(&s_wg_ctx);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "wg peer up");
            return ESP_OK;
        }
        vTaskDelay(step);
        waited += step;
    }
    return ESP_ERR_TIMEOUT;
}

esp_err_t app_wireguard_get_peer(app_wireguard_peer_info_t *out)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    if (!s_started) return ESP_ERR_INVALID_STATE;
    strncpy(out->allowed_ip, s_allowed_ip, sizeof(out->allowed_ip) - 1);
    out->allowed_ip[sizeof(out->allowed_ip) - 1] = '\0';
    return ESP_OK;
}

static esp_err_t bin_to_base64(const uint8_t *in, size_t in_len,
                               char *out, size_t out_size)
{
    static const char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    if (out_size < ((in_len + 2) / 3) * 4 + 1) {
        return ESP_ERR_INVALID_SIZE;
    }
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
    return ESP_OK;
}

static esp_err_t parse_endpoint(const char *raw, char *host, size_t host_size,
                                int *port)
{
    if (raw == NULL || host == NULL || port == NULL) return ESP_ERR_INVALID_ARG;

    const char *colon = strrchr(raw, ':');
    if (colon == NULL || colon == raw) return ESP_ERR_INVALID_ARG;

    size_t host_len = (size_t)(colon - raw);
    if (host_len + 1 > host_size) return ESP_ERR_INVALID_SIZE;
    memcpy(host, raw, host_len);
    host[host_len] = '\0';

    long p = strtol(colon + 1, NULL, 10);
    if (p <= 0 || p > 65535) return ESP_ERR_INVALID_ARG;
    *port = (int)p;
    return ESP_OK;
}
