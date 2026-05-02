// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "tinylink.h"

#include <string.h>

#include "esp_log.h"
#include "nvs.h"

#include "control_key.h"
#include "keys.h"
#include "mapreq.h"
#include "netmap.h"
#include "register.h"
#include "ts2021_client.h"
#include "wg_dataplane.h"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

static const char *TAG = "tinylink";

static const char k_version[] =
    STR(TINYLINK_VERSION_MAJOR) "."
    STR(TINYLINK_VERSION_MINOR) "."
    STR(TINYLINK_VERSION_PATCH);

static tinylink_keys_t s_keys;
static uint8_t         s_control_pub[32];
static bool            s_initialized;

const char *tinylink_version_string(void)
{
    return k_version;
}

esp_err_t tinylink_init(void)
{
    esp_err_t err = keys_load_or_generate(&s_keys);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "keys_load_or_generate failed: 0x%x", err);
        return err;
    }
    err = control_key_get(s_control_pub);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "control_key_get failed: 0x%x", err);
        return err;
    }
    s_initialized = true;
    return ESP_OK;
}

esp_err_t tinylink_get_keys(tinylink_keys_t *out)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    memcpy(out, &s_keys, sizeof(*out));
    return ESP_OK;
}

static esp_err_t read_auth_key(char *out, size_t out_size)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open("tl_creds", NVS_READONLY, &h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open(tl_creds) failed: 0x%x", err);
        return err;
    }
    size_t len = out_size;
    err = nvs_get_str(h, "auth_key", out, &len);
    nvs_close(h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "auth_key missing from NVS: 0x%x", err);
    }
    return err;
}

esp_err_t tinylink_register(void)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;

    char auth_key[128];
    esp_err_t err = read_auth_key(auth_key, sizeof(auth_key));
    if (err != ESP_OK) return err;

    ts2021_conn_t conn;
    err = ts2021_connect(&conn, s_keys.machine_priv, s_keys.machine_pub,
                         s_control_pub);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ts2021_connect failed: 0x%x", err);
        return err;
    }

    err = register_emit(&conn, &s_keys, auth_key);
    ts2021_close(&conn);

    /* Best-effort scrub of the auth key in stack memory. */
    memset(auth_key, 0, sizeof(auth_key));
    return err;
}

esp_err_t tinylink_dataplane_start(void)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;

    /* Open a fresh ts2021 channel for /machine/map. The control plane
     * is happy to serve a non-stream MapRequest on a new connection;
     * keeping register and map on separate connections also keeps the
     * register flow's auth-key scrubbing simple. */
    ts2021_conn_t conn;
    esp_err_t err = ts2021_connect(&conn, s_keys.machine_priv,
                                   s_keys.machine_pub, s_control_pub);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ts2021_connect (map) failed: 0x%x", err);
        return err;
    }

    static tl_netmap_t netmap;  /* ~1 KiB; stash in BSS, not the stack. */
    err = mapreq_fetch_once(&conn, &s_keys, &netmap);
    ts2021_close(&conn);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mapreq_fetch_once failed: 0x%x", err);
        return err;
    }
    ESP_LOGI(TAG, "netmap: self.id=%llu peers=%u derp_regions=%u",
             (unsigned long long)netmap.self_id,
             (unsigned)netmap.n_peers,
             (unsigned)netmap.n_derp_regions);

    return wg_dataplane_start(&s_keys, &netmap);
}
