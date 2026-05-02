// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// tinylink Milestone 1 entrypoint.
// State machine: NVS -> netif/event-loop (in app_wifi) -> WiFi STA ->
//                WireGuard (static peer) -> TMP117 -> UDP telemetry task.

#include "esp_err.h"
#include "esp_log.h"

#include "tinylink.h"

#include "app_nvs.h"
#include "app_sensor.h"
#include "app_telemetry.h"
#include "app_wifi.h"
#include "app_wireguard.h"

static const char *TAG = "tinylink";

#define WIFI_TIMEOUT_MS 30000
#define WG_TIMEOUT_MS   30000

static esp_err_t bringup(void)
{
    ESP_LOGI(TAG, "tinylink %s starting on %s",
             tinylink_version_string(), CONFIG_TINYLINK_DEVICE_HOSTNAME);

    esp_err_t err = app_nvs_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs init failed: 0x%x", err);
        return err;
    }

    err = app_wifi_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wifi start failed: 0x%x", err);
        return err;
    }
    err = app_wifi_wait_connected(WIFI_TIMEOUT_MS);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wifi did not connect within %d ms", WIFI_TIMEOUT_MS);
        return err;
    }

    err = app_wireguard_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wireguard start failed: 0x%x", err);
        return err;
    }
    err = app_wireguard_wait_up(WG_TIMEOUT_MS);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wireguard peer did not come up within %d ms",
                 WG_TIMEOUT_MS);
        return err;
    }

    err = app_sensor_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "sensor init failed: 0x%x", err);
        return err;
    }

    app_wireguard_peer_info_t peer;
    err = app_wireguard_get_peer(&peer);
    if (err != ESP_OK) return err;

    err = app_telemetry_start(peer.allowed_ip);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "telemetry start failed: 0x%x", err);
        return err;
    }

    ESP_LOGI(TAG, "bringup complete");
    return ESP_OK;
}

void app_main(void)
{
    esp_err_t err = bringup();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "bringup aborted: 0x%x — staying up for diagnostics", err);
    }
}
