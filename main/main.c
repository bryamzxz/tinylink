// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// tinylink M1 + M2 entrypoint:
//   1. WiFi up.
//   2. tinylink_init() — load/generate Curve25519 identities and pin the
//      control plane public key.
//   3. tinylink_register() — POST /machine/register; retry slow on
//      MachineAuthorized=false until the operator approves the node.
//   4. tinylink_dataplane_start() — fetch one MapResponse and bring up
//      the WireGuard netif against the home peer it announces. The
//      long-lived `Stream:true` MapRequest loop and DISCO/STUN follow
//      in M3.

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_err.h"
#include "esp_log.h"

#include "tinylink.h"

#include "app_nvs.h"
#include "app_wifi.h"

static const char *TAG = "tinylink";

#define WIFI_TIMEOUT_MS 30000

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

    err = tinylink_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tinylink_init failed: 0x%x", err);
        return err;
    }

    /* Register loop: control plane may answer MachineAuthorized=false until
     * the operator approves the new node. Retry on a slow cadence. */
    for (;;) {
        err = tinylink_register();
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "node registered");
            break;
        }
        ESP_LOGW(TAG, "register attempt failed: 0x%x — retrying in %d ms",
                 err, CONFIG_TINYLINK_REGISTER_RETRY_MS);
        vTaskDelay(pdMS_TO_TICKS(CONFIG_TINYLINK_REGISTER_RETRY_MS));
    }

    err = tinylink_dataplane_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "dataplane bringup failed: 0x%x", err);
        return err;
    }
    err = tinylink_long_poll_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "long-poll start failed: 0x%x", err);
        return err;
    }
    err = tinylink_telemetry_start();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "telemetry start failed: 0x%x — continuing", err);
        /* fall through: telemetry isn't load-bearing for the rest of
         * the system. */
    }
    ESP_LOGI(TAG, "tinylink up: WG + map long-poll + telemetry");
    return ESP_OK;
}

void app_main(void)
{
    esp_err_t err = bringup();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "bringup aborted: 0x%x — staying up for diagnostics", err);
    }
}
