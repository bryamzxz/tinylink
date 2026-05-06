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

    /* M4 — best-effort STUN probe. Runs once before the first
     * MapRequest so HostInfo.Endpoints can advertise our reflexive
     * AddrPort to the control plane (which forwards it to peers).
     * Non-load-bearing: a probe failure leaves us with no endpoint
     * advertised, identical to the pre-M4 baseline. */
    esp_err_t serr = tinylink_stun_probe();
    if (serr != ESP_OK) {
        ESP_LOGW(TAG, "stun probe failed: 0x%x — continuing without endpoint", serr);
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

    /* DERP login MUST happen before the long-poll grabs heap. Two
     * modes:
     *  - SUPERVISED=y: tinylink_derp_supervised_start() establishes a
     *    persistent conn synchronously and hands it to a recv-loop
     *    task. The smoke is redundant in this mode.
     *  - SUPERVISED=n: one-shot smoke that connects+logs in+closes.
     * Either way, failure here is non-fatal. */
#if CONFIG_TINYLINK_DERP_SUPERVISED
    esp_err_t derp_sup_err = tinylink_derp_supervised_start();
    if (derp_sup_err != ESP_OK) {
        ESP_LOGW(TAG, "derp supervised start failed: 0x%x — continuing",
                 derp_sup_err);
    }
#else
    esp_err_t derr = tinylink_derp_smoke();
    if (derr != ESP_OK) {
        ESP_LOGW(TAG, "derp smoke: 0x%x — continuing", derr);
    }
#endif

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

    /* Periodic STUN re-probe so HostInfo.Endpoints stays fresh against
     * NAT rebinds and WAN address changes. Best-effort, silent on
     * transient failures (cached value remains in use). */
    esp_err_t rerr = tinylink_stun_reprobe_start();
    if (rerr != ESP_OK) {
        ESP_LOGW(TAG, "stun reprobe start failed: 0x%x — continuing static", rerr);
    }

    ESP_LOGI(TAG, "tinylink up: WG + map long-poll + telemetry + stun-reprobe");
    return ESP_OK;
}

void app_main(void)
{
    esp_err_t err = bringup();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "bringup aborted: 0x%x — staying up for diagnostics", err);
    }
}
