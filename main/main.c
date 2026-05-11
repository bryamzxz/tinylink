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
#include "esp_pm.h"

#include "tinylink.h"
#include "tinylink_bench.h"

#include "app_nvs.h"
#include "app_wifi.h"

static const char *TAG = "tinylink";

#define WIFI_TIMEOUT_MS 30000

/* Enable automatic light-sleep entry from FreeRTOS tickless idle. Without
 * this call, esp_pm/pm_impl.c:561+829 short-circuit the tickless idle
 * sleep path (PM_MODE_LIGHT_SLEEP is never selected when
 * s_light_sleep_en is false). Pair with esp_wifi_set_ps(WIFI_PS_MIN_MODEM)
 * in app_wifi_start() so the WiFi modem also sleeps between DTIM beacons. */
static esp_err_t configure_pm(void)
{
    esp_pm_config_t cfg = {
        .max_freq_mhz       = 240,
        .min_freq_mhz       = 80,
        .light_sleep_enable = true,
    };
    return esp_pm_configure(&cfg);
}

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

    /* Enable light-sleep PM only AFTER WiFi associates. If we enable it
     * before assoc, tickless idle can put the chip to sleep during AUTH
     * /ASSOC where the WiFi PS state machine isn't engaged yet, and the
     * AP kicks us out after ~6 s of missed beacons. esp_wifi_set_ps()
     * has been called in app_wifi_start() and takes effect on first
     * assoc, so by the time wait_connected() returns the modem-sleep
     * path is fully primed and safe for tickless light sleep to use. */
    esp_err_t pm_err = configure_pm();
    if (pm_err != ESP_OK) {
        ESP_LOGW(TAG, "pm configure failed: 0x%x — continuing without light sleep", pm_err);
    } else {
        ESP_LOGI(TAG, "pm: light-sleep enabled, DFS 240/80 MHz");
    }

    err = tinylink_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tinylink_init failed: 0x%x", err);
        return err;
    }

    /* TAI64N floor must be installed before the first WG handshake
     * so the post-reboot timestamp strictly exceeds what the responder
     * already saw pre-reboot. Fail-soft: on NVS error the function
     * logs a warning and falls back to legacy unprotected behavior;
     * we proceed anyway since the device shouldn't refuse to boot
     * just because TAI64N persistence is broken. */
    esp_err_t terr = tinylink_tai64n_floor_init();
    if (terr != ESP_OK) {
        ESP_LOGW(TAG, "tai64n floor init failed: 0x%x — continuing without "
                      "cross-reboot handshake monotonicity", terr);
    }

#if CONFIG_TINYLINK_BENCH_AEAD
    /* AEAD baseline. Runs before register/dataplane so the heap is
     * still pristine and the timer numbers aren't confounded by
     * background TLS/long-poll work. The 8 s delay is purely so the
     * host serial capture can attach after `idf.py flash` releases the
     * port — without it the bench fires before capture is listening
     * and the numbers are lost. */
    vTaskDelay(pdMS_TO_TICKS(8000));
    (void)tinylink_bench_aead();
#endif

    /* Bring up the WG UDP socket EARLY (bind only — no handshake yet)
     * so the boot-time STUN probe can run on the same socket the
     * dataplane will eventually use. This is what makes the public
     * AddrPort we advertise to peers match the NAT mapping that WG
     * keepalives keep pinned: peers dialing the advertised AddrPort
     * actually reach our WG socket, and direct UDP path discovery
     * (DISCO ping/pong) works. Without this, STUN runs on its own
     * ephemeral socket whose NAT mapping closes immediately, so
     * peers fall back to DERP forever. */
    err = tinylink_wg_socket_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wg socket init failed: 0x%x", err);
        return err;
    }

    /* Persistent endpoint-updater task. Spawned NOW — before any TLS
     * handshake (register, long-poll, derp supervisor) lands and
     * fragments the heap — so the 16 KiB stack allocation lands on a
     * still-pristine arena. Doing this lazily at first NAT-rebind time
     * was the bug we just fixed: after hours of mbedtls + nghttp2 churn,
     * largest_free_block drops below 16 KiB and xTaskCreate fails. The
     * task just sleeps on a semaphore until the STUN re-probe path
     * signals it, so spawning early costs nothing observable but
     * guarantees the task exists when needed. */
    esp_err_t epuerr = tinylink_endpoint_updater_start();
    if (epuerr != ESP_OK) {
        ESP_LOGW(TAG, "endpoint updater start failed: 0x%x — "
                      "STUN re-probe will log dropped pushes",
                 epuerr);
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

    /* SUPERVISED=n boot path: keep the legacy one-shot smoke before
     * long-poll. Smoke connects+logs in+closes before long-poll claims
     * heap so it sees an unfragmented heap; failure is non-fatal. */
#if !CONFIG_TINYLINK_DERP_SUPERVISED
    esp_err_t derr = tinylink_derp_smoke();
    if (derr != ESP_OK) {
        ESP_LOGW(TAG, "derp smoke: 0x%x — continuing", derr);
    }
#endif

    /* Long-poll FIRST so its TLS conn + nghttp2 session land on a
     * fresh heap. The long-poll task runs at priority IDLE+4 (higher
     * than this bringup task) so it preempts here and starts its
     * handshake immediately. */
    err = tinylink_long_poll_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "long-poll start failed: 0x%x", err);
        return err;
    }

#if CONFIG_TINYLINK_DERP_SUPERVISED
    /* Wait for the long-poll's first netmap before we bring up the
     * supervised DERP conn. Two reasons:
     *
     *   1. Heap order: the long-poll's mbedtls cert verify needs ~12
     *      KiB contiguous; if we let DERP supervisor's TLS conn fragment
     *      the heap first, the long-poll handshake fails (we observed
     *      the "Certificate matched but signature verification failed"
     *      pattern this triggers).
     *
     *   2. Reachability: the FIRST MapRequest is what tells the
     *      control plane our PreferredDERP region. Before that lands,
     *      a remote peer doing `tailscale ping <us>` doesn't know
     *      which DERP region to relay through — its ping never
     *      arrives at the supervisor. Bringing up DERP after the
     *      first MapResponse means our HostInfo.NetInfo is already
     *      registered when DERP starts taking traffic.
     *
     * 30 s is generous: register + first MapRequest typically lands
     * in 5-10 s on this hardware. On timeout we still try to start
     * the supervisor — best-effort, the recv loop will reconnect on
     * its own backoff cadence. */
    esp_err_t wait_err = tinylink_wait_dataplane_ms(30000);
    if (wait_err != ESP_OK) {
        ESP_LOGW(TAG, "dataplane did not come up in 30 s — "
                      "starting supervised DERP anyway");
    }
    esp_err_t derp_sup_err = tinylink_derp_supervised_start();
    if (derp_sup_err != ESP_OK) {
        ESP_LOGW(TAG, "derp supervised start failed: 0x%x — continuing",
                 derp_sup_err);
    }
#endif

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
