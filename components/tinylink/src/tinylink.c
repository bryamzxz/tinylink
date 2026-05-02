// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "tinylink.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "nvs.h"
#include "sdkconfig.h"

#include "control_key.h"
#include "keys.h"
#include "mapreq.h"
#include "netmap.h"
#include "register.h"
#include "telemetry.h"
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

/* Persistent ts2021/Noise channel to the control plane, mirroring
 * upstream's controlclient.Direct.noiseClient (one client reused for
 * register, map and map-stream). Avoids the heap-corruption assert we
 * hit when ts2021_close+ts2021_connect cycles ran back-to-back, AND
 * saves a Noise IK + TLS handshake on every long-poll reconnect. */
static ts2021_conn_t   s_conn;
static bool            s_conn_open;

static esp_err_t ensure_control_conn(void)
{
    if (s_conn_open) return ESP_OK;
    esp_err_t err = ts2021_connect(&s_conn, s_keys.machine_priv,
                                   s_keys.machine_pub, s_control_pub);
    if (err == ESP_OK) s_conn_open = true;
    return err;
}

static void drop_control_conn(void)
{
    if (!s_conn_open) return;
    ts2021_close(&s_conn);
    s_conn_open = false;
}

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

    err = ensure_control_conn();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ts2021_connect failed: 0x%x", err);
        memset(auth_key, 0, sizeof(auth_key));
        return err;
    }

    err = register_emit(&s_conn, &s_keys, auth_key);

    /* Best-effort scrub of the auth key in stack memory. */
    memset(auth_key, 0, sizeof(auth_key));

    /* Drop the conn after register. Reusing the same ts2021 channel for
     * /machine/map fails because our h2_drive_request creates+destroys
     * a fresh nghttp2 session per request, and the GOAWAY emitted on
     * the first session_del causes the SECOND submit to land on a
     * half-closed transport (server returns HTTP 0).
     *
     * Until h2_client is refactored to keep ONE persistent nghttp2
     * session per ts2021 conn (matching upstream's go-http2 behavior),
     * the safe pattern is one ts2021 conn per request. The 24 KiB
     * long-poll stack now absorbs the second handshake without
     * blowing — see tinylink_long_poll_start. */
    drop_control_conn();
    return err;
}

esp_err_t tinylink_dataplane_start(void)
{
    /* Mirrors upstream's controlclient.Direct: there is NO separate
     * "fetch one MapResponse, then start streaming" call. The streaming
     * /machine/map request itself delivers the initial netmap as its
     * first frame and subsequent updates as follow-up frames on the same
     * stream. So this entry point now only validates state — the actual
     * WG bring-up happens inside long_poll_handler on the first netmap
     * the stream emits. Kept in the API for backward compatibility with
     * the boot sequence in main.c. */
    return s_initialized ? ESP_OK : ESP_ERR_INVALID_STATE;
}

/* ---- long-poll MapRequest task ----------------------------------------- */

static bool s_dataplane_started;

static esp_err_t long_poll_handler(const tl_netmap_t *nm, void *ctx)
{
    (void)ctx;
    if (!s_dataplane_started) {
        ESP_LOGI(TAG, "netmap (initial): self.id=%llu peers=%u derp_regions=%u",
                 (unsigned long long)nm->self_id,
                 (unsigned)nm->n_peers,
                 (unsigned)nm->n_derp_regions);
        esp_err_t err = wg_dataplane_start(&s_keys, nm);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "wg_dataplane_start failed: 0x%x", err);
            return err;
        }
        s_dataplane_started = true;
        /* Now that the WG netif is up and the 100.64.0.0/10 route
         * exists, it's safe to start telemetry (it sendto's to a
         * 100.64.0.1 address that would otherwise punt into the WiFi
         * default route). */
        esp_err_t terr = telemetry_start();
        if (terr != ESP_OK) {
            ESP_LOGW(TAG, "telemetry_start failed: 0x%x — continuing", terr);
        }
        return ESP_OK;
    }
    ESP_LOGI(TAG, "netmap (update): peers=%u derp_regions=%u",
             (unsigned)nm->n_peers, (unsigned)nm->n_derp_regions);
    /* wg_dataplane_update_peer already guards on n_peers==0 (rare server
     * push during a tailnet reconfigure). */
    return wg_dataplane_update_peer(&s_keys, nm);
}

static void long_poll_task(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "long-poll task: starting");
    for (;;) {
        esp_err_t err = ensure_control_conn();
        if (err == ESP_OK) {
            err = mapreq_run_stream(&s_conn, &s_keys, long_poll_handler, NULL);
            /* Stream ended: either the server closed it (idle / ping
             * failure / restart) or our side errored. Drop the conn so
             * the next iteration brings up a fresh one. */
            ESP_LOGW(TAG, "long-poll stream ended: 0x%x — reconnecting", err);
            drop_control_conn();
        } else {
            ESP_LOGW(TAG, "long-poll connect failed: 0x%x — backing off", err);
        }
        vTaskDelay(pdMS_TO_TICKS(CONFIG_TINYLINK_REGISTER_RETRY_MS));
    }
}

esp_err_t tinylink_long_poll_start(void)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    /* 24 KiB stack — same budget as CONFIG_ESP_MAIN_TASK_STACK_SIZE.
     * The earlier 8 KiB note was wrong: ts2021_connect builds an
     * mbedtls TLS handshake (cert chain verification, ECDSA, X.509
     * parsing, ~12 KiB peak) PLUS our Noise IK init (~2 KiB) on the
     * task stack. Running this in 8 KiB blew the stack and looked
     * like random heap corruption / alignment / load-prohibited
     * panics depending on what the overflow happened to overwrite. */
    BaseType_t ok = xTaskCreate(long_poll_task, "tinylink_lp",
                                24576, NULL, tskIDLE_PRIORITY + 4, NULL);
    if (ok != pdPASS) {
        ESP_LOGE(TAG, "xTaskCreate(long_poll) failed");
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

esp_err_t tinylink_telemetry_start(void)
{
    /* Telemetry now starts implicitly from the long-poll handler the
     * first time the control plane delivers a netmap (so we don't
     * sendto a 100.64.x.y destination before the WG netif exists).
     * This entry point is a no-op kept for boot-sequence backward
     * compatibility with main.c. */
    return ESP_OK;
}
