// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "app_wifi.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"

#include "app_nvs.h"
#include "backoff.h"
#include "tinylink.h"

static const char *TAG = "app_wifi";

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT      BIT1

#define WIFI_SSID_KEY "wifi_ssid"
#define WIFI_PASS_KEY "wifi_pass"

#define WIFI_SSID_MAX 32
#define WIFI_PASS_MAX 64

static EventGroupHandle_t s_wifi_events;
static int s_retry_count;

/* Reconnect pacing (2026-09). The handler used to call esp_wifi_connect()
 * synchronously on every STA_DISCONNECTED, i.e. a tight loop against an
 * AP that is down or rejecting us (auth failure, full AP) — and in a
 * fleet, a synchronised one. The retry now goes through a one-shot
 * esp_timer paced by the same jittered ladder the control plane and DERP
 * use: 500 ms → 30 s cap, reset on GOT_IP. */
#define WIFI_RECONNECT_BASE_MS 500u
#define WIFI_RECONNECT_CAP_MS  30000u
static esp_timer_handle_t s_reconnect_timer;

/* Boot power-save switch (round 1.3.1). The station starts with
 * WIFI_PS_NONE so the boot exchange is not paced by DTIM beacons; this
 * periodic esp_timer turns modem sleep on once the WG session is up, or
 * PS_AWAKE_CAP_MS after Wi-Fi start whatever happened (register waiting
 * for approval, control down) — the modem never stays awake unbounded.
 * A timer rather than a wait in bringup(): app_main must return to free
 * its 24 KiB stack before the DERP TLS handshake. */
#define PS_POLL_MS       500u
#define PS_AWAKE_CAP_MS  60000u
static esp_timer_handle_t s_ps_timer;
static int64_t s_ps_armed_us;
static bool s_ps_warned;

static void ps_timer_cb(void *arg)
{
    (void)arg;
    const bool up = tinylink_session_up();
    const int64_t awake_ms = (esp_timer_get_time() - s_ps_armed_us) / 1000;
    if (!up && awake_ms < (int64_t)PS_AWAKE_CAP_MS) return;
    esp_err_t ps_err = esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
    if (ps_err != ESP_OK) {
        /* Retried on the next poll; warn once. */
        if (!s_ps_warned) {
            ESP_LOGW(TAG, "esp_wifi_set_ps(MIN_MODEM) failed: 0x%x — retrying", ps_err);
            s_ps_warned = true;
        }
        return;
    }
    (void)esp_timer_stop(s_ps_timer);
    ESP_LOGI(TAG, "modem sleep (MIN_MODEM) on after %u ms awake%s",
             (unsigned)awake_ms, up ? "" : " — WG session not up yet");
}

static void reconnect_timer_cb(void *arg)
{
    (void)arg;
    esp_err_t cerr = esp_wifi_connect();
    if (cerr != ESP_OK) {
        ESP_LOGW(TAG, "esp_wifi_connect (reconnect) failed: 0x%x", cerr);
    }
}

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data)
{
    (void)arg;
    (void)data;

    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        ESP_LOGI(TAG, "STA start, connecting");
        esp_err_t cerr = esp_wifi_connect();
        if (cerr != ESP_OK) {
            /* A synchronous error queues no DISCONNECTED event, so the
             * reconnect chain below never fires — surface it instead of
             * silently going offline. */
            ESP_LOGW(TAG, "esp_wifi_connect (STA start) failed: 0x%x", cerr);
        }
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        const wifi_event_sta_disconnected_t *d = (const wifi_event_sta_disconnected_t *)data;
        const uint32_t delay_ms = tl_backoff_ms((uint32_t)s_retry_count,
                                                WIFI_RECONNECT_BASE_MS,
                                                WIFI_RECONNECT_CAP_MS,
                                                esp_random());
        if (s_retry_count < 1000) s_retry_count++;
        ESP_LOGW(TAG, "disconnected (reason %u), retry %d in %u ms",
                 d ? (unsigned)d->reason : 0u, s_retry_count, (unsigned)delay_ms);
        xEventGroupClearBits(s_wifi_events, WIFI_CONNECTED_BIT);
        if (s_reconnect_timer != NULL) {
            (void)esp_timer_stop(s_reconnect_timer);   /* coalesce bursts */
            esp_err_t terr = esp_timer_start_once(s_reconnect_timer,
                                                  (uint64_t)delay_ms * 1000ULL);
            if (terr != ESP_OK) {
                ESP_LOGW(TAG, "reconnect timer start failed: 0x%x — connecting now", terr);
                reconnect_timer_cb(NULL);
            }
        } else {
            reconnect_timer_cb(NULL);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "got ip " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_count = 0;
        xEventGroupSetBits(s_wifi_events, WIFI_CONNECTED_BIT);
    }
}

esp_err_t app_wifi_start(void)
{
    s_wifi_events = xEventGroupCreate();
    if (s_wifi_events == NULL) {
        return ESP_ERR_NO_MEM;
    }

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_t *netif = esp_netif_create_default_wifi_sta();
    ESP_ERROR_CHECK(esp_netif_set_hostname(netif, CONFIG_TINYLINK_DEVICE_HOSTNAME));

    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    /* +512 B over IDF's 3 072 (round 1.3.1): the driver's own log lines
     * run through Log V2's deeper esp_log_va → esp_log_format →
     * esp_log_printf chain (≈ +150–200 B per call vs V1), and the task
     * bottomed out at 584 B free in the M16 6-h soak under V1. */
    init_cfg.wifi_task_stack_size += 512;
    ESP_ERROR_CHECK(esp_wifi_init(&init_cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    char ssid[WIFI_SSID_MAX + 1] = {0};
    char pass[WIFI_PASS_MAX + 1] = {0};
    esp_err_t err = app_nvs_read_str(WIFI_SSID_KEY, ssid, sizeof(ssid));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "missing nvs key %s", WIFI_SSID_KEY);
        return err;
    }
    err = app_nvs_read_str(WIFI_PASS_KEY, pass, sizeof(pass));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "missing nvs key %s", WIFI_PASS_KEY);
        return err;
    }

    wifi_config_t wifi_cfg = {0};
    /* memcpy + strnlen instead of strncpy(dst, src, sizeof(dst)) — the
     * classic form trips -Wstringop-truncation at -O2 because gcc can't
     * prove src is NUL-terminated even when app_nvs_read_str() guarantees
     * it. The struct is zero-init'd above, so a shorter copy leaves the
     * tail at 0 which is what the WiFi driver expects. */
    memcpy(wifi_cfg.sta.ssid, ssid,
           strnlen(ssid, sizeof(wifi_cfg.sta.ssid)));
    memcpy(wifi_cfg.sta.password, pass,
           strnlen(pass, sizeof(wifi_cfg.sta.password)));
    wifi_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_cfg.sta.pmf_cfg.capable = true;

    const esp_timer_create_args_t targs = {
        .callback = reconnect_timer_cb,
        .name     = "wifi_reconn",
    };
    esp_err_t terr = esp_timer_create(&targs, &s_reconnect_timer);
    if (terr != ESP_OK) {
        ESP_LOGW(TAG, "reconnect timer create failed: 0x%x — immediate retries", terr);
        s_reconnect_timer = NULL;
    }

    /* RAM storage must be selected BEFORE set_config: with the default
     * FLASH storage esp_wifi_set_config also writes the SSID/passphrase
     * into the driver's own NVS namespace (nvs.net80211) — a second,
     * undocumented copy of the credentials on flash. The deployed
     * sensor's NVS shows exactly that from the old ordering. */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    /* Modem awake for the boot exchange (round 1.3.1): under modem
     * sleep every inbound burst of DHCP, DNS, the two TLS handshakes,
     * register, netmap and the WG handshake waits for the next DTIM
     * beacon. ps_timer_cb() switches to WIFI_PS_MIN_MODEM once the WG
     * session is up (≤ 60 s). While the modem is awake esp_wifi holds
     * its APB_FREQ_MAX PM lock, so light sleep stays off until then.
     *
     * WIFI_PS_MIN_MODEM wakes on every DTIM beacon (does not skip
     * beacons). Together with esp_pm_configure(light_sleep_enable=true)
     * in main.c, this lets the modem sleep between beacons without
     * losing inbound packets. WIFI_PS_MAX_MODEM (DTIM-skipping) is
     * unsafe for tinylink because the sensor must receive WG/DISCO
     * traffic reliably. If the timer cannot be armed, modem sleep goes
     * on immediately (the pre-1.3.1 behaviour). */
    const esp_timer_create_args_t ps_args = {
        .callback = ps_timer_cb,
        .name     = "wifi_ps",
    };
    s_ps_armed_us = esp_timer_get_time();
    bool ps_armed = esp_timer_create(&ps_args, &s_ps_timer) == ESP_OK &&
                    esp_timer_start_periodic(s_ps_timer,
                                             (uint64_t)PS_POLL_MS * 1000ULL) == ESP_OK;
    esp_err_t ps_err = esp_wifi_set_ps(ps_armed ? WIFI_PS_NONE : WIFI_PS_MIN_MODEM);
    if (ps_err != ESP_OK) {
        ESP_LOGW(TAG, "esp_wifi_set_ps(%s) failed: 0x%x",
                 ps_armed ? "NONE" : "MIN_MODEM", ps_err);
    }

    return ESP_OK;
}

esp_err_t app_wifi_wait_connected(uint32_t timeout_ms)
{
    if (s_wifi_events == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_events, WIFI_CONNECTED_BIT, pdFALSE, pdTRUE,
        pdMS_TO_TICKS(timeout_ms));
    return (bits & WIFI_CONNECTED_BIT) ? ESP_OK : ESP_ERR_TIMEOUT;
}
