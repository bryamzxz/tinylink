// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "app_wifi.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#include "esp_attr.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "nvs.h"

#include "app_nvs.h"
#include "backoff.h"
#include "tinylink.h"
#include "wifi_diag.h"
#include "wifi_hint.h"

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

/* Association hint and retry policy (round 1.3.7, wifi_hint.h). s_conn is
 * written by the event handler (sys_evt) and read by the persist hook
 * (telemetry task), both under s_conn_mux; the event handler hands the
 * next attempt (s_next) to reconnect_timer_cb (esp_timer task) the same
 * way. s_cfg_channel — the channel the driver config holds — is written
 * by app_wifi_start and then only on the reconnect path. */
static RTC_NOINIT_ATTR tl_wifi_rtc_t s_hint_rtc;
static tl_wifi_retry_t s_conn;
static tl_wifi_next_t  s_next;
static tl_wifi_blob_t  s_hint_nvs;        /* what NVS holds (telemetry task) */
static uint32_t        s_ssid_hash;
static uint8_t         s_cfg_channel;
static portMUX_TYPE    s_conn_mux = portMUX_INITIALIZER_UNLOCKED;

/* Boot power-save switch (round 1.3.1). The station starts with
 * WIFI_PS_NONE so the boot exchange is not paced by DTIM beacons; this
 * periodic esp_timer turns modem sleep on once the WG session is up, or
 * PS_AWAKE_CAP_MS after Wi-Fi start whatever happened (register waiting
 * for approval, control down) — the modem never stays awake unbounded.
 * A timer rather than a wait in bringup(): app_main returns as soon as
 * the long-poll runs, its stack back to the heap, without waiting for
 * the session. */
#define PS_POLL_MS       500u
#define PS_AWAKE_CAP_MS  60000u
/* The steady-state mode: MIN_MODEM; MAX_MODEM only as the round-1.3.7
 * A/B knob (Kconfig help, tools/power/). */
#if CONFIG_TINYLINK_WIFI_PS_MAX_MODEM
#define PS_STEADY        WIFI_PS_MAX_MODEM
#define PS_STEADY_NAME   "MAX_MODEM"
#else
#define PS_STEADY        WIFI_PS_MIN_MODEM
#define PS_STEADY_NAME   "MIN_MODEM"
#endif
static esp_timer_handle_t s_ps_timer;
static int64_t s_ps_armed_us;
static bool s_ps_warned;

static void ps_timer_cb(void *arg)
{
    (void)arg;
    const bool up = tinylink_session_up();
    const int64_t awake_ms = (esp_timer_get_time() - s_ps_armed_us) / 1000;
    if (!up && awake_ms < (int64_t)PS_AWAKE_CAP_MS) return;
    esp_err_t ps_err = esp_wifi_set_ps(PS_STEADY);
    if (ps_err != ESP_OK) {
        /* Retried on the next poll; warn once. */
        if (!s_ps_warned) {
            ESP_LOGW(TAG, "esp_wifi_set_ps(" PS_STEADY_NAME ") failed: 0x%x — retrying", ps_err);
            s_ps_warned = true;
        }
        return;
    }
    (void)esp_timer_stop(s_ps_timer);
    ESP_LOGI(TAG, "modem sleep (" PS_STEADY_NAME ") on after %u ms awake%s",
             (unsigned)awake_ms, up ? "" : " — WG session not up yet");
}

/* The station config again, with `channel` as the scan hint. It also
 * drops the driver's BSSID blacklist (wifi_set_config_process calls
 * cnx_clear_blacklist first thing) — the point of the immediate retry
 * after a 4-way timeout. The PMK should survive: the same routine keeps
 * it on a hit in the driver's cache of SSID + passphrase entries, so no
 * second PBKDF2 (≈ 33 M instructions, ~165 ms at 240 MHz). The ~180-B
 * config is what the esp_timer task's static worst case grows by
 * (tools/stack_worst.py: 3 248 → 3 328 of 4 608 B — esp_wifi_set_config's
 * ioctl chain is as deep as esp_wifi_connect's); not inlined, so a plain
 * reconnect does not carry it. */
static __attribute__((noinline)) void apply_channel(uint8_t channel)
{
    wifi_config_t cfg;
    esp_err_t err = esp_wifi_get_config(WIFI_IF_STA, &cfg);
    if (err == ESP_OK) {
        cfg.sta.channel = channel;
        err = esp_wifi_set_config(WIFI_IF_STA, &cfg);
    }
    if (err == ESP_OK) {
        s_cfg_channel = channel;
    } else {
        ESP_LOGW(TAG, "esp_wifi_set_config (channel %u) failed: 0x%x", (unsigned)channel, err);
    }
}

static void reconnect_timer_cb(void *arg)
{
    (void)arg;
    portENTER_CRITICAL(&s_conn_mux);
    const tl_wifi_next_t n = s_next;
    s_next.reapply = false;
    portEXIT_CRITICAL(&s_conn_mux);
    if (tl_wifi_needs_config(&n, s_cfg_channel)) apply_channel(n.channel);
    esp_err_t cerr = esp_wifi_connect();
    if (cerr != ESP_OK) {
        ESP_LOGW(TAG, "esp_wifi_connect (reconnect) failed: 0x%x", cerr);
    }
}

static int hint_nvs_write(const uint8_t *b, size_t n, void *ctx)
{
    (void)ctx;
    nvs_handle_t h;
    esp_err_t err = nvs_open(TL_WIFI_HINT_NS, NVS_READWRITE, &h);
    if (err == ESP_OK) {
        err = nvs_set_blob(h, TL_WIFI_HINT_KEY, b, n);
        if (err == ESP_OK) err = nvs_commit(h);
        nvs_close(h);
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "wifi hint: nvs write failed: 0x%x — a cold boot scans 1..N", err);
    }
    return err == ESP_OK ? 0 : -1;
}

/* tinylink_set_persist_hook: the 60-s housekeeping on the telemetry task
 * writes the record when it differs from NVS — after a connect to a new
 * channel / BSSID, never on the boot path. */
static void hint_persist(void)
{
    portENTER_CRITICAL(&s_conn_mux);
    const tl_wifi_ap_t ap = s_conn.ap;
    portEXIT_CRITICAL(&s_conn_mux);
    if (!tl_wifi_ap_ok(&ap, s_ssid_hash)) return;          /* nothing learned yet */
    if (tl_wifi_blob_store(&s_hint_nvs, &ap, hint_nvs_write, NULL) == 1) {
        ESP_LOGI(TAG, "wifi hint: channel %u stored", (unsigned)ap.channel);
    }
}

/* Boot: the RTC copy (a warm reset) or the NVS record (any reset) for
 * this SSID, else none. Read-only. */
static uint8_t hint_load(void)
{
    nvs_handle_t h;
    if (nvs_open(TL_WIFI_HINT_NS, NVS_READONLY, &h) == ESP_OK) {
        size_t n = sizeof(s_hint_nvs.b);
        s_hint_nvs.len = (nvs_get_blob(h, TL_WIFI_HINT_KEY, s_hint_nvs.b, &n) == ESP_OK &&
                          n <= sizeof(s_hint_nvs.b)) ? (uint8_t)n : 0;
        nvs_close(h);
    }
    tl_wifi_ap_t ap;
    const tl_wifi_hint_src_t src = tl_wifi_ap_boot(&s_hint_rtc, s_hint_nvs.b, s_hint_nvs.len,
                                                   s_ssid_hash, &ap);
    tl_wifi_retry_init(&s_conn, &ap, s_ssid_hash);
    if (src == TL_WIFI_HINT_NONE) {
        ESP_LOGI(TAG, "wifi hint: none stored — scanning channels 1..N");
    } else {
        ESP_LOGI(TAG, "wifi hint: channel %u first (%s record)", (unsigned)ap.channel,
                 src == TL_WIFI_HINT_RTC ? "RTC" : "NVS");
    }
    return tl_wifi_channel(&s_conn);
}

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data)
{
    (void)arg;
    (void)data;

    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        ESP_LOGI(TAG, "STA start, connecting");
#if CONFIG_TINYLINK_WIFI_DIAG
        wifi_diag_start();
#endif
        esp_err_t cerr = esp_wifi_connect();
        if (cerr != ESP_OK) {
            /* A synchronous error queues no DISCONNECTED event, so the
             * reconnect chain below never fires — surface it instead of
             * silently going offline. */
            ESP_LOGW(TAG, "esp_wifi_connect (STA start) failed: 0x%x", cerr);
        }
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_CONNECTED) {
        const wifi_event_sta_connected_t *c = (const wifi_event_sta_connected_t *)data;
        if (c == NULL) return;
        portENTER_CRITICAL(&s_conn_mux);
        const bool changed = tl_wifi_on_connected(&s_conn, c->channel, c->bssid, s_ssid_hash);
        const tl_wifi_ap_t ap = s_conn.ap;
        portEXIT_CRITICAL(&s_conn_mux);
#if CONFIG_TINYLINK_WIFI_DIAG
        wifi_diag_note(WIFI_DIAG_CONNECTED, c->channel, 0);
#endif
        if (ap.channel != 0) tl_wifi_rtc_put(&s_hint_rtc, &ap);     /* free: every connect */
        if (changed) {
            ESP_LOGI(TAG, "wifi hint: AP on channel %u — in RTC now, NVS at the next housekeeping",
                     (unsigned)ap.channel);
        }
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        const wifi_event_sta_disconnected_t *d = (const wifi_event_sta_disconnected_t *)data;
        const unsigned reason = d ? (unsigned)d->reason : 0u;
        portENTER_CRITICAL(&s_conn_mux);
        const tl_wifi_next_t n = tl_wifi_on_disconnected(&s_conn, (uint16_t)reason,
                                                         d ? d->bssid : NULL);
        s_next.reapply = s_next.reapply || n.reapply;      /* until an attempt applies it */
        s_next.channel = n.channel;
        portEXIT_CRITICAL(&s_conn_mux);
        uint32_t delay_ms = 0;
        if (n.now) {
            ESP_LOGW(TAG, "disconnected (reason %u), retry now — 4-way timeout after "
                          "association: config re-applied, channel %u first",
                     reason, (unsigned)n.channel);
        } else {
            delay_ms = tl_backoff_ms((uint32_t)s_retry_count, WIFI_RECONNECT_BASE_MS,
                                     WIFI_RECONNECT_CAP_MS, esp_random());
            if (s_retry_count < 1000) s_retry_count++;
            if (n.channel != 0) {
                ESP_LOGW(TAG, "disconnected (reason %u), retry %d in %u ms, channel %u first",
                         reason, s_retry_count, (unsigned)delay_ms, (unsigned)n.channel);
            } else {
                ESP_LOGW(TAG, "disconnected (reason %u), retry %d in %u ms, channels 1..N",
                         reason, s_retry_count, (unsigned)delay_ms);
            }
        }
#if CONFIG_TINYLINK_WIFI_DIAG
        wifi_diag_note(WIFI_DIAG_DISCONNECTED, (uint16_t)reason, d ? d->rssi : 0);
        wifi_diag_note(WIFI_DIAG_RETRY, n.channel, (int16_t)(delay_ms < 32767u ? delay_ms : 32767u));
        wifi_diag_flush();
#endif
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
#if CONFIG_TINYLINK_WIFI_DIAG
        wifi_diag_note(WIFI_DIAG_GOT_IP, 0, 0);
        wifi_diag_flush();
#endif
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
#if CONFIG_TINYLINK_WIFI_PS_MAX_MODEM
    wifi_cfg.sta.listen_interval = CONFIG_TINYLINK_WIFI_LISTEN_INTERVAL;
#endif

    /* Round 1.3.7: scan the last AP's channel first (wifi_hint.h). */
    s_ssid_hash = tl_wifi_ssid_hash(wifi_cfg.sta.ssid, strnlen(ssid, sizeof(wifi_cfg.sta.ssid)));
    wifi_cfg.sta.channel = hint_load();
    s_cfg_channel = wifi_cfg.sta.channel;
    tinylink_set_persist_hook(hint_persist);

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
    esp_err_t ps_err = esp_wifi_set_ps(ps_armed ? WIFI_PS_NONE : PS_STEADY);
    if (ps_err != ESP_OK) {
        ESP_LOGW(TAG, "esp_wifi_set_ps(%s) failed: 0x%x",
                 ps_armed ? "NONE" : PS_STEADY_NAME, ps_err);
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
