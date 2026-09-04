// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "tl_time.h"

#ifdef ESP_PLATFORM

#include <sys/time.h>
#include <time.h>

#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_sntp.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "nvs.h"
#include "sdkconfig.h"

static const char *TAG = "tl_time";

/* Seconds since the Unix epoch at configure time, injected by the
 * component CMakeLists (string(TIMESTAMP ...)). 0 = unknown. */
#ifndef TL_BUILD_EPOCH
#define TL_BUILD_EPOCH 0ULL
#endif

#define NVS_NS   "tl_state"
#define NVS_KEY  "time_floor"

/* Persist at most this often (NVS wear; one write per hour is nothing). */
#define PERSIST_MIN_INTERVAL_S 3600ULL

static volatile bool s_synced;
static volatile bool s_persist_pending;
static uint64_t      s_floor;            /* what NVS/build gave us, or last persisted */
static uint64_t      s_last_sync_s;

/* IDF's bundle verify callback is a non-static symbol in
 * esp_crt_bundle.c but not declared in its public header; the project
 * pins ESP-IDF v5.5.4, where the signature is exactly this. */
extern int esp_crt_verify_callback(void *buf, mbedtls_x509_crt *const crt,
                                   const int depth, uint32_t *const flags);

static esp_err_t load_floor(uint64_t *out)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    err = nvs_get_u64(h, NVS_KEY, out);
    nvs_close(h);
    return err;
}

static esp_err_t save_floor(uint64_t v)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_u64(h, NVS_KEY, v);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

esp_err_t tl_time_init(void)
{
    uint64_t floor = TL_BUILD_EPOCH;
    uint64_t persisted = 0;
    if (load_floor(&persisted) == ESP_OK && persisted > floor) {
        floor = persisted;
    }
    s_floor = floor;

    struct timeval now;
    gettimeofday(&now, NULL);
    if ((uint64_t)now.tv_sec < floor) {
        struct timeval set = { .tv_sec = (time_t)floor, .tv_usec = 0 };
        settimeofday(&set, NULL);
        ESP_LOGI(TAG, "clock floored to %lu (%s) — certificate dates checked "
                      "loosely until the first NTP sync",
                 (unsigned long)floor,
                 persisted > TL_BUILD_EPOCH ? "last NTP sync" : "build time");
    }
    return ESP_OK;
}

static void on_sntp_sync(struct timeval *tv)
{
    /* lwIP/SNTP context: no NVS, no logging beyond a line. */
    s_last_sync_s = (uint64_t)tv->tv_sec;
    s_synced = true;
    if (s_last_sync_s >= s_floor + PERSIST_MIN_INTERVAL_S) {
        s_persist_pending = true;
    }
    ESP_LOGI(TAG, "ntp sync: %lu", (unsigned long)s_last_sync_s);
}

esp_err_t tl_time_start_sntp(void)
{
    if (esp_sntp_enabled()) return ESP_OK;
    esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, CONFIG_TINYLINK_SNTP_SERVER);
    sntp_set_time_sync_notification_cb(on_sntp_sync);
    esp_sntp_init();
    ESP_LOGI(TAG, "sntp started (%s, poll every %d s)",
             CONFIG_TINYLINK_SNTP_SERVER, CONFIG_LWIP_SNTP_UPDATE_DELAY / 1000);
    return ESP_OK;
}

bool tl_time_synced(void)
{
    return s_synced;
}

void tl_time_poll_persist(void)
{
    if (!s_persist_pending) return;
    s_persist_pending = false;
    const uint64_t v = s_last_sync_s;
    esp_err_t err = save_floor(v);
    if (err == ESP_OK) {
        s_floor = v;
        ESP_LOGI(TAG, "time floor persisted: %lu", (unsigned long)v);
    } else {
        ESP_LOGW(TAG, "time floor persist failed: 0x%x (retry next sync)", err);
        s_persist_pending = true;
    }
}

static int tl_verify_cb(void *buf, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    if (!s_synced) {
        const uint32_t date_flags =
            *flags & (MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE);
        if (date_flags != 0) {
            ESP_LOGW(TAG, "cert depth %d: validity dates not checked yet "
                          "(clock not NTP-synced)", depth);
            *flags &= ~date_flags;
        }
    }
    return esp_crt_verify_callback(buf, crt, depth, flags);
}

esp_err_t tl_crt_bundle_attach(void *conf)
{
    esp_err_t err = esp_crt_bundle_attach(conf);
    if (err != ESP_OK) return err;
    mbedtls_ssl_conf_verify((mbedtls_ssl_config *)conf, tl_verify_cb, NULL);
    return ESP_OK;
}

#endif /* ESP_PLATFORM */
