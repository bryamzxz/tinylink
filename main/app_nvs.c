// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "app_nvs.h"

#include <string.h>

#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "app_nvs";

/* True once the optional dedicated credentials partition mounted. */
static bool s_creds_partition_ok;

esp_err_t app_nvs_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "nvs flash needs erase (err=0x%x), erasing", err);
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if (err != ESP_OK) return err;

    /* Best-effort mount of the dedicated `nvs_creds` partition. A blank
     * (0xFF) partition mounts fine as "empty" and every lookup on it
     * simply misses; a missing partition-table entry or a corrupt
     * partition is logged and skipped — never erased, never fatal. */
    esp_err_t perr = nvs_flash_init_partition(APP_NVS_CREDS_PARTITION);
    if (perr == ESP_OK) {
        s_creds_partition_ok = true;
    } else {
        ESP_LOGI(TAG, "creds partition %s not usable (0x%x) — using default nvs",
                 APP_NVS_CREDS_PARTITION, perr);
    }
    return ESP_OK;
}

/* Candidate (partition, namespace) pairs in lookup order — see app_nvs.h. */
typedef struct {
    const char *partition;   /* NULL = default `nvs` */
    const char *ns;
} nvs_candidate_t;

static const nvs_candidate_t k_candidates[] = {
    { APP_NVS_CREDS_PARTITION, APP_NVS_NAMESPACE        },
    { NULL,                    APP_NVS_NAMESPACE        },
    { NULL,                    APP_NVS_NAMESPACE_LEGACY },
};

static esp_err_t open_candidate(const nvs_candidate_t *c, nvs_handle_t *h)
{
    if (c->partition != NULL) {
        if (!s_creds_partition_ok) return ESP_ERR_NVS_NOT_FOUND;
        return nvs_open_from_partition(c->partition, c->ns, NVS_READONLY, h);
    }
    return nvs_open(c->ns, NVS_READONLY, h);
}

esp_err_t app_nvs_read_str(const char *key, char *out, size_t out_size)
{
    if (key == NULL || out == NULL || out_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = ESP_ERR_NVS_NOT_FOUND;
    for (size_t i = 0; i < sizeof(k_candidates) / sizeof(k_candidates[0]); i++) {
        const nvs_candidate_t *c = &k_candidates[i];
        nvs_handle_t h;
        err = open_candidate(c, &h);
        if (err != ESP_OK) continue;
        size_t len = out_size;
        err = nvs_get_str(h, key, out, &len);
        nvs_close(h);
        if (err == ESP_OK) {
            if (i == 2) {
                ESP_LOGW(TAG, "%s found in legacy namespace %s — re-provision "
                              "under %s when convenient",
                         key, c->ns, APP_NVS_NAMESPACE);
            }
            return ESP_OK;
        }
    }
    ESP_LOGE(TAG, "missing nvs key %s (looked in %s:%s, nvs:%s, nvs:%s): 0x%x",
             key, APP_NVS_CREDS_PARTITION, APP_NVS_NAMESPACE,
             APP_NVS_NAMESPACE, APP_NVS_NAMESPACE_LEGACY, err);
    return err;
}

esp_err_t app_nvs_read_blob(const char *key, void *out, size_t expected_size)
{
    if (key == NULL || out == NULL || expected_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = ESP_ERR_NVS_NOT_FOUND;
    size_t len = expected_size;
    for (size_t i = 0; i < sizeof(k_candidates) / sizeof(k_candidates[0]); i++) {
        nvs_handle_t h;
        err = open_candidate(&k_candidates[i], &h);
        if (err != ESP_OK) continue;
        len = expected_size;
        err = nvs_get_blob(h, key, out, &len);
        nvs_close(h);
        if (err == ESP_OK) break;
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_get_blob(%s) failed in every namespace: 0x%x", key, err);
        return err;
    }
    if (len != expected_size) {
        ESP_LOGE(TAG, "nvs blob %s has size %u, expected %u",
                 key, (unsigned)len, (unsigned)expected_size);
        return ESP_ERR_INVALID_SIZE;
    }
    return ESP_OK;
}
