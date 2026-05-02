// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "app_nvs.h"

#include <string.h>

#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "app_nvs";

esp_err_t app_nvs_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "nvs flash needs erase (err=0x%x), erasing", err);
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    return err;
}

esp_err_t app_nvs_read_str(const char *key, char *out, size_t out_size)
{
    if (key == NULL || out == NULL || out_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t h;
    esp_err_t err = nvs_open(APP_NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open(%s) failed: 0x%x", APP_NVS_NAMESPACE, err);
        return err;
    }

    size_t len = out_size;
    err = nvs_get_str(h, key, out, &len);
    nvs_close(h);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_get_str(%s) failed: 0x%x", key, err);
    }
    return err;
}

esp_err_t app_nvs_read_blob(const char *key, void *out, size_t expected_size)
{
    if (key == NULL || out == NULL || expected_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t h;
    esp_err_t err = nvs_open(APP_NVS_NAMESPACE, NVS_READONLY, &h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open(%s) failed: 0x%x", APP_NVS_NAMESPACE, err);
        return err;
    }

    size_t len = expected_size;
    err = nvs_get_blob(h, key, out, &len);
    nvs_close(h);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_get_blob(%s) failed: 0x%x", key, err);
        return err;
    }
    if (len != expected_size) {
        ESP_LOGE(TAG, "nvs blob %s has size %u, expected %u",
                 key, (unsigned)len, (unsigned)expected_size);
        return ESP_ERR_INVALID_SIZE;
    }
    return ESP_OK;
}
