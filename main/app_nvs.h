// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define APP_NVS_NAMESPACE "tinylink"

esp_err_t app_nvs_init(void);

esp_err_t app_nvs_read_str(const char *key, char *out, size_t out_size);

esp_err_t app_nvs_read_blob(const char *key, void *out, size_t expected_size);

#ifdef __cplusplus
}
#endif
