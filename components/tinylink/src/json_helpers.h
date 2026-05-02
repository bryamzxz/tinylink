// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "cJSON.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Read a string field. Returns ESP_ERR_NOT_FOUND if missing,
 * ESP_ERR_INVALID_SIZE if it doesn't fit in out_size. */
esp_err_t json_get_string(const cJSON *root, const char *key,
                          char *out, size_t out_size);

esp_err_t json_get_bool(const cJSON *root, const char *key, bool *out);

const cJSON *json_get_object(const cJSON *root, const char *key);

#ifdef __cplusplus
}
#endif
