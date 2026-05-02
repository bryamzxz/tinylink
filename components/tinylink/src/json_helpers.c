// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "json_helpers.h"

#include <string.h>

esp_err_t json_get_string(const cJSON *root, const char *key,
                          char *out, size_t out_size)
{
    if (root == NULL || key == NULL || out == NULL || out_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    const cJSON *node = cJSON_GetObjectItemCaseSensitive(root, key);
    if (node == NULL) return ESP_ERR_NOT_FOUND;
    if (!cJSON_IsString(node) || node->valuestring == NULL) {
        return ESP_ERR_INVALID_RESPONSE;
    }
    size_t len = strlen(node->valuestring);
    if (len + 1 > out_size) return ESP_ERR_INVALID_SIZE;
    memcpy(out, node->valuestring, len + 1);
    return ESP_OK;
}

esp_err_t json_get_bool(const cJSON *root, const char *key, bool *out)
{
    if (root == NULL || key == NULL || out == NULL) return ESP_ERR_INVALID_ARG;
    const cJSON *node = cJSON_GetObjectItemCaseSensitive(root, key);
    if (node == NULL) return ESP_ERR_NOT_FOUND;
    if (!cJSON_IsBool(node)) return ESP_ERR_INVALID_RESPONSE;
    *out = cJSON_IsTrue(node);
    return ESP_OK;
}

const cJSON *json_get_object(const cJSON *root, const char *key)
{
    if (root == NULL || key == NULL) return NULL;
    const cJSON *node = cJSON_GetObjectItemCaseSensitive(root, key);
    if (node == NULL || !cJSON_IsObject(node)) return NULL;
    return node;
}
