// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Provisioner-supplied credentials live in namespace "tl_creds" — the
 * namespace docs/PROVISIONING.md, tools/credentials.csv.example and the
 * auth-key reader in tinylink.c all use. Firmware before 2026-09 read the
 * WiFi credentials from a different namespace ("tinylink"), so devices
 * provisioned against that firmware keep booting via the legacy fallback.
 * Lookup order per key, first hit wins:
 *   1. partition APP_NVS_CREDS_PARTITION, namespace APP_NVS_NAMESPACE
 *      (the dedicated `nvs_creds` slot in partitions.csv, if provisioned)
 *   2. default `nvs` partition, namespace APP_NVS_NAMESPACE
 *   3. default `nvs` partition, namespace APP_NVS_NAMESPACE_LEGACY */
#define APP_NVS_NAMESPACE         "tl_creds"
#define APP_NVS_NAMESPACE_LEGACY  "tinylink"
#define APP_NVS_CREDS_PARTITION   "nvs_creds"

esp_err_t app_nvs_init(void);

esp_err_t app_nvs_read_str(const char *key, char *out, size_t out_size);

esp_err_t app_nvs_read_blob(const char *key, void *out, size_t expected_size);

#ifdef __cplusplus
}
#endif
