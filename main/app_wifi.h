// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t app_wifi_start(void);

esp_err_t app_wifi_wait_connected(uint32_t timeout_ms);

/* Writes the association hint (wifi_hint.h) to NVS if it changed. For a
 * caller that is idle anyway and runs before the telemetry task's 60-s
 * housekeeping exists — main's register retry loop. Never on the boot
 * critical path. */
void app_wifi_persist_hint(void);

#ifdef __cplusplus
}
#endif
