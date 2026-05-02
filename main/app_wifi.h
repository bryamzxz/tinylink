// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t app_wifi_start(void);

esp_err_t app_wifi_wait_connected(uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
