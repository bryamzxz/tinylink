// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t app_telemetry_start(const char *peer_allowed_ip);

#ifdef __cplusplus
}
#endif
