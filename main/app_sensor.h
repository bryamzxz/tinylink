// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t app_sensor_init(void);

esp_err_t app_sensor_read_temperature_c(float *out_temp_c);

#ifdef __cplusplus
}
#endif
