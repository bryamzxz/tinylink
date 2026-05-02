// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// TMP117 driver. Continuous-conversion mode with 8-sample averaging
// (the chip's reset default for the AVG/CONV bits, so we don't bother
// writing CONFIGURATION). Returns temperature in milli-degrees Celsius
// — the device's 7.8125 m°C/LSB resolution × signed 16-bit raw value.
//
// Datasheet: TI TMP117 (Rev. December 2021), §7.5 register map.

#pragma once

#ifdef ESP_PLATFORM

#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t tmp117_init(int sda_gpio, int scl_gpio, uint8_t i2c_addr);

/* Returns ESP_OK + sets *out_milli_c on success. The TMP117 may report
 * 0x8000 when a conversion is in progress — the driver retries once
 * with a short delay before returning ESP_ERR_TIMEOUT. */
esp_err_t tmp117_read_milli_c(int32_t *out_milli_c);

#ifdef __cplusplus
}
#endif

#endif /* ESP_PLATFORM */
