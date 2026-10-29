/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host-only stand-in for ESP-IDF's esp_err.h: the type and the handful of
 * codes the host-built sources return (values match IDF v5.5). */
#pragma once

typedef int esp_err_t;

#define ESP_OK                 0
#define ESP_FAIL              -1
#define ESP_ERR_NO_MEM         0x101
#define ESP_ERR_INVALID_ARG    0x102
#define ESP_ERR_INVALID_STATE  0x103
#define ESP_ERR_INVALID_SIZE   0x104
