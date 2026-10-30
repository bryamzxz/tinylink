/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host-only stand-in for FreeRTOS.h: the types and macros derp_client.c
 * names when test_derp_wlock.c builds it on the host. */
#pragma once

#include <stdint.h>

typedef uint32_t TickType_t;
typedef int      BaseType_t;

#define pdFALSE           0
#define pdTRUE            1
#define pdPASS            1
#define portMAX_DELAY     0xffffffffu
#define pdMS_TO_TICKS(ms) ((TickType_t)(ms))
