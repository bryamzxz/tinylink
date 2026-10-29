/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host-only stand-in for ESP-IDF's esp_timer.h: the monotonic clock
 * ts2021_client.c reads. Each test that links it defines
 * esp_timer_get_time (a scripted clock). */
#pragma once

#include <stdint.h>

int64_t esp_timer_get_time(void);
