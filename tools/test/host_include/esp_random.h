/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host-only stand-in for ESP-IDF's esp_random.h; the test that links a
 * user defines the functions (a deterministic generator). */
#pragma once

#include <stddef.h>
#include <stdint.h>

void     esp_fill_random(void *buf, size_t len);
uint32_t esp_random(void);
