// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Task-WDT helpers for the application tasks (wg_rx, wg_tx, telemetry,
// DERP supervisor, long-poll). Until 2026-09 only the two idle tasks were
// subscribed, so a wedged application task silently bricked its function
// (docs/ROADMAP.md "No general task watchdog"). Each task now subscribes
// at entry and feeds once per loop iteration; blocking TLS reads feed
// through the tls_io poll hook every SO_RCVTIMEO (30 s); long sleeps go
// through tl_wdt_sleep_ms so a 5-min Retry-After cannot trip the 90-s
// budget (CONFIG_ESP_TASK_WDT_TIMEOUT_S, sdkconfig.defaults). With
// CONFIG_ESP_TASK_WDT_PANIC=y a genuinely stuck task reboots the device
// into the known-good boot path — the same stance as the control-path
// wedge restart, applied to every task.
//
// CONFIG_TINYLINK_APP_TASK_WDT=n (tinylink core menu) turns all of this
// into no-ops for bench debugging. Host builds compile the no-op path.

#pragma once

#include <stdint.h>

#if defined(ESP_PLATFORM) && CONFIG_TINYLINK_APP_TASK_WDT

#include "esp_task_wdt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* Subscribe the calling task. Idempotent (a second add returns
 * ESP_ERR_INVALID_ARG, which is ignored). */
static inline void tl_wdt_subscribe(void)
{
    (void)esp_task_wdt_add(NULL);
}

/* Feed from the calling task. Safe to call from tasks that never
 * subscribed (returns ESP_ERR_NOT_FOUND, ignored) — the tls_io hook
 * relies on that. */
static inline void tl_wdt_feed(void)
{
    (void)esp_task_wdt_reset();
}

/* Must precede vTaskDelete(NULL) in a subscribed task: the WDT keeps the
 * task handle in its list and a deleted task never feeds again. */
static inline void tl_wdt_unsubscribe(void)
{
    (void)esp_task_wdt_delete(NULL);
}

/* vTaskDelay that keeps feeding: sleeps in ≤ 10-s slices. */
static inline void tl_wdt_sleep_ms(uint32_t ms)
{
    while (ms > 0) {
        uint32_t slice = ms > 10000u ? 10000u : ms;
        vTaskDelay(pdMS_TO_TICKS(slice));
        tl_wdt_feed();
        ms -= slice;
    }
}

#else  /* host build or CONFIG_TINYLINK_APP_TASK_WDT=n */

#ifdef ESP_PLATFORM
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
static inline void tl_wdt_sleep_ms(uint32_t ms) { vTaskDelay(pdMS_TO_TICKS(ms)); }
#else
static inline void tl_wdt_sleep_ms(uint32_t ms) { (void)ms; }
#endif
static inline void tl_wdt_subscribe(void) {}
static inline void tl_wdt_feed(void) {}
static inline void tl_wdt_unsubscribe(void) {}

#endif
