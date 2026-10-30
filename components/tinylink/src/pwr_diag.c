// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Power diagnostic (round 1.3.7): the ESP-IDF side of pwr_diag.h. Off by
// default; CONFIG_TINYLINK_POWER_DIAG=y (tools/power/sdkconfig.power-diag)
// selects CONFIG_PM_LIGHT_SLEEP_CALLBACKS and FreeRTOS run-time stats.
//
// Why not esp_pm_dump_locks / esp_timer_dump (CONFIG_PM_PROFILING /
// CONFIG_ESP_TIMER_PROFILING): both print their counters with %lld, and
// this firmware's printf is the ROM's newlib-nano
// (CONFIG_LIBC_NEWLIB_NANO_FORMAT), which has no 64-bit conversions —
// every field from the first %lld on comes out wrong. Full newlib printf
// would need more stack on tasks with ~1 KB free (wifi). The numbers are
// collected here instead, from the light-sleep callbacks: they see every
// sleep, its plan and its length.

#include "sdkconfig.h"

#if CONFIG_TINYLINK_POWER_DIAG

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_pm.h"
#include "esp_timer.h"

#include "pwr_diag.h"

static const char *TAG = "tinylink";

/* Written only by the callbacks, which IDF runs inside vApplicationSleep
 * under its PM spinlock (s_switch_lock): the two cores' idle tasks never
 * run them at the same time, and an enter is always followed by its exit
 * on the same core before the lock is released. The dump reads the
 * 32-bit fields without a lock; a sleep that lands mid-copy is split
 * between two intervals. */
static tl_pwr_counts_t s_counts;
static int64_t         s_planned_us;
static int             s_class;

static esp_err_t pwr_enter_cb(int64_t sleep_time_us, void *arg)
{
    (void)arg;
    const int64_t to_alarm = esp_timer_get_next_alarm_for_wake_up() - esp_timer_get_time();
    s_planned_us = sleep_time_us;
    s_class      = tl_pwr_classify(sleep_time_us, to_alarm);
    return ESP_OK;
}

static esp_err_t pwr_exit_cb(int64_t slept_us, void *arg)
{
    (void)arg;
    tl_pwr_note(&s_counts, s_class, s_planned_us, slept_us);
    return ESP_OK;
}

/* Dump state: touched only under s_busy. */
static volatile bool   s_busy;
static bool            s_armed;
static tl_pwr_counts_t s_prev;
static int64_t         s_prev_us;
static TickType_t      s_prev_tick;
static tl_pwr_counts_t s_now, s_d;          /* off the tlm stack */
static tl_pwr_tasks_t  s_tasks[2];
static unsigned        s_cur;                /* s_tasks[s_cur]: previous dump */
static uint32_t        s_delta[TL_PWR_MAX_TASKS];
static char            s_line[352];

static void pwr_arm(int64_t now, TickType_t tick)
{
    esp_pm_sleep_cbs_register_config_t cfg = {
        .enter_cb = pwr_enter_cb,
        .exit_cb  = pwr_exit_cb,
    };
    const esp_err_t err = esp_pm_light_sleep_register_cbs(&cfg);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "pwr diag: light-sleep callbacks not registered: 0x%x", err);
        return;
    }
    s_prev      = s_counts;
    s_prev_us   = now;
    s_prev_tick = tick;
    s_armed     = true;
    ESP_LOGI(TAG, "pwr diag: armed (first interval at the next dump)");
}

void tl_pwr_diag_dump(const TaskStatus_t *snap, unsigned n)
{
    if (__atomic_exchange_n(&s_busy, true, __ATOMIC_ACQUIRE)) return;
    const int64_t    now  = esp_timer_get_time();
    const TickType_t tick = xTaskGetTickCount();
    if (!s_armed) {
        pwr_arm(now, tick);
        /* Baseline for the cpu line: every task's counter as of now. */
        static const tl_pwr_tasks_t none;      /* nothing seen before */
        s_tasks[s_cur].n = 0;
        for (unsigned i = 0; i < n && i < TL_PWR_MAX_TASKS; i++) {
            (void)tl_pwr_task_delta(&none, &s_tasks[s_cur], snap[i].xHandle,
                                    snap[i].ulRunTimeCounter);
        }
        __atomic_store_n(&s_busy, false, __ATOMIC_RELEASE);
        return;
    }

    s_now = s_counts;
    tl_pwr_delta(&s_d, &s_now, &s_prev);
    const int64_t dt_us = now - s_prev_us;
    const int64_t tick_ms = (int64_t)(TickType_t)(tick - s_prev_tick) * portTICK_PERIOD_MS;
    const int32_t drift_ms = (int32_t)(tick_ms - dt_us / 1000);
    s_prev      = s_now;
    s_prev_us   = now;
    s_prev_tick = tick;
    if (dt_us <= 0) {
        __atomic_store_n(&s_busy, false, __ATOMIC_RELEASE);
        return;
    }

    (void)tl_pwr_fmt_sleep(s_line, sizeof(s_line), &s_d, dt_us, drift_ms);
    ESP_LOGI(TAG, "pwr diag: %s", s_line);
    (void)tl_pwr_fmt_bins(s_line, sizeof(s_line), &s_d);
    ESP_LOGI(TAG, "pwr diag: %s", s_line);

    const tl_pwr_tasks_t *prev = &s_tasks[s_cur];
    tl_pwr_tasks_t       *next = &s_tasks[s_cur ^ 1u];
    next->n = 0;
    uint64_t busy = 0;
    if (n > TL_PWR_MAX_TASKS) n = TL_PWR_MAX_TASKS;
    for (unsigned i = 0; i < n; i++) {
        s_delta[i] = tl_pwr_task_delta(prev, next, snap[i].xHandle, snap[i].ulRunTimeCounter);
        if (!tl_pwr_is_idle(snap[i].pcTaskName)) busy += s_delta[i];
    }
    s_cur ^= 1u;
    const uint32_t bp = tl_pwr_pct(busy, (uint64_t)dt_us, 1000);
    size_t at = tl_pwr_adv(snprintf(s_line, sizeof(s_line), "cpu busy=%lu.%03lu%%",
                                    (unsigned long)(bp / 1000), (unsigned long)(bp % 1000)),
                           sizeof(s_line));
    for (unsigned i = 0; i < n; i++) {
        if (tl_pwr_is_idle(snap[i].pcTaskName)) continue;
        at = tl_pwr_fmt_task(s_line, sizeof(s_line), at, snap[i].pcTaskName, s_delta[i], dt_us);
    }
    ESP_LOGI(TAG, "pwr diag: %s", s_line);
    __atomic_store_n(&s_busy, false, __ATOMIC_RELEASE);
}

#endif /* CONFIG_TINYLINK_POWER_DIAG */
