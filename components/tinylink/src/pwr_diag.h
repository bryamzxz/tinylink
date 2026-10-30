// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Power diagnostic (round 1.3.7, CONFIG_TINYLINK_POWER_DIAG, default n):
// the platform-free part. pwr_diag.c feeds it from IDF's light-sleep
// callbacks (CONFIG_PM_LIGHT_SLEEP_CALLBACKS) and FreeRTOS run-time stats,
// and appends three lines to the 60-s stack diag:
//
//   pwr diag: dt=60000 ms sleep=95.02% lslp=612 rate=10.20/s tmr=462 rtos=150 early=0 short=12 tick_drift=+780 ms
//   pwr diag: slen ms<30/110/260/520/1100/5100/inf tmr=0/455/3/2/2/0/0 rtos=0/10/70/40/30/0/0
//   pwr diag: cpu busy=3.412% tiT=0.311 wifi=0.522 wg_rx=0.050 ...
//
// sleep    time in light sleep (both CPUs stalled, radio off) / dt
// lslp     light sleeps taken; rate = lslp / dt
// tmr/rtos what ended each sleep: an esp_timer alarm (in steady state
//          the Wi-Fi driver's beacon timers: the firmware's own esp_timers
//          are idle by then, and the ESP32 has no Wi-Fi wake source,
//          SOC_PM_SUPPORT_WIFI_WAKEUP) or a FreeRTOS timeout (a task
//          wait, an lwIP timer). The hardware cause register says TIMER
//          for both — auto light sleep arms nothing else — so this split
//          is the cause.
// early    sleeps that ended before half their planned length (a rejected
//          or aborted sleep); counted in tmr/rtos too
// short    idle stretches too short to sleep (< IDLE_TIME_BEFORE_SLEEP)
// tick_drift  RTOS tick time minus esp_timer time over dt: every light
//          sleep steps the tick count by whole ticks and then forces one
//          more tick, so the RTOS clock (log timestamps, vTaskDelay,
//          SO_RCVTIMEO) runs ahead of esp_timer under auto light sleep
// slen     sleep lengths per class, upper bin edges in ms. Chosen so the
//          steady-state periods fall in different bins: a DTIM-1 beacon
//          (102 ms) < 110, lwIP's TCP timer (250 ms) < 260, a DTIM-3
//          beacon (307 ms) < 520, lwIP's ARP timer (1 s) < 1100, the 5-s
//          wg_rx cap and telemetry < 5100
// cpu      run time per task in % of one core over dt (3 decimals); busy
//          is their sum. The IDLE tasks are left out: a run-time counter
//          only moves at a context switch, so an IDLE task that has been
//          running since before the last dump would read as 0.
//
// All counters are uint32_t and wrap (slept µs every 71.6 min); only
// interval deltas are printed, so a wrap between two dumps is harmless.
// tools/test/test_pwr_diag.c pins the classification, the bins, the
// deltas and the line formats.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TL_PWR_BINS     7
#define TL_PWR_TMR      0
#define TL_PWR_RTOS     1
/* The PM code plans min(next RTOS timeout, next esp_timer alarm); the
 * callback reads the alarm a few µs after the plan was made. */
#define TL_PWR_CLASS_SLACK_US 200
#define TL_PWR_MAX_TASKS 20

/* Upper bin edges (ms); the last bin is open. */
static const uint32_t k_tl_pwr_bin_ms[TL_PWR_BINS - 1] = { 30, 110, 260, 520, 1100, 5100 };

typedef struct {
    uint32_t sleeps;                      /* light sleeps taken (slept > 0) */
    uint32_t shorts;                      /* idle, but too short to sleep */
    uint32_t early;                       /* ended before half the plan */
    uint32_t slept_us;                    /* Σ slept (wraps) */
    uint32_t by_class[2];                 /* TL_PWR_TMR / TL_PWR_RTOS */
    uint32_t bins[2][TL_PWR_BINS];
} tl_pwr_counts_t;

/* What ends a sleep planned for planned_us when the next esp_timer alarm
 * is to_alarm_us away (INT64_MAX-ish: none armed). */
static inline int tl_pwr_classify(int64_t planned_us, int64_t to_alarm_us)
{
    return to_alarm_us <= planned_us + TL_PWR_CLASS_SLACK_US ? TL_PWR_TMR : TL_PWR_RTOS;
}

static inline unsigned tl_pwr_bin(int64_t slept_us)
{
    unsigned i = 0;
    while (i < TL_PWR_BINS - 1 && slept_us >= (int64_t)k_tl_pwr_bin_ms[i] * 1000) i++;
    return i;
}

/* One light-sleep exit: slept_us is 0 when the sleep was not attempted. */
static inline void tl_pwr_note(tl_pwr_counts_t *c, int cls, int64_t planned_us,
                               int64_t slept_us)
{
    if (slept_us <= 0) {
        c->shorts++;
        return;
    }
    cls = cls ? TL_PWR_RTOS : TL_PWR_TMR;
    c->sleeps++;
    c->slept_us += (uint32_t)slept_us;
    c->by_class[cls]++;
    c->bins[cls][tl_pwr_bin(slept_us)]++;
    if (slept_us * 2 < planned_us) c->early++;
}

/* d = now - prev, field by field, modulo 2^32 (the struct is uint32_t
 * only). One word at a time: no copies on the dump's stack. */
static inline void tl_pwr_delta(tl_pwr_counts_t *d, const tl_pwr_counts_t *now,
                                const tl_pwr_counts_t *prev)
{
    for (size_t i = 0; i < sizeof(*d); i += sizeof(uint32_t)) {
        uint32_t a, b;
        memcpy(&a, (const uint8_t *)now + i, sizeof(a));
        memcpy(&b, (const uint8_t *)prev + i, sizeof(b));
        a -= b;
        memcpy((uint8_t *)d + i, &a, sizeof(a));
    }
}

/* part / whole in units of 1/scale percent, rounded down (0 if whole is 0). */
static inline uint32_t tl_pwr_pct(uint64_t part, uint64_t whole, uint32_t scale)
{
    return whole ? (uint32_t)(part * 100u * scale / whole) : 0;
}

/* Clip snprintf's return to what was written (cap - 1 at most). */
static inline size_t tl_pwr_adv(int n, size_t left)
{
    if (n < 0) return 0;
    return (size_t)n < left ? (size_t)n : (left ? left - 1 : 0);
}

/* The sleep line, without the "pwr diag: " prefix. dt_us > 0. */
static inline int tl_pwr_fmt_sleep(char *out, size_t cap, const tl_pwr_counts_t *d,
                                   int64_t dt_us, int32_t drift_ms)
{
    const uint32_t pct  = tl_pwr_pct(d->slept_us, (uint64_t)dt_us, 100);
    const uint32_t rate = dt_us > 0 ? (uint32_t)((uint64_t)d->sleeps * 100000000ull / (uint64_t)dt_us) : 0;
    return snprintf(out, cap,
                    "dt=%lu ms sleep=%lu.%02lu%% lslp=%lu rate=%lu.%02lu/s tmr=%lu rtos=%lu "
                    "early=%lu short=%lu tick_drift=%c%ld ms",
                    (unsigned long)(dt_us / 1000), (unsigned long)(pct / 100),
                    (unsigned long)(pct % 100), (unsigned long)d->sleeps,
                    (unsigned long)(rate / 100), (unsigned long)(rate % 100),
                    (unsigned long)d->by_class[TL_PWR_TMR],
                    (unsigned long)d->by_class[TL_PWR_RTOS], (unsigned long)d->early,
                    (unsigned long)d->shorts, drift_ms < 0 ? '-' : '+',
                    (long)(drift_ms < 0 ? -(int64_t)drift_ms : drift_ms));
}

/* The sleep-length line, without the prefix. */
static inline int tl_pwr_fmt_bins(char *out, size_t cap, const tl_pwr_counts_t *d)
{
    size_t at = 0;
    at += tl_pwr_adv(snprintf(out, cap, "slen ms<"), cap);
    for (unsigned i = 0; i < TL_PWR_BINS - 1; i++) {
        at += tl_pwr_adv(snprintf(out + at, cap - at, "%lu/", (unsigned long)k_tl_pwr_bin_ms[i]),
                         cap - at);
    }
    at += tl_pwr_adv(snprintf(out + at, cap - at, "inf"), cap - at);
    for (int c = 0; c < 2; c++) {
        at += tl_pwr_adv(snprintf(out + at, cap - at, c ? " rtos=" : " tmr="), cap - at);
        for (unsigned i = 0; i < TL_PWR_BINS; i++) {
            at += tl_pwr_adv(snprintf(out + at, cap - at, i ? "/%lu" : "%lu",
                                      (unsigned long)d->bins[c][i]),
                             cap - at);
        }
    }
    return (int)at;
}

/* Run-time counters per task between two dumps, keyed by FreeRTOS's task
 * number (xTaskNumber, unique per created task): a handle can come back
 * for a new task at the same address (wg_rx / wg_tx after a data-plane
 * restart), which would inherit the old counter and read as a wrap. */
typedef struct {
    uint32_t key[TL_PWR_MAX_TASKS];
    uint32_t last[TL_PWR_MAX_TASKS];
    unsigned n;
} tl_pwr_tasks_t;

/* Delta of one task's run-time counter since the previous dump (its whole
 * counter the first time it is seen), recorded into `next` for the next
 * dump. Tasks gone since then simply drop out of `next`. */
static inline uint32_t tl_pwr_task_delta(const tl_pwr_tasks_t *prev, tl_pwr_tasks_t *next,
                                         uint32_t key, uint32_t counter)
{
    uint32_t base = 0;
    for (unsigned i = 0; i < prev->n; i++) {
        if (prev->key[i] == key) {
            base = prev->last[i];
            break;
        }
    }
    if (next->n < TL_PWR_MAX_TASKS) {
        next->key[next->n]  = key;
        next->last[next->n] = counter;
        next->n++;
    }
    return counter - base;
}

/* Is this one of the per-core idle tasks ("IDLE0", "IDLE1"; "IDLE" on a
 * single core)? */
static inline bool tl_pwr_is_idle(const char *name)
{
    return strncmp(name, "IDLE", 4) == 0 &&
           (name[4] == '\0' || (name[4] >= '0' && name[4] <= '9' && name[5] == '\0'));
}

/* Append " name=p.ppp" (p in % of one core) to a cpu line being built. */
static inline size_t tl_pwr_fmt_task(char *out, size_t cap, size_t at, const char *name,
                                     uint32_t delta_us, int64_t dt_us)
{
    if (at >= cap) return at;
    const uint32_t p = tl_pwr_pct(delta_us, (uint64_t)dt_us, 1000);
    return at + tl_pwr_adv(snprintf(out + at, cap - at, " %s=%lu.%03lu", name,
                                    (unsigned long)(p / 1000), (unsigned long)(p % 1000)),
                           cap - at);
}

#if defined(ESP_PLATFORM)
#include "sdkconfig.h"
#if CONFIG_TINYLINK_POWER_DIAG
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
/* Print the interval's three lines (pwr_diag.c). Called from the stack
 * diag with its uxTaskGetSystemState snapshot; the first call registers
 * the light-sleep callbacks and prints nothing but "armed". A concurrent
 * second caller (the wedge-restart dump) returns at once. */
void tl_pwr_diag_dump(const TaskStatus_t *snap, unsigned n);
#endif
#endif

#ifdef __cplusplus
}
#endif
