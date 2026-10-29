// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Pure timing helpers for wg_netif's RX task (round 1.3.2, B7/B21).
//
// Until 1.3.1 the RX task woke on a fixed 1-s SO_RCVTIMEO tick and only
// then checked its timers, so a REKEY_TIMEOUT retry fired 5–6 s after
// the INIT instead of 5 s, and an idle tunnel woke the CPU from light
// sleep every second. The task now sleeps until the earliest timer
// deadline instead. Every timer there is "more than T since t"
// (wg_timer_due); wg_timer_at gives the first instant that holds, and
// wg_recv_timeout_ms turns a deadline into a receive timeout that
// cannot wake early, cannot be 0 (lwIP reads a 0-ms SO_RCVTIMEO as
// "block forever") and never exceeds a cap. Header-only, no platform
// dependencies: tools/test/test_wg_timers.c pins the edge cases.

#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The RX-task timer predicate: more than period_us since t_us. */
static inline bool wg_timer_due(int64_t now_us, int64_t t_us, int64_t period_us)
{
    return (now_us - t_us) > period_us;
}

/* First instant at which wg_timer_due(·, t_us, period_us) holds. */
static inline int64_t wg_timer_at(int64_t t_us, int64_t period_us)
{
    return t_us + period_us + 1;
}

/* Receive timeout (ms) for a task that must run at or after deadline_us.
 * A FreeRTOS wait of N ticks lasts between N-1 and N tick periods (the
 * first tick is partial), so the remaining time is rounded up to whole
 * ticks plus one: the wait can end late by up to two ticks, never early.
 * An overdue deadline gives one tick (yield, then run the timers);
 * INT64_MAX ("no timer armed") or anything past cap_ms gives cap_ms. */
static inline uint32_t wg_recv_timeout_ms(int64_t now_us, int64_t deadline_us,
                                          uint32_t cap_ms, uint32_t tick_ms)
{
    if (tick_ms == 0) tick_ms = 1;
    if (cap_ms < tick_ms) cap_ms = tick_ms;
    if (deadline_us <= now_us) return tick_ms;
    const uint64_t rem_us  = (uint64_t)(deadline_us - now_us);
    const uint64_t tick_us = (uint64_t)tick_ms * 1000u;
    if (rem_us >= (uint64_t)cap_ms * 1000u) return cap_ms;
    const uint64_t ms = ((rem_us + tick_us - 1) / tick_us + 1) * tick_ms;
    return ms > cap_ms ? cap_ms : (uint32_t)ms;
}

#ifdef __cplusplus
}
#endif
