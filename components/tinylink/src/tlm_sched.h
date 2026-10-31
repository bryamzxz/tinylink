// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Wake planning for the telemetry task (round 1.3.7). The task samples
// every CONFIG_TINYLINK_TELEMETRY_PERIOD_MS and also runs the 60-s
// housekeeping (stack diag, NVS persists) and the 5-min STUN re-probe.
// Until 1.3.6 it cost two light-sleep exits per sample and two more for
// each housekeeping pass and re-probe:
//
//  - Its waits are FreeRTOS tick counts, and under auto light sleep the
//    tick count runs ahead of esp_timer, whose deadlines the loop plans
//    with: IDF steps the count by whole ticks after every light sleep
//    and then forces one more tick (+1.25–1.47 % over the 1.3.x soaks:
//    the logs' timestamps against the capture's wall clock, or the 60-s
//    stack diag every ~60.75 s of log time). A 5-s wait ended ~50–65 ms
//    before its deadline, found nothing due and slept again for the
//    rest. A sample now runs when its instant is within tlm_slack_us.
//  - The three kept their own phases, so the housekeeping and the
//    re-probe never shared a sample's wake.
//
// Now the samples run on a fixed grid, and the other two at the last
// sample wake before they are due, at most one period (≤
// TLM_EARLY_MAX_US) early, never late; without sampling (tunnel down, no
// sensor) they keep their own deadlines and take a wake that ended up to
// TLM_SLACK_MAX_US early (the loop's longest wait is 30 s: ≤ 0.45 s of
// drift). Header-only, no platform dependencies: tools/test/
// test_tlm_sched.c replays the loop with the measured tick drift.

#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Upper bound on how early a housekeeping pass or a re-probe may run to
 * share a sample's wake. Above it (telemetry periods of 11–600 s) the
 * work only shares a wake when a sample happens to fall in the window. */
#define TLM_EARLY_MAX_US (10LL * 1000LL * 1000LL)

/* How early a sample may run: a wake that a FreeRTOS wait ended ahead
 * of the grid instant (the tick drift above, ≤ 1.5 % of the wait) is the
 * sample's. 1/16 of the period, at most TLM_SLACK_MAX_US. */
#define TLM_SLACK_MAX_US (1000LL * 1000LL)

static inline int64_t tlm_slack_us(int64_t period_us)
{
    const int64_t s = period_us > 0 ? period_us / 16 : 0;
    return s < TLM_SLACK_MAX_US ? s : TLM_SLACK_MAX_US;
}

/* The next instant of a fixed grid after the one at prev_us, at least
 * half a period from now: an instant the task reaches late (a STUN probe
 * blocked through it) is dropped, not sent a few ms after the late one.
 * prev_us 0 (none yet) starts the grid one period from now. */
static inline int64_t tlm_next_on_grid(int64_t prev_us, int64_t period_us, int64_t now_us)
{
    if (prev_us <= 0 || period_us <= 0) return now_us + (period_us > 0 ? period_us : 0);
    int64_t next = prev_us + period_us;
    const int64_t floor_us = now_us + period_us / 2;
    while (next < floor_us) next += period_us;   /* ≤ 1 step unless far behind */
    return next;
}

/* How early the housekeeping or a re-probe may run: one sample period
 * (capped) while sampling, else the tick-drift slack. */
static inline int64_t tlm_early_us(bool sampling, int64_t period_us)
{
    if (!sampling || period_us <= 0) return TLM_SLACK_MAX_US;
    return period_us < TLM_EARLY_MAX_US ? period_us : TLM_EARLY_MAX_US;
}

/* Work due at due_us runs at this wake. */
static inline bool tlm_due(int64_t now_us, int64_t due_us, int64_t early_us)
{
    return now_us >= due_us - early_us;
}

/* When to wake for work due at due_us: at the sample wake anchor_us if it
 * comes no later than due_us and no more than early_us before it (the
 * work then runs there, tlm_due), else at due_us itself. */
static inline int64_t tlm_wake_at(int64_t due_us, int64_t anchor_us, int64_t early_us)
{
    return (anchor_us <= due_us && due_us - anchor_us <= early_us) ? anchor_us : due_us;
}

/* Round 1.3.9: a due sample waits for the WireGuard session. The WG
 * netif — and with it telemetry_start — comes up at the netmap, the
 * session one handshake later (80–200 ms on the sensor), and the first
 * sample of every boot went out in between and was lost (`sendto
 * failed: errno=-1`, every 1.3.x boot log). Held at most TLM_HOLD_MAX_US
 * past its instant, re-checked every TLM_HOLD_POLL_US: a session still
 * down by then (the cold-handshake fallback) gets the old behaviour —
 * send, fail, next instant. */
#define TLM_HOLD_MAX_US  (2LL * 1000LL * 1000LL)
#define TLM_HOLD_POLL_US (100LL * 1000LL)

static inline bool tlm_hold(bool session_up, int64_t now_us, int64_t due_us)
{
    return !session_up && now_us - due_us < TLM_HOLD_MAX_US;
}

#ifdef __cplusplus
}
#endif
