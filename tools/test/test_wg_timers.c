/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for wg_timers.h — the RX task's deadline-based wait (round
 * 1.3.2, B7/B21). The properties that matter on the device:
 *
 *   - wg_timer_at(t, T) is the first instant wg_timer_due(·, t, T) holds
 *     (the RX task's timer blocks and its deadline must agree, or the
 *     wait either spins or sleeps through a timer).
 *   - wg_recv_timeout_ms never returns 0 (lwIP: 0 ms = block forever),
 *     never exceeds the cap, and — modelling a FreeRTOS wait of N ticks
 *     that starts anywhere inside the current tick — never wakes before
 *     the deadline and at most two ticks after it.
 */

#include <stdint.h>
#include <stdio.h>

#include "wg_timers.h"

static int fails = 0;

static void ok(const char *name, int cond)
{
    if (cond) { printf("[%s] OK\n", name); }
    else      { printf("[%s] FAIL\n", name); fails++; }
}

static void test_due_at(void)
{
    static const int64_t periods[] = { 0, 1, 999, 5000000, 110000000 };
    static const int64_t stamps[]  = { 0, 1, 123456789, -5000000, 4000000000000LL };
    int good = 1;
    for (unsigned i = 0; i < sizeof(periods) / sizeof(periods[0]); i++) {
        for (unsigned j = 0; j < sizeof(stamps) / sizeof(stamps[0]); j++) {
            const int64_t at = wg_timer_at(stamps[j], periods[i]);
            good &= !wg_timer_due(at - 1, stamps[j], periods[i]);
            good &=  wg_timer_due(at,     stamps[j], periods[i]);
        }
    }
    ok("due/at-is-first-due-instant", good);
    ok("due/rekey-timeout-strict",
       !wg_timer_due(5000000, 0, 5000000) && wg_timer_due(5000001, 0, 5000000));
}

static void test_timeout_edges(void)
{
    ok("timeout/overdue-one-tick", wg_recv_timeout_ms(1000000, 0, 5000, 10) == 10);
    ok("timeout/now-one-tick", wg_recv_timeout_ms(777, 777, 5000, 10) == 10);
    ok("timeout/no-timer-cap", wg_recv_timeout_ms(0, INT64_MAX, 5000, 10) == 5000);
    ok("timeout/far-cap", wg_recv_timeout_ms(0, 60000000, 1000, 10) == 1000);
    ok("timeout/at-cap", wg_recv_timeout_ms(0, 1000000, 1000, 10) == 1000);
    ok("timeout/1us-two-ticks", wg_recv_timeout_ms(0, 1, 1000, 10) == 20);
    ok("timeout/one-tick-exact", wg_recv_timeout_ms(0, 10000, 1000, 10) == 20);
    ok("timeout/one-tick-plus", wg_recv_timeout_ms(0, 10001, 1000, 10) == 30);
    ok("timeout/zero-tick-safe", wg_recv_timeout_ms(0, 5000, 1000, 0) == 6);
    ok("timeout/cap-below-tick", wg_recv_timeout_ms(0, 0, 3, 10) == 10);
    /* The B7 boot case: INIT at t, retry deadline t + 5 s + 1 us, the
     * task wakes at t + 4.3 s with the 1-s cap → 710 ms, not a 1-s tick. */
    const int64_t t = 8252000;
    const int64_t d = wg_timer_at(t, 5000000);
    ok("timeout/retry-on-time", wg_recv_timeout_ms(t + 4300000, d, 1000, 10) == 720);
}

/* FreeRTOS: a wait of N ticks issued at phase p (µs into the current
 * tick, 0 <= p < tick) ends at the N-th tick boundary, i.e. after
 * N*tick - p µs. lwIP turns ms into ticks by integer division. */
static void test_timeout_never_early(void)
{
    const uint32_t tick = 10, cap = 5000;
    int never_zero = 1, within_cap = 1, never_early = 1, at_most_two_late = 1;
    for (int64_t rem = 1; rem <= (int64_t)cap * 1000; rem += 997) {
        const uint32_t ms = wg_recv_timeout_ms(0, rem, cap, tick);
        never_zero &= ms > 0;
        within_cap &= ms <= cap;
        const int64_t n = ms / tick;
        for (int64_t p = 0; p < (int64_t)tick * 1000; p += 1250) {
            const int64_t waited = n * tick * 1000 - p;
            if (ms < cap) {
                never_early      &= waited >= rem;
                at_most_two_late &= waited - rem < 2 * (int64_t)tick * 1000;
            }
        }
    }
    ok("timeout/never-zero", never_zero);
    ok("timeout/within-cap", within_cap);
    ok("timeout/never-early", never_early);
    ok("timeout/late-by-under-two-ticks", at_most_two_late);
}

int main(void)
{
    test_due_at();
    test_timeout_edges();
    test_timeout_never_early();
    if (fails) {
        printf("\n[FAIL] %d wg_timers assertion(s) failed\n", fails);
        return 1;
    }
    printf("\n[PASS] all wg_timers assertions passed\n");
    return 0;
}
