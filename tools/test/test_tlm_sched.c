/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host tests for tlm_sched.h — the telemetry task's wake planning (round
 * 1.3.7). The loop below is telemetry_task's, step for step, over a fake
 * clock whose waits behave like the device's: a wait is a FreeRTOS tick
 * count (tlm_wait's ms, lwIP select's round-up + 1 tick), it ends at a
 * tick boundary, and the ticks run ahead of esp_timer by the drift the
 * 1.3.x soaks measured (1.25–1.47 %). What has to hold:
 *
 *   - one wake per sample: no second wake for the last ms of a wait the
 *     tick drift ended early, none of its own for the housekeeping or a
 *     re-probe (1.3.6's loop, modelled alongside, takes twice as many);
 *   - samples on a fixed grid, each at most the slack before its instant;
 *   - housekeeping and re-probes never late, never more than `early`
 *     before their due time, at their nominal average period;
 *   - without sampling, the old deadlines (≤ 1 s early, never late).
 */

#include <stdint.h>
#include <stdio.h>

#include "tlm_sched.h"

static int fails = 0;

static void ok(const char *name, int cond)
{
    if (cond) { printf("[%s] OK\n", name); }
    else      { printf("[%s] FAIL\n", name); fails++; }
}

#define S(x)    ((int64_t)(x) * 1000000LL)
#define MS(x)   ((int64_t)(x) * 1000LL)
#define TICK_US 10000LL

static uint32_t s_rng = 12345u;
static uint32_t rnd(void) { s_rng = s_rng * 1103515245u + 12345u; return s_rng >> 8; }

/* esp_timer µs a wait for `left_us` of esp_timer time really lasts. */
static int64_t waited_us(int64_t left_us, int32_t drift_ppm)
{
    const int64_t ms = (left_us + 999) / 1000;              /* tlm_wait */
    const int64_t ticks = (ms + 9) / 10 + 1;                /* sys_arch_sem_wait */
    const int64_t phase = (int64_t)(rnd() % TICK_US);       /* into the current tick */
    const int64_t tick_time = ticks * TICK_US - phase;
    return tick_time * 1000000LL / (1000000LL + drift_ppm);
}

typedef struct {
    unsigned wakes, samples, hk, stun, empty, tail;   /* tail: empty after a < 1-s wait */
    int64_t  max_sample_early, max_sample_late;
    int64_t  max_hk_early, max_hk_late, max_stun_early, max_stun_late;
    int64_t  first_hk, last_hk, first_stun, last_stun;
    int      grid_exact;
} run_t;

static void note_window(int64_t at, int64_t due, int64_t *max_early, int64_t *max_late)
{
    if (due - at > *max_early) *max_early = due - at;
    if (at - due > *max_late) *max_late = at - due;
}

/* telemetry_task (1.3.7) with sampling on or off, over `span` µs. */
static run_t run_new(int64_t period, int sampling, int32_t drift_ppm, int64_t span)
{
    run_t r = { 0 };
    r.grid_exact = 1;
    r.max_sample_early = r.max_sample_late = r.max_hk_early = r.max_hk_late = INT64_MIN;
    r.max_stun_early = r.max_stun_late = INT64_MIN;
    const int64_t t0 = S(40);
    int64_t t = t0;
    int64_t next_sample = 0, prev_grid = -1;
    int64_t next_hk = t0 + S(60);
    int64_t stun_due = t0 + S(300);
    int64_t last_wait = 0;
    while (t < t0 + span) {
        unsigned did = 0;
        int64_t now = t;
        int64_t deadline = now + (sampling ? S(5) : S(30));
        int64_t early = tlm_early_us(0, 0), anchor = INT64_MAX;
        if (sampling) {
            if (tlm_due(now, next_sample, tlm_slack_us(period))) {
                if (next_sample != 0) note_window(now, next_sample, &r.max_sample_early,
                                                  &r.max_sample_late);
                r.samples++; did++;
                const int64_t grid = tlm_next_on_grid(next_sample, period, now);
                if (prev_grid >= 0 && grid - prev_grid != period) r.grid_exact = 0;
                prev_grid = grid;
                next_sample = grid;
                t += MS(2); now = t;                       /* the sample */
            }
            early  = tlm_early_us(1, period);
            anchor = next_sample;
            if (next_sample < deadline + tlm_slack_us(period)) deadline = next_sample;
        }
        if (tlm_due(now, next_hk, early)) {
            note_window(now, next_hk, &r.max_hk_early, &r.max_hk_late);
            if (!r.hk) r.first_hk = now;
            r.last_hk = now;
            r.hk++; did++;
            t += MS(15); now = t;                          /* stack diag on the UART */
            next_hk = tlm_next_on_grid(next_hk, S(60), now);
        }
        const int64_t hk_at = tlm_wake_at(next_hk, anchor, early);
        if (hk_at < deadline) deadline = hk_at;
        if (now + early >= stun_due) {                     /* tinylink_stun_reprobe_poll */
            note_window(now, stun_due, &r.max_stun_early, &r.max_stun_late);
            if (!r.stun) r.first_stun = now;
            r.last_stun = now;
            r.stun++; did++;
            t += MS(60); now = t;                          /* one STUN round trip */
            stun_due = now + S(300);
        }
        const int64_t stun_at = tlm_wake_at(stun_due, anchor, early);
        if (stun_at < deadline) deadline = stun_at;
        if (deadline > now) {
            if (r.wakes && !did) {
                r.empty++;
                if (last_wait < S(1)) r.tail++;
            }
            last_wait = waited_us(deadline - now, drift_ppm);
            t = now + last_wait;
            r.wakes++;
        }
    }
    return r;
}

/* The 1.3.6 loop, for the comparison: sample one period after its end,
 * strict deadlines, each kept on its own phase. */
static run_t run_old(int64_t period, int32_t drift_ppm, int64_t span)
{
    run_t r = { 0 };
    const int64_t t0 = S(40);
    int64_t t = t0, next_sample = 0, next_hk = t0 + S(60), stun_due = t0 + S(300);
    int64_t last_wait = 0;
    while (t < t0 + span) {
        unsigned did = 0;
        int64_t now = t;
        int64_t deadline = now + S(5);
        if (now >= next_sample) {
            r.samples++; did++;
            t += MS(2); now = t;
            next_sample = now + period;
        }
        if (next_sample < deadline) deadline = next_sample;
        if (now >= next_hk) {
            r.hk++; did++;
            t += MS(15); now = t;
            next_hk = now + S(60);
        }
        if (next_hk < deadline) deadline = next_hk;
        if (now >= stun_due) {
            r.stun++; did++;
            t += MS(60); now = t;
            stun_due = now + S(300);
        }
        if (stun_due < deadline) deadline = stun_due;
        if (r.wakes && !did) {
            r.empty++;
            if (last_wait < S(1)) r.tail++;
        }
        last_wait = waited_us(deadline - now, drift_ppm);
        t = now + last_wait;
        r.wakes++;
    }
    return r;
}

static void test_helpers(void)
{
    ok("grid/next", tlm_next_on_grid(S(100), S(5), S(101)) == S(105));
    ok("grid/early-wake-keeps-instant", tlm_next_on_grid(S(100), S(5), S(100) - MS(60)) == S(105));
    ok("grid/half-period-kept", tlm_next_on_grid(S(100), S(5), S(102) + MS(500)) == S(105));
    ok("grid/close-instant-dropped", tlm_next_on_grid(S(100), S(5), S(104)) == S(110));
    ok("grid/at-instant-dropped", tlm_next_on_grid(S(100), S(5), S(105)) == S(110));
    ok("grid/far-behind-stays-on-grid", tlm_next_on_grid(S(100), S(5), S(117)) == S(120));
    ok("grid/first-sample", tlm_next_on_grid(0, S(5), S(40)) == S(45));
    ok("grid/first-sample-long-period", tlm_next_on_grid(0, S(600), S(40)) == S(640));
    /* Review of 1.3.7: a sample reached late (a STUN probe blocked
     * through its instant) must not be followed by the next one a few ms
     * later. Every lateness up to three periods, P = 0.5 s … 600 s. */
    static const int64_t periods[] = { MS(500), S(5), S(30), S(600) };
    int spaced = 1, on_grid = 1;
    for (unsigned i = 0; i < sizeof(periods) / sizeof(periods[0]); i++) {
        const int64_t p = periods[i], g = S(1000);
        for (int64_t late = -tlm_slack_us(p); late < 3 * p; late += p / 97 + 1) {
            const int64_t now = g + late, next = tlm_next_on_grid(g, p, now);
            spaced  &= next - now >= p / 2;
            on_grid &= (next - g) % p == 0 && next > g;
        }
    }
    ok("grid/no-burst-after-late-sample", spaced);
    ok("grid/stays-on-grid", on_grid);
    ok("slack/5s", tlm_slack_us(S(5)) == MS(312) + 500);
    ok("slack/capped", tlm_slack_us(S(600)) == TLM_SLACK_MAX_US);
    ok("slack/zero", tlm_slack_us(0) == 0 && tlm_slack_us(-5) == 0);
    ok("early/sampling-5s", tlm_early_us(1, S(5)) == S(5));
    ok("early/sampling-capped", tlm_early_us(1, S(30)) == TLM_EARLY_MAX_US);
    ok("early/idle", tlm_early_us(0, S(5)) == TLM_SLACK_MAX_US);
    ok("due/strict-without-early", !tlm_due(S(10) - 1, S(10), 0) && tlm_due(S(10), S(10), 0));
    ok("due/early", tlm_due(S(7), S(10), S(3)) && !tlm_due(S(7) - 1, S(10), S(3)));
    ok("wake/anchor-in-window", tlm_wake_at(S(60), S(57), S(5)) == S(57));
    ok("wake/anchor-at-due", tlm_wake_at(S(60), S(60), S(5)) == S(60));
    ok("wake/anchor-too-early", tlm_wake_at(S(60), S(54), S(5)) == S(60));
    ok("wake/anchor-after-due", tlm_wake_at(S(60), S(61), S(5)) == S(60));
    ok("wake/no-anchor", tlm_wake_at(S(60), INT64_MAX, S(5)) == S(60));
    ok("wake/nothing-due", tlm_wake_at(INT64_MAX, S(57), S(5)) == INT64_MAX);
    ok("wake/both-max", tlm_wake_at(INT64_MAX, INT64_MAX, S(5)) == INT64_MAX);
    /* 1.3.9: the first sample of a boot waits for the session. */
    ok("hold/session-up-sends", !tlm_hold(true, S(10), S(10)));
    ok("hold/early-wake-held", tlm_hold(false, S(10) - MS(60), S(10)));
    ok("hold/until-session", tlm_hold(false, S(10) + MS(150), S(10)));
    ok("hold/bounded", tlm_hold(false, S(10) + TLM_HOLD_MAX_US - 1, S(10)) &&
                       !tlm_hold(false, S(10) + TLM_HOLD_MAX_US, S(10)));
    ok("hold/bound-below-period", TLM_HOLD_MAX_US + TLM_HOLD_POLL_US < S(5) / 2);
}

static void test_one_wake_per_sample(void)
{
    static const int32_t drifts[] = { 0, 12500, 13000, 14700, 30000 };
    const int64_t hour = S(3600);
    for (unsigned i = 0; i < sizeof(drifts) / sizeof(drifts[0]); i++) {
        const int32_t d = drifts[i];
        const run_t n = run_new(S(5), 1, d, hour);
        const run_t o = run_old(S(5), d, hour);
        char name[64];
        printf("  (drift %ld ppm: 1.3.7 %u wakes / %u samples / %u hk / %u stun; "
               "1.3.6 %u wakes / %u samples / %u empty)\n", (long)d, n.wakes, n.samples, n.hk,
               n.stun, o.wakes, o.samples, o.empty);
        snprintf(name, sizeof(name), "loop/%ldppm-one-wake-per-sample", (long)d);
        ok(name, n.wakes == n.samples && n.empty == 0 && n.tail == 0);
        snprintf(name, sizeof(name), "loop/%ldppm-720-samples", (long)d);
        ok(name, n.samples == 720 || n.samples == 721);
        snprintf(name, sizeof(name), "loop/%ldppm-grid", (long)d);
        ok(name, n.grid_exact && n.max_sample_early <= tlm_slack_us(S(5)) &&
                 n.max_sample_late <= 3 * TICK_US);
        snprintf(name, sizeof(name), "loop/%ldppm-hk-window", (long)d);
        ok(name, n.hk == 60 && n.max_hk_late <= 0 && n.max_hk_early <= S(5) &&
                 (n.last_hk - n.first_hk) / 59 > S(60) - MS(100) &&
                 (n.last_hk - n.first_hk) / 59 < S(60) + MS(100));
        snprintf(name, sizeof(name), "loop/%ldppm-stun-window", (long)d);
        ok(name, n.stun >= 11 && n.stun <= 13 && n.max_stun_late <= 0 &&
                 n.max_stun_early <= S(5));
        if (d >= 12500) {
            /* 1.3.6: the early wake per sample, plus the housekeeping's
             * and the re-probe's own (each twice). */
            snprintf(name, sizeof(name), "loop/%ldppm-old-loop-twice", (long)d);
            ok(name, o.wakes >= 2 * o.samples && o.empty >= o.samples - 2);
        }
    }
}

static void test_longer_periods(void)
{
    const run_t a = run_new(S(30), 1, 13000, S(3600));
    ok("loop/30s-period-hk-window", a.hk == 60 && a.max_hk_late <= 0 &&
                                    a.max_hk_early <= TLM_EARLY_MAX_US);
    ok("loop/30s-period-samples", (a.samples == 120 || a.samples == 121) && a.grid_exact &&
                                  a.max_sample_early <= tlm_slack_us(S(30)));
    const run_t b = run_new(S(600), 1, 13000, S(7200));
    ok("loop/600s-period", (b.samples == 12 || b.samples == 13) && b.grid_exact &&
                           b.hk == 120 && b.max_hk_late <= 0 &&
                           b.max_hk_early <= TLM_EARLY_MAX_US &&
                           b.max_sample_early <= TLM_SLACK_MAX_US);
}

static void test_not_sampling(void)
{
    const run_t r = run_new(S(5), 0, 13000, S(3600));
    ok("idle/no-samples", r.samples == 0);
    ok("idle/hk-never-late", r.hk == 60 && r.max_hk_late <= 0 &&
                             r.max_hk_early <= TLM_SLACK_MAX_US);
    ok("idle/stun-never-late", r.stun >= 11 && r.max_stun_late <= 0 &&
                               r.max_stun_early <= TLM_SLACK_MAX_US);
    ok("idle/no-tail-wakes", r.tail == 0);
}

int main(void)
{
    test_helpers();
    test_one_wake_per_sample();
    test_longer_periods();
    test_not_sampling();
    if (fails) {
        printf("\n[FAIL] %d tlm_sched assertion(s) failed\n", fails);
        return 1;
    }
    printf("\n[PASS] all tlm_sched assertions passed\n");
    return 0;
}
