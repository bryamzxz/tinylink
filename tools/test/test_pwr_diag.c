/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host tests for pwr_diag.h — the power diagnostic's bookkeeping (round
 * 1.3.7, CONFIG_TINYLINK_POWER_DIAG). What has to hold on the device:
 *
 *   - a sleep is charged to the esp_timer alarm that ends it, or else to
 *     the FreeRTOS timeout, from the plan alone (the hardware cause
 *     register says TIMER for both);
 *   - the sleep-length bins put the steady-state periods (a 102-ms
 *     beacon, lwIP's 250-ms TCP and 1-s ARP timers, the 5-s waits) in
 *     different bins;
 *   - interval deltas survive the 32-bit wraps (slept µs every 71.6 min,
 *     run-time counters likewise);
 *   - the lines parse: fixed key=value tokens, integer fixed point.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pwr_diag.h"

static int fails = 0;

static void ok(const char *name, int cond)
{
    if (cond) { printf("[%s] OK\n", name); }
    else      { printf("[%s] FAIL\n", name); fails++; }
}

static void test_classify(void)
{
    ok("classify/alarm-before-plan", tl_pwr_classify(100000, 60000) == TL_PWR_TMR);
    ok("classify/alarm-at-plan", tl_pwr_classify(100000, 100000) == TL_PWR_TMR);
    ok("classify/alarm-within-slack",
       tl_pwr_classify(100000, 100000 + TL_PWR_CLASS_SLACK_US) == TL_PWR_TMR);
    ok("classify/alarm-past-slack",
       tl_pwr_classify(100000, 100001 + TL_PWR_CLASS_SLACK_US) == TL_PWR_RTOS);
    ok("classify/no-alarm", tl_pwr_classify(250000, INT64_MAX / 2) == TL_PWR_RTOS);
    ok("classify/alarm-overdue", tl_pwr_classify(30000, -5) == TL_PWR_TMR);
}

static void test_bins(void)
{
    ok("bins/zero", tl_pwr_bin(0) == 0);
    ok("bins/below-30ms", tl_pwr_bin(29999) == 0);
    ok("bins/30ms", tl_pwr_bin(30000) == 1);
    ok("bins/beacon-dtim1", tl_pwr_bin(102400) == 1);
    ok("bins/110ms", tl_pwr_bin(110000) == 2);
    ok("bins/dtim2", tl_pwr_bin(204800) == 2);
    ok("bins/tcp-tmr", tl_pwr_bin(250000) == 2);
    ok("bins/dtim3", tl_pwr_bin(307200) == 3);
    ok("bins/arp-1s", tl_pwr_bin(1000000) == 4);
    ok("bins/rx-cap-5s", tl_pwr_bin(5000000) == 5);
    ok("bins/5100ms-open", tl_pwr_bin(5100000) == 6);
    ok("bins/huge", tl_pwr_bin(INT64_MAX / 4) == 6);
    int mono = 1;
    for (int64_t us = 0; us < 7000000; us += 777) mono &= tl_pwr_bin(us) <= tl_pwr_bin(us + 777);
    ok("bins/monotonic", mono);
}

static void test_note(void)
{
    tl_pwr_counts_t c;
    memset(&c, 0, sizeof(c));
    tl_pwr_note(&c, TL_PWR_RTOS, 20000, 0);
    ok("note/short-only", c.shorts == 1 && c.sleeps == 0 && c.slept_us == 0 &&
                          c.by_class[0] == 0 && c.by_class[1] == 0);
    tl_pwr_note(&c, TL_PWR_TMR, 102000, 101500);
    ok("note/tmr-sleep", c.sleeps == 1 && c.slept_us == 101500 && c.by_class[TL_PWR_TMR] == 1 &&
                         c.bins[TL_PWR_TMR][1] == 1 && c.early == 0);
    tl_pwr_note(&c, TL_PWR_RTOS, 250000, 90);
    ok("note/rejected-is-early", c.early == 1 && c.by_class[TL_PWR_RTOS] == 1 &&
                                 c.bins[TL_PWR_RTOS][0] == 1);
    tl_pwr_note(&c, TL_PWR_RTOS, 250000, 125000);
    ok("note/half-plan-not-early", c.early == 1);
    tl_pwr_note(&c, 7, 1000000, 990000);   /* any non-zero class is RTOS */
    ok("note/class-normalised", c.by_class[TL_PWR_RTOS] == 3 && c.bins[TL_PWR_RTOS][4] == 1);
    tl_pwr_note(&c, TL_PWR_TMR, 1000, -3);
    ok("note/negative-is-short", c.shorts == 2 && c.sleeps == 4);
}

static void test_delta_wrap(void)
{
    tl_pwr_counts_t prev, now, d;
    memset(&prev, 0, sizeof(prev));
    memset(&now, 0, sizeof(now));
    prev.slept_us = 0xFFFFFF00u;
    now.slept_us  = 0x00000100u;
    prev.sleeps = 4294967290u;
    now.sleeps  = 6u;
    prev.bins[1][6] = 3;
    now.bins[1][6]  = 10;
    now.shorts = 5;
    tl_pwr_delta(&d, &now, &prev);
    ok("delta/slept-wrap", d.slept_us == 0x200u);
    ok("delta/count-wrap", d.sleeps == 12u);
    ok("delta/last-field", d.bins[1][6] == 7u);
    ok("delta/plain", d.shorts == 5u && d.early == 0u);
    ok("delta/struct-is-u32-only", sizeof(tl_pwr_counts_t) % 4 == 0 &&
                                   sizeof(tl_pwr_counts_t) == (4 + 2 + 2 * TL_PWR_BINS) * 4);
}

static void test_pct(void)
{
    ok("pct/sleep", tl_pwr_pct(57010000, 60000000, 100) == 9501);
    ok("pct/whole-zero", tl_pwr_pct(5, 0, 100) == 0);
    ok("pct/all", tl_pwr_pct(60000000, 60000000, 100) == 10000);
    ok("pct/task-milli", tl_pwr_pct(186600, 60000000, 1000) == 311);
    ok("pct/two-cores", tl_pwr_pct(90000000, 60000000, 1000) == 150000);
    ok("pct/no-overflow-71min", tl_pwr_pct(0xFFFFFFFFu, 0xFFFFFFFFull, 1000) == 100000);
}

static void test_fmt(void)
{
    tl_pwr_counts_t d;
    memset(&d, 0, sizeof(d));
    d.sleeps = 612; d.shorts = 12; d.early = 1; d.slept_us = 57010000;
    d.by_class[TL_PWR_TMR] = 462; d.by_class[TL_PWR_RTOS] = 150;
    char buf[200];
    int n = tl_pwr_fmt_sleep(buf, sizeof(buf), &d, 60000000, 780);
    ok("fmt/sleep-line",
       strcmp(buf, "dt=60000 ms sleep=95.01% lslp=612 rate=10.20/s tmr=462 rtos=150 "
                   "early=1 short=12 tick_drift=+780 ms") == 0 && n == (int)strlen(buf));
    (void)tl_pwr_fmt_sleep(buf, sizeof(buf), &d, 60500000, -40);
    ok("fmt/sleep-negative-drift", strstr(buf, "tick_drift=-40 ms") != NULL &&
                                   strstr(buf, "dt=60500 ms") != NULL &&
                                   strstr(buf, "rate=10.11/s") != NULL);
    memset(&d, 0, sizeof(d));
    (void)tl_pwr_fmt_sleep(buf, sizeof(buf), &d, 1000, 0);
    ok("fmt/sleep-empty", strstr(buf, "sleep=0.00% lslp=0 rate=0.00/s") != NULL &&
                          strstr(buf, "tick_drift=+0 ms") != NULL);

    memset(&d, 0, sizeof(d));
    d.bins[0][1] = 455; d.bins[0][2] = 3; d.bins[0][3] = 2; d.bins[0][4] = 2;
    d.bins[1][1] = 10; d.bins[1][2] = 70; d.bins[1][3] = 40; d.bins[1][4] = 30; d.bins[1][6] = 1;
    n = tl_pwr_fmt_bins(buf, sizeof(buf), &d);
    ok("fmt/bins-line",
       strcmp(buf, "slen ms<30/110/260/520/1100/5100/inf tmr=0/455/3/2/2/0/0 "
                   "rtos=0/10/70/40/30/0/1") == 0 && n == (int)strlen(buf));
    char tiny[16];
    volatile size_t cap12 = 12;
    memset(tiny, 'x', sizeof(tiny));
    n = tl_pwr_fmt_bins(tiny, cap12, &d);
    ok("fmt/bins-truncates", n <= 11 && tiny[11] == '\0' && tiny[12] == 'x');

    size_t at = (size_t)snprintf(buf, sizeof(buf), "cpu busy=0.361%%");
    at = tl_pwr_fmt_task(buf, sizeof(buf), at, "tiT", 186600, 60000000);
    at = tl_pwr_fmt_task(buf, sizeof(buf), at, "wifi", 30000, 60000000);
    ok("fmt/cpu-line", strcmp(buf, "cpu busy=0.361% tiT=0.311 wifi=0.050") == 0 &&
                       at == strlen(buf));
    /* Deliberate truncation; volatile keeps gcc from proving it at -O2. */
    char small[20];
    volatile size_t cap16 = 16;
    memset(small, 'x', sizeof(small));
    at = (size_t)snprintf(small, cap16, "cpu busy=0.1%%");
    for (int i = 0; i < 5; i++) {
        at = tl_pwr_fmt_task(small, cap16, at, "tinylink_tlm", 600, 60000000);
    }
    ok("fmt/cpu-truncates", at <= 15 && small[15] == '\0' && small[16] == 'x');
}

static void test_tasks(void)
{
    static tl_pwr_tasks_t a, b;
    static uint32_t k[TL_PWR_MAX_TASKS + 3];
    for (unsigned i = 0; i < TL_PWR_MAX_TASKS + 3; i++) k[i] = 100u + i;   /* task numbers */
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    ok("tasks/first-seen-whole", tl_pwr_task_delta(&a, &b, k[0], 5000) == 5000);
    ok("tasks/second-new", tl_pwr_task_delta(&a, &b, k[1], 70) == 70 && b.n == 2);
    a = b;
    memset(&b, 0, sizeof(b));
    ok("tasks/delta", tl_pwr_task_delta(&a, &b, k[0], 8000) == 3000);
    /* A task recreated after the last dump (wg_rx after a data-plane
     * restart) has a new number: its whole counter, not a wrap. */
    ok("tasks/recreated-new-number", tl_pwr_task_delta(&a, &b, k[2], 10) == 10);
    a.last[1] = 0xFFFFFFF0u;
    ok("tasks/counter-wrap", tl_pwr_task_delta(&a, &b, k[1], 0x10u) == 0x20u);
    ok("tasks/gone-dropped", b.n == 3 && b.key[0] == k[0] && b.key[1] == k[2]);
    memset(&b, 0, sizeof(b));
    int capped = 1;
    for (int i = 0; i < TL_PWR_MAX_TASKS + 3; i++) {
        capped &= tl_pwr_task_delta(&a, &b, k[i], 1) <= 1 || i < 3;
    }
    ok("tasks/table-capped", b.n == TL_PWR_MAX_TASKS && capped);
}

static void test_idle(void)
{
    ok("idle/IDLE0", tl_pwr_is_idle("IDLE0"));
    ok("idle/IDLE1", tl_pwr_is_idle("IDLE1"));
    ok("idle/unicore", tl_pwr_is_idle("IDLE"));
    ok("idle/not-tiT", !tl_pwr_is_idle("tiT"));
    ok("idle/not-IDLE10", !tl_pwr_is_idle("IDLE10"));
    ok("idle/not-IDLEX", !tl_pwr_is_idle("IDLEX"));
    ok("idle/not-lowercase", !tl_pwr_is_idle("idle0"));
    ok("idle/not-prefix", !tl_pwr_is_idle("IDL"));
}

/* The PM's plan replayed over a minute of a steady state: a beacon
 * esp_timer every 102.4 ms (DTIM 1), lwIP's TCP timer every 250 ms and
 * ARP every 1 s as FreeRTOS timeouts, telemetry every 5 s. Every wake is
 * charged to whichever of the two came first, and the bins show the
 * beacon as the tmr peak below 110 ms. */
static void test_replay_steady_state(void)
{
    tl_pwr_counts_t c;
    memset(&c, 0, sizeof(c));
    const int64_t end = 60000000;
    int64_t t = 0, beacon = 102400, tcp = 250000, arp = 1000000, tlm = 5000000;
    unsigned wakes = 0, beacon_wakes = 0;
    while (t < end) {
        int64_t rtos = tcp < arp ? tcp : arp;
        if (tlm < rtos) rtos = tlm;
        const int64_t next = beacon < rtos ? beacon : rtos;
        const int64_t planned = next - t;
        const int cls = tl_pwr_classify(planned, beacon - t);
        tl_pwr_note(&c, cls, planned, planned);
        wakes++;
        if (cls == TL_PWR_TMR) beacon_wakes++;
        t = next + 1000;   /* 1 ms awake; whatever fell due meanwhile runs too */
        while (beacon < t) beacon += 102400;
        while (tcp < t) tcp += 250000;
        while (arp < t) arp += 1000000;
        while (tlm < t) tlm += 5000000;
    }
    ok("replay/every-wake-classified", c.sleeps == wakes &&
                                       c.by_class[TL_PWR_TMR] + c.by_class[TL_PWR_RTOS] == wakes);
    /* 586 beacons in 60 s; TCP, ARP and telemetry wakes that do not fall
     * within a beacon's 1-ms wake (240 + 60 + 12 minus the few that do). */
    ok("replay/beacons-are-tmr", beacon_wakes >= 580 && beacon_wakes <= 586 &&
                                 c.by_class[TL_PWR_TMR] == beacon_wakes);
    ok("replay/tcp-arp-tlm-are-rtos", c.by_class[TL_PWR_RTOS] == wakes - beacon_wakes &&
                                      c.by_class[TL_PWR_RTOS] >= 230 &&
                                      c.by_class[TL_PWR_RTOS] <= 252);
    ok("replay/tmr-below-110ms", c.bins[TL_PWR_TMR][0] + c.bins[TL_PWR_TMR][1] ==
                                 c.by_class[TL_PWR_TMR]);
    ok("replay/no-early", c.early == 0 && c.shorts == 0);
    /* Every µs outside the 1-ms wakes is slept: 98.6 % here. */
    const uint32_t res = tl_pwr_pct(c.slept_us, (uint64_t)t, 100);
    printf("  (replay: %u wakes, %u beacon, residency %u.%02u%%)\n",
           wakes, beacon_wakes, res / 100, res % 100);
    ok("replay/residency", c.slept_us == (uint32_t)(t - 1000 * (int64_t)wakes) &&
                           res >= 9850 && res <= 9870);
}

int main(void)
{
    test_classify();
    test_bins();
    test_note();
    test_delta_wrap();
    test_pct();
    test_fmt();
    test_tasks();
    test_idle();
    test_replay_steady_state();
    if (fails) {
        printf("\n[FAIL] %d pwr_diag assertion(s) failed\n", fails);
        return 1;
    }
    printf("\n[PASS] all pwr_diag assertions passed\n");
    return 0;
}
