/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host tests for the boot STUN probe hand-off (stun_boot.h, round
 * 1.3.5). The probe task and the waiter (tinylink_dataplane_start) each
 * run their transitions under one lock, so a run is an interleaving of
 * atomic steps. Every probe program (DNS failure; k unanswered reads
 * then an answer; k unanswered reads then the timeout) is run with the
 * waiter's give-up at every position — and once without a give-up, when
 * the probe beats the waiter's bound — and checked for:
 *   - no socket read and no publish after an abandon (wg_rx may be the
 *     reader by then; a result published after the push is never
 *     pushed);
 *   - exactly one side frees the completion signal (the waiter iff it
 *     takes it, the probe iff finish says nobody waits);
 *   - the waiter only takes the signal when the probe has finished, and
 *     what it then reads as "published" is final.
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "stun_boot.h"

static int fails;

static int ok(const char *name, int cond)
{
    if (cond) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL\n", name);
    return 1;
}

/* One atomic probe step (one lock hold in tinylink.c). */
typedef enum {
    OP_CLAIM,       /* after DNS: stun_boot_claim; stop if refused */
    OP_READ,        /* select said readable: may_read, read, no match */
    OP_ANSWER,      /* may_read, read, match → publish */
    OP_FINISH,      /* last step */
} op_t;

typedef struct {
    bool reads_after_abandon;
    bool publish_after_abandon;
    bool published;
    bool waiter_took_signal;
    bool probe_freed_signal;
    bool waiter_saw_published;
    bool signal_before_finish;
} outcome_t;

/* Run `prog` with the waiter's give-up before step `gu` (gu == n: after
 * the whole program; gu < 0: no give-up — the waiter got the signal
 * within its bound). */
static outcome_t run(const op_t *prog, int n, int gu)
{
    outcome_t o;
    memset(&o, 0, sizeof(o));
    stun_boot_state_t s = STUN_BOOT_RESOLVING;
    bool abandoned = false, finished = false, finish_ret = false;
    bool stopped = false;   /* the probe left its loop (refused) */
    for (int i = 0; i <= n; i++) {
        if (i == gu) {
            const bool done = stun_boot_give_up(&s);
            if (done) {
                /* The waiter takes the signal: given right after the
                 * probe's finish, which must come and say "awaited". */
                o.waiter_took_signal = true;
                o.waiter_saw_published = o.published;
                if (!finished) o.signal_before_finish = true;   /* checked below */
            } else {
                abandoned = true;
                o.waiter_saw_published = o.published;
            }
        }
        if (i == n) break;
        if (stopped && prog[i] != OP_FINISH) continue;
        switch (prog[i]) {
        case OP_CLAIM:
            if (stun_boot_claim(&s)) {
                if (abandoned) o.reads_after_abandon = true;
            } else {
                stopped = true;
            }
            break;
        case OP_READ:
            if (stun_boot_may_read(&s)) {
                if (abandoned) o.reads_after_abandon = true;
            } else {
                stopped = true;
            }
            break;
        case OP_ANSWER:
            if (stun_boot_may_read(&s)) {
                if (abandoned) o.reads_after_abandon = true;
                if (stun_boot_publish(&s)) {
                    if (abandoned) o.publish_after_abandon = true;
                    o.published = true;
                }
                stopped = true;   /* done reading either way */
            } else {
                stopped = true;
            }
            break;
        case OP_FINISH:
            finish_ret = stun_boot_finish(&s);
            finished = true;
            if (finish_ret) {
                /* signal given; with no give-up the waiter takes it now */
                if (gu < 0) {
                    o.waiter_took_signal = true;
                    o.waiter_saw_published = o.published;
                }
            } else {
                o.probe_freed_signal = true;
            }
            break;
        }
    }
    /* A give-up that saw DONE waits for the signal of the finish that
     * follows: it must exist and must say "awaited". */
    if (o.signal_before_finish && finished && finish_ret) o.signal_before_finish = false;
    return o;
}

static int check(const char *what, const op_t *prog, int n)
{
    int bad = 0;
    for (int gu = -1; gu <= n; gu++) {
        outcome_t o = run(prog, n, gu);
        if (o.reads_after_abandon || o.publish_after_abandon) bad++;
        /* exactly one owner frees the signal */
        if (o.waiter_took_signal == o.probe_freed_signal) bad++;
        if (o.signal_before_finish) bad++;
        /* what the waiter acts on is final */
        if (o.waiter_saw_published != o.published) bad++;
        if (gu < 0 && !o.waiter_took_signal) bad++;
    }
    char name[80];
    snprintf(name, sizeof(name), "stun_boot/%s/%d-steps", what, n);
    return ok(name, bad == 0);
}

static void test_programs(void)
{
    const op_t dns_fail[] = { OP_FINISH };
    fails += check("dns-fail", dns_fail, 1);
    for (int k = 0; k <= 4; k++) {
        op_t prog[8];
        int n = 0;
        prog[n++] = OP_CLAIM;
        for (int r = 0; r < k; r++) prog[n++] = OP_READ;
        prog[n++] = OP_ANSWER;
        prog[n++] = OP_FINISH;
        fails += check("answer", prog, n);

        n = 0;
        prog[n++] = OP_CLAIM;
        for (int r = 0; r < k; r++) prog[n++] = OP_READ;
        prog[n++] = OP_FINISH;
        fails += check("timeout", prog, n);
    }
}

/* The single transitions, spelled out. */
static void test_transitions(void)
{
    stun_boot_state_t s = STUN_BOOT_RESOLVING;
    fails += ok("claim/resolving", stun_boot_claim(&s) && s == STUN_BOOT_ON_SOCKET);
    fails += ok("claim/twice-refused", !stun_boot_claim(&s) && s == STUN_BOOT_ON_SOCKET);
    fails += ok("may_read/on-socket", stun_boot_may_read(&s));
    fails += ok("publish/on-socket", stun_boot_publish(&s) && s == STUN_BOOT_DONE);
    fails += ok("may_read/done", !stun_boot_may_read(&s));
    fails += ok("publish/twice-refused", !stun_boot_publish(&s));
    fails += ok("finish/done-awaited", stun_boot_finish(&s) && s == STUN_BOOT_DONE);
    fails += ok("give_up/done", stun_boot_give_up(&s) && s == STUN_BOOT_DONE);

    s = STUN_BOOT_RESOLVING;
    fails += ok("give_up/resolving", !stun_boot_give_up(&s) && s == STUN_BOOT_ABANDONED);
    fails += ok("claim/abandoned", !stun_boot_claim(&s));
    fails += ok("may_read/abandoned", !stun_boot_may_read(&s));
    fails += ok("publish/abandoned", !stun_boot_publish(&s));
    fails += ok("finish/abandoned", !stun_boot_finish(&s) && s == STUN_BOOT_ABANDONED);

    s = STUN_BOOT_ON_SOCKET;
    fails += ok("give_up/on-socket", !stun_boot_give_up(&s) && s == STUN_BOOT_ABANDONED);
    fails += ok("give_up/abandoned-twice", !stun_boot_give_up(&s) && s == STUN_BOOT_ABANDONED);

    s = STUN_BOOT_ON_SOCKET;
    fails += ok("finish/no-answer", stun_boot_finish(&s) && s == STUN_BOOT_DONE);
}

int main(void)
{
    test_transitions();
    test_programs();
    if (fails) {
        printf("\n[FAIL] %d assertion(s) failed\n", fails);
        return 1;
    }
    printf("\n[PASS] all stun_boot assertions passed\n");
    return 0;
}
