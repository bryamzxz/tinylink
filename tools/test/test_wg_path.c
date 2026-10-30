/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host tests for wg_path.h — the data-plane path selection of round
 * 1.3.6. Two parts:
 *
 *   1. Unit cases, time-driven: every transition at its exact instant
 *      (one µs before: nothing), the deadline / tick agreement, betterAddr
 *      with hysteresis, pong rounds (flapping), the one-way rules.
 *   2. A simulation of the sensor and its peer: our telemetry every 5 s
 *      (jittered), a rekey every 110 s, and the peer's wireguard-go
 *      timers — a passive keepalive KEEPALIVE_TIMEOUT after the first data
 *      packet it receives with no send of its own, any send cancelling it;
 *      its handshake response and its TSMP disco advert on every new
 *      keypair are sends — over paths that work, die both ways, die one
 *      way, heal, or answer DISCO while WireGuard is silent (a broken
 *      session, a WG-dropping middlebox). It counts lapses, pings, DERP
 *      copies, rekeys and lost telemetry: hours of a healthy path must
 *      cost nothing.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wg_path.h"

static int fails = 0;

static void ok(const char *name, int cond)
{
    if (cond) { printf("[%s] OK\n", name); }
    else      { printf("[%s] FAIL\n", name); fails++; }
}

#define MS(x) ((int64_t)(x) * 1000LL)
#define S(x)  ((int64_t)(x) * 1000000LL)

/* Start well away from 0 (0 = "never" in the struct). */
#define T0 S(100)

static const uint32_t EP_A = 0xC0000201u;   /* 192.0.2.1 (RFC 5737), host order */
static const uint32_t EP_LAN = 0xC0A80105u; /* 192.168.1.5 */

/* DIRECT at `t` via a pong from the current endpoint. */
static void confirm_at(wg_path_t *p, int64_t t, uint32_t rtt_us)
{
    (void)wg_path_on_pong(p, t, rtt_us, true, 0, 0, false, false, NULL);
}

static uint32_t send_data(wg_path_t *p, int64_t t, wg_path_mode_t *m)
{
    return wg_path_on_send(p, t, true, m);
}

/* ------------------------------------------------------------------ */

static void test_private(void)
{
    ok("private/10", wg_path_v4_private(0x0A000001u));
    ok("private/172.16", wg_path_v4_private(0xAC100001u) && wg_path_v4_private(0xAC1FFFFEu));
    ok("private/172.32-not", !wg_path_v4_private(0xAC200001u));
    ok("private/192.168", wg_path_v4_private(EP_LAN));
    ok("private/link-local", wg_path_v4_private(0xA9FE0101u));
    ok("private/public-not", !wg_path_v4_private(EP_A) && !wg_path_v4_private(0xCB007101u));
    ok("private/cgnat-not", !wg_path_v4_private(0x64400001u));
}

static void test_better(void)
{
    /* Equal latency, same class: never (upstream needs >1 point; here >15). */
    ok("better/equal", !wg_path_better(50000, false, 50000, false));
    /* The later-pinged endpoint of a round looks faster by the ping spacing. */
    ok("better/10ms-bias", !wg_path_better(240000, false, 250000, false));
    ok("better/20ms-bias", !wg_path_better(30000, false, 50000, false));
    /* 2x faster and > 25 ms: yes; 2x faster but 5 ms: no (LAN noise). */
    ok("better/2x", wg_path_better(100000, false, 200000, false));
    ok("better/2x-tiny", !wg_path_better(5000, false, 10000, false));
    /* 15 % faster (and > 25 ms): not clearly better; 20 %: yes. */
    ok("better/15pct", !wg_path_better(170000, false, 200000, false));
    ok("better/20pct", wg_path_better(160000, false, 200000, false));
    /* Private beats public at equal latency (upstream +20)... */
    ok("better/private-tie", wg_path_better(50000, true, 50000, false));
    /* ...but not when clearly slower; public needs >35 % over private. */
    ok("better/private-slower", !wg_path_better(100000, true, 50000, false));
    ok("better/public-vs-private-30pct", !wg_path_better(70000, false, 100000, true));
    ok("better/public-vs-private-60pct", wg_path_better(40000, false, 100000, true));
    ok("better/not-symmetric", !wg_path_better(200000, false, 100000, false));
    ok("better/zero-current", !wg_path_better(50000, false, 0, false));
}

static void test_start_dual_relay(void)
{
    wg_path_t p;
    wg_path_init(&p, T0, true);
    ok("start/dual", p.mode == WG_PATH_DUAL && p.why == WG_PATH_WHY_START);
    ok("start/init-relay", wg_path_init_wants_relay(&p, T0));
    ok("start/may-roam", wg_path_may_roam(&p, T0));
    ok("start/deadline-now", wg_path_next_deadline(&p) == T0);
    wg_path_mode_t m;
    ok("start/send-dual", wg_path_on_send(&p, T0, true, &m) == 0 && m == WG_PATH_DUAL);
    /* First tick asks for the ping, once. */
    ok("start/tick-ping", wg_path_tick(&p, T0 + 10) == WG_PATH_ACT_PING);
    ok("start/tick-once", wg_path_tick(&p, T0 + 20) == 0);
    const int64_t dl = wg_path_next_deadline(&p);
    ok("start/deadline-timeout", dl == T0 + 10 + MS(WG_PATH_PING_TIMEOUT_MS) + 1);
    ok("start/no-relay-early", wg_path_tick(&p, dl - 1) == 0 && p.mode == WG_PATH_DUAL);
    ok("start/relay-probe", wg_path_tick(&p, dl) == WG_PATH_ACT_PROBE &&
                            p.mode == WG_PATH_RELAY && p.deaths == 1);
    ok("start/send-relay", wg_path_on_send(&p, dl + 1, true, &m) == 0 && m == WG_PATH_RELAY);
    /* A keepalive in RELAY proves nothing about the direct path. */
    wg_path_on_keepalive(&p, dl + 2);
    ok("start/ka-no-confirm", p.mode == WG_PATH_RELAY);
    /* A pong does. */
    confirm_at(&p, dl + MS(100), 80000);
    ok("start/pong-direct", p.mode == WG_PATH_DIRECT && p.confirms == 1 &&
                            p.was_off_us == dl + MS(100) - T0);
    ok("start/direct-send", wg_path_on_send(&p, dl + MS(200), true, &m) == 0 &&
                            m == WG_PATH_DIRECT);
    ok("start/valid", wg_path_valid(&p, dl + MS(200)) &&
                      !wg_path_init_wants_relay(&p, dl + MS(200)) &&
                      !wg_path_may_roam(&p, dl + MS(200)));
}

/* The answer window: our first unanswered data frame + 12 s. */
static void test_answer_window(void)
{
    wg_path_t p;
    wg_path_mode_t m;
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    const int64_t s1 = T0 + S(1);
    ok("answer/first-direct", send_data(&p, s1, &m) == 0 && m == WG_PATH_DIRECT &&
                              p.await_us == s1);
    /* Later frames do not move the clock. */
    ok("answer/second", send_data(&p, s1 + S(5), &m) == 0 && p.await_us == s1);
    const int64_t dl = wg_path_next_deadline(&p);
    ok("answer/deadline", dl == s1 + MS(WG_PATH_ANSWER_MS) + 1);
    ok("answer/tick-early", wg_path_tick(&p, dl - 1) == 0 && p.mode == WG_PATH_DIRECT);
    ok("answer/tick-lapse", wg_path_tick(&p, dl) == WG_PATH_ACT_PING &&
                            p.mode == WG_PATH_DUAL && p.why == WG_PATH_WHY_ANSWER &&
                            p.lapses == 1 && p.unconfirmed_us == dl - s1);
    /* The ping is the lapse's own: the DUAL tick does not ask again. */
    ok("answer/no-second-ping", wg_path_tick(&p, dl + 1) == 0);
    ok("answer/frame-dual", send_data(&p, dl + 2, &m) == 0 && m == WG_PATH_DUAL);
    ok("answer/init-relay", wg_path_init_wants_relay(&p, dl + 2));
    /* Its ping unanswered: RELAY, and the frames the dead path may have
     * eaten go again via DERP. */
    ok("answer/confirmed-rescue",
       wg_path_tick(&p, dl + MS(WG_PATH_PING_TIMEOUT_MS) + 1) ==
       (WG_PATH_ACT_PROBE | WG_PATH_ACT_RESCUE) && p.mode == WG_PATH_RELAY);

    /* The send path sees the lapse too, at the same instant (wg_rx may
     * wake up to two ticks late). */
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    (void)send_data(&p, s1, &m);
    ok("answer/send-early", send_data(&p, s1 + MS(WG_PATH_ANSWER_MS), &m) == 0 &&
                            m == WG_PATH_DIRECT);
    ok("answer/send-lapse",
       send_data(&p, s1 + MS(WG_PATH_ANSWER_MS) + 1, &m) == WG_PATH_ACT_PING &&
       m == WG_PATH_DUAL && p.lapses == 1);

    /* A keepalive inside the window answers: the clock restarts at the
     * next frame. */
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    (void)send_data(&p, s1, &m);
    wg_path_on_keepalive(&p, s1 + S(10) + MS(200));
    ok("answer/ka-clears", p.await_us == 0 && p.proof_us == s1 + S(10) + MS(200));
    ok("answer/ka-no-deadline", wg_path_next_deadline(&p) == INT64_MAX);
    (void)send_data(&p, s1 + S(11), &m);
    ok("answer/restart", p.await_us == s1 + S(11) && m == WG_PATH_DIRECT);
    /* Our own keepalives are never answered: they start no clock. */
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    ok("answer/own-ka", wg_path_on_send(&p, s1, false, &m) == 0 && p.await_us == 0 &&
                        m == WG_PATH_DIRECT);
}

/* Peer data proves nothing (one-way path); the first after a handshake
 * restarts the window once. */
static void test_one_way_rules(void)
{
    wg_path_t p;
    wg_path_mode_t m;
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    const int64_t s1 = T0 + S(1);
    (void)send_data(&p, s1, &m);
    for (int i = 1; i <= 11; i++) wg_path_on_peer_data(&p, s1 + S(i));
    ok("oneway/data-no-proof", p.await_us == s1 && p.proof_us == T0);
    ok("oneway/data-lapses", wg_path_tick(&p, s1 + MS(WG_PATH_ANSWER_MS) + 1) ==
                             WG_PATH_ACT_PING && p.mode == WG_PATH_DUAL);
    /* In DUAL a keepalive or more data never returns to DIRECT. */
    wg_path_on_keepalive(&p, s1 + S(13));
    wg_path_on_peer_data(&p, s1 + S(13));
    ok("oneway/dual-stays", p.mode == WG_PATH_DUAL);

    /* Handshake grace: response + the peer's advert. */
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    (void)send_data(&p, s1, &m);
    const int64_t hs = s1 + S(4);
    wg_path_on_handshake(&p, hs);
    ok("grace/hs-clears", p.await_us == 0);
    (void)send_data(&p, hs + MS(1), &m);       /* our advert */
    ok("grace/advert-starts", p.await_us == hs + MS(1));
    wg_path_on_peer_data(&p, hs + MS(120));   /* the peer's advert */
    ok("grace/peer-advert-clears", p.await_us == 0 && p.grace_used);
    (void)send_data(&p, hs + S(1), &m);
    wg_path_on_peer_data(&p, hs + S(2));      /* no second grace */
    ok("grace/once", p.await_us == hs + S(1));
    /* No grace once the window after the handshake is over. */
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    wg_path_on_handshake(&p, s1);
    wg_path_on_keepalive(&p, s1 + S(12));
    (void)send_data(&p, s1 + S(13), &m);
    wg_path_on_peer_data(&p, s1 + S(13) + MS(1));
    ok("grace/expires", p.await_us == s1 + S(13) && !p.grace_used);
    /* Handshake while not DIRECT: no effect on the mode. */
    wg_path_init(&p, T0, true);
    wg_path_on_handshake(&p, s1);
    ok("grace/dual-hs", p.mode == WG_PATH_DUAL);
}

static void test_idle(void)
{
    wg_path_t p;
    wg_path_mode_t m;
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    /* First frame 12 s after the proof: no lapse at the edge, lapse past it. */
    ok("idle/edge", send_data(&p, T0 + MS(WG_PATH_ANSWER_MS), &m) == 0 &&
                    m == WG_PATH_DIRECT);
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    ok("idle/first-after-pause",
       send_data(&p, T0 + S(60), &m) == WG_PATH_ACT_PING && m == WG_PATH_DUAL &&
       p.why == WG_PATH_WHY_IDLE && p.unconfirmed_us == S(60));
    /* Regular data with recent keepalives: never idle. */
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    int lapsed = 0;
    for (int i = 1; i <= 100; i++) {
        const int64_t t = T0 + S(5) * i;
        lapsed |= send_data(&p, t, &m) != 0;
        /* the answer to the frame of 10 s ago */
        if (i % 2 == 0) wg_path_on_keepalive(&p, t + MS(300));
    }
    ok("idle/steady", !lapsed && p.mode == WG_PATH_DIRECT);
    /* Sparse data (one frame / 20 s) answered by keepalives: no lapse. */
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    lapsed = 0;
    for (int i = 1; i <= 30; i++) {
        const int64_t t = T0 + S(10) + S(20) * (i - 1);
        lapsed |= send_data(&p, t, &m) != 0;
        wg_path_on_keepalive(&p, t + S(10) + MS(100));
    }
    ok("idle/sparse-answered", !lapsed);
    /* A stale DIRECT (no proof for 30 s) is not valid: INITs get a DERP
     * copy, another source may roam. */
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    ok("idle/valid-30s", wg_path_valid(&p, T0 + MS(WG_PATH_TRUST_MS)));
    ok("idle/stale", !wg_path_valid(&p, T0 + MS(WG_PATH_TRUST_MS) + 1) &&
                     wg_path_init_wants_relay(&p, T0 + MS(WG_PATH_TRUST_MS) + 1) &&
                     wg_path_may_roam(&p, T0 + MS(WG_PATH_TRUST_MS) + 1));
}

static void test_relay_reprobe(void)
{
    wg_path_t p;
    wg_path_mode_t m;
    wg_path_init(&p, T0, true);
    (void)wg_path_tick(&p, T0);                          /* ping */
    const int64_t tr = T0 + MS(WG_PATH_PING_TIMEOUT_MS) + 1;
    ok("reprobe/relay", wg_path_tick(&p, tr) == WG_PATH_ACT_PROBE);
    /* Not active (no data ever): no deadline, no re-probe. */
    ok("reprobe/idle-none", wg_path_next_deadline(&p) == INT64_MAX &&
                            wg_path_tick(&p, tr + S(30)) == 0);
    /* Data every 5 s: re-probes at +10, +20, +40, +60, +60 s. */
    int64_t t = tr;
    int64_t last = tr;
    const int64_t want[] = { 10, 20, 40, 60, 60, 60 };
    int good = 1, n = 0;
    for (int i = 0; i < 1000 && n < 6; i++) {
        t += MS(500);
        if (i % 10 == 0) (void)wg_path_on_send(&p, t, true, &m);
        const int64_t dl = wg_path_next_deadline(&p);
        if (dl <= t) {
            const uint32_t a = wg_path_tick(&p, t);
            good &= a == (WG_PATH_ACT_PING | WG_PATH_ACT_PROBE);
            good &= t - last >= S(want[n]) && t - last <= S(want[n]) + MS(500);
            last = t;
            n++;
        } else {
            good &= wg_path_tick(&p, t) == 0;
        }
    }
    ok("reprobe/backoff", good && n == 6);
    /* Data stops: no re-probe once the last frame is 45 s old, even with
     * one overdue. */
    const int64_t quiet = p.last_data_us;
    ok("reprobe/stops-when-idle", wg_path_tick(&p, quiet + S(200)) == 0 &&
                                  wg_path_next_deadline(&p) == INT64_MAX);
    /* A pong ends it; the back-off resets. */
    confirm_at(&p, quiet + S(50), 60000);
    ok("reprobe/pong-direct", p.mode == WG_PATH_DIRECT && p.reprobe_ms == 0);
}

/* The 1.3.5 flap: two endpoints of the peer answer every round ~10 ms
 * apart; the current one must stay. */
static void test_flapping(void)
{
    wg_path_t p;
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);          /* current: 192.0.2.1:41641 */
    int roams = 0, good = 1;
    for (int r = 0; r < 40; r++) {
        const int64_t t = T0 + S(180) * (r + 1);
        wg_path_on_keepalive(&p, t - S(3));             /* path in use */
        /* Round: the other endpoint (:24759) answers first or second,
         * up to 25 ms faster in either order; same DTIM wake. */
        const uint32_t dtim = (uint32_t)((r * 37) % 300) * 1000u;
        const uint32_t cur_rtt = 40000 + dtim;
        const uint32_t oth_rtt = cur_rtt - (r % 2 ? 10000 : 0) + (r % 3 ? 0 : 15000);
        wg_path_pong_t a, b;
        if (r % 2) {
            a = wg_path_on_pong(&p, t, oth_rtt, false, EP_A, 24759, false, false, NULL);
            b = wg_path_on_pong(&p, t + MS(10), cur_rtt, true, 0, 0, false, false, NULL);
        } else {
            b = wg_path_on_pong(&p, t, cur_rtt, true, 0, 0, false, false, NULL);
            a = wg_path_on_pong(&p, t + MS(10), oth_rtt, false, EP_A, 24759, false, false, NULL);
        }
        good &= a == WG_PATH_PONG_KEPT && b == WG_PATH_PONG_CONFIRMED;
        roams += (a >= WG_PATH_PONG_ROAM) + (b >= WG_PATH_PONG_ROAM);
    }
    ok("flap/40-rounds-0-roams", good && roams == 0 && p.roams == 0);

    /* A stale RTT from an older round does not decide: the other endpoint
     * answering first, much faster than the current's last (slow DTIM)
     * sample, waits for the current's pong of the same round. */
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 300000);         /* a slow DTIM wake */
    wg_path_on_keepalive(&p, T0 + S(10));
    const int64_t t = T0 + S(20);
    ok("flap/stale-rtt-waits",
       wg_path_on_pong(&p, t, 50000, false, EP_A, 24759, false, false, NULL) ==
       WG_PATH_PONG_KEPT && p.cand_valid);
    ok("flap/same-round-keeps",
       wg_path_on_pong(&p, t + MS(10), 45000, true, 0, 0, false, false, NULL) ==
       WG_PATH_PONG_CONFIRMED && !p.cand_valid);
    /* ...and a candidate whose current never answers expires. */
    ok("flap/cand-pending",
       wg_path_on_pong(&p, t + S(30), 20000, false, EP_A, 24759, false, false, NULL) ==
       WG_PATH_PONG_KEPT);
    wg_path_on_keepalive(&p, t + S(31));
    ok("flap/cand-expires",
       wg_path_on_pong(&p, t + S(32), 400000, true, 0, 0, false, false, NULL) ==
       WG_PATH_PONG_CONFIRMED);

    /* Clearly better (the LAN address, same latency) wins once, whichever
     * comes first; then stays. */
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    wg_path_on_keepalive(&p, T0 + S(5));
    ok("flap/lan-after-current",
       wg_path_on_pong(&p, T0 + S(6), 52000, true, 0, 0, false, false, NULL) ==
       WG_PATH_PONG_CONFIRMED &&
       wg_path_on_pong(&p, T0 + S(6) + MS(5), 50000, false, EP_LAN, 41641, true, false, NULL) ==
       WG_PATH_PONG_ROAM && p.roams == 1);
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    wg_path_on_keepalive(&p, T0 + S(5));
    ok("flap/lan-first-pending",
       wg_path_on_pong(&p, T0 + S(6), 50000, false, EP_LAN, 41641, true, false, NULL) ==
       WG_PATH_PONG_KEPT);
    ok("flap/lan-on-current",
       wg_path_on_pong(&p, T0 + S(6) + MS(5), 52000, true, 0, 0, false, false, NULL) ==
       WG_PATH_PONG_ROAM_CAND && p.cand_v4_be == EP_LAN && p.cand_port == 41641 &&
       p.rtt_us == 50000 && p.mode == WG_PATH_DIRECT);
    /* Now on the LAN address: the public one never takes it back at
     * similar latency. */
    ok("flap/lan-sticks",
       wg_path_on_pong(&p, T0 + S(60), 48000, true, 0, 0, true, true, NULL) ==
       WG_PATH_PONG_CONFIRMED &&
       wg_path_on_pong(&p, T0 + S(60) + MS(5), 40000, false, EP_A, 41641, false, true, NULL) ==
       WG_PATH_PONG_KEPT);

    /* Not valid (DUAL / RELAY / stale): the first pong wins, the second
     * of the round only if clearly better. */
    wg_path_init(&p, T0, true);
    ok("flap/untrusted-first-wins",
       wg_path_on_pong(&p, T0 + S(1), 60000, false, EP_A, 24759, false, false, NULL) ==
       WG_PATH_PONG_ROAM && p.mode == WG_PATH_DIRECT);
    ok("flap/untrusted-second-kept",
       wg_path_on_pong(&p, T0 + S(1) + MS(10), 55000, false, EP_A, 41641, false, false, NULL) ==
       WG_PATH_PONG_KEPT);
}

static void test_endpoint_change(void)
{
    wg_path_t p;
    wg_path_mode_t m;
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    wg_path_on_endpoint_change(&p, T0 + S(1));
    ok("ep/dual", p.mode == WG_PATH_DUAL && p.why == WG_PATH_WHY_ENDPOINT &&
                  p.proof_us == 0 && p.rtt_at_us == 0);
    ok("ep/ping-now", wg_path_next_deadline(&p) == T0 + S(1) &&
                      wg_path_tick(&p, T0 + S(1)) == WG_PATH_ACT_PING);
    ok("ep/frames-dual", wg_path_on_send(&p, T0 + S(2), true, &m) == 0 &&
                         m == WG_PATH_DUAL);
    /* From RELAY too. */
    ok("ep/relay-no-rescue", wg_path_tick(&p, T0 + S(7)) == WG_PATH_ACT_PROBE &&
                             p.mode == WG_PATH_RELAY);
    wg_path_on_endpoint_change(&p, T0 + S(8));
    ok("ep/relay-to-dual", p.mode == WG_PATH_DUAL &&
                           wg_path_tick(&p, T0 + S(8)) == WG_PATH_ACT_PING);
}

/* A lapse resolved elsewhere than by the current endpoint's own pong
 * confirms it: re-send. Resolved by that pong: nothing was lost. */
static void test_lapse_resolution(void)
{
    wg_path_t p;
    wg_path_mode_t m;
    uint32_t act = 99;
    const int64_t s1 = T0 + S(1);
    const int64_t lapse = s1 + MS(WG_PATH_ANSWER_MS) + 1;
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    (void)send_data(&p, s1, &m);
    wg_path_on_peer_data(&p, s1 + S(3));        /* the session is alive */
    (void)wg_path_tick(&p, lapse);
    ok("resolve/own-pong-no-rescue",
       wg_path_on_pong(&p, lapse + MS(80), 80000, true, 0, 0, false, false, &act) ==
       WG_PATH_PONG_CONFIRMED && act == 0 && p.mode == WG_PATH_DIRECT);

    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    (void)send_data(&p, s1, &m);
    (void)wg_path_tick(&p, lapse);
    ok("resolve/other-pong-rescues",
       wg_path_on_pong(&p, lapse + MS(80), 80000, false, EP_A, 24759, false, false, &act) ==
       WG_PATH_PONG_ROAM && act == WG_PATH_ACT_RESCUE && p.mode == WG_PATH_DIRECT);

    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    (void)send_data(&p, s1, &m);
    (void)wg_path_tick(&p, lapse);
    ok("resolve/roam-rescues",
       wg_path_on_endpoint_change(&p, lapse + S(1)) == WG_PATH_ACT_RESCUE &&
       p.mode == WG_PATH_DUAL && p.why == WG_PATH_WHY_ENDPOINT);
    /* ...once: the new endpoint's own timeout sends nothing again. */
    (void)wg_path_tick(&p, lapse + S(1));
    ok("resolve/then-relay-no-rescue",
       wg_path_tick(&p, lapse + S(1) + MS(WG_PATH_PING_TIMEOUT_MS) + 1) == WG_PATH_ACT_PROBE);
    /* Never lapsed (start, or after a roam): nothing to re-send. */
    wg_path_init(&p, T0, true);
    ok("resolve/start-roam-none", wg_path_on_endpoint_change(&p, T0 + S(1)) == 0);
    ok("resolve/start-pong-none",
       wg_path_on_pong(&p, T0 + S(2), 50000, false, EP_A, 41641, false, false, &act) ==
       WG_PATH_PONG_ROAM && act == 0);
}

/* The 1.3.5 soak: every DISCO ping answered, not one WireGuard packet
 * from the peer for 30 s (seen direct=0 derp=0) until the RX-stale rekey.
 * A pong to the ping of an ANSWER lapse with nothing from the peer since
 * the unanswered frame → DERP only, re-send, rekey. */
static void test_silent(void)
{
    wg_path_t p;
    wg_path_mode_t m;
    uint32_t act = 99;
    const int64_t s1 = T0 + S(1);
    const int64_t lapse = s1 + MS(WG_PATH_ANSWER_MS) + 1;
    const int64_t pong = lapse + MS(80);
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    wg_path_on_peer_data(&p, s1 - 1);           /* before the frame: does not count */
    (void)send_data(&p, s1, &m);
    (void)send_data(&p, s1 + S(5), &m);
    (void)wg_path_tick(&p, lapse);
    ok("silent/pong",
       wg_path_on_pong(&p, pong, 80000, true, 0, 0, false, false, &act) ==
       WG_PATH_PONG_SILENT && act == (WG_PATH_ACT_RESCUE | WG_PATH_ACT_REKEY) &&
       p.mode == WG_PATH_RELAY && p.why == WG_PATH_WHY_SILENT &&
       p.silences == 1 && p.deaths == 0 && p.unconfirmed_us == pong - s1 &&
       p.rtt_us == 80000);
    ok("silent/derp-only", send_data(&p, pong + 1, &m) == 0 && m == WG_PATH_RELAY &&
                           wg_path_init_wants_relay(&p, pong + 1) &&
                           wg_path_may_roam(&p, pong + 1));
    /* The rekey's response and the peer's data after it do not end it:
     * back to direct only on a re-probe's pong. */
    wg_path_on_handshake(&p, pong + MS(60));
    wg_path_on_peer_data(&p, pong + MS(70));
    ok("silent/stays-relay", p.mode == WG_PATH_RELAY);
    const int64_t rp = pong + MS(WG_PATH_REPROBE_MIN_MS);
    ok("silent/reprobe-deadline", wg_path_next_deadline(&p) == rp);
    ok("silent/reprobe", wg_path_tick(&p, rp - 1) == 0 &&
                         wg_path_tick(&p, rp) == (WG_PATH_ACT_PING | WG_PATH_ACT_PROBE));
    ok("silent/reconfirm",
       wg_path_on_pong(&p, rp + MS(50), 50000, true, 0, 0, false, false, &act) ==
       WG_PATH_PONG_CONFIRMED && act == 0 && p.mode == WG_PATH_DIRECT && p.confirms == 2);

    /* Silent again with no keepalive in between: the fresh session did not
     * help — no second rekey, the re-probe backs off: 20, 40, 60, 60 s. */
    int64_t t = rp + S(1);
    int good = 1;
    const uint32_t want_ms[] = { 20000, 40000, 60000, 60000 };
    for (int i = 0; i < 4; i++) {
        (void)send_data(&p, t, &m);
        const int64_t l = t + MS(WG_PATH_ANSWER_MS) + 1;
        good &= wg_path_tick(&p, l) == WG_PATH_ACT_PING;
        good &= wg_path_on_pong(&p, l + MS(80), 80000, true, 0, 0, false, false, &act) ==
                WG_PATH_PONG_SILENT;
        good &= act == WG_PATH_ACT_RESCUE;
        good &= p.reprobe_ms == want_ms[i] && p.reprobe_us == l + MS(80) + MS(want_ms[i]);
        confirm_at(&p, l + S(1), 50000);        /* a probe's pong, say */
        t = l + S(2);
    }
    ok("silent/streak-backs-off", good && p.silences == 5);
    /* A keepalive on DIRECT ends the streak: the next silence rekeys. */
    (void)send_data(&p, t, &m);
    wg_path_on_keepalive(&p, t + S(10));
    ok("silent/ka-ends-streak", p.silent_streak == 0);
    t += S(11);
    (void)send_data(&p, t, &m);
    (void)wg_path_tick(&p, t + MS(WG_PATH_ANSWER_MS) + 1);
    ok("silent/rekeys-again",
       wg_path_on_pong(&p, t + MS(WG_PATH_ANSWER_MS) + MS(90), 90000, true, 0, 0,
                       false, false, &act) == WG_PATH_PONG_SILENT &&
       act == (WG_PATH_ACT_RESCUE | WG_PATH_ACT_REKEY) && p.reprobe_ms == WG_PATH_REPROBE_MIN_MS);

    /* Not silent: anything authenticated from the peer since the frame —
     * a keepalive late past the window, its data (a peer that streams to
     * us sends no keepalives), a handshake. */
    for (int k = 0; k < 3; k++) {
        wg_path_init(&p, T0, true);
        confirm_at(&p, T0, 50000);
        (void)send_data(&p, s1, &m);
        (void)wg_path_tick(&p, lapse);
        if (k == 0) wg_path_on_keepalive(&p, lapse + MS(40));
        if (k == 1) wg_path_on_peer_data(&p, s1 + S(4));
        if (k == 2) wg_path_on_handshake(&p, lapse + MS(40));
        good = wg_path_on_pong(&p, pong, 80000, true, 0, 0, false, false, &act) ==
               WG_PATH_PONG_CONFIRMED && act == 0 && p.mode == WG_PATH_DIRECT &&
               p.silences == 0;
        ok(k == 0 ? "silent/not-late-ka" : k == 1 ? "silent/not-peer-data"
                                                  : "silent/not-handshake", good);
    }
    /* Nor a lapse that awaited no answer: the first frame after a pause
     * (the peer had nothing to answer), the start, a roam. */
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    const int64_t late = T0 + MS(WG_PATH_ANSWER_MS) + S(5);
    ok("silent/not-idle", send_data(&p, late, &m) == WG_PATH_ACT_PING &&
                          p.why == WG_PATH_WHY_IDLE &&
                          wg_path_on_pong(&p, late + MS(80), 80000, true, 0, 0, false,
                                          false, &act) == WG_PATH_PONG_CONFIRMED);
    wg_path_init(&p, T0, true);
    (void)send_data(&p, T0 + S(1), &m);
    ok("silent/not-start", wg_path_on_pong(&p, T0 + S(20), 80000, true, 0, 0, false,
                                           false, &act) == WG_PATH_PONG_CONFIRMED);
    (void)wg_path_on_endpoint_change(&p, T0 + S(21));
    ok("silent/not-endpoint", wg_path_on_pong(&p, T0 + S(40), 80000, true, 0, 0, false,
                                              false, &act) == WG_PATH_PONG_CONFIRMED);
    /* Another endpoint's pong is not the current one answering. */
    wg_path_init(&p, T0, true);
    confirm_at(&p, T0, 50000);
    (void)send_data(&p, s1, &m);
    (void)wg_path_tick(&p, lapse);
    ok("silent/other-roams",
       wg_path_on_pong(&p, pong, 80000, false, EP_A, 24759, false, false, &act) ==
       WG_PATH_PONG_ROAM && act == WG_PATH_ACT_RESCUE && p.silences == 0);
    /* The counter survives a DiscoKey arriving late. */
    p.silences = 7;
    wg_path_set_managed(&p, pong + 1, false);
    wg_path_set_managed(&p, pong + 2, true);
    ok("silent/counter-kept", p.silences == 7 && p.silent_streak == 0);
}

static void test_unmanaged(void)
{
    wg_path_t p;
    wg_path_mode_t m;
    wg_path_init(&p, T0, false);
    ok("unmanaged/direct", wg_path_on_send(&p, T0, true, &m) == 0 && m == WG_PATH_DIRECT);
    ok("unmanaged/no-timers", wg_path_tick(&p, T0 + S(100)) == 0 &&
                              wg_path_next_deadline(&p) == INT64_MAX);
    ok("unmanaged/roams", wg_path_may_roam(&p, T0));
    wg_path_set_managed(&p, T0 + S(5), true);
    ok("unmanaged/then-managed", p.managed && p.mode == WG_PATH_DUAL &&
                                 wg_path_tick(&p, T0 + S(5)) == WG_PATH_ACT_PING);
}

/* Every mode: the deadline is the first instant tick acts. */
static void test_deadline_agrees(void)
{
    int good = 1;
    for (int mode = 0; mode < 4; mode++) {
        wg_path_t p;
        wg_path_mode_t m;
        wg_path_init(&p, T0, true);
        if (mode == 0) { confirm_at(&p, T0, 1); (void)wg_path_on_send(&p, T0 + 7, true, &m); }
        if (mode == 1) { (void)wg_path_tick(&p, T0 + 3); }
        if (mode == 2) {
            (void)wg_path_tick(&p, T0);
            (void)wg_path_on_send(&p, T0 + 1, true, &m);
            (void)wg_path_tick(&p, T0 + MS(WG_PATH_PING_TIMEOUT_MS) + 1);
        }
        if (mode == 3) {                        /* RELAY on a WG-silent pong */
            confirm_at(&p, T0, 1);
            (void)wg_path_on_send(&p, T0 + 7, true, &m);
            (void)wg_path_tick(&p, T0 + 7 + MS(WG_PATH_ANSWER_MS) + 1);
            (void)wg_path_on_pong(&p, T0 + S(13), 1, true, 0, 0, false, false, NULL);
            good &= p.why == WG_PATH_WHY_SILENT;
        }
        const int64_t dl = wg_path_next_deadline(&p);
        wg_path_t q = p;
        good &= dl != INT64_MAX;
        good &= wg_path_tick(&q, dl - 1) == 0;
        q = p;
        good &= wg_path_tick(&q, dl) != 0;
    }
    ok("deadline/tick-agrees", good);
}

static void test_init_fresh(void)
{
    /* The 1.3.5 bound (1 s) replaced INITs whose answers were still in
     * flight; at 2.5 s an answer 1–2.5 s late finds its INIT. */
    ok("init/young-resend", !wg_init_fresh_due(S(10) + MS(1500), S(10)));
    ok("init/edge", !wg_init_fresh_due(S(10) + MS(WG_INIT_FRESH_AFTER_MS), S(10)));
    ok("init/old-fresh", wg_init_fresh_due(S(10) + MS(WG_INIT_FRESH_AFTER_MS) + 1, S(10)));
    ok("init/below-rekey-timeout", WG_INIT_FRESH_AFTER_MS < 5000);
}

/* ---------------------------------------------------------------------
 * Simulation: the sensor (this module + the RX task's timer passes) and
 * its peer (wireguard-go's keepalive timer) over configurable paths. */

static uint64_t s_rng = 0x2545F4914F6CDD1DULL;
static uint32_t rnd(uint32_t n)
{
    s_rng ^= s_rng << 13; s_rng ^= s_rng >> 7; s_rng ^= s_rng << 17;
    return (uint32_t)(s_rng % n);
}

typedef enum {
    EV_TELEMETRY, EV_REKEY,
    EV_PEER_GOT_DATA, EV_PEER_GOT_INIT, EV_PEER_GOT_PING, EV_PEER_CHAT,
    EV_US_GOT_KA, EV_US_GOT_DATA, EV_US_GOT_RESP, EV_US_GOT_PONG,
} ev_kind_t;

/* arg — EV_US_GOT_KA / _DATA / _RESP: the source, 0 = via DERP, 1 + the
 * peer endpoint it came from if direct; pings and pongs: the ping's time
 * in ms since T0, times 2, plus the endpoint pinged. */
typedef struct { int64_t t; ev_kind_t k; int arg; } ev_t;

typedef struct {
    /* paths, by time: the direct path to endpoint 0 */
    int64_t up_dead_at, up_heal_at;     /* us → peer */
    int64_t down_dead_at, down_heal_at; /* peer → us */
    int64_t rebind_at;                  /* the peer's NAT moves to endpoint 1 */
    int64_t wg_dead_at;                 /* the peer's session breaks: it drops our
                                           transport, sends none, answers DISCO —
                                           until an INIT from us (the 1.3.5 soak) */
    int64_t wg_block_at;                /* WireGuard dropped on the direct path,
                                           both ways, DISCO passes (DPI-like) */
    bool    peer_chatty;                /* peer sends data every second */
    bool    peer_advert;                /* TSMP advert on every new keypair */
    int64_t end;
    /* results */
    uint32_t frames, lost, lost_after_break, derp_copies, direct_after_relay;
    uint32_t pings, probes, lapses, deaths, confirms, roams;
    uint32_t rescued, rescue_copies;    /* lost frames re-sent / all re-sent */
    int64_t  rescue_delay_max;
    int64_t  lapse_after_break;         /* first lapse at or after the break; 0 none */
    int64_t  direct_again_at;           /* first DIRECT after the heal / rebind */
    int      final_ep;
    uint32_t silences, forced_rekeys;
    int64_t  silent_at;                 /* first WG-silent pong after the break */
    int64_t  silent_after_rx;           /* ...after the peer's last WG packet */
    int64_t  direct_after_silent;       /* first DIRECT after it */
    bool     wg_fixed;                  /* runtime: the peer got an INIT since */
} sim_t;

/* Our direct-only frames of the last WG_PATH_RESCUE_MS (wg_netif keeps
 * the wire bytes; here only whether the frame got through). */
#define RESCUE_N 8
typedef struct { int64_t t; bool lost; bool dead_keys; } sent_t;
static sent_t s_sent[RESCUE_N];
static int    s_sent_head;
static int    s_cur;                    /* our current endpoint, 0 or 1 */

#define MAXEV 256
static ev_t s_q[MAXEV];
static int  s_n;

static void push(int64_t t, ev_kind_t k, int arg)
{
    if (s_n < MAXEV) s_q[s_n++] = (ev_t){ t, k, arg };
}

static bool pop(ev_t *out)
{
    if (s_n == 0) return false;
    int b = 0;
    for (int i = 1; i < s_n; i++) if (s_q[i].t < s_q[b].t) b = i;
    *out = s_q[b];
    s_q[b] = s_q[--s_n];
    return true;
}

/* Does a datagram from us to endpoint `ep` arrive? */
static bool up_ok(const sim_t *s, int64_t t, int ep)
{
    if (ep == 1) return t >= s->rebind_at;
    if (t >= s->rebind_at) return false;
    return !(t >= s->up_dead_at && t < s->up_heal_at);
}
/* Does the peer's direct datagram reach us (from its current mapping)? */
static bool down_ok(const sim_t *s, int64_t t)
{
    return !(t >= s->down_dead_at && t < s->down_heal_at);
}
static int peer_ep(const sim_t *s, int64_t t) { return t >= s->rebind_at ? 1 : 0; }

static int64_t one_way(void) { return MS(20 + rnd(130)); }        /* 20–150 ms */
static int64_t derp_way(void) { return MS(60 + rnd(200)); }       /* 60–260 ms */
static int64_t dtim(void) { return MS(rnd(300)); }                /* modem sleep */

/* The peer's session is broken (wg_dead_at, no INIT since). */
static bool wg_broken(const sim_t *s, int64_t t)
{
    return t >= s->wg_dead_at && !s->wg_fixed;
}

/* Peer → us (WireGuard): direct if it works, else DERP (the peer's own
 * path choice — DISCO passing, it keeps a WG-blocked path). */
static void peer_send(const sim_t *s, int64_t t, ev_kind_t k)
{
    const bool direct = down_ok(s, t);
    if (direct && t >= s->wg_block_at) return;
    push(t + (direct ? one_way() : derp_way()) + dtim(), k,
         direct ? 1 + peer_ep(s, t) : 0);
}

static void sim_ping(sim_t *s, int64_t t, int ep)
{
    s->pings++;
    if (up_ok(s, t, ep)) push(t + one_way(), EV_PEER_GOT_PING, (int)((t - T0) / 1000) * 2 + ep);
}

/* An authenticated packet from `arg`: roam there unless the current
 * endpoint is valid (wg_netif's handle_transport / response roam). */
static uint32_t sim_from(sim_t *s, wg_path_t *p, int64_t t, int arg)
{
    if (arg == 0 || arg - 1 == s_cur || !wg_path_may_roam(p, t)) return 0;
    s_cur = arg - 1;
    s->roams++;
    return wg_path_on_endpoint_change(p, t);
}

/* An INIT from us: direct, plus DERP unless the path is valid. */
static bool sim_init(const sim_t *s, wg_path_t *p, int64_t t)
{
    const bool relay = wg_path_init_wants_relay(p, t);
    const bool direct = up_ok(s, t, s_cur) && t < s->wg_block_at;
    if (!direct && !relay) return false;
    push(t + (direct ? one_way() : derp_way()), EV_PEER_GOT_INIT, 0);
    return true;
}

/* The lapse's re-send: every frame of the window goes via DERP; the
 * peer's replay window drops the ones it has, the lost ones arrive —
 * unless the peer lost the keys they are sealed with. */
static void sim_rescue(sim_t *s, int64_t t, int64_t break_at)
{
    for (int i = 0; i < RESCUE_N; i++) {
        if (s_sent[i].t == 0 || wg_timer_due(t, s_sent[i].t, MS(WG_PATH_RESCUE_MS))) continue;
        s->rescue_copies++;
        if (s_sent[i].lost && !s_sent[i].dead_keys) {
            s->rescued++;
            s->lost--;
            if (s_sent[i].t >= break_at) s->lost_after_break--;
            if (t - s_sent[i].t > s->rescue_delay_max) s->rescue_delay_max = t - s_sent[i].t;
            push(t + derp_way(), EV_PEER_GOT_DATA, 0);
        }
        s_sent[i].t = 0;
    }
}

typedef struct {
    bool ka_pending;
    int64_t ka_at;
    bool new_keypair;     /* advert owed on the first data under it */
} peer_t;

static void run_sim(sim_t *s)
{
    wg_path_t p;
    peer_t peer = { 0 };
    s_n = 0;
    s_cur = 0;
    int64_t t = T0;
    wg_path_init(&p, t, true);
    int64_t break_at = s->up_dead_at < s->down_dead_at ? s->up_dead_at : s->down_dead_at;
    if (s->rebind_at < break_at) break_at = s->rebind_at;
    if (s->wg_dead_at < break_at) break_at = s->wg_dead_at;
    if (s->wg_block_at < break_at) break_at = s->wg_block_at;
    const int64_t heal_at = s->rebind_at != INT64_MAX ? s->rebind_at
                          : (s->up_heal_at > s->down_heal_at ? s->up_heal_at : s->down_heal_at);
    s->lapse_after_break = 0;
    s->direct_again_at = 0;
    s->silent_at = s->silent_after_rx = s->direct_after_silent = 0;
    s->forced_rekeys = 0;
    s->wg_fixed = false;
    int64_t last_rx = t;                        /* the peer's last WG packet */
    memset(s_sent, 0, sizeof(s_sent));
    s_sent_head = 0;
    push(t + S(1), EV_TELEMETRY, 0);
    push(t + S(110), EV_REKEY, 0);
    if (s->peer_chatty) push(t + S(1), EV_PEER_CHAT, 0);
    bool relayed_once = false;
    ev_t e = { 0, EV_TELEMETRY, 0 };

    for (;;) {
        /* RX-task timer pass at its deadline (wakes at most 5 s apart). */
        const int64_t dl = wg_path_next_deadline(&p);
        int64_t q_min = INT64_MAX;
        for (int i = 0; i < s_n; i++) if (s_q[i].t < q_min) q_min = s_q[i].t;
        int64_t next_tick = dl < t + S(5) ? dl : t + S(5);
        if (next_tick < t) next_tick = t;
        if (peer.ka_pending && peer.ka_at < q_min) q_min = peer.ka_at;
        if (q_min > s->end && next_tick > s->end) break;
        uint32_t act = 0;
        const uint32_t lapses0 = p.lapses;
        const uint32_t silences0 = p.silences;
        if (next_tick <= q_min) {
            t = next_tick;
            act = wg_path_tick(&p, t);
            if (act == 0 && dl <= t) {          /* deadline without an action: spin */
                printf("  sim: deadline %lld without action\n", (long long)dl);
                fails++;
                break;
            }
        } else if (peer.ka_pending && peer.ka_at == q_min) {
            t = q_min;
            peer.ka_pending = false;              /* the keepalive is a send */
            if (!wg_broken(s, t)) peer_send(s, t, EV_US_GOT_KA);
            continue;
        } else {
            if (!pop(&e)) break;
            t = e.t;
            switch (e.k) {
            case EV_TELEMETRY: {
                wg_path_mode_t m;
                act = wg_path_on_send(&p, t, true, &m);
                s->frames++;
                const bool direct = m != WG_PATH_RELAY;
                const bool derp   = m != WG_PATH_DIRECT;
                if (derp) s->derp_copies++;
                if (m == WG_PATH_RELAY) relayed_once = true;
                if (relayed_once && direct && m == WG_PATH_DUAL && t < heal_at) {
                    s->direct_after_relay++;
                }
                const bool via_direct = direct && up_ok(s, t, s_cur) && t < s->wg_block_at;
                const bool keys = !wg_broken(s, t);
                if (keys && (via_direct || derp)) {
                    push(t + (via_direct ? one_way() : derp_way()), EV_PEER_GOT_DATA, 0);
                } else {
                    s->lost++;
                    if (t >= break_at) s->lost_after_break++;
                }
                if (m == WG_PATH_DIRECT) {
                    s_sent[s_sent_head] = (sent_t){ t, !(keys && via_direct), !keys };
                    s_sent_head = (s_sent_head + 1) % RESCUE_N;
                }
                push(t + S(5) + MS(rnd(500)) - MS(250), EV_TELEMETRY, 0);
                break;
            }
            case EV_REKEY:                        /* else the REKEY_TIMEOUT retry */
                push(t + (sim_init(s, &p, t) ? S(110) : S(5)), EV_REKEY, 0);
                break;
            case EV_PEER_GOT_INIT:
                if (t >= s->wg_dead_at) s->wg_fixed = true;
                peer.ka_pending = false;          /* the response is a send */
                peer.new_keypair = true;
                peer_send(s, t, EV_US_GOT_RESP);
                break;
            case EV_US_GOT_RESP: {
                last_rx = t;
                wg_path_on_handshake(&p, t);
                act = sim_from(s, &p, t, e.arg);
                /* Our TSMP advert: data under the new keys at once. */
                wg_path_mode_t m;
                act |= wg_path_on_send(&p, t, true, &m);
                const bool via_direct = m != WG_PATH_RELAY && up_ok(s, t, s_cur) &&
                                        t < s->wg_block_at;
                if (via_direct || m != WG_PATH_DIRECT) {
                    push(t + (via_direct ? one_way() : derp_way()), EV_PEER_GOT_DATA, 0);
                }
                break;
            }
            case EV_PEER_GOT_DATA:
                if (!peer.ka_pending) { peer.ka_pending = true; peer.ka_at = t + S(10); }
                if (peer.new_keypair && s->peer_advert) {
                    peer.new_keypair = false;
                    peer.ka_pending = false;      /* its advert is a send */
                    peer_send(s, t, EV_US_GOT_DATA);
                }
                break;
            case EV_PEER_CHAT:
                peer.ka_pending = false;
                peer_send(s, t, EV_US_GOT_DATA);
                push(t + S(1), EV_PEER_CHAT, 0);
                break;
            case EV_PEER_GOT_PING:
                /* The pong leaves by the mapping that was pinged. */
                if (down_ok(s, t)) push(t + one_way() + dtim(), EV_US_GOT_PONG, e.arg);
                break;
            case EV_US_GOT_KA:
                last_rx = t;
                wg_path_on_keepalive(&p, t);
                act = sim_from(s, &p, t, e.arg);
                break;
            case EV_US_GOT_DATA:
                last_rx = t;
                wg_path_on_peer_data(&p, t);
                act = sim_from(s, &p, t, e.arg);
                break;
            case EV_US_GOT_PONG: {
                const int ep = e.arg & 1;
                const int64_t sent = T0 + MS(e.arg / 2);
                uint32_t pact = 0;
                const wg_path_pong_t r = wg_path_on_pong(
                    &p, t, (uint32_t)(t - sent), ep == s_cur,
                    EP_A + (uint32_t)ep, (uint16_t)(41641 + ep), false, false, &pact);
                if (r == WG_PATH_PONG_ROAM) { s_cur = ep; s->roams++; }
                if (r == WG_PATH_PONG_ROAM_CAND) { s_cur = (int)(p.cand_v4_be - EP_A); s->roams++; }
                act = pact;
                if (t >= heal_at && p.mode == WG_PATH_DIRECT && s->direct_again_at == 0) {
                    s->direct_again_at = t;
                }
                if (s->silent_at != 0 && p.mode == WG_PATH_DIRECT &&
                    s->direct_after_silent == 0) {
                    s->direct_after_silent = t;
                }
                break;
            }
            default: break;
            }
        }
        if (p.lapses != lapses0 && t >= break_at && s->lapse_after_break == 0) {
            s->lapse_after_break = t;
        }
        if (p.silences != silences0 && t >= break_at && s->silent_at == 0) {
            s->silent_at = t;
            s->silent_after_rx = t - last_rx;
        }
        if (act & WG_PATH_ACT_REKEY) {          /* wg_netif: unless one is in flight */
            s->forced_rekeys++;
            (void)sim_init(s, &p, t);
        }
        if (act & WG_PATH_ACT_RESCUE) sim_rescue(s, t, break_at);
        if (act & WG_PATH_ACT_PING) sim_ping(s, t, s_cur);
        if (act & WG_PATH_ACT_PROBE) {          /* every endpoint the netmap lists */
            s->probes++;
            sim_ping(s, t, 0);
            if (s->rebind_at != INT64_MAX && t >= s->rebind_at) sim_ping(s, t, 1);
        }
    }
    s->lapses   = p.lapses;
    s->deaths   = p.deaths;
    s->confirms = p.confirms;
    s->silences = p.silences;
    s->final_ep = s_cur;
}

static sim_t sim_base(void)
{
    sim_t s = { 0 };
    s.up_dead_at = s.down_dead_at = INT64_MAX;
    s.up_heal_at = s.down_heal_at = INT64_MAX;
    s.rebind_at = INT64_MAX;
    s.wg_dead_at = s.wg_block_at = INT64_MAX;
    s.peer_advert = true;
    s.end = T0 + S(6 * 3600);
    return s;
}

static void test_sim(void)
{
    /* Healthy, 6 h: one confirm at start, then nothing extra. */
    sim_t s = sim_base();
    run_sim(&s);
    printf("  healthy 6 h: frames=%u lost=%u lapses=%u pings=%u derp=%u rescue copies=%u\n",
           s.frames, s.lost, s.lapses, s.pings, s.derp_copies, s.rescue_copies);
    ok("sim/healthy-no-lapse", s.lapses == 0 && s.deaths == 0 && s.confirms == 1);
    ok("sim/healthy-one-ping", s.pings == 1);
    ok("sim/healthy-no-loss", s.lost == 0);
    ok("sim/healthy-no-derp", s.derp_copies <= 1 && s.rescue_copies == 0);
    ok("sim/healthy-no-rekey", s.silences == 0 && s.forced_rekeys == 0);

    /* Same without the peer's advert (older tailscaled): still nothing. */
    s = sim_base();
    s.peer_advert = false;
    run_sim(&s);
    ok("sim/healthy-no-advert", s.lapses == 0 && s.pings == 1 && s.lost == 0);

    /* Both directions die at 1 h, for good. */
    s = sim_base();
    s.up_dead_at = s.down_dead_at = T0 + S(3600);
    s.end = T0 + S(3600 + 1800);
    run_sim(&s);
    const int64_t fo = s.lapse_after_break - s.up_dead_at;
    printf("  dead both ways: lapse %.1f s after the break, %u frames re-sent late "
           "(max %.1f s), %u lost; probes=%u pings=%u, direct copies after RELAY=%u\n",
           fo / 1e6, s.rescued, s.rescue_delay_max / 1e6, s.lost_after_break,
           s.probes, s.pings, s.direct_after_relay);
    ok("sim/dead-no-loss", s.lost_after_break == 0 && s.rescued >= 1);
    /* The lapse comes 12 s after the first unanswered frame, which a
     * keepalive in flight can push one period past the break. */
    ok("sim/dead-lapse", fo > 0 && fo <= MS(WG_PATH_ANSWER_MS) + S(17));
    ok("sim/dead-relay", s.deaths == 1 && s.direct_after_relay == 0);
    /* 30 min of RELAY: back-off to one probe round a minute. */
    ok("sim/dead-reprobe-rate", s.probes >= 25 && s.probes <= 40);

    /* One-way: us -> peer dies, peer -> us keeps working. The peer gets
     * nothing, sends nothing; our pings never arrive. */
    s = sim_base();
    s.up_dead_at = T0 + S(3600);
    s.end = T0 + S(3600 + 1800);
    run_sim(&s);
    const int64_t fo1 = s.lapse_after_break - s.up_dead_at;
    printf("  one-way (us->peer dead): lapse %.1f s after, %u re-sent, %u lost, confirms=%u\n",
           fo1 / 1e6, s.rescued, s.lost_after_break, s.confirms);
    ok("sim/oneway-no-loss", s.lost_after_break == 0);
    ok("sim/oneway-lapse", fo1 > 0 && fo1 <= MS(WG_PATH_ANSWER_MS) + S(17));
    ok("sim/oneway-never-direct", s.confirms == 1 && s.deaths == 1);

    /* One-way with a peer that streams data to us every second (its data
     * proves nothing; no keepalives at all): DIRECT only between pongs. */
    s = sim_base();
    s.peer_chatty = true;
    s.up_dead_at = T0 + S(3600);
    s.end = T0 + S(3600 + 600);
    run_sim(&s);
    printf("  one-way + chatty peer: %u lost, %u lapses in the healthy hour "
           "(one ping each), %u frames re-sent in all\n",
           s.lost_after_break, s.lapses - 1, s.rescue_copies);
    ok("sim/chatty-oneway-no-loss", s.lost_after_break == 0);
    ok("sim/chatty-oneway-relay", s.deaths >= 1);
    ok("sim/chatty-no-rescue-bursts", s.rescue_copies <= RESCUE_N * s.deaths);
    ok("sim/chatty-no-rekey", s.silences == 0 && s.forced_rekeys == 0);

    /* Reverse one-way: peer -> us dies; our direct sends still arrive and
     * the peer's keepalives come by DERP — we stay direct. */
    s = sim_base();
    s.down_dead_at = T0 + S(3600);
    s.end = T0 + S(7200);
    run_sim(&s);
    ok("sim/reverse-oneway-stays-direct", s.lapses == 0 && s.lost == 0);

    /* Outage then heal: back to DIRECT within a re-probe interval. */
    s = sim_base();
    s.up_dead_at = s.down_dead_at = T0 + S(3600);
    s.up_heal_at = s.down_heal_at = T0 + S(3600 + 600);
    s.end = T0 + S(3600 + 900);
    run_sim(&s);
    const int64_t back = s.direct_again_at - s.up_heal_at;
    printf("  heal after 10 min: direct again %.1f s later, %u lost\n",
           back / 1e6, s.lost_after_break);
    ok("sim/heal-direct", s.direct_again_at != 0 && back <= MS(WG_PATH_REPROBE_MAX_MS) + S(1));
    ok("sim/heal-no-loss", s.lost_after_break == 0);

    /* The peer's NAT rebinds: the old endpoint dies both ways, the peer's
     * packets come from a new one (listed by the netmap). Its packets do
     * not move a valid endpoint; once the old one lapsed and failed its
     * ping, the probe finds the new one. */
    s = sim_base();
    s.rebind_at = T0 + S(3600);
    s.end = T0 + S(3600 + 600);
    run_sim(&s);
    printf("  peer NAT rebind: lapse %.1f s after, direct on the new endpoint "
           "%.1f s after, %u lost, %u re-sent, roams=%u\n",
           (s.lapse_after_break - s.rebind_at) / 1e6,
           (s.direct_again_at - s.rebind_at) / 1e6, s.lost_after_break, s.rescued, s.roams);
    ok("sim/rebind-moves", s.final_ep == 1 && s.direct_again_at != 0 &&
                           s.direct_again_at - s.rebind_at <= MS(WG_PATH_ANSWER_MS) + S(25));
    ok("sim/rebind-no-loss", s.lost_after_break == 0);
    ok("sim/rebind-one-roam", s.roams == 1);

    /* The 1.3.5 soak: the peer's session breaks — nothing from it by any
     * path, DISCO answered — until it gets an INIT (there the RX-stale
     * rekey at 30 s, answered in 60 ms). Between two proactive rekeys. */
    s = sim_base();
    s.wg_dead_at = T0 + S(3525);
    s.end = T0 + S(3525 + 600);
    run_sim(&s);
    printf("  WG silent, DISCO alive: rekey %.1f s after the break (%.1f s after "
           "the peer's last packet), direct again %.1f s later; %u lost "
           "(sealed with the dead keys), silences=%u rekeys=%u\n",
           (s.silent_at - s.wg_dead_at) / 1e6, s.silent_after_rx / 1e6,
           (s.direct_after_silent - s.silent_at) / 1e6, s.lost_after_break,
           s.silences, s.forced_rekeys);
    ok("sim/silent-rekeys", s.silences == 1 && s.forced_rekeys == 1 && s.deaths == 0);
    ok("sim/silent-fast", s.silent_after_rx > 0 &&
                          s.silent_after_rx <= MS(WG_PATH_ANSWER_MS) + S(6));
    ok("sim/silent-direct-again", s.direct_after_silent != 0 &&
                                  s.direct_after_silent - s.silent_at <=
                                  MS(WG_PATH_REPROBE_MIN_MS) + S(1));
    ok("sim/silent-then-healthy", s.lapses == 1 && s.lost_after_break <= 6);

    /* ...at random instants: the rekey within the 12-s window plus a
     * telemetry period of the peer's last packet; the frames lost are the
     * ones sealed before it (1.3.5: until 30 s after that packet). */
    int64_t sworst = 0, ssum = 0, sbrk_worst = 0;
    uint32_t slost = 0, slost_worst = 0, sn = 0;
    int sgood = 1;
    for (int trial = 0; trial < 100; trial++) {
        s = sim_base();
        const int64_t brk = T0 + S(552) + MS((trial * 7919) % 40000);
        s.wg_dead_at = brk;
        s.end = brk + S(90);
        run_sim(&s);
        sgood &= s.silences == 1 && s.forced_rekeys == 1;
        if (s.silent_after_rx > sworst) sworst = s.silent_after_rx;
        if (s.silent_at - brk > sbrk_worst) sbrk_worst = s.silent_at - brk;
        ssum += s.silent_after_rx;
        slost += s.lost_after_break;
        if (s.lost_after_break > slost_worst) slost_worst = s.lost_after_break;
        sn++;
    }
    printf("  100 random WG-silent breaks: rekey mean %.1f s, max %.1f s after the "
           "peer's last packet (max %.1f s after the break); lost mean %.1f, max %u\n",
           ssum / 1e6 / sn, sworst / 1e6, sbrk_worst / 1e6, (double)slost / sn, slost_worst);
    ok("sim/silent-random-rekey", sgood);
    ok("sim/silent-random-bounded", sworst <= MS(WG_PATH_ANSWER_MS) + S(6));

    /* WireGuard dropped on the direct path both ways, DISCO passing (a
     * DPI box): the first silence rekeys, the fresh session is silent
     * too; DERP carries everything, the direct re-tests back off. */
    s = sim_base();
    s.wg_block_at = T0 + S(3600);
    s.end = T0 + S(3600 + 3600);
    run_sim(&s);
    printf("  WG blocked on direct, DISCO passes, 1 h: %u lost, %u re-sent, "
           "silences=%u rekeys=%u pings=%u\n",
           s.lost_after_break, s.rescued, s.silences, s.forced_rekeys, s.pings);
    ok("sim/blocked-no-loss", s.lost_after_break == 0);
    ok("sim/blocked-one-rekey", s.forced_rekeys == 1);
    ok("sim/blocked-backs-off", s.silences >= 40 && s.silences <= 60);

    /* Random break instants, both ways and one way: never a frame lost,
     * and the worst lapse delay. */
    int64_t worst = 0, sum = 0;
    uint32_t lost = 0, n = 0;
    for (int trial = 0; trial < 200; trial++) {
        s = sim_base();
        const int64_t brk = T0 + S(600) + MS((trial * 7919) % 60000);
        s.up_dead_at = brk;
        if (trial & 1) s.down_dead_at = brk;
        s.end = brk + S(90);
        run_sim(&s);
        const int64_t d = s.lapse_after_break - brk;
        if (d > worst) worst = d;
        sum += d;
        lost += s.lost_after_break;
        n++;
    }
    printf("  200 random breaks: lapse mean %.1f s, max %.1f s, %u frames lost\n",
           sum / 1e6 / n, worst / 1e6, lost);
    ok("sim/random-breaks-no-loss", lost == 0);
    ok("sim/random-breaks-bounded", worst <= MS(WG_PATH_ANSWER_MS) + S(17));
}

int main(void)
{
    test_private();
    test_better();
    test_start_dual_relay();
    test_answer_window();
    test_one_way_rules();
    test_idle();
    test_relay_reprobe();
    test_flapping();
    test_endpoint_change();
    test_lapse_resolution();
    test_silent();
    test_unmanaged();
    test_deadline_agrees();
    test_init_fresh();
    test_sim();
    if (fails) {
        printf("test_wg_path: %d FAIL\n", fails);
        return 1;
    }
    printf("test_wg_path: all OK\n");
    return 0;
}
