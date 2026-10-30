// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Data-plane path selection for the WG peer (round 1.3.6): which way the
// next frame goes — direct UDP only, direct + DERP, or DERP only — when
// to ask for proof with a DISCO ping, and when a pong may move the
// endpoint. Header-only and platform-free; wg_netif.c calls it under
// g.lock and does the I/O, tools/test/test_wg_path.c drives it in time.
//
// Until 1.3.5 the direct path counted as confirmed by ANY authenticated
// datagram on the UDP socket and stayed so for the 30-s RX-stale window.
// On the sensor (2026-10-29) the collector sat behind another WAN link
// for ~1 h: after each rekey via DERP one direct transport packet arrived
// ("direct path confirmed (transport)"), the DERP copies stopped, and
// nothing we sent direct reached the peer — 42 RX-stale events in 47 min,
// each ~30 s of telemetry lost (seen direct=0 derp=0: the peer, getting
// nothing, sent nothing). A packet FROM the peer proves peer→us only.
//
// Modes (upstream magicsock: bestAddr trusted / untrusted / cleared):
//
//   DUAL    unconfirmed: every frame direct AND via DERP. At start, after
//           a lapse, after a roam to an address no pong has proven.
//   DIRECT  confirmed: direct only. Entered ONLY on a pong to our ping
//           (txid + source bound by disco_prober: a round trip on that
//           address pair). Kept while the peer keeps answering our data.
//   RELAY   the current endpoint failed a ping, or answered it while
//           WireGuard stayed silent: DERP only, re-probed.
//
//        +-- pong (from the current endpoint, or any: roam) --+
//        v                                                    |
//     DIRECT --lapse--> DUAL --no pong in PING_TIMEOUT--> RELAY
//        ^                |   --pong, but WG silent ----->    |
//        +-----pong-------+<------- endpoint change ----------+
//
// What keeps DIRECT without extra packets: WireGuard's passive keepalive
// (whitepaper §6.5). A peer that receives a data packet and has nothing
// to send for KEEPALIVE_TIMEOUT (10 s) sends a keepalive; tailscaled
// configures no persistent keepalive, so a keepalive from it answers data
// it received — data that went direct only, since DIRECT sends nothing
// via DERP. Hence the answer window: the first data frame sent after the
// last proof must be answered within KEEPALIVE_TIMEOUT + slack, else the
// path lapses (→ DUAL + one ping). A keepalive arriving by either path
// counts (the peer's way back to us is its own choice). The peer's own
// data proves nothing about our sends — a one-way path (peer→us works,
// us→peer dead) delivers it too — so only keepalives and pongs renew.
// Upstream instead pings bestAddr every heartbeatInterval (3 s) while
// the session is active and trusts it for trustUDPAddrDuration (6.5 s):
// 20 pings + 20 pongs a minute per side. Here the steady state costs
// none (the test simulates hours of it); a lapse costs one ping. The
// price is detection latency — a keepalive answers a frame ~10 s old —
// paid back by re-sending, once a lapse is confirmed, the direct-only
// frames that may have been lost (WG_PATH_RESCUE_MS).
//
// Exceptions handled: the peer's handshake response and its first data
// packet after a handshake (the capver-144 TSMP disco advert on every new
// keypair) each cancel its pending keepalive (wireguard-go deletes the
// timer on any authenticated send) — both restart the window once per
// handshake, so a rekey every 110 s does not look like a dead path. After
// a pause in our data (no frame for a window, no proof for a window) the
// first frame goes DUAL with a ping, as magicsock sends to both once its
// trust expired. A keepalive triggered by a DUAL frame sent just before
// the pong that entered DIRECT counts too: it extends DIRECT by at most
// one window, once.
//
// A pong proves the address pair, not the WireGuard session. In the 1.3.5
// soak (peer healthy) a CallMeMaybe round moved the endpoint twice, then
// for 30 s not one WG packet came by either path (seen direct=0 derp=0)
// while the peer answered DISCO; the RX-stale rekey at 30 s fixed it in
// 60 ms. So when the pong answering a lapse of our data comes from the
// current endpoint but nothing authenticated came from the peer since
// the unanswered frame — no keepalive, no data, no handshake: a late
// keepalive or a chatty peer's data say the session is alive — the path
// is WG-silent (WG_PATH_WHY_SILENT): DERP only (RELAY, re-probed as for
// a dead one), the direct-only frames re-sent via DERP, and a
// make-before-break rekey at once (WG_PATH_ACT_REKEY) — one ping RTT
// after the 12-s window: within WG_PATH_ANSWER_MS + a telemetry period of
// the peer's last packet (test_wg_path, 100 instants: mean 16.1 s, max
// 17.5 s), where the RX-stale rekey waits 30 s. Only for the first
// silence of a streak (a keepalive on DIRECT ends it): a fresh session
// that is silent too means the keys are not the problem — WireGuard
// itself is dropped on that path — and the re-probe backs off instead
// (10 → 60 s; simulated hour of it: 50 direct re-tests, 0 frames lost).
//
// Endpoint choice (upstream betterAddr): while the current endpoint is
// valid — DIRECT with a proof within WG_PATH_TRUST_MS — another
// endpoint's pong moves it only if clearly better (latency points with
// hysteresis, private addresses preferred), compared against the current
// endpoint's pong from the same ping round: pongs of one round arrive
// within one DTIM wake of each other, rounds minutes apart differ by up
// to ~300 ms of modem-sleep delay (direct RTT 23 ms min / 147 ms avg over
// 2 301 pings, ROADMAP M6). Not valid: the first pong wins (upstream:
// bestUntrusted). On the sensor two endpoints of the peer on one IP
// (41641 and its NAT mapping) answered every round ~10 ms apart and the
// endpoint followed each in turn: 41 roams in 2 h.

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "wg_timers.h"

#ifdef __cplusplus
extern "C" {
#endif

/* WireGuard KEEPALIVE_TIMEOUT (whitepaper §6.5; wireguard-go
 * KeepaliveTimeout): a peer that received data answers within this. */
#define WG_PATH_KEEPALIVE_TIMEOUT_MS 10000

/* Slack on top of it: the round trip (direct 23–403 ms measured, DERP a
 * few hundred more) plus a DTIM wake for the keepalive to reach us. A
 * late keepalive costs one ping; a large slack costs telemetry. */
#define WG_PATH_ANSWER_SLACK_MS 2000
#define WG_PATH_ANSWER_MS (WG_PATH_KEEPALIVE_TIMEOUT_MS + WG_PATH_ANSWER_SLACK_MS)

/* DUAL → RELAY when the ping to the current endpoint got no pong in
 * this long: upstream pingTimeoutDuration, = DISCO_PROBER_TIMEOUT_MS
 * (the prober drops the txid then). */
#define WG_PATH_PING_TIMEOUT_MS 5000

/* RELAY re-probes (a ping to the current endpoint plus one to every
 * endpoint of the netmap) run while data went out within this long
 * (upstream sessionActiveTimeout), first after MIN, doubling to MAX: a
 * one-hour outage costs ~60 rounds, not 360. The peer's own discovery
 * (its CallMeMaybe, every time its trust in us lapses) punches back in
 * between. */
#define WG_PATH_ACTIVE_MS      45000
#define WG_PATH_REPROBE_MIN_MS 10000
#define WG_PATH_REPROBE_MAX_MS 60000

/* The current endpoint is valid (pongs from others need to be clearly
 * better, an authenticated packet from another source does not roam,
 * INITs get no DERP copy) while DIRECT with a proof this recent — the
 * RX-stale window the 1.3.5 "direct path confirmed" used. */
#define WG_PATH_TRUST_MS 30000

/* Pongs within this of each other belong to one ping round. */
#define WG_PATH_ROUND_MS 1000

/* betterAddr: upstream's latency points (percent faster than the slower
 * of the two) and +20 for a private address; upstream switches at >1
 * point, this needs > WG_PATH_BETTER_POINTS and a latency gain of at
 * least WG_PATH_BETTER_MIN_US. Within one round the endpoint pinged
 * later looks faster by the ping spacing (the prepunch seals each ping
 * with its own X25519, ~10 ms apart on the sensor; pongs of a round are
 * delivered in the same DTIM wake): 25 ms covers two spacings. */
#define WG_PATH_BETTER_POINTS  15
#define WG_PATH_BETTER_MIN_US  25000
#define WG_PATH_PRIVATE_POINTS 20

/* B7/B7b (1.3.2), retuned in 1.3.6: a path event (DERP login, a pong
 * that changed the path) while an INIT is unanswered re-sends that INIT
 * if it is younger than this, else replaces it with a new one — a
 * response may still be in flight until then. 1 s until 1.3.5: on the
 * sensor three answers to INITs replaced by a pong-driven fresh one
 * arrived later ("handshake response rejected (path=rekey)"). Half of
 * REKEY_TIMEOUT: the regular retry still bounds a lost response. */
#define WG_INIT_FRESH_AFTER_MS 2500

typedef enum {
    WG_PATH_DUAL = 0,
    WG_PATH_DIRECT,
    WG_PATH_RELAY,
} wg_path_mode_t;

/* Why the path left DIRECT (or was never in it), for the log. */
typedef enum {
    WG_PATH_WHY_START = 0,   /* session start: nothing proven yet */
    WG_PATH_WHY_ANSWER,      /* our data unanswered for WG_PATH_ANSWER_MS */
    WG_PATH_WHY_IDLE,        /* first frame after a pause, no recent proof */
    WG_PATH_WHY_ENDPOINT,    /* moved to an address no pong has proven */
    WG_PATH_WHY_SILENT,      /* RELAY: it answers DISCO, WireGuard is silent */
} wg_path_why_t;

/* When a lapse is confirmed — its ping got no pong (DUAL → RELAY), the
 * pong came with WireGuard silent, or the endpoint moved elsewhere
 * before the current one answered — the data frames sent direct-only
 * within this long are re-sent via DERP (WG_PATH_ACT_RESCUE). Passive
 * evidence is late by construction: a keepalive answers the frame the
 * peer got KEEPALIVE_TIMEOUT before sending it, so one sent just before
 * the path died still arrives ~10 s after, restarts the window, and the
 * lapse comes up to ~27 s after the break (test_wg_path, 200 random
 * break instants: mean 20 s; without the re-send 3–5 frames lost per
 * break). The peer's replay window drops every frame it already got; the
 * lost ones arrive up to ~35 s late (the telemetry carries its sequence
 * number). The same ciphertexts: if the peer lost the session keys they
 * are lost again — the rekey only saves what follows. Not at the lapse
 * itself: a lapse whose ping is answered while the peer's packets keep
 * coming sends nothing twice — with a peer that streams data to us (no
 * keepalives) that is every lapse. */
#define WG_PATH_RESCUE_MS 40000

/* Actions for the caller (bitmask). */
#define WG_PATH_ACT_PING   0x01u   /* DISCO ping to the current endpoint */
#define WG_PATH_ACT_PROBE  0x02u   /* ping every endpoint the netmap lists */
#define WG_PATH_ACT_RESCUE 0x04u   /* lapse confirmed: re-send recent direct-only frames via DERP */
#define WG_PATH_ACT_REKEY  0x08u   /* WG-silent: start a rekey unless one is in flight */

/* DUAL because the path lapsed, and the endpoint has not answered since:
 * the direct-only frames sent before the lapse may be lost. */
#define WG_PATH_LAPSE_PENDING(p) \
    ((p)->mode == WG_PATH_DUAL && \
     ((p)->why == WG_PATH_WHY_ANSWER || (p)->why == WG_PATH_WHY_IDLE))

typedef enum {
    WG_PATH_PONG_KEPT = 0,   /* another endpoint, not clearly better / pending */
    WG_PATH_PONG_CONFIRMED,  /* from the current endpoint */
    WG_PATH_PONG_ROAM,       /* move the endpoint to the pong's source */
    WG_PATH_PONG_ROAM_CAND,  /* move to this round's candidate (cand_*) */
    WG_PATH_PONG_SILENT,     /* from the current endpoint, WG silent: → RELAY */
} wg_path_pong_t;

typedef struct {
    bool           managed;     /* false: no DiscoKey — direct only, no pings */
    wg_path_mode_t mode;
    wg_path_why_t  why;
    int64_t since_us;           /* entered the current mode */
    int64_t off_direct_us;      /* left DIRECT (or start) */
    int64_t proof_us;           /* last pong / keepalive while DIRECT; 0 none */
    int64_t await_us;           /* first data frame since the proof; 0 none */
    int64_t last_data_us;       /* last data frame sent; 0 none */
    int64_t hs_us;              /* last completed handshake; 0 none */
    int64_t peer_wg_us;         /* last authenticated WG packet from the peer */
    int64_t lapse_from_us;      /* at a lapse: the unanswered frame / proof */
    uint8_t silent_streak;      /* WG-silent lapses since a keepalive on DIRECT */
    bool    grace_used;         /* the peer's first data after hs_us seen */
    int64_t ping_us;            /* last ping asked for; < since_us: none in this mode */
    int64_t reprobe_us;         /* RELAY: next re-probe */
    uint32_t reprobe_ms;        /* RELAY: current back-off */
    uint32_t rtt_us;            /* current endpoint: RTT of its last pong */
    int64_t  rtt_at_us;         /* ...and when it came; 0 none */
    bool     cand_valid;        /* another endpoint answered this round first */
    bool     cand_private;
    uint16_t cand_port;         /* host order */
    uint32_t cand_v4_be;
    uint32_t cand_rtt_us;
    int64_t  cand_at_us;
    /* For the transition logs. */
    int64_t  unconfirmed_us;    /* at a lapse: since the unanswered frame / proof */
    int64_t  was_off_us;        /* at a confirm: time spent off DIRECT */
    /* Counters since start. */
    uint32_t lapses;            /* DIRECT → DUAL */
    uint32_t deaths;            /* DUAL → RELAY */
    uint32_t confirms;          /* → DIRECT */
    uint32_t roams;             /* pong-driven endpoint moves */
    uint32_t silences;          /* DUAL → RELAY on a pong, WG silent */
} wg_path_t;

/* RFC 1918 or link-local, host-order IPv4 (upstream: IsPrivate +20,
 * IsLinkLocalUnicast +30; one bonus is enough for v4). */
static inline bool wg_path_v4_private(uint32_t v4)
{
    return (v4 >> 24) == 10 ||
           (v4 >> 20) == ((172u << 4) | 1u) ||     /* 172.16/12 */
           (v4 >> 16) == ((192u << 8) | 168u) ||   /* 192.168/16 */
           (v4 >> 16) == ((169u << 8) | 254u);     /* 169.254/16 */
}

/* Is a (RTT a_rtt_us, private a_priv) clearly better than b? Upstream
 * betterAddr's points with hysteresis — see WG_PATH_BETTER_POINTS. */
static inline bool wg_path_better(uint32_t a_rtt_us, bool a_priv,
                                  uint32_t b_rtt_us, bool b_priv)
{
    int a_pts = 0, b_pts = 0;
    if ((uint64_t)a_rtt_us + WG_PATH_BETTER_MIN_US < b_rtt_us) {
        a_pts = (int)(100 - ((uint64_t)a_rtt_us * 100u) / b_rtt_us);
    } else if ((uint64_t)b_rtt_us + WG_PATH_BETTER_MIN_US < a_rtt_us) {
        b_pts = (int)(100 - ((uint64_t)b_rtt_us * 100u) / a_rtt_us);
    }
    if (a_priv) a_pts += WG_PATH_PRIVATE_POINTS;
    if (b_priv) b_pts += WG_PATH_PRIVATE_POINTS;
    return a_pts > b_pts + WG_PATH_BETTER_POINTS;
}

static inline void wg_path_enter_dual_(wg_path_t *p, int64_t now,
                                       wg_path_why_t why)
{
    if (p->mode == WG_PATH_DIRECT) p->off_direct_us = now;
    p->mode       = WG_PATH_DUAL;
    p->why        = why;
    p->since_us   = now;
    p->await_us   = 0;
    p->reprobe_ms = 0;
}

/* Session start (wg_netif_start): nothing proven. `managed` = the peer
 * has a DiscoKey (no pings, no pongs without one; WireGuard-only peers
 * are not on DERP either). */
static inline void wg_path_init(wg_path_t *p, int64_t now, bool managed)
{
    *p = (wg_path_t){0};
    p->managed       = managed;
    p->mode          = WG_PATH_DUAL;
    p->why           = WG_PATH_WHY_START;
    p->since_us      = now;
    p->off_direct_us = now;
}

/* The peer's DiscoKey arrived after the start (wg_netif_update_peer_keys):
 * start over, unconfirmed, with a ping at the next tick. */
static inline void wg_path_set_managed(wg_path_t *p, int64_t now, bool managed)
{
    if (p->managed == managed) return;
    if (managed) {
        const wg_path_t old = *p;
        wg_path_init(p, now, true);
        p->lapses   = old.lapses;
        p->deaths   = old.deaths;
        p->confirms = old.confirms;
        p->roams    = old.roams;
        p->silences = old.silences;
    } else {
        p->managed = false;
    }
}

/* The current endpoint is valid: see WG_PATH_TRUST_MS. */
static inline bool wg_path_valid(const wg_path_t *p, int64_t now)
{
    return p->mode == WG_PATH_DIRECT && p->proof_us != 0 &&
           !wg_timer_due(now, p->proof_us, (int64_t)WG_PATH_TRUST_MS * 1000LL);
}

/* May an authenticated transport / handshake response from another
 * source roam the endpoint (whitepaper roaming, M16)? Not while the
 * current one is valid: upstream never roams on the source of WG
 * packets, and a one-way path is exactly a source we cannot send to. */
static inline bool wg_path_may_roam(const wg_path_t *p, int64_t now)
{
    return !p->managed || !wg_path_valid(p, now);
}

/* Does an INIT get a DERP copy (B7)? Unless the current endpoint is valid. */
static inline bool wg_path_init_wants_relay(const wg_path_t *p, int64_t now)
{
    return !wg_path_valid(p, now);
}

static inline uint32_t wg_path_lapse_(wg_path_t *p, int64_t now,
                                      wg_path_why_t why, int64_t from_us)
{
    wg_path_enter_dual_(p, now, why);
    p->unconfirmed_us = now - from_us;
    p->lapse_from_us  = from_us;
    p->ping_us = now;
    p->lapses++;
    return WG_PATH_ACT_PING;
}

/* DIRECT and our oldest unanswered data frame is past the window. */
static inline uint32_t wg_path_check_answer_(wg_path_t *p, int64_t now)
{
    if (p->mode == WG_PATH_DIRECT && p->await_us != 0 &&
        wg_timer_due(now, p->await_us, (int64_t)WG_PATH_ANSWER_MS * 1000LL)) {
        return wg_path_lapse_(p, now, WG_PATH_WHY_ANSWER, p->await_us);
    }
    return 0;
}

/* A transport frame is about to go out (wg_tx). `data`: it carries a
 * payload (keepalives are never answered). *mode is how to send it. */
static inline uint32_t wg_path_on_send(wg_path_t *p, int64_t now, bool data,
                                       wg_path_mode_t *mode)
{
    if (!p->managed) {
        *mode = WG_PATH_DIRECT;
        return 0;
    }
    uint32_t act = wg_path_check_answer_(p, now);
    if (data) {
        const int64_t win = (int64_t)WG_PATH_ANSWER_MS * 1000LL;
        if (p->mode == WG_PATH_DIRECT &&
            (p->last_data_us == 0 || wg_timer_due(now, p->last_data_us, win)) &&
            wg_timer_due(now, p->proof_us, win)) {
            act |= wg_path_lapse_(p, now, WG_PATH_WHY_IDLE, p->proof_us);
        }
        if (p->mode == WG_PATH_DIRECT && p->await_us == 0) p->await_us = now;
        p->last_data_us = now;
    }
    *mode = p->mode;
    return act;
}

static inline bool wg_path_active_(const wg_path_t *p, int64_t now)
{
    return p->last_data_us != 0 &&
           !wg_timer_due(now, p->last_data_us, (int64_t)WG_PATH_ACTIVE_MS * 1000LL);
}

/* The RX task's timer pass. */
static inline uint32_t wg_path_tick(wg_path_t *p, int64_t now)
{
    if (!p->managed) return 0;
    switch (p->mode) {
    case WG_PATH_DIRECT:
        return wg_path_check_answer_(p, now);
    case WG_PATH_DUAL:
        if (p->ping_us < p->since_us) {          /* none asked in this mode yet */
            p->ping_us = now;
            return WG_PATH_ACT_PING;
        }
        if (wg_timer_due(now, p->ping_us, (int64_t)WG_PATH_PING_TIMEOUT_MS * 1000LL)) {
            const bool lapsed = WG_PATH_LAPSE_PENDING(p);
            p->mode       = WG_PATH_RELAY;
            p->since_us   = now;
            p->reprobe_ms = WG_PATH_REPROBE_MIN_MS;
            p->reprobe_us = now + (int64_t)WG_PATH_REPROBE_MIN_MS * 1000LL;
            p->deaths++;
            /* The current one just failed: look for another; and if it had
             * been carrying our data, re-send what may not have arrived. */
            return WG_PATH_ACT_PROBE | (lapsed ? WG_PATH_ACT_RESCUE : 0);
        }
        return 0;
    case WG_PATH_RELAY:
        if (wg_path_active_(p, now) && now >= p->reprobe_us) {
            p->ping_us    = now;
            p->reprobe_ms = p->reprobe_ms * 2 > WG_PATH_REPROBE_MAX_MS
                                ? WG_PATH_REPROBE_MAX_MS : p->reprobe_ms * 2;
            p->reprobe_us = now + (int64_t)p->reprobe_ms * 1000LL;
            return WG_PATH_ACT_PING | WG_PATH_ACT_PROBE;
        }
        return 0;
    }
    return 0;
}

/* Earliest instant wg_path_tick acts (INT64_MAX: none) — the same
 * conditions; tools/test/test_wg_path.c checks the two agree. */
static inline int64_t wg_path_next_deadline(const wg_path_t *p)
{
    if (!p->managed) return INT64_MAX;
    switch (p->mode) {
    case WG_PATH_DIRECT:
        return p->await_us != 0
            ? wg_timer_at(p->await_us, (int64_t)WG_PATH_ANSWER_MS * 1000LL)
            : INT64_MAX;
    case WG_PATH_DUAL:
        return p->ping_us < p->since_us
            ? p->since_us
            : wg_timer_at(p->ping_us, (int64_t)WG_PATH_PING_TIMEOUT_MS * 1000LL);
    case WG_PATH_RELAY: {
        if (p->last_data_us == 0) return INT64_MAX;
        const int64_t last_active = p->last_data_us + (int64_t)WG_PATH_ACTIVE_MS * 1000LL;
        return p->reprobe_us <= last_active ? p->reprobe_us : INT64_MAX;
    }
    }
    return INT64_MAX;
}

static inline void wg_path_confirm_(wg_path_t *p, int64_t now)
{
    if (p->mode != WG_PATH_DIRECT) {
        p->was_off_us = now - p->off_direct_us;
        p->mode       = WG_PATH_DIRECT;
        p->since_us   = now;
        p->reprobe_ms = 0;
        p->confirms++;
    }
    p->proof_us = now;
    p->await_us = 0;
}

/* A transport keepalive (no payload) from the peer, either path. */
static inline void wg_path_on_keepalive(wg_path_t *p, int64_t now)
{
    p->peer_wg_us = now;
    if (p->mode != WG_PATH_DIRECT) return;   /* our frames went via DERP too */
    p->proof_us = now;
    p->await_us = 0;
    p->silent_streak = 0;                    /* WireGuard both ways, direct */
}

/* A transport packet with a payload from the peer, either path. Proves
 * nothing; only the first after a handshake restarts the window. */
static inline void wg_path_on_peer_data(wg_path_t *p, int64_t now)
{
    p->peer_wg_us = now;
    if (p->mode == WG_PATH_DIRECT && p->hs_us != 0 && !p->grace_used &&
        !wg_timer_due(now, p->hs_us, (int64_t)WG_PATH_ANSWER_MS * 1000LL)) {
        p->grace_used = true;
        p->await_us   = 0;
    }
}

/* A handshake response was accepted (cold or rekey, either path). */
static inline void wg_path_on_handshake(wg_path_t *p, int64_t now)
{
    p->hs_us      = now;
    p->peer_wg_us = now;
    p->grace_used = false;
    if (p->mode == WG_PATH_DIRECT) p->await_us = 0;
}

/* The endpoint moved to an address no pong has proven (a roam on an
 * authenticated packet, control's endpoint): DUAL, and ping it. Moving
 * off a lapsed endpoint confirms the lapse (WG_PATH_ACT_RESCUE). */
static inline uint32_t wg_path_on_endpoint_change(wg_path_t *p, int64_t now)
{
    const uint32_t act = WG_PATH_LAPSE_PENDING(p) ? WG_PATH_ACT_RESCUE : 0;
    wg_path_enter_dual_(p, now, WG_PATH_WHY_ENDPOINT);
    p->ping_us    = 0;
    p->proof_us   = 0;
    p->rtt_us     = 0;
    p->rtt_at_us  = 0;
    p->cand_valid = false;
    return act;
}

/* The current endpoint answered the ping of an ANSWER lapse, and nothing
 * authenticated came from the peer since the unanswered frame: see the
 * header ("A pong proves the address pair"). */
static inline uint32_t wg_path_silent_(wg_path_t *p, int64_t now)
{
    if (p->silent_streak < UINT8_MAX) p->silent_streak++;
    p->silences++;
    p->unconfirmed_us = now - p->lapse_from_us;
    p->cand_valid = false;
    p->mode       = WG_PATH_RELAY;
    p->why        = WG_PATH_WHY_SILENT;
    p->since_us   = now;
    const unsigned shift = p->silent_streak > 3 ? 3u : p->silent_streak - 1u;
    p->reprobe_ms = (uint32_t)WG_PATH_REPROBE_MIN_MS << shift;
    if (p->reprobe_ms > WG_PATH_REPROBE_MAX_MS) p->reprobe_ms = WG_PATH_REPROBE_MAX_MS;
    p->reprobe_us = now + (int64_t)p->reprobe_ms * 1000LL;
    return WG_PATH_ACT_RESCUE | (p->silent_streak == 1 ? WG_PATH_ACT_REKEY : 0);
}

/* A pong we solicited (disco_prober match: our txid, from the address we
 * pinged) from the WG peer. `from_current`: that address is the current
 * endpoint; `src_private` / `cur_private`: wg_path_v4_private of each.
 * *act (may be NULL) gets WG_PATH_ACT_RESCUE when the pong moves the
 * endpoint off a lapsed one, RESCUE | REKEY (the first of a streak) when
 * it answers DISCO with WireGuard silent (WG_PATH_PONG_SILENT). */
static inline wg_path_pong_t wg_path_on_pong(wg_path_t *p, int64_t now,
                                             uint32_t rtt_us, bool from_current,
                                             uint32_t src_v4_be, uint16_t src_port,
                                             bool src_private, bool cur_private,
                                             uint32_t *act)
{
    const int64_t round = (int64_t)WG_PATH_ROUND_MS * 1000LL;
    if (act != NULL) *act = 0;
    if (from_current) {
        p->rtt_us    = rtt_us;
        p->rtt_at_us = now;
        if (p->mode == WG_PATH_DUAL && p->why == WG_PATH_WHY_ANSWER &&
            p->peer_wg_us < p->lapse_from_us) {
            const uint32_t a = wg_path_silent_(p, now);
            if (act != NULL) *act = a;
            return WG_PATH_PONG_SILENT;
        }
        wg_path_confirm_(p, now);
        const bool cand = p->cand_valid && !wg_timer_due(now, p->cand_at_us, round);
        p->cand_valid = false;
        if (cand && wg_path_better(p->cand_rtt_us, p->cand_private,
                                   rtt_us, cur_private)) {
            p->rtt_us    = p->cand_rtt_us;
            p->rtt_at_us = p->cand_at_us;
            p->roams++;
            return WG_PATH_PONG_ROAM_CAND;
        }
        return WG_PATH_PONG_CONFIRMED;
    }
    const bool take =
        !wg_path_valid(p, now) ||                       /* first pong wins */
        (p->rtt_at_us != 0 && !wg_timer_due(now, p->rtt_at_us, round) &&
         wg_path_better(rtt_us, src_private, p->rtt_us, cur_private));
    if (take) {
        if (act != NULL && WG_PATH_LAPSE_PENDING(p)) *act = WG_PATH_ACT_RESCUE;
        p->rtt_us     = rtt_us;
        p->rtt_at_us  = now;
        p->cand_valid = false;
        wg_path_confirm_(p, now);
        p->roams++;
        return WG_PATH_PONG_ROAM;
    }
    /* The current endpoint has not answered this round (yet): keep the
     * best other answer until it does or the round ends. */
    if (!p->cand_valid || wg_timer_due(now, p->cand_at_us, round) ||
        (src_private && !p->cand_private) ||
        (src_private == p->cand_private && rtt_us < p->cand_rtt_us)) {
        p->cand_valid   = true;
        p->cand_v4_be   = src_v4_be;
        p->cand_port    = src_port;
        p->cand_private = src_private;
        p->cand_rtt_us  = rtt_us;
        p->cand_at_us   = now;
    }
    return WG_PATH_PONG_KEPT;
}

/* B7b: replace the unanswered INIT built at init_us on a path event? */
static inline bool wg_init_fresh_due(int64_t now, int64_t init_us)
{
    return wg_timer_due(now, init_us, (int64_t)WG_INIT_FRESH_AFTER_MS * 1000LL);
}

#ifdef __cplusplus
}
#endif
