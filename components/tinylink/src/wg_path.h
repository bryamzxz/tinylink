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
//           a lapse, after a roam to an address no pong has proven;
//           DOUBT: the lapse's pong came, WireGuard has not (yet).
//   DIRECT  confirmed: direct only. Entered ONLY on a pong to our ping
//           (txid + source bound by disco_prober: a round trip on that
//           address pair), or a doubt ended by WireGuard. Kept while the
//           peer keeps answering our data.
//   RELAY   the current endpoint failed a ping, or a doubt ended badly
//           (SILENT, UNDELIVERED): DERP only, re-probed.
//
//        +-- pong (from the current endpoint, or any: roam) --+
//        v                                                    |
//     DIRECT --lapse--> DUAL --no pong in PING_TIMEOUT--> RELAY
//        ^              | ^ pong, WG silent                   |
//        +-WG packet-- DOUBT --2nd window / again--> RELAY    |
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
// frames that may have been lost (WG_PATH_RESCUE_MAX_MS).
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
// 60 ms. Two windows: when the pong answering a lapse of our data comes
// from the current endpoint but nothing authenticated came from the
// peer since the unanswered frame (no keepalive, data or handshake: a
// late keepalive or a chatty peer's data say the session lives), the
// path is in DOUBT — still DUAL, no rekey, no re-send. One lost
// keepalive, one lost first frame after a proof (the keepalive then
// comes one period late), one lost TSMP advert after a rekey all look
// exactly like this (the review of 1.3.6: declaring WG silent on the
// first window cost 9 / 21 / 47 forced rekeys per 6 h at 0.5 / 1 / 2 %
// loss). The first WG packet from the peer ends the doubt: back to
// DIRECT, a few frames went both ways. Only a second window — opened by
// the next data frame, sent both ways — without any WG packet is
// SILENT: DERP only (RELAY, re-probed), the direct-only frames re-sent,
// and a make-before-break rekey (WG_PATH_ACT_REKEY), the first of a
// streak only (any transport packet from the peer ends it; a fresh
// session silent too means the keys are not the problem). That comes
// 24–29 s after the first unanswered frame, against 30 s after the
// peer's last packet for the RX-stale rekey — WireGuard's own
// newHandshake timer (KEEPALIVE + REKEY_TIMEOUT after an unanswered
// send) would rekey on one lost keepalive. And a doubt ended again,
// before any keepalive proved the direct path (one that can only answer
// direct-only frames: none went via DERP within a window before it),
// means the peer gets what goes via DERP and not what goes direct:
// UNDELIVERED, DERP only, no rekey, the direct re-tests backed off
// 10 → 60 s with the doubts.
//
// Round 1.3.8: a doubt is tested at once with a handshake
// (WG_PATH_ACT_TEST). In the 1.3.6 soak (25 doubts in 3.5 h) two ran into
// the RX-stale rekey 13 s after the doubt, 30 s after the peer's last
// packet (seen direct=0 derp=0): in one nothing came until that rekey's
// response, ~130 ms after its INIT — the 1.3.5 failure, a session only an
// INIT revives; in the other a keepalive answering our first frame sent
// both ways came 30 ms after the INIT. The others were a lost frame or
// keepalive, settled by the peer's own WireGuard 1.3–8.0 s after the
// lapse. A make-before-break INIT, sent direct and via DERP while the
// current session keeps carrying our data, settles every kind within a
// round trip: its response is a WireGuard packet from the peer and ends
// the doubt like a keepalive does (wg_path_resolve_ — the INIT went both
// ways, so it proves the session, not our direct path), and a broken
// session is replaced by the response. Recovery from
// that failure (test_wg_path, 100 random instants, the peer's keypair
// slots and our DERP send queue modelled): the session is back 12.3–13.0
// s after the first unanswered frame, 16.4 s on average (max 17.9) after
// the peer's last packet — 1.3.7: 25.2–27.9 s and 29.9 s (the RX-stale
// rekey). The
// price: a handshake per doubt, +6 / +12.5 / +27 handshakes per 6 h on
// 195 at 0.5 / 1 / 2 % loss (20 runs each, against the same rules without
// the test; a doubt's handshake also moves the next proactive one 110 s
// on). A doubt now ends within a round trip, so fewer frames go both ways
// during one (DERP copies 21 / 44 / 91 → 1.6 / 3.0 / 17 per 6 h, frames
// lost to the random loss 21.7 / 41.4 / 80.5 → 21.4 / 41.0 / 78.4), and
// the RX-stale rekeys the loss caused (0.25 / 0.70 / 1.80 per 6 h, each
// after 30 s of silence) are gone. An INIT that would make the peer delete
// the keypair of frames still to re-send goes via DERP behind their
// re-send (wg_path_init_route): 2.3 / 4.5 / 11 of the 13 / 26 / 54 tests.
// Only one INIT in flight: wg_path_rekey_gate starts one only when no
// handshake is pending, REKEY_TIMEOUT after the last INIT (whitepaper
// §6.1, wireguard-go SendHandshakeInitiation), else the pending one's
// response does the same. Once per silent streak: after a silence (the test's own session
// silent too) a doubt is not tested again until a transport packet from
// the peer arrives.
//
// An in-tunnel probe was considered instead. An empty keepalive is never
// answered (wireguard-go arms its passive keepalive only for packets with
// a payload). A TSMP ping is answered by tailscaled (tstun, before the
// filter) without a new session, but into a broken session it goes
// unanswered, so the failure above would still need a timeout and then
// the INIT — 1–2 s later than the INIT alone — for ~25 ms of X25519
// saved per doubt (a few per hour), and it depends on the peer being
// tailscaled.
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
#include <stddef.h>
#include <stdint.h>

#include "wg_rescue.h"
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
    WG_PATH_WHY_DOUBT,       /* DUAL: its pong came, no WG packet since the frame */
    WG_PATH_WHY_SILENT,      /* RELAY: no WG packet by either path for two windows */
    WG_PATH_WHY_UNDELIVERED, /* RELAY: the peer answers what goes via DERP only */
} wg_path_why_t;

/* When a lapse is confirmed — its ping got no pong (DUAL → RELAY), the
 * doubt after its pong ended SILENT or UNDELIVERED, or the endpoint
 * moved elsewhere before the current one answered — the data frames sent
 * direct-only since the last proof of their delivery are re-sent via
 * DERP (WG_PATH_ACT_RESCUE), and frames whose DERP copy was refused count
 * as direct-only. Passive evidence is late by construction: a keepalive
 * answers the frame the peer got KEEPALIVE_TIMEOUT before sending it, so
 * one sent just before the path died still arrives ~10 s after, restarts
 * the window, and the lapse comes up to ~27 s after the break
 * (test_wg_path, 200 random break instants: mean 20 s; without the
 * re-send 3–5 frames lost per break). The peer's replay window drops
 * every frame it already got; the lost ones arrive late (the telemetry
 * carries its sequence number). The same ciphertexts: if the peer lost
 * the session keys they are lost again — the rekey only saves what
 * follows. Not at the lapse itself: a lapse whose ping is answered while
 * the peer's packets keep coming sends nothing twice — with a peer that
 * streams data to us (no keepalives) that is every lapse.
 *
 * The proof (round 1.3.8, wg_path_rescue_from): a keepalive that proves
 * the direct path (no frame via DERP within a window before it) answers
 * a frame the peer received KEEPALIVE_TIMEOUT before sending it — frames
 * sent before that instant got through the direct path, those after may
 * not have. Until 1.3.7 the ring kept the last 40 s instead: with only
 * our direct WireGuard toward the peer dropped, the first episode
 * (direct → doubt → direct again → doubt → UNDELIVERED) outlasts 40 s and
 * lost the 3–6 frames sent first (1.3.6 "Known gap"). The ring
 * (WG_RESCUE_SLOTS) bounds how many; this bounds how old — the peer
 * rejects anything sealed under a keypair older than REJECT_AFTER_TIME
 * (whitepaper §6.2), so an older frame can never be accepted. */
#define WG_PATH_RESCUE_MAX_MS 180000

/* Actions for the caller (bitmask). */
#define WG_PATH_ACT_PING   0x01u   /* DISCO ping to the current endpoint */
#define WG_PATH_ACT_PROBE  0x02u   /* ping every endpoint the netmap lists */
#define WG_PATH_ACT_RESCUE 0x04u   /* lapse confirmed: re-send recent direct-only frames via DERP */
#define WG_PATH_ACT_REKEY  0x08u   /* SILENT: start a rekey unless one is in flight */
#define WG_PATH_ACT_TEST   0x10u   /* DOUBT: the same, to test the session (1.3.8) */

/* DUAL because the path lapsed, and neither the endpoint nor WireGuard
 * has answered since: the direct-only frames before it may be lost. */
#define WG_PATH_LAPSE_PENDING(p) \
    ((p)->mode == WG_PATH_DUAL && \
     ((p)->why == WG_PATH_WHY_ANSWER || (p)->why == WG_PATH_WHY_IDLE || \
      (p)->why == WG_PATH_WHY_DOUBT))

/* The lapse's ping was answered by the current endpoint, but nothing
 * authenticated came from the peer since the unanswered frame. */
#define WG_PATH_IN_DOUBT(p) ((p)->mode == WG_PATH_DUAL && (p)->why == WG_PATH_WHY_DOUBT)

typedef enum {
    WG_PATH_PONG_KEPT = 0,   /* another endpoint, not clearly better / pending */
    WG_PATH_PONG_CONFIRMED,  /* from the current endpoint */
    WG_PATH_PONG_ROAM,       /* move the endpoint to the pong's source */
    WG_PATH_PONG_ROAM_CAND,  /* move to this round's candidate (cand_*) */
    WG_PATH_PONG_DOUBT,      /* from the current endpoint, WG silent: → DOUBT */
} wg_path_pong_t;

typedef struct {
    bool           managed;     /* false: no DiscoKey — direct only, no pings */
    wg_path_mode_t mode;
    wg_path_why_t  why;
    int64_t since_us;           /* entered the current mode */
    int64_t off_direct_us;      /* left DIRECT (or start) */
    int64_t proof_us;           /* last pong / direct-proving keepalive; 0 none */
    int64_t ka_us;              /* last keepalive while DIRECT, proving or not */
    int64_t await_us;           /* first data frame since the proof (DIRECT) or
                                   since the doubt began (DOUBT); 0 none */
    int64_t last_data_us;       /* last data frame sent; 0 none */
    int64_t last_relay_data_us; /* last data frame that also went via DERP */
    int64_t hs_us;              /* last completed handshake; 0 none */
    int64_t init_hold_us;       /* the first INIT held behind a re-send since
                                   then, DERP up all along (wg_path_init_route);
                                   0 none */
    int64_t peer_wg_us;         /* last authenticated WG packet from the peer */
    int64_t peer_tr_us;         /* ...transport (keepalive / data): under our current
                                   keypair, the only one wg_netif receives on */
    int64_t lapse_from_us;      /* at a lapse: the unanswered frame / proof */
    int64_t test_at_us;         /* DOUBT: a handshake test is owed from then; 0 none */
    int64_t delivered_us;       /* direct-only data frames sent before this were
                                   delivered (wg_path_rescue_from); 0 none */
    uint8_t doubts;             /* doubts since a keepalive that proved direct
                                   (any endpoint): the re-test back-off */
    uint8_t silent_streak;      /* silences since a transport packet from the peer */
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
    uint32_t doubts_total;      /* → DOUBT */
    uint32_t silences;          /* DOUBT → RELAY: no WG packet for two windows */
    uint32_t undelivered;       /* DOUBT → RELAY: WG answered via DERP only */
    uint32_t tests;             /* doubts tested with a handshake (asked for) */
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
        p->doubts_total = old.doubts_total;
        p->silences = old.silences;
        p->undelivered = old.undelivered;
        p->tests    = old.tests;
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
 * payload (keepalives are never answered). *mode is how to send it.
 *
 * After a pause — no frame for a window, no keepalive or proof for a
 * window — the first frame goes DUAL with a ping. With a telemetry
 * period above ~22 s (KEEPALIVE_TIMEOUT + WG_PATH_ANSWER_MS: the
 * keepalive answering a sample comes 10 s after it; Kconfig allows up
 * to 600 s, the default is 5 s) that is every sample: one DERP copy and
 * one ping / pong each (the ping is sealed with the cached key, no
 * X25519). Kept on purpose: the proof is a keepalive ~10 s old by
 * construction, and after minutes nothing says the path still works —
 * magicsock does the same (any send after trustBestAddrUntil, 6.5 s past
 * the last pong, goes to both and pings). Scaling the trust with the
 * period would save those two packets per sample but deliver a sample
 * sent into a path that died during the pause only once a lapse is
 * confirmed (≥ 17 s late) — and never when the doubt needs a second
 * window the next sample opens minutes later, past WG_PATH_RESCUE_MAX_MS. */
static inline uint32_t wg_path_on_send(wg_path_t *p, int64_t now, bool data,
                                       wg_path_mode_t *mode)
{
    if (!p->managed) {
        *mode = WG_PATH_DIRECT;
        return 0;
    }
    uint32_t act = wg_path_check_answer_(p, now);
    if (data) {
        /* Any keepalive counts here, not only a direct-proving one: after
         * a first frame that went both ways, the keepalive answering it
         * proves only the session — but the path is not idle, and the
         * next frame (a period of 12-22 s) must not be "first after a
         * pause" again (simulated: every sample of the hour after one
         * pause). */
        const int64_t win = (int64_t)WG_PATH_ANSWER_MS * 1000LL;
        const int64_t seen = p->ka_us > p->proof_us ? p->ka_us : p->proof_us;
        if (p->mode == WG_PATH_DIRECT &&
            (p->last_data_us == 0 || wg_timer_due(now, p->last_data_us, win)) &&
            wg_timer_due(now, seen, win)) {
            act |= wg_path_lapse_(p, now, WG_PATH_WHY_IDLE, seen);
        }
        if ((p->mode == WG_PATH_DIRECT || WG_PATH_IN_DOUBT(p)) && p->await_us == 0) {
            p->await_us = now;
        }
        if (p->mode != WG_PATH_DIRECT) p->last_relay_data_us = now;
        p->last_data_us = now;
    }
    *mode = p->mode;
    return act;
}

/* RELAY: is the scheduled re-probe one that falls due while data flows
 * (sent within WG_PATH_ACTIVE_MS before it)? Judged at reprobe_us, not at
 * the wake: an RX task waking after the last frame aged out must still
 * run the re-probe that was due (and move reprobe_us on), else its
 * deadline stays in the past and the task spins at the tick rate until
 * the next frame (review of 1.3.6: 1 tick late is enough). */
static inline bool wg_path_reprobe_live_(const wg_path_t *p)
{
    return p->last_data_us != 0 &&
           p->reprobe_us <= p->last_data_us + (int64_t)WG_PATH_ACTIVE_MS * 1000LL;
}

/* The re-sent direct-only frames go via DERP: keepalives within a window
 * of them may answer those, not the direct path. */
static inline uint32_t wg_path_rescue_(wg_path_t *p, int64_t now)
{
    p->last_relay_data_us = now;
    return WG_PATH_ACT_RESCUE;
}

/* RELAY after a failed direct test (SILENT / UNDELIVERED): the re-test
 * backs off with the doubts since the last direct proof, 10 → 60 s. */
static inline void wg_path_enter_relay_(wg_path_t *p, int64_t now, wg_path_why_t why)
{
    p->mode       = WG_PATH_RELAY;
    p->why        = why;
    p->since_us   = now;
    p->cand_valid = false;
    const unsigned shift = p->doubts > 3 ? 3u : p->doubts > 0 ? p->doubts - 1u : 0u;
    p->reprobe_ms = (uint32_t)WG_PATH_REPROBE_MIN_MS << shift;
    if (p->reprobe_ms > WG_PATH_REPROBE_MAX_MS) p->reprobe_ms = WG_PATH_REPROBE_MAX_MS;
    p->reprobe_us = now + (int64_t)p->reprobe_ms * 1000LL;
}

/* DOUBT and its window passed with no WG packet by either path, though
 * frames went both ways: see the header ("Two windows"). */
static inline uint32_t wg_path_silent_(wg_path_t *p, int64_t now)
{
    if (p->silent_streak < UINT8_MAX) p->silent_streak++;
    p->silences++;
    p->unconfirmed_us = now - p->lapse_from_us;
    wg_path_enter_relay_(p, now, WG_PATH_WHY_SILENT);
    return wg_path_rescue_(p, now) | (p->silent_streak == 1 ? WG_PATH_ACT_REKEY : 0);
}

/* → DIRECT (a pong, a doubt ended by WireGuard): the answer window
 * restarts at the next frame. Already DIRECT, a pong renews the proof of
 * the address pair but leaves the window alone — DISCO is not WireGuard:
 * the RX-stale probe or a CallMeMaybe round answering every < 12 s kept a
 * path whose WireGuard was dropped DIRECT (simulated: 30-s DIRECT
 * phases, a frame lost past the re-send window). */
static inline void wg_path_confirm_(wg_path_t *p, int64_t now)
{
    if (p->mode != WG_PATH_DIRECT) {
        p->was_off_us = now - p->off_direct_us;
        p->mode       = WG_PATH_DIRECT;
        p->since_us   = now;
        p->reprobe_ms = 0;
        p->await_us   = 0;
        p->confirms++;
    }
    p->proof_us = now;
}

/* A WG packet from the peer ends a doubt: the session lives. The first
 * time, back to DIRECT — one lost keepalive or frame looks just like
 * this, and costs a few DUAL frames. Again before any direct proof: what
 * we send direct does not reach the peer, what goes via DERP does — DERP
 * only, re-test backed off, no rekey (the session is fine). */
static inline uint32_t wg_path_resolve_(wg_path_t *p, int64_t now)
{
    if (p->doubts < 2) {
        wg_path_confirm_(p, now);
        return 0;
    }
    p->undelivered++;
    p->unconfirmed_us = now - p->lapse_from_us;
    wg_path_enter_relay_(p, now, WG_PATH_WHY_UNDELIVERED);
    return wg_path_rescue_(p, now);
}

/* The RX task's timer pass. */
static inline uint32_t wg_path_tick(wg_path_t *p, int64_t now)
{
    if (!p->managed) return 0;
    switch (p->mode) {
    case WG_PATH_DIRECT:
        return wg_path_check_answer_(p, now);
    case WG_PATH_DUAL:
        if (p->why == WG_PATH_WHY_DOUBT) {
            uint32_t act = 0;
            if (p->test_at_us != 0 && now >= p->test_at_us) {
                p->test_at_us = 0;
                p->tests++;
                act = WG_PATH_ACT_TEST;
            }
            if (p->await_us != 0 &&
                wg_timer_due(now, p->await_us, (int64_t)WG_PATH_ANSWER_MS * 1000LL)) {
                act |= wg_path_silent_(p, now);
            }
            return act;
        }
        if (p->ping_us < p->since_us) {          /* none asked in this mode yet */
            /* Once per entry even when `now` predates it (the caller's
             * clock read before another task moved the endpoint). */
            p->ping_us = now > p->since_us ? now : p->since_us;
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
            return WG_PATH_ACT_PROBE | (lapsed ? wg_path_rescue_(p, now) : 0);
        }
        return 0;
    case WG_PATH_RELAY:
        if (wg_path_reprobe_live_(p) && now >= p->reprobe_us) {
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
 * conditions; tools/test/test_wg_path.c checks the two agree, and that
 * after any tick, however late, the deadline lies ahead. */
static inline int64_t wg_path_next_deadline(const wg_path_t *p)
{
    if (!p->managed) return INT64_MAX;
    switch (p->mode) {
    case WG_PATH_DIRECT:
        return p->await_us != 0
            ? wg_timer_at(p->await_us, (int64_t)WG_PATH_ANSWER_MS * 1000LL)
            : INT64_MAX;
    case WG_PATH_DUAL:
        if (p->why == WG_PATH_WHY_DOUBT) {
            const int64_t w2 = p->await_us != 0
                ? wg_timer_at(p->await_us, (int64_t)WG_PATH_ANSWER_MS * 1000LL)
                : INT64_MAX;
            return p->test_at_us != 0 && p->test_at_us < w2 ? p->test_at_us : w2;
        }
        return p->ping_us < p->since_us
            ? p->since_us
            : wg_timer_at(p->ping_us, (int64_t)WG_PATH_PING_TIMEOUT_MS * 1000LL);
    case WG_PATH_RELAY:
        return wg_path_reprobe_live_(p) ? p->reprobe_us : INT64_MAX;
    }
    return INT64_MAX;
}

/* A transport keepalive (no payload) from the peer, either path. Returns
 * WG_PATH_ACT_RESCUE when it ends a doubt that sends the path to DERP.
 *
 * In DIRECT it restarts the answer window, whatever it answers. It
 * proves the direct path — renews proof_us, clears the doubts — only if
 * no frame went via DERP within WG_PATH_ANSWER_MS before it: the frame
 * a keepalive answers armed the peer's timer KEEPALIVE_TIMEOUT earlier,
 * and right after DUAL / RELAY that may be a DERP copy (the review of
 * 1.3.6: with our direct WireGuard dropped, such keepalives renewed every
 * re-test — 120 rekeys an hour). */
static inline uint32_t wg_path_on_keepalive(wg_path_t *p, int64_t now)
{
    p->peer_wg_us    = now;
    p->peer_tr_us    = now;
    p->silent_streak = 0;                    /* the session works */
    if (WG_PATH_IN_DOUBT(p)) return wg_path_resolve_(p, now);
    if (p->mode != WG_PATH_DIRECT) return 0;   /* our frames went via DERP too */
    p->await_us = 0;
    p->ka_us    = now;
    if (p->last_relay_data_us == 0 ||
        wg_timer_due(now, p->last_relay_data_us, (int64_t)WG_PATH_ANSWER_MS * 1000LL)) {
        p->proof_us = now;
        p->doubts   = 0;
        /* The frame it answers armed the peer's timer KEEPALIVE_TIMEOUT
         * plus a round trip and a wake before now; frames sent after that
         * one are proven by nothing (review of 1.3.8: one sent 150 ms
         * after it, lost, was never re-sent). The answer window's slack
         * covers the round trip and the wake (MAX_MODEM at a 3-beacon
         * listen interval: up to ~307 ms), so frames sent before now -
         * WG_PATH_ANSWER_MS went out before it. See WG_PATH_RESCUE_MAX_MS. */
        const int64_t d = now - (int64_t)WG_PATH_ANSWER_MS * 1000LL;
        if (d > p->delivered_us) p->delivered_us = d;
    }
    return 0;
}

/* Data frames sent direct-only before this instant are proven delivered
 * (0: none): a confirmed lapse re-sends via DERP the ones sent at or
 * after it (wg_rescue_flush), WG_PATH_RESCUE_MAX_MS at most. */
static inline int64_t wg_path_rescue_from(const wg_path_t *p)
{
    return p->delivered_us;
}

/* Has the peer confirmed the keypair of our last handshake — sent us a
 * transport packet under it (its `current`; wg_netif receives on that
 * keypair only)? Until then it may still hold it as `next`
 * (wg_rescue_init_risk). */
static inline bool wg_path_keys_confirmed(const wg_path_t *p)
{
    return p->peer_tr_us > p->hs_us;
}

/* Whether wg_netif starts a rekey the path selection asks for (SILENT's
 * WG_PATH_ACT_REKEY, a doubt's WG_PATH_ACT_TEST). One INIT in flight: a
 * responder that gets a second keeps only the second session (see
 * WG_INIT_FRESH_AFTER_MS), and the pending one's answer does the same
 * job; a new one only REKEY_TIMEOUT after the last (whitepaper §6.1,
 * wireguard-go SendHandshakeInitiation); none without a session (a cold
 * handshake has its own retries). Which way the INIT goes is
 * wg_path_init_route's. Pure, so the host tests drive the same decision
 * wg_netif makes. */
typedef enum {
    WG_REKEY_GO = 0,
    WG_REKEY_NO_SESSION,
    WG_REKEY_IN_FLIGHT,
    WG_REKEY_TOO_SOON,
} wg_rekey_gate_t;

#define WG_PATH_REKEY_TIMEOUT_MS 5000   /* = wg_netif's WG_REKEY_TIMEOUT_MS */

static inline wg_rekey_gate_t wg_path_rekey_gate(bool up, bool in_flight, int64_t now,
                                                 int64_t last_init_us)
{
    if (!up) return WG_REKEY_NO_SESSION;
    if (in_flight) return WG_REKEY_IN_FLIGHT;
    if (!wg_timer_due(now, last_init_us, (int64_t)WG_PATH_REKEY_TIMEOUT_MS * 1000LL)) {
        return WG_REKEY_TOO_SOON;
    }
    return WG_REKEY_GO;
}

/* Which way an INIT may leave — any INIT, new or re-sent, whatever
 * started it (a doubt's test, SILENT, the proactive or RX-stale rekey, a
 * retry, a fresh one at a path event, the re-sends at a DERP login, a
 * CallMeMaybe, link-up or a pong). An INIT the peer consumes deletes a
 * keypair (wg_rescue_init_risk): while one still seals a frame to
 * re-send, or one just re-sent, the INIT goes via DERP only, behind the
 * re-send on the same stream — the peer looks a transport packet's
 * keypair up as it arrives, before its handshake queue gets the INIT —
 * and wg_netif queues the re-send first and sends that copy with the
 * waiting write the re-send uses (a best-effort write is refused once
 * lwIP holds 8 unacknowledged segments: TCP_SNDQUEUELOWAT, TCP_NODELAY).
 * Only while DERP is connected (`relay_up`): with it down the held copy
 * could not go, and the INIT goes as in 1.3.7 (the frames at risk are
 * lost as then). And for one attempt at most (WG_PATH_INIT_HOLD_MS from
 * the first INIT held, DERP up all along): the REKEY_TIMEOUT retry of an
 * unanswered held INIT goes both ways — with the peer's keys lost and the
 * ring never drained (every new frame under a keypair not yet confirmed)
 * the hold would otherwise last until the cold fallback, 60 s. A
 * handshake, the risk's end or DERP dropping ends the hold. Review of
 * 1.3.8: the doubt's test sent as it comes lost 3.1 frames per episode
 * with only our direct WireGuard dropped (2 000 random instants); 81134de
 * held only the test, and our DERP down 3 / 8 / 20 s within the episode
 * lost 59 / 166 / 403 in 500 to a deleted keypair (the login kick's INIT,
 * the 5-s retry, a pong's re-send went direct first; now 1 / 3 / 22, all
 * pushed out of the full ring by the outage); fee2336 held every INIT but
 * dropped the held copy behind a re-send of 8+ frames (best-effort write)
 * and, DERP down for good with the peer's keys lost before it confirmed
 * ours, held until the cold fallback: 72 s, now 12.6 s. Withholding the
 * test instead left a third of the simulated WG-silent failures to the
 * RX-stale rekey (a proactive rekey leaves frames of the previous keypair
 * pending for ~20 s). A cold handshake (`rekey` false: none yet, or the
 * rekey gave up after 60 s) goes as before: no session carries data. */
typedef enum {
    WG_INIT_ANY_PATH = 0,
    WG_INIT_DERP_BEHIND_RESEND,
} wg_init_route_t;

#define WG_PATH_INIT_HOLD_MS WG_PATH_REKEY_TIMEOUT_MS

static inline wg_init_route_t wg_path_init_route(wg_path_t *p, const wg_rescue_sum_t *ring,
                                                 bool rekey, bool relay_up, int64_t now,
                                                 uint32_t cur_gen)
{
    if (!rekey || !relay_up ||
        !wg_rescue_init_risk(ring, now, wg_path_rescue_from(p),
                             (int64_t)WG_PATH_RESCUE_MAX_MS * 1000LL, cur_gen,
                             wg_path_keys_confirmed(p))) {
        p->init_hold_us = 0;
        return WG_INIT_ANY_PATH;
    }
    if (p->init_hold_us == 0) p->init_hold_us = now;
    return wg_timer_due(now, p->init_hold_us, (int64_t)WG_PATH_INIT_HOLD_MS * 1000LL)
               ? WG_INIT_ANY_PATH : WG_INIT_DERP_BEHIND_RESEND;
}

/* A transport packet with a payload from the peer, either path. Proves
 * nothing about our sends; only the first after a handshake restarts the
 * window. Ends a doubt (the session lives): see wg_path_resolve_. */
static inline uint32_t wg_path_on_peer_data(wg_path_t *p, int64_t now)
{
    p->peer_wg_us    = now;
    p->peer_tr_us    = now;
    p->silent_streak = 0;
    if (WG_PATH_IN_DOUBT(p)) return wg_path_resolve_(p, now);
    if (p->mode == WG_PATH_DIRECT && p->hs_us != 0 && !p->grace_used &&
        !wg_timer_due(now, p->hs_us, (int64_t)WG_PATH_ANSWER_MS * 1000LL)) {
        p->grace_used = true;
        p->await_us   = 0;
    }
    return 0;
}

/* A handshake response was accepted (cold or rekey, either path). Ends a
 * doubt; the silent streak stays — a fresh session silent too is what
 * stops the rekeys. */
static inline uint32_t wg_path_on_handshake(wg_path_t *p, int64_t now)
{
    p->hs_us      = now;
    p->peer_wg_us = now;
    p->grace_used = false;
    p->init_hold_us = 0;              /* a new session: a new hold may start */
    if (WG_PATH_IN_DOUBT(p)) return wg_path_resolve_(p, now);
    if (p->mode == WG_PATH_DIRECT) p->await_us = 0;
    return 0;
}

/* The endpoint moved to an address no pong has proven (a roam on an
 * authenticated packet, control's endpoint): DUAL, and ping it. Moving
 * off a lapsed endpoint confirms the lapse (WG_PATH_ACT_RESCUE). The
 * doubts stay — only a keepalive proving the direct path clears them, so
 * endpoints taking turns do not reset the back-off. */
static inline uint32_t wg_path_on_endpoint_change(wg_path_t *p, int64_t now)
{
    const uint32_t act = WG_PATH_LAPSE_PENDING(p) ? wg_path_rescue_(p, now) : 0;
    wg_path_enter_dual_(p, now, WG_PATH_WHY_ENDPOINT);
    p->ping_us    = 0;
    p->proof_us   = 0;
    p->rtt_us     = 0;
    p->rtt_at_us  = 0;
    p->cand_valid = false;
    return act;
}

/* RELAY after a failed WireGuard test (SILENT, UNDELIVERED): DISCO was
 * known to work there, so a pong says nothing new — only the re-test's
 * own round (within WG_PATH_PING_TIMEOUT_MS of its ping) ends it. Else the
 * RX-stale probe (every 30 s while nothing decrypts) or a CallMeMaybe
 * punch would re-test at their rate, not the back-off's (simulated hour
 * of WireGuard dropped on the direct path: 85 re-tests, not 42). */
static inline bool wg_path_retest_hold_(const wg_path_t *p, int64_t now)
{
    return p->mode == WG_PATH_RELAY &&
           (p->why == WG_PATH_WHY_SILENT || p->why == WG_PATH_WHY_UNDELIVERED) &&
           !(p->ping_us >= p->since_us &&
             !wg_timer_due(now, p->ping_us, (int64_t)WG_PATH_PING_TIMEOUT_MS * 1000LL));
}

/* A pong we solicited (disco_prober match: our txid, from the address we
 * pinged) from the WG peer. `from_current`: that address is the current
 * endpoint; `src_private` / `cur_private`: wg_path_v4_private of each.
 * *act (may be NULL) gets WG_PATH_ACT_RESCUE when the pong moves the
 * endpoint off a lapsed one. From the current endpoint answering a lapse
 * of our data while nothing came from the peer since the unanswered
 * frame: WG_PATH_PONG_DOUBT (see the header, "Two windows"). */
static inline wg_path_pong_t wg_path_on_pong(wg_path_t *p, int64_t now,
                                             uint32_t rtt_us, bool from_current,
                                             uint32_t src_v4_be, uint16_t src_port,
                                             bool src_private, bool cur_private,
                                             uint32_t *act)
{
    const int64_t round = (int64_t)WG_PATH_ROUND_MS * 1000LL;
    if (act != NULL) *act = 0;
    if (wg_path_retest_hold_(p, now)) {
        if (from_current) {
            p->rtt_us    = rtt_us;
            p->rtt_at_us = now;
        }
        return WG_PATH_PONG_KEPT;
    }
    if (from_current) {
        p->rtt_us    = rtt_us;
        p->rtt_at_us = now;
        if (WG_PATH_IN_DOUBT(p)) {
            p->cand_valid = false;
            return WG_PATH_PONG_KEPT;           /* DISCO again; WireGuard decides */
        }
        if (p->mode == WG_PATH_DUAL && p->why == WG_PATH_WHY_ANSWER &&
            p->peer_wg_us < p->lapse_from_us) {
            if (p->doubts < UINT8_MAX) p->doubts++;
            p->doubts_total++;
            p->why            = WG_PATH_WHY_DOUBT;
            p->await_us       = 0;               /* the next frame opens window 2 */
            p->unconfirmed_us = now - p->lapse_from_us;
            p->cand_valid     = false;
            /* Tested at the next timer pass (the RX task runs one right
             * after the pong), once per silent streak: see the header. */
            p->test_at_us     = p->silent_streak == 0 ? now : 0;
            return WG_PATH_PONG_DOUBT;
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
    /* Not valid (and not in doubt, where the current endpoint did answer):
     * the first pong wins (upstream: bestUntrusted). */
    const bool take =
        (!wg_path_valid(p, now) && !WG_PATH_IN_DOUBT(p)) ||
        (p->rtt_at_us != 0 && !wg_timer_due(now, p->rtt_at_us, round) &&
         wg_path_better(rtt_us, src_private, p->rtt_us, cur_private));
    if (take) {
        if (act != NULL && WG_PATH_LAPSE_PENDING(p)) *act = wg_path_rescue_(p, now);
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
