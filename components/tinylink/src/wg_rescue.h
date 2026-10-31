// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Rescue ring (round 1.3.6, WG_PATH_RESCUE_MAX_MS in wg_path.h): copies
// of the last data frames that went direct only, re-sent via DERP when a
// lapse of the direct path is confirmed — those sent since the last proof
// of their delivery (1.3.8; the last 40 s until 1.3.7). Telemetry-sized
// frames only — the 160-B JSON buffer is at most 224 B on the wire, a
// typical sample 112 B; a bigger frame (a /stats reply) belongs to an
// exchange whose requester retries; nor the TSMP advert sent on every
// new keypair (not application data). 10 slots (8 until 1.3.7): the
// first episode with only our direct WireGuard toward the peer dropped
// (direct → doubt → direct → lapse → doubt → UNDELIVERED) can leave 9
// direct-only samples since the last proof — test_wg_path's keypair-aware
// sim, 2 000 random block instants: 8 slots lose 59 frames, 9 lose 19,
// 10 none. 240 B each, on the heap. Header-only and platform-free: wg_netif.c owns one (wg_tx
// alone writes and reads it), tools/test/test_wg_path.c drives it.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "wg_timers.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WG_RESCUE_SLOTS 10
#define WG_RESCUE_MAX   224

/* How long a frame handed to the relay counts as still on its way: the
 * DERP stream is TCP, and a segment the Wi-Fi lost waits for its
 * retransmission (lwIP: 1 s and more); a direct INIT sent meanwhile
 * could reach the peer first (review of 1.3.8, second pass). One
 * REKEY_TIMEOUT, from when the re-send's last frame left
 * (wg_rescue_sent_by). A guard: no simulated scenario changes with it at
 * 0 (an INIT seldom follows a re-send within a DERP transit). */
#define WG_RESCUE_TRANSIT_MS 5000

typedef struct {
    int64_t  at_us;                   /* sent at; 0 = empty */
    uint32_t gen;                     /* keypair generation that sealed it */
    uint16_t len;
    bool     owed;                    /* a re-send was refused: not proven by a
                                         later proof of delivery (1.3.8 review) */
    uint8_t  buf[WG_RESCUE_MAX];
} wg_rescue_t;

typedef struct {
    wg_rescue_t slot[WG_RESCUE_SLOTS];
    uint8_t     head;                 /* next to write = the oldest */
    uint32_t    sent_gen[2];          /* the two newest keypairs a re-send handed
                                         to the relay ([0] newest; 0 = none)... */
    int64_t     sent_us[2];           /* ...and when */
} wg_rescue_ring_t;

/* Keep a copy of a frame sent direct only (or whose DERP copy was
 * refused), sealed under keypair `gen`; the oldest goes when the ring is
 * full. */
static inline void wg_rescue_keep(wg_rescue_ring_t *r, const uint8_t *buf, size_t len,
                                  int64_t now, uint32_t gen)
{
    if (len > WG_RESCUE_MAX) return;
    wg_rescue_t *s = &r->slot[r->head];
    memcpy(s->buf, buf, len);
    s->len   = (uint16_t)len;
    s->at_us = now;
    s->gen   = gen;
    s->owed  = false;
    r->head  = (uint8_t)((r->head + 1) % WG_RESCUE_SLOTS);
}

/* A frame still to re-send at a confirmed lapse: owed, or sent at or
 * after from_us (before it: proven delivered, wg_path_rescue_from), and
 * younger than max_age_us. */
static inline bool wg_rescue_pending_(const wg_rescue_t *s, int64_t now, int64_t from_us,
                                      int64_t max_age_us)
{
    return s->at_us != 0 && (s->owed || s->at_us >= from_us) &&
           !wg_timer_due(now, s->at_us, max_age_us);
}

/* Re-send, oldest first, the pending frames (wg_rescue_pending_) through
 * `send` (true: the relay took it); the others are dropped. The first
 * refusal (DERP not connected) stops the pass and keeps it and the rest
 * for the next one, owed — until 1.3.6's review the ring was emptied
 * either way, losing what the relay refused; until 1.3.8's review a
 * direct proof arriving before the relay came back marked them delivered
 * (it proves the path works again, not that frames the dead path ate got
 * through). Returns the frames sent; *kept (may be NULL) gets those left
 * for later. */
static inline unsigned wg_rescue_flush(wg_rescue_ring_t *r, int64_t now, int64_t from_us,
                                       int64_t max_age_us,
                                       bool (*send)(const uint8_t *buf, size_t len, void *user),
                                       void *user, unsigned *kept)
{
    unsigned sent = 0, left = 0;
    for (unsigned i = 0; i < WG_RESCUE_SLOTS; i++) {
        wg_rescue_t *s = &r->slot[(r->head + i) % WG_RESCUE_SLOTS];
        if (s->at_us == 0) continue;
        if (!wg_rescue_pending_(s, now, from_us, max_age_us)) {
            s->at_us = 0;                     /* delivered, or too old to matter */
            continue;
        }
        if (left == 0 && send(s->buf, s->len, user)) {
            sent++;
            s->at_us = 0;
            if (s->gen != r->sent_gen[0]) {   /* oldest first: gens only grow */
                r->sent_gen[1] = r->sent_gen[0];
                r->sent_us[1]  = r->sent_us[0];
                r->sent_gen[0] = s->gen;
            }
            r->sent_us[0] = now;
        } else {
            left++;
            s->owed = true;
        }
    }
    if (kept != NULL) *kept = left;
    return sent;
}

/* The frames a flush at `flushed_at` handed to the relay left by `left_at`
 * (a waiting write blocks while lwIP's send queue is full): their transit
 * window starts then — review of 1.3.8, third pass. */
static inline void wg_rescue_sent_by(wg_rescue_ring_t *r, int64_t flushed_at, int64_t left_at)
{
    for (unsigned i = 0; i < 2; i++) {
        if (r->sent_gen[i] != 0 && r->sent_us[i] == flushed_at) r->sent_us[i] = left_at;
    }
}

/* What the ring holds, per keypair, for a task that does not own it
 * (wg_tx owns the ring; wg_rx decides on a handshake): the two newest
 * keypairs with frames in it, and for each the newest frame and the
 * newest owed one (0: none). Frames are kept in send order, so "a frame
 * of keypair g still pending" is a test on these two instants. Also the
 * two newest keypairs the last re-sends handed to the relay, and when. */
typedef struct {
    uint32_t gen[2];                  /* [0] the newest; 0 = no frame */
    int64_t  newest_us[2];
    int64_t  owed_us[2];
    uint32_t sent_gen[2];
    int64_t  sent_us[2];
} wg_rescue_sum_t;

static inline void wg_rescue_summarize(const wg_rescue_ring_t *r, wg_rescue_sum_t *out)
{
    memset(out, 0, sizeof(*out));
    for (unsigned i = 0; i < 2; i++) {
        out->sent_gen[i] = r->sent_gen[i];
        out->sent_us[i]  = r->sent_us[i];
    }
    for (unsigned i = 0; i < WG_RESCUE_SLOTS; i++) {
        const wg_rescue_t *s = &r->slot[(r->head + i) % WG_RESCUE_SLOTS];   /* oldest first */
        if (s->at_us == 0) continue;
        if (s->gen != out->gen[0]) {          /* a newer keypair starts */
            out->gen[1] = out->gen[0];
            out->newest_us[1] = out->newest_us[0];
            out->owed_us[1] = out->owed_us[0];
            out->gen[0] = s->gen;
            out->newest_us[0] = 0;
            out->owed_us[0] = 0;
        }
        out->newest_us[0] = s->at_us;
        if (s->owed) out->owed_us[0] = s->at_us;
    }
}

/* Would a new INIT, once the peer consumes it, delete a keypair that
 * still seals a pending frame? wireguard-go as responder
 * (noise-protocol.go BeginSymmetricSession) parks the new keypair as
 * `next` and deletes the old `next` and `previous`; the first packet
 * under `next` promotes it (previous = current). With our keypair
 * `cur_gen` confirmed — a packet of the peer under it, sealed with its
 * `current` — the INIT deletes cur_gen - 1. Unconfirmed, the peer holds
 * cur_gen - 1 as current and cur_gen as next (the INIT deletes cur_gen),
 * or has promoted it unseen (the INIT deletes cur_gen - 1). Older
 * keypairs are gone already. A frame of such a keypair re-sent less than
 * WG_RESCUE_TRANSIT_MS ago counts too: it may still be on the DERP
 * stream, behind which only a DERP copy of the INIT is sure to stay. A
 * re-sent frame sealed under a deleted
 * keypair is dropped by the peer: the review of 1.3.8 measured 3.1 lost
 * frames per episode with only our direct WireGuard dropped, two doubts'
 * handshakes in a row (2 000 random instants; 1.3.7, 8 slots and a fixed
 * 40 s: 2.3). */
static inline bool wg_rescue_gen_at_risk_(uint32_t g, uint32_t cur_gen, bool confirmed)
{
    return g != 0 && (g == cur_gen - 1u || (!confirmed && g == cur_gen));
}

static inline bool wg_rescue_init_risk(const wg_rescue_sum_t *sum, int64_t now,
                                       int64_t from_us, int64_t max_age_us,
                                       uint32_t cur_gen, bool confirmed)
{
    for (unsigned i = 0; i < 2; i++) {
        if (wg_rescue_gen_at_risk_(sum->sent_gen[i], cur_gen, confirmed) &&
            !wg_timer_due(now, sum->sent_us[i], (int64_t)WG_RESCUE_TRANSIT_MS * 1000LL)) {
            return true;
        }
        const uint32_t g = sum->gen[i];
        if (!wg_rescue_gen_at_risk_(g, cur_gen, confirmed)) continue;
        const int64_t last = sum->owed_us[i] != 0 && sum->newest_us[i] < from_us
                                 ? sum->owed_us[i] : sum->newest_us[i];
        if ((sum->owed_us[i] != 0 || sum->newest_us[i] >= from_us) &&
            !wg_timer_due(now, last, max_age_us)) {
            return true;
        }
    }
    return false;
}

#ifdef __cplusplus
}
#endif
