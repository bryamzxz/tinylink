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
// direct-only samples since the last proof — test_wg_path, 2 000 random
// block instants: 8 slots lose up to 3, 9 up to 1, 10 none. 240 B each,
// on the heap. Header-only and platform-free: wg_netif.c owns one (wg_tx
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

typedef struct {
    int64_t  at_us;                   /* sent at; 0 = empty */
    uint16_t len;
    uint8_t  buf[WG_RESCUE_MAX];
} wg_rescue_t;

typedef struct {
    wg_rescue_t slot[WG_RESCUE_SLOTS];
    uint8_t     head;                 /* next to write = the oldest */
} wg_rescue_ring_t;

/* Keep a copy of a frame sent direct only (or whose DERP copy was
 * refused); the oldest goes when the ring is full. */
static inline void wg_rescue_keep(wg_rescue_ring_t *r, const uint8_t *buf, size_t len,
                                  int64_t now)
{
    if (len > WG_RESCUE_MAX) return;
    wg_rescue_t *s = &r->slot[r->head];
    memcpy(s->buf, buf, len);
    s->len   = (uint16_t)len;
    s->at_us = now;
    r->head  = (uint8_t)((r->head + 1) % WG_RESCUE_SLOTS);
}

/* Re-send, oldest first, the frames sent at or after from_us (frames
 * before it are proven delivered: wg_path_rescue_from) and younger than
 * max_age_us through `send` (true: the relay took it); the others are
 * dropped. The first refusal (DERP not connected) stops the pass and
 * keeps it and the rest for the next one — until 1.3.6's review the ring
 * was emptied either way, losing what the relay refused. Returns the
 * frames sent; *kept (may be NULL) gets those left for later. */
static inline unsigned wg_rescue_flush(wg_rescue_ring_t *r, int64_t now, int64_t from_us,
                                       int64_t max_age_us,
                                       bool (*send)(const uint8_t *buf, size_t len, void *user),
                                       void *user, unsigned *kept)
{
    unsigned sent = 0, left = 0;
    for (unsigned i = 0; i < WG_RESCUE_SLOTS; i++) {
        wg_rescue_t *s = &r->slot[(r->head + i) % WG_RESCUE_SLOTS];
        if (s->at_us == 0) continue;
        if (s->at_us < from_us || wg_timer_due(now, s->at_us, max_age_us)) {
            s->at_us = 0;                     /* delivered, or too old to matter */
            continue;
        }
        if (left == 0 && send(s->buf, s->len, user)) {
            sent++;
            s->at_us = 0;
        } else {
            left++;
        }
    }
    if (kept != NULL) *kept = left;
    return sent;
}

#ifdef __cplusplus
}
#endif
