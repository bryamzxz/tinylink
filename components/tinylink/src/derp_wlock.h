// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// The DERP write lock (round 1.3.9): who may write a frame on the relay
// conn, how long anyone waits for the lock, and how a close stops a
// writer stuck on a stalled conn.
//
// Two tasks write DERP frames, both subscribed to the 60-s task WDT:
// wg_tx (tinylink_relay_via_derp: relayed frames, the re-send, held INIT
// copies) and the supervisor (pongs to the server's pings, DISCO pongs,
// and the close that frees the conn). A waiting write on a stalled conn
// holds the lock up to DERP_MAX_IDLE_POLLS x SO_SNDTIMEO (4 x 30 s),
// feeding its own WDT on every poll (tls_io's hook). Until 1.3.9 the
// other task waited for the lock with portMAX_DELAY and fed nothing: a
// supervisor closing a conn that went half-open under a waiting write of
// wg_tx's could sit out its 60-s budget and reset the board.
//
//   - Every wait for the lock goes in slices with a WDT feed between
//     them, and a writer stops waiting, without the lock, once the conn
//     it set out for is closing or gone (derp_wl_acquire). The feeds
//     stop after `fed_max_ms` of waiting in total, with one call to
//     derp_wl_overdue: a lock never given back (a leak) then ends in the
//     task WDT's reset instead of a DERP hung for good.
//   - `connected` is the writers' abort flag: a frame's write stops at its
//     next poll once the conn is closing (derp_wl_may_write).
//   - A close drops `connected`, gives a writer mid-frame a grace to end
//     it, then cuts the conn's I/O (the socket's shutdown: lwIP fails a
//     blocked send at once) and waits for the lock in slices. It always
//     gets it: nothing is freed under a writer (derp_wl_close_lock).
//   - A failed write closes the conn to frames (derp_wl_write_failed). It
//     may have left part of a TLS record on the stream, and mbedtls then
//     flushes that record's tail on the next write and reports the NEW
//     frame as written (ssl_write_real, out_left != 0): nothing may follow
//     it there. derp_client.c also tells the reader to leave (abort_reads,
//     at its next poll), so the supervisor reconnects; the socket is not
//     cut there — a shutdown on wg_tx would run lwIP's TCP close and the
//     Wi-Fi TX under it on that task's 5-KiB stack (+288 B static worst).
//   - `gen` counts connects: a frame that set out on one conn is never
//     written on the next one.
//
// Header-only. The type and derp_wl_up are for anyone (derp_client.h);
// the protocol is compiled where DERP_WL_IMPL is defined, and the five
// primitives it declares are the includer's — a FreeRTOS mutex,
// tl_wdt_feed, shutdown() and an E line in derp_client.c; pthreads with
// counters and forced interleavings in tools/test/test_derp_wlock.c,
// which builds derp_client.c itself over host fakes — so the host test
// drives this exact code.

#ifndef DERP_WLOCK_H_TYPES
#define DERP_WLOCK_H_TYPES

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    void    *lock;        /* created on the first connect, never deleted */
    bool     connected;   /* frames admitted (atomic access only) */
    uint32_t gen;         /* bumped by every connect (atomic access only) */
} derp_wl_t;

typedef enum {
    DERP_WL_HELD = 0,     /* lock taken, the conn `gen` still takes frames */
    DERP_WL_BUSY,         /* no_wait, and another writer holds the lock */
    DERP_WL_CLOSED,       /* that conn closed or was replaced; lock not held */
} derp_wl_turn_t;

static inline bool derp_wl_up(const derp_wl_t *w)
{
    return __atomic_load_n(&w->connected, __ATOMIC_ACQUIRE);
}

#endif /* DERP_WLOCK_H_TYPES */

#if defined(DERP_WL_IMPL) && !defined(DERP_WLOCK_H_IMPL)
#define DERP_WLOCK_H_IMPL

/* Take `lock` within `ms` (0: only if free now); true when taken. */
static bool derp_wl_take(void *lock, uint32_t ms);
static void derp_wl_give(void *lock);
/* Feed the calling task's watchdog. */
static void derp_wl_feed(void);
/* Make the conn's blocked and later I/O fail at once. */
static void derp_wl_cut(void *io);
/* A wait passed its fed_max_ms (`waited_ms` so far): the last feed. */
static void derp_wl_overdue(uint32_t waited_ms);

static inline uint32_t derp_wl_gen(const derp_wl_t *w)
{
    return __atomic_load_n(&w->gen, __ATOMIC_ACQUIRE);
}

/* The connecting task, before the new conn exists: whatever set out on
 * the last one stays refused. */
static inline void derp_wl_new_conn(derp_wl_t *w)
{
    __atomic_store_n(&w->connected, false, __ATOMIC_RELEASE);
    __atomic_store_n(&w->gen, derp_wl_gen(w) + 1u, __ATOMIC_RELEASE);
}

/* The connecting task, once logged in: frames admitted. */
static inline void derp_wl_set_up(derp_wl_t *w)
{
    __atomic_store_n(&w->connected, true, __ATOMIC_RELEASE);
}

/* One more wait of `ms` for the lock: fed while the wait's total stays
 * under fed_max_ms; past it, said once and no more feeds. */
static inline void derp_wl_waited(uint32_t *total, uint32_t ms, uint32_t fed_max_ms)
{
    if (*total >= fed_max_ms) return;
    *total = ms > fed_max_ms - *total ? fed_max_ms : *total + ms;
    if (*total < fed_max_ms) {
        derp_wl_feed();
    } else {
        derp_wl_overdue(*total);
    }
}

/* A writer's first step, unlocked: the conn it sets out for (`*gen`, read
 * before `connected`) and whether that one takes frames. */
static inline bool derp_wl_admits(const derp_wl_t *w, uint32_t *gen)
{
    *gen = derp_wl_gen(w);
    return derp_wl_up(w);
}

/* A writer's turn on conn `gen`: the lock, waited for in `slice_ms`
 * slices with a feed after each (derp_wl_waited), or one try with
 * no_wait. A wait ends without the lock once that conn is closing or
 * replaced. */
static inline derp_wl_turn_t derp_wl_acquire(derp_wl_t *w, uint32_t gen,
                                             bool no_wait, uint32_t slice_ms,
                                             uint32_t fed_max_ms)
{
    void *const lock = w->lock;
    uint32_t waited = 0;
    for (;;) {
        if (derp_wl_take(lock, no_wait ? 0u : slice_ms)) {
            if (derp_wl_up(w) && derp_wl_gen(w) == gen) return DERP_WL_HELD;
            derp_wl_give(lock);
            return DERP_WL_CLOSED;
        }
        if (!derp_wl_up(w) || derp_wl_gen(w) != gen) return DERP_WL_CLOSED;
        if (no_wait) return DERP_WL_BUSY;
        derp_wl_waited(&waited, slice_ms, fed_max_ms);
    }
}

/* A writer holding the lock, before each write call of its frame: false
 * once the conn is closing — the frame is cut short, a failed write. */
static inline bool derp_wl_may_write(const derp_wl_t *w)
{
    return derp_wl_up(w);
}

/* A write of the conn failed (lock held): no frame may follow it there.
 * True when this closed the conn to frames; false when a close got there
 * first. A close racing the load only stores the same false; it cannot
 * finish, nor the next connect start, before the lock is given. */
static inline bool derp_wl_write_failed(derp_wl_t *w)
{
    if (!derp_wl_up(w)) return false;
    __atomic_store_n(&w->connected, false, __ATOMIC_RELEASE);
    return true;
}

/* derp_client_close's wait, on the only task that closes: refuse new
 * frames, let a writer mid-frame end it within grace_ms, then cut `io`
 * (NULL: no conn) and wait for the lock in slice_ms slices, fed as in
 * derp_wl_acquire. Returns with the lock held — always — and whether a
 * writer was cut. */
static inline bool derp_wl_close_lock(derp_wl_t *w, void *io, uint32_t grace_ms,
                                      uint32_t slice_ms, uint32_t fed_max_ms)
{
    void *const lock = w->lock;
    __atomic_store_n(&w->connected, false, __ATOMIC_RELEASE);
    if (derp_wl_take(lock, grace_ms)) return false;
    uint32_t waited = 0;
    derp_wl_waited(&waited, grace_ms, fed_max_ms);
    if (io != NULL) derp_wl_cut(io);
    while (!derp_wl_take(lock, slice_ms)) derp_wl_waited(&waited, slice_ms, fed_max_ms);
    return true;
}

#endif /* DERP_WL_IMPL */
