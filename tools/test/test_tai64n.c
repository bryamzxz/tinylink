// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// KATs for the TAI64N floor / reservation logic in wg_proto.c
// (PR #51): cross-reboot monotonicity of the WireGuard handshake
// timestamp. Host build: time(NULL) is the real wall clock, so the
// tests pin the floor ABOVE it to exercise the clamp deterministically.

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "wg_proto.h"

static int g_fail;
#define CHECK(name, cond) do { \
    if (cond) printf("[%s] OK\n", name); \
    else { printf("[%s] FAIL\n", name); g_fail = 1; } } while (0)

static uint64_t be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static int      g_persist_calls;
static uint64_t g_persist_last;
static int      g_persist_rc;
static int persist_cb(uint64_t reservation_secs)
{
    g_persist_calls++;
    g_persist_last = reservation_secs;
    return g_persist_rc;
}

#define TAI_EPOCH 0x4000000000000000ULL

int main(void)
{
    uint8_t ts[WG_TAI64N_LEN];
    const uint64_t now = (uint64_t)time(NULL);

    /* 1. Floor far in the future: every emit is clamped to floor+1,
     *    floor+2, ... (strictly increasing), never the wall clock. */
    {
        const uint64_t floor = now + 1000000;
        wg_tai64n_init(floor, floor + WG_TAI64N_RESERVE_CHUNK_SECS, NULL);
        wg_tai64n_now(ts);
        uint64_t s1 = be64(ts) - TAI_EPOCH;
        wg_tai64n_now(ts);
        uint64_t s2 = be64(ts) - TAI_EPOCH;
        CHECK("floor/clamped-above-wallclock", s1 == floor + 1);
        CHECK("floor/strictly-monotonic", s2 == s1 + 1);
        CHECK("floor/high-water-tracks", wg_tai64n_high_water_secs() == s2);
        CHECK("floor/tai-epoch-bit", (be64(ts) & TAI_EPOCH) != 0);
    }

    /* 2. Wall clock ahead of the floor: emits follow the clock (>= now)
     *    and stay >= floor. */
    {
        wg_tai64n_init(now - 100, now + WG_TAI64N_RESERVE_CHUNK_SECS, NULL);
        wg_tai64n_now(ts);
        uint64_t s = be64(ts) - TAI_EPOCH;
        CHECK("clock/follows-wallclock", s >= now && s <= now + 5);
    }

    /* 3. Reservation extend: the persist callback fires exactly when an
     *    emit reaches the reservation, once, with reservation = secs +
     *    chunk; subsequent emits inside the new chunk do not call it. */
    {
        const uint64_t floor = now + 2000000;
        g_persist_calls = 0; g_persist_rc = 0;
        wg_tai64n_init(floor, floor + 2, persist_cb);   /* tiny reservation */
        wg_tai64n_now(ts);                              /* floor+1 < res: no persist */
        CHECK("reserve/no-call-inside", g_persist_calls == 0);
        wg_tai64n_now(ts);                              /* floor+2 == res: persist */
        uint64_t s = be64(ts) - TAI_EPOCH;
        CHECK("reserve/call-at-boundary", g_persist_calls == 1 &&
              g_persist_last == s + WG_TAI64N_RESERVE_CHUNK_SECS);
        wg_tai64n_now(ts);
        CHECK("reserve/one-call-per-chunk", g_persist_calls == 1);
    }

    /* 4. Persist failure: the counter still advances (bounded fallout),
     *    and the callback is retried on the next emit. */
    {
        const uint64_t floor = now + 3000000;
        g_persist_calls = 0; g_persist_rc = -1;
        wg_tai64n_init(floor, floor + 1, persist_cb);
        wg_tai64n_now(ts);
        uint64_t s1 = be64(ts) - TAI_EPOCH;
        wg_tai64n_now(ts);
        uint64_t s2 = be64(ts) - TAI_EPOCH;
        CHECK("persist-fail/still-monotonic", s2 == s1 + 1 && s1 == floor + 1);
        CHECK("persist-fail/retried", g_persist_calls == 2);
    }

    /* 5. Wire layout: 8-byte BE seconds then 4-byte BE nanos (< 1e9). */
    {
        uint32_t n = ((uint32_t)ts[8] << 24) | ((uint32_t)ts[9] << 16) |
                     ((uint32_t)ts[10] << 8) | ts[11];
        CHECK("layout/nanos-in-range", n < 1000000000u);
    }

    if (g_fail) { printf("\nFAIL\n"); return 1; }
    printf("\n[PASS] all tai64n assertions passed\n");
    return 0;
}
