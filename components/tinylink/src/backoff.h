// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Pure exponential-backoff-with-jitter helper for reconnect loops.
//
// Replaces fixed-interval reconnect delays (which sync a fleet into a
// thundering herd against the control plane and recover slowly from a
// transient blip) with capped exponential backoff plus decorrelating
// jitter — the same shape upstream tailscale controlclient uses. Pure
// and deterministic given `rnd`, so the reconnect policy is host-tested
// without a clock or RNG; the caller injects esp_random() on target.

#pragma once

#include <stdint.h>

/* Backoff for the Nth consecutive failure (attempt = 0,1,2,...).
 *
 *   step = min(base_ms << attempt, cap_ms)        // capped exponential
 *   return step scaled by a jitter factor in [75%, 125%] derived from rnd
 *
 * attempt==0 returns ~base_ms; the caller resets attempt to 0 once a
 * connection is healthy again so the next blip recovers from base, not
 * from the cap. Overflow-safe: the shift saturates at cap_ms. */
static inline uint32_t tl_backoff_ms(uint32_t attempt, uint32_t base_ms,
                                     uint32_t cap_ms, uint32_t rnd)
{
    uint32_t step = base_ms;
    for (uint32_t i = 0; i < attempt; i++) {
        if (step >= cap_ms / 2) { step = cap_ms; break; }  /* saturate, no overflow */
        step *= 2;
    }
    if (step > cap_ms) step = cap_ms;

    /* Decorrelating jitter: factor in [75%, 125%] of the capped step. */
    uint32_t pct = 75u + (rnd % 51u);
    return (uint32_t)((uint64_t)step * pct / 100u);
}
