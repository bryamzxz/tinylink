/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for backoff.h — capped exponential backoff with jitter used
 * by the control-plane reconnect loop (RC-2). Deterministic given the
 * injected `rnd`, so we can pin exact values:
 *   - jitter factor = 75 + (rnd % 51)  →  rnd%51==25 gives exactly 100%.
 *   - exponential doubling per attempt, saturating at the cap.
 *   - jitter always within [75%, 125%] of the (capped) step.
 */

#include <stdio.h>
#include <stdint.h>

#include "backoff.h"

static int fails = 0;

static int ok(const char *name, int condition) {
    if (condition) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL\n", name);
    return 1;
}

/* rnd value that yields jitter factor exactly 100% (rnd % 51 == 25). */
#define RND_NEUTRAL 25u

int main(void) {
    const uint32_t base = 1000, cap = 30000;

    /* Exponential doubling at neutral jitter. */
    fails += ok("attempt0=base",  tl_backoff_ms(0, base, cap, RND_NEUTRAL) == 1000);
    fails += ok("attempt1=2x",    tl_backoff_ms(1, base, cap, RND_NEUTRAL) == 2000);
    fails += ok("attempt2=4x",    tl_backoff_ms(2, base, cap, RND_NEUTRAL) == 4000);
    fails += ok("attempt3=8x",    tl_backoff_ms(3, base, cap, RND_NEUTRAL) == 8000);
    fails += ok("attempt4=16x",   tl_backoff_ms(4, base, cap, RND_NEUTRAL) == 16000);

    /* Saturates at the cap (16x*2=32000 > 30000). */
    fails += ok("attempt5=cap",   tl_backoff_ms(5, base, cap, RND_NEUTRAL) == 30000);
    fails += ok("attempt99=cap",  tl_backoff_ms(99, base, cap, RND_NEUTRAL) == 30000);

    /* Jitter bounds: factor in [75%, 125%]. rnd%51==0 → 75%, ==50 → 125%. */
    fails += ok("jitter-min",     tl_backoff_ms(0, base, cap, 0u)  == 750);   /* 1000*75/100 */
    fails += ok("jitter-max",     tl_backoff_ms(0, base, cap, 50u) == 1250);  /* 1000*125/100 */

    /* Jitter applies to the capped step too, and stays in-bounds for all rnd. */
    int in_bounds = 1;
    for (uint32_t r = 0; r < 1000; r++) {
        uint32_t v = tl_backoff_ms(7, base, cap, r);   /* attempt 7 → capped at 30000 */
        if (v < 30000u * 75u / 100u || v > 30000u * 125u / 100u) { in_bounds = 0; break; }
    }
    fails += ok("jitter-bounds-at-cap", in_bounds);

    if (fails == 0) { printf("\n[PASS] all backoff assertions passed\n"); return 0; }
    printf("\n[FAIL] %d backoff assertion(s) failed\n", fails);
    return 1;
}
