/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for jsmn_skip.h — the depth-bounded JSON value skipper used by
 * the MapResponse parser (mapreq.c skip_value). The security property: an
 * adversarial control plane sending deeply-nested JSON must NOT be able to
 * recurse the skipper deep enough to overflow the 24 KiB long-poll task
 * stack. We can't reproduce a stack overflow on the host (8 MB stack), so
 * we test the bound directly: skipping is exact at/below the cap and
 * provably bounded (returns early, stays in range) past it.
 */

#include <stdio.h>
#include <string.h>

#define JSMN_STATIC
#include "jsmn.h"
#include "jsmn_skip.h"

static int fails = 0;

static int ok(const char *name, int cond) {
    if (cond) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL\n", name);
    return 1;
}

static jsmntok_t g_toks[1024];

/* Parse js, return jsmn_skip(toks,0); set *ntoks to the token count. */
static int skip_of(const char *js, int *ntoks) {
    jsmn_parser p;
    jsmn_init(&p);
    int n = jsmn_parse(&p, js, strlen(js), g_toks, 1024);
    *ntoks = n;
    if (n < 1) return -999;
    return jsmn_skip(g_toks, 0);
}

/* Write D '[' then D ']' (a D-deep nested array) into buf. */
static void nested(char *buf, int D) {
    for (int i = 0; i < D; i++) buf[i] = '[';
    for (int i = 0; i < D; i++) buf[D + i] = ']';
    buf[2 * D] = '\0';
}

int main(void) {
    int nt;
    char buf[2048];

    /* --- Regression: legitimate skipping is unchanged. --- */
    fails += ok("flat-array",   skip_of("[1,2,3]", &nt) == nt && nt == 4);
    fails += ok("object",       skip_of("{\"a\":1,\"b\":[1,2],\"c\":\"x\"}", &nt) == nt && nt > 0);
    fails += ok("shallow-nest", skip_of("[[[[[]]]]]", &nt) == nt && nt == 5);

    /* --- At the cap boundary: still an exact skip (cap not exceeded). A
     * legitimately deep (but under-limit) netmap is never truncated. --- */
    nested(buf, JSMN_SKIP_MAX_DEPTH + 1);   /* deepest token sits at depth==MAX */
    int r_boundary = skip_of(buf, &nt);
    fails += ok("at-boundary-tokcount", nt == JSMN_SKIP_MAX_DEPTH + 1);
    fails += ok("at-boundary-exact",    r_boundary == nt);

    /* --- Past the cap: the skip is BOUNDED. With no guard the skipper
     * would recurse the full 600 levels (the bug); with the guard it bails
     * early, so the returned index is strictly less than the full subtree
     * end yet always in [1, ntoks] (never out of bounds / negative). --- */
    nested(buf, 600);
    int r_deep = skip_of(buf, &nt);
    fails += ok("deep-parsed",     nt == 600);
    fails += ok("deep-bounded",    r_deep > 0 && r_deep < nt);
    fails += ok("deep-in-bounds",  r_deep >= 1 && r_deep <= nt);

    if (fails == 0) { printf("\n[PASS] all jsmn_skip assertions passed\n"); return 0; }
    printf("\n[FAIL] %d jsmn_skip assertion(s) failed\n", fails);
    return 1;
}
