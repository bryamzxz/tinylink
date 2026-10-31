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

/* Parse js and run jsmn_tree_ok; *ntoks = the token count. */
static int tree_of(const char *js, int *ntoks) {
    jsmn_parser p;
    jsmn_init(&p);
    int n = jsmn_parse(&p, js, strlen(js), g_toks, 1024);
    *ntoks = n;
    return n >= 1 && jsmn_tree_ok(g_toks, n);
}

/* Reference for jsmn_tree_ok: jsmn_skip_d's walk, recursive, every index
 * checked against ntok; -1 where it would leave the tokens or nest past
 * the cap. */
static int ref_walk(const jsmntok_t *t, int i, int ntok, int depth) {
    if (i >= ntok || depth > JSMN_SKIP_MAX_DEPTH) return -1;
    int next = i + 1;
    if (t[i].type == JSMN_OBJECT) {
        for (int k = 0; k < t[i].size; k++) {
            if ((next = ref_walk(t, next + 1, ntok, depth + 1)) < 0) return -1;
        }
    } else if (t[i].type == JSMN_ARRAY) {
        for (int k = 0; k < t[i].size; k++) {
            if ((next = ref_walk(t, next, ntok, depth + 1)) < 0) return -1;
        }
    }
    return next;
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

    /* --- jsmn_tree_ok (round 1.3.4): a walk in key/value pairs that
     * stays inside the tokens jsmn produced. --- */
    int n;
    fails += ok("tree/valid-object", tree_of("{\"a\":1,\"b\":[1,{\"c\":\"x\"}],\"d\":{}}", &n) == 1);
    fails += ok("tree/valid-scalars", tree_of("\"s\"", &n) == 1 && tree_of("42", &n) == 1 &&
                                      tree_of("[]", &n) == 1 && tree_of("{}", &n) == 1);
    /* A member without its colon: jsmn counts key and value as two
     * children, a pair walk runs one token past the end. */
    fails += ok("tree/missing-colon-refused", tree_of("{\"a\" 1}", &n) == 0 && n == 3);
    fails += ok("tree/missing-colon-nested-refused", tree_of("[1,{\"x\":{\"a\" \"b\",\"c\":2}}]", &n) == 0);
    /* The extra "pairs" borrow the parent's tokens, so the shortfall
     * always surfaces before the root ends. */
    fails += ok("tree/missing-colon-borrowing-refused", tree_of("[{\"a\" 1},2,3]", &n) == 0 &&
                                                        tree_of("{\"a\" 1 \"b\" 2}", &n) == 0);
    nested(buf, JSMN_SKIP_MAX_DEPTH + 1);
    fails += ok("tree/depth-at-cap", tree_of(buf, &n) == 1);
    nested(buf, JSMN_SKIP_MAX_DEPTH + 2);
    fails += ok("tree/depth-over-cap-refused", tree_of(buf, &n) == 0);
    fails += ok("tree/no-tokens", jsmn_tree_ok(g_toks, 0) == false);

    /* Random JSON-ish text: jsmn_tree_ok must agree with a recursive,
     * bounds-checked pair walk, and on an accepted tree jsmn_skip ends
     * inside the tokens. 300 000 strings. */
    {
        static const char alpha[] = "{}[]\",: 1a";
        unsigned seed = 777; int agree = 1, skip_in = 1; long accepted = 0;
        char s[40];
        for (int t = 0; t < 300000; t++) {
            size_t len = 1 + ((seed = seed * 1103515245u + 12345u) >> 16) % (sizeof(s) - 1);
            for (size_t i = 0; i < len; i++) {
                seed = seed * 1103515245u + 12345u;
                s[i] = alpha[(seed >> 16) % (sizeof(alpha) - 1)];
            }
            s[len] = '\0';
            jsmn_parser p; jsmn_init(&p);
            int nt = jsmn_parse(&p, s, len, g_toks, 1024);
            if (nt < 1) continue;
            int okw = ref_walk(g_toks, 0, nt, 0) >= 0;
            agree &= (okw == jsmn_tree_ok(g_toks, nt));
            if (okw) { accepted++; skip_in &= jsmn_skip(g_toks, 0) <= nt; }
        }
        fails += ok("tree/random-agrees-with-bounded-walk", agree && accepted > 1000);
        fails += ok("tree/accepted-skip-stays-in-tokens", skip_in);
    }

    if (fails == 0) { printf("\n[PASS] all jsmn_skip assertions passed\n"); return 0; }
    printf("\n[FAIL] %d jsmn_skip assertion(s) failed\n", fails);
    return 1;
}
