// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include <stdbool.h>

#include "jsmn.h"

/* Maximum JSON nesting jsmn_skip will recurse through. A real MapResponse
 * nests only a handful of levels (object -> Peers array -> peer object ->
 * Addresses array -> string), so 64 is far above anything legitimate. The
 * cap exists purely to stop an adversarial control plane from sending
 * deeply-nested JSON that recurses jsmn_skip deep enough to overflow the
 * 24 KiB long-poll task stack (a frame is ~32-48 B on Xtensa, so a few
 * hundred levels overflow). At 64 the recursion is bounded to ~3 KiB. */
#define JSMN_SKIP_MAX_DEPTH 64

/* Return the token index just past the value at toks[i] (i.e. skip the
 * whole subtree rooted at i). `depth` tracks the current nesting level so
 * the walk can stop recursing once it exceeds JSMN_SKIP_MAX_DEPTH. On that
 * overflow it returns i + 1 — a deliberately shallow, always-in-bounds
 * advance: the returned index is never larger than the true subtree end
 * (so callers never read out of bounds) and the recursion can never blow
 * the stack. The only effect on a pathologically deep (adversarial) value
 * is that the rest of its subtree is parsed as if it were a sibling, which
 * for malformed input is a bounded misparse, not a crash. Legitimate
 * netmaps never reach the cap, so their skipping is exact.
 *
 * Plain `static` (not `static inline`) on purpose: the `inline` hint makes
 * -O2 recursively inline this self-call up to ~8 levels deep, bloating the
 * image by ~8-11 KiB for zero speed gain on a once-per-field cold walk. */
static int jsmn_skip_d(const jsmntok_t *toks, int i, int depth)
{
    if (depth > JSMN_SKIP_MAX_DEPTH) return i + 1;
    int children = toks[i].size;
    int next = i + 1;
    if (toks[i].type == JSMN_OBJECT) {
        for (int k = 0; k < children; k++) {
            /* A JSON object key is always a single string token (a leaf),
             * so skipping it is just +1 — no recursive call. This also
             * keeps the object branch to ONE self-call like the array
             * branch; with two self-calls the -O2 recursive inliner
             * expands this exponentially (~2^depth copies, ~+11 KiB). */
            next += 1;                                   /* key (string)  */
            next = jsmn_skip_d(toks, next, depth + 1);   /* value         */
        }
        return next;
    }
    if (toks[i].type == JSMN_ARRAY) {
        for (int k = 0; k < children; k++) {
            next = jsmn_skip_d(toks, next, depth + 1);
        }
        return next;
    }
    return i + 1;
}

static inline int jsmn_skip(const jsmntok_t *toks, int i)
{
    return jsmn_skip_d(toks, i, 0);
}

/* Can the token tree jsmn_parse just produced (ntok tokens) be walked the
 * way jsmn_skip and mapreq.c's parsers walk it? (Round 1.3.4, found by
 * D2's differential fuzz.) They take an object's children as key / value
 * PAIRS (key = one token, value = a subtree) and never look at the token
 * count; jsmn in non-strict mode counts a member written without its colon
 * (`{"NodeID"02,…}`) as TWO children. Such an object sends every walker
 * past the last token jsmn wrote: into stale tokens of an earlier
 * sub-parse in the static table, whose sizes lead further, past the end
 * of the table, and whose start/end offsets reach tok_copy /
 * parse_keyed_hex / strncmp as `js + start`. This walks the same pairs,
 * bounded by ntok and by JSMN_SKIP_MAX_DEPTH, and says no where a walker
 * would leave the table or nest past the cap — on a tree it accepts,
 * every walk stays below ntok and jsmn_skip is exact. Iterative (a
 * 260-B stack array instead of up to 65 recursive frames). Valid JSON
 * nested ≤ 64 deep is always accepted. */
static inline bool jsmn_tree_ok(const jsmntok_t *toks, int ntok)
{
    /* Per open container: values still to visit << 1 | is-object. */
    int left[JSMN_SKIP_MAX_DEPTH + 1];
    int d = -1;   /* innermost open container */
    int i = 0;    /* next token */
    for (;;) {
        if (d >= 0) {
            if (left[d] < 2) {          /* no values left: close it */
                d--;
                if (d < 0) return true;
                continue;
            }
            left[d] -= 2;
            if (left[d] & 1) i++;       /* an object member's key, one token */
        }
        if (i >= ntok || d + 1 > JSMN_SKIP_MAX_DEPTH) return false;
        const jsmntok_t *t = &toks[i++];
        if (t->type == JSMN_OBJECT || t->type == JSMN_ARRAY) {
            if (t->size < 0) return false;
            left[++d] = (t->size << 1) | (t->type == JSMN_OBJECT);
        } else if (d < 0) {
            return true;                /* a scalar root */
        }
    }
}
