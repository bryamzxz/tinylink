/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host test for h2_parse_retry_after_seconds. Drives the parser through
 * RFC 7231 §7.1.3 delta-seconds form, clamp boundaries, malformed input,
 * and HTTP-date fallback (which we deliberately do not support).
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "h2_retry_after.h"

static int check_eq(const char *name, int got, int want)
{
    if (got == want) {
        printf("[%s] OK\n", name);
        return 0;
    }
    printf("[%s] FAIL: got=%d want=%d\n", name, got, want);
    return 1;
}

static int parse_str(const char *s)
{
    return h2_parse_retry_after_seconds((const uint8_t *)s, strlen(s));
}

int main(void)
{
    int fails = 0;

    /* RFC 7231 §7.1.3 delta-seconds — the canonical Tailscale shape. */
    fails += check_eq("integer-1",        parse_str("1"),     1);
    fails += check_eq("integer-30",       parse_str("30"),    30);
    fails += check_eq("integer-300-max",  parse_str("300"),   300);

    /* Above the 300 s sanity cap. */
    fails += check_eq("clamp-301",        parse_str("301"),   300);
    fails += check_eq("clamp-3600",       parse_str("3600"),  300);
    fails += check_eq("clamp-99999",      parse_str("99999"), 300);

    /* Non-positive values carry no usable hint; caller falls back to its
     * own backoff schedule. */
    fails += check_eq("zero",             parse_str("0"),     0);
    fails += check_eq("negative",         parse_str("-5"),    0);

    /* Malformed inputs (no leading digits) → 0. */
    fails += check_eq("empty",            parse_str(""),      0);
    fails += check_eq("alpha",            parse_str("abc"),   0);
    fails += check_eq("only-whitespace",  parse_str("   "),   0);

    /* HTTP-date form (RFC 7231 §7.1.3 alternative); we don't parse dates,
     * so the leading non-digit forces a fallback. */
    fails += check_eq("http-date",
                      parse_str("Wed, 21 Oct 2015 07:28:00 GMT"), 0);

    /* Permissive trailing junk: strtol stops at the first non-digit. The
     * server should never emit these shapes but we accept the leading
     * integer rather than dropping the hint entirely. */
    fails += check_eq("digits-then-junk", parse_str("10abc"), 10);
    fails += check_eq("trailing-newline", parse_str("42\n"),  42);
    fails += check_eq("trailing-space",   parse_str("7 "),    7);

    if (fails == 0) {
        printf("all OK (15 cases)\n");
        return 0;
    }
    printf("%d failure(s)\n", fails);
    return fails;
}
