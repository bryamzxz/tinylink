/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host test for the capver-147 rate-limit rules (h2_retry_after.h),
 * mirroring tailscale control/controlclient direct.go
 * isRateLimitedResponse + parseRateLimitError and auto.go
 * waitRetryAfter: Atoi-or-HTTP-date parsing, the ≤0 / >1 h → 5–10 s
 * default, the 5-min cap, and 503 counting only with a Retry-After.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "h2_retry_after.h"

static int check_eq(const char *name, long got, long want)
{
    if (got == want) {
        printf("[%s] OK\n", name);
        return 0;
    }
    printf("[%s] FAIL: got=%ld want=%ld\n", name, got, want);
    return 1;
}

static int parse_at(const char *s, int64_t now)
{
    return h2_parse_retry_after_seconds((const uint8_t *)s, strlen(s), now);
}

static int parse_str(const char *s) { return parse_at(s, 0); }

int main(void)
{
    int fails = 0;
    /* 2015-10-21T07:28:00Z, the RFC 9110 example date. */
    const int64_t date = 1445412480;

    /* delta-seconds, strconv.Atoi semantics. */
    fails += check_eq("secs/1",              parse_str("1"),      1);
    fails += check_eq("secs/30",             parse_str("30"),     30);
    fails += check_eq("secs/plus-sign",      parse_str("+30"),    30);
    fails += check_eq("secs/3600-max-valid", parse_str("3600"),   3600);
    fails += check_eq("secs/3601-invalid",   parse_str("3601"),   0);
    fails += check_eq("secs/huge-invalid",   parse_str("99999999999999999999"), 0);
    fails += check_eq("secs/zero-invalid",   parse_str("0"),      0);
    fails += check_eq("secs/negative",       parse_str("-5"),     0);
    /* Atoi rejects anything but sign + digits: no partial parse. */
    fails += check_eq("secs/junk-tail",      parse_str("10abc"),  0);
    fails += check_eq("secs/space-tail",     parse_str("7 "),     0);
    fails += check_eq("secs/newline-tail",   parse_str("42\n"),   0);
    fails += check_eq("secs/sign-only",      parse_str("+"),      0);
    fails += check_eq("empty",               parse_str(""),       0);
    fails += check_eq("alpha",               parse_str("abc"),    0);

    /* HTTP-date (IMF-fixdate) minus now — needs a synced clock. */
    fails += check_eq("date/120s-ahead",
                      parse_at("Wed, 21 Oct 2015 07:30:00 GMT", date), 120);
    fails += check_eq("date/no-clock",
                      parse_at("Wed, 21 Oct 2015 07:30:00 GMT", 0), 0);
    fails += check_eq("date/in-past",
                      parse_at("Wed, 21 Oct 2015 07:27:00 GMT", date), 0);
    fails += check_eq("date/over-1h",
                      parse_at("Wed, 21 Oct 2015 09:28:01 GMT", date), 0);
    fails += check_eq("date/rfc850-not-accepted",
                      parse_at("Wednesday, 21-Oct-15 07:30:00 GMT", date), 0);

    /* Wait decision. rnd = 1234 → default 5000 + 1234 = 6234 ms. */
    fails += check_eq("wait/200",            h2_rate_limit_wait_ms(200, true, 30, 1234), 0);
    fails += check_eq("wait/500",            h2_rate_limit_wait_ms(500, true, 30, 1234), 0);
    fails += check_eq("wait/429-valid",      h2_rate_limit_wait_ms(429, true, 30, 1234), 30000);
    fails += check_eq("wait/429-no-header",  h2_rate_limit_wait_ms(429, false, 0, 1234), 6234);
    fails += check_eq("wait/429-invalid",    h2_rate_limit_wait_ms(429, true, 0, 1234), 6234);
    fails += check_eq("wait/503-no-header",  h2_rate_limit_wait_ms(503, false, 0, 1234), 0);
    fails += check_eq("wait/503-valid",      h2_rate_limit_wait_ms(503, true, 12, 1234), 12000);
    fails += check_eq("wait/503-invalid",    h2_rate_limit_wait_ms(503, true, 0, 99999), 5000 + 99999 % 5000);
    fails += check_eq("wait/cap-300s",       h2_rate_limit_wait_ms(429, true, 3600, 0), 300000);
    fails += check_eq("wait/default-max",    h2_rate_limit_wait_ms(429, false, 0, 4999), 9999);

    if (fails == 0) {
        printf("\n[PASS] all retry_after assertions passed\n");
        return 0;
    }
    printf("\n[FAIL] %d retry_after assertion(s) failed\n", fails);
    return 1;
}
