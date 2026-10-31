/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host test for tl_date.h — RFC 3339 (Go time.Time JSON: Node.KeyExpiry)
 * and HTTP IMF-fixdate (Retry-After). Expected Unix times computed with
 * Python's calendar.timegm.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "tl_date.h"

static int check(const char *name, bool ok)
{
    printf("[%s] %s\n", name, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static bool rfc(const char *s, int64_t want)
{
    int64_t t = 0;
    return tl_parse_rfc3339(s, strlen(s), &t) && t == want;
}

static bool rfc_bad(const char *s)
{
    int64_t t = 0;
    return !tl_parse_rfc3339(s, strlen(s), &t);
}

static bool imf(const char *s, int64_t want)
{
    int64_t t = 0;
    return tl_parse_imf_fixdate(s, strlen(s), &t) && t == want;
}

static bool imf_bad(const char *s)
{
    int64_t t = 0;
    return !tl_parse_imf_fixdate(s, strlen(s), &t);
}

int main(void)
{
    int fails = 0;

    fails += check("civil/epoch",        tl_days_from_civil(1970, 1, 1) == 0);
    fails += check("civil/leap-2024",    tl_days_from_civil(2024, 3, 1) -
                                         tl_days_from_civil(2024, 2, 28) == 2);
    fails += check("civil/2000-not-skip",tl_days_from_civil(2000, 3, 1) -
                                         tl_days_from_civil(2000, 2, 28) == 2);
    fails += check("civil/1900-skip",    tl_days_from_civil(1900, 3, 1) -
                                         tl_days_from_civil(1900, 2, 28) == 1);

    fails += check("rfc3339/headscale-deleted", rfc("1970-01-01T00:00:01Z", 1));
    fails += check("rfc3339/plain-z",           rfc("2026-10-28T12:00:00Z", 1793188800));
    fails += check("rfc3339/nanos-truncated",   rfc("2027-04-26T12:34:56.123456789Z", 1808742896));
    fails += check("rfc3339/offset-plus",       rfc("2026-10-28T14:00:00+02:00", 1793188800));
    fails += check("rfc3339/offset-minus",      rfc("2026-10-28T07:00:00-05:00", 1793188800));
    fails += check("rfc3339/go-zero-time",      rfc("0001-01-01T00:00:00Z", -62135596800LL));
    fails += check("rfc3339/leap-day",          rfc("2028-02-29T00:00:00Z", 1835395200));
    fails += check("rfc3339/bad-no-zone",       rfc_bad("2026-10-28T12:00:00"));
    fails += check("rfc3339/bad-month",         rfc_bad("2026-13-01T00:00:00Z"));
    fails += check("rfc3339/bad-trailing",      rfc_bad("2026-10-28T12:00:00Zjunk"));
    fails += check("rfc3339/bad-empty-frac",    rfc_bad("2026-10-28T12:00:00.Z"));
    fails += check("rfc3339/bad-short",         rfc_bad("2026-10-28"));

    fails += check("imf/rfc9110-example",  imf("Sun, 06 Nov 1994 08:49:37 GMT", 784111777));
    fails += check("imf/2015",             imf("Wed, 21 Oct 2015 07:28:00 GMT", 1445412480));
    fails += check("imf/bad-month",        imf_bad("Sun, 06 Foo 1994 08:49:37 GMT"));
    fails += check("imf/bad-day-name",     imf_bad("Xyz, 06 Nov 1994 08:49:37 GMT"));
    fails += check("imf/bad-zone",         imf_bad("Sun, 06 Nov 1994 08:49:37 UTC"));
    fails += check("imf/rfc850-rejected",  imf_bad("Sunday, 06-Nov-94 08:49:37 GMT"));
    fails += check("imf/asctime-rejected", imf_bad("Sun Nov  6 08:49:37 1994"));

    if (fails == 0) {
        printf("\n[PASS] all tl_date assertions passed\n");
        return 0;
    }
    printf("\n[FAIL] %d tl_date assertion(s) failed\n", fails);
    return 1;
}
