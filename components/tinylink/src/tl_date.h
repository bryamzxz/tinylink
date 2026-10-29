// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Timestamp parsers for the two date shapes the control plane sends:
// RFC 3339 (Go time.Time JSON, e.g. Node.KeyExpiry) and the HTTP
// IMF-fixdate (Retry-After). Header-only and libc-free (no timegm on
// newlib) so the host KATs exercise exactly what the firmware runs.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Days since 1970-01-01 of a proleptic-Gregorian civil date
 * (H. Hinnant's days_from_civil). m in 1..12, d in 1..31. */
static inline int64_t tl_days_from_civil(int64_t y, unsigned m, unsigned d)
{
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = (unsigned)(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

/* Read exactly `n` ASCII digits at s[*i]; false if any is not a digit. */
static inline bool tl_date_digits(const char *s, size_t len, size_t *i,
                                  unsigned n, unsigned *out)
{
    unsigned v = 0;
    for (unsigned k = 0; k < n; k++) {
        if (*i >= len || s[*i] < '0' || s[*i] > '9') return false;
        v = v * 10 + (unsigned)(s[(*i)++] - '0');
    }
    *out = v;
    return true;
}

static inline bool tl_date_lit(const char *s, size_t len, size_t *i, char c)
{
    if (*i >= len || s[*i] != c) return false;
    (*i)++;
    return true;
}

static inline bool tl_date_fields_ok(unsigned mo, unsigned d, unsigned h,
                                     unsigned mi, unsigned se)
{
    return mo >= 1 && mo <= 12 && d >= 1 && d <= 31 &&
           h <= 23 && mi <= 59 && se <= 60;   /* 60 = leap second */
}

/* RFC 3339 / Go time.RFC3339Nano: "YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)".
 * Fractional seconds are truncated. Writes Unix seconds (may be negative
 * — Go's zero time is year 1) and returns true on a well-formed value. */
static inline bool tl_parse_rfc3339(const char *s, size_t len, int64_t *out)
{
    size_t i = 0;
    unsigned y, mo, d, h, mi, se;
    if (!tl_date_digits(s, len, &i, 4, &y) || !tl_date_lit(s, len, &i, '-') ||
        !tl_date_digits(s, len, &i, 2, &mo) || !tl_date_lit(s, len, &i, '-') ||
        !tl_date_digits(s, len, &i, 2, &d)) {
        return false;
    }
    if (i >= len || (s[i] != 'T' && s[i] != 't')) return false;
    i++;
    if (!tl_date_digits(s, len, &i, 2, &h) || !tl_date_lit(s, len, &i, ':') ||
        !tl_date_digits(s, len, &i, 2, &mi) || !tl_date_lit(s, len, &i, ':') ||
        !tl_date_digits(s, len, &i, 2, &se)) {
        return false;
    }
    if (!tl_date_fields_ok(mo, d, h, mi, se)) return false;
    if (i < len && s[i] == '.') {
        i++;
        size_t frac0 = i;
        while (i < len && s[i] >= '0' && s[i] <= '9') i++;
        if (i == frac0) return false;
    }
    int64_t off = 0;
    if (i < len && (s[i] == 'Z' || s[i] == 'z')) {
        i++;
    } else if (i < len && (s[i] == '+' || s[i] == '-')) {
        const int sign = (s[i] == '-') ? -1 : 1;
        i++;
        unsigned oh, om;
        if (!tl_date_digits(s, len, &i, 2, &oh) || !tl_date_lit(s, len, &i, ':') ||
            !tl_date_digits(s, len, &i, 2, &om) || oh > 23 || om > 59) {
            return false;
        }
        off = sign * (int64_t)(oh * 3600 + om * 60);
    } else {
        return false;
    }
    if (i != len) return false;
    *out = tl_days_from_civil(y, mo, d) * 86400 +
           (int64_t)(h * 3600 + mi * 60 + se) - off;
    return true;
}

/* HTTP IMF-fixdate (RFC 9110 §5.6.7), the form senders MUST generate:
 * "Sun, 06 Nov 1994 08:49:37 GMT". The day name is checked for shape,
 * not consistency (Go's http.ParseTime does the same). The two obsolete
 * forms (RFC 850, asctime) are not accepted; for Retry-After the caller
 * then takes the same 5–10 s default upstream uses for anything it
 * cannot parse. */
static inline bool tl_parse_imf_fixdate(const char *s, size_t len, int64_t *out)
{
    static const char days[] = "MonTueWedThuFriSatSun";
    static const char mons[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    if (len != 29) return false;
    bool day_ok = false;
    for (int k = 0; k < 7; k++) {
        if (memcmp(s, days + 3 * k, 3) == 0) { day_ok = true; break; }
    }
    if (!day_ok || s[3] != ',' || s[4] != ' ') return false;
    size_t i = 5;
    unsigned d, y, h, mi, se, mo = 0;
    if (!tl_date_digits(s, len, &i, 2, &d) || !tl_date_lit(s, len, &i, ' ')) return false;
    for (unsigned k = 0; k < 12; k++) {
        if (memcmp(s + i, mons + 3 * k, 3) == 0) { mo = k + 1; break; }
    }
    if (mo == 0) return false;
    i += 3;
    if (!tl_date_lit(s, len, &i, ' ') || !tl_date_digits(s, len, &i, 4, &y) ||
        !tl_date_lit(s, len, &i, ' ') ||
        !tl_date_digits(s, len, &i, 2, &h) || !tl_date_lit(s, len, &i, ':') ||
        !tl_date_digits(s, len, &i, 2, &mi) || !tl_date_lit(s, len, &i, ':') ||
        !tl_date_digits(s, len, &i, 2, &se) || memcmp(s + i, " GMT", 4) != 0) {
        return false;
    }
    if (!tl_date_fields_ok(mo, d, h, mi, se)) return false;
    *out = tl_days_from_civil(y, mo, d) * 86400 + (int64_t)(h * 3600 + mi * 60 + se);
    return true;
}
