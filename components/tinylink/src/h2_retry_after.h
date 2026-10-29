// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Control-plane rate limiting (capver 147, tailscale 29cfb0b4c):
// Retry-After parsing and the "how long to wait" decision for
// /machine/register and /machine/map. Header-only so the host test
// target can exercise it without nghttp2 / esp-tls.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tl_date.h"

/* Upstream control/controlclient: direct.go parseRateLimitError treats a
 * delay ≤ 0 or > 1 h as "no valid Retry-After"; auto.go waitRetryAfter
 * caps the wait at maxRetryWindow = 5 min. */
#define H2_RETRY_AFTER_VALID_MAX_S 3600
#define H2_RETRY_AFTER_CAP_MS      300000u
/* Default when the server gave no usable value: uniform 5–10 s. */
#define H2_RATE_LIMIT_DEFAULT_MS   5000u
#define H2_RATE_LIMIT_JITTER_MS    5000u

/* Parse a Retry-After value. Returns the delay in seconds when it is
 * valid — 1..H2_RETRY_AFTER_VALID_MAX_S — and 0 otherwise.
 *
 * Same acceptance as upstream (strconv.Atoi, then http.ParseTime):
 *   - delta-seconds: optional sign then digits, the whole value;
 *   - HTTP-date: IMF-fixdate only (the form RFC 9110 senders MUST
 *     generate), minus `now_unix`; pass now_unix = 0 when the clock is
 *     not NTP-synced and a date can't be turned into a delay.
 * Anything else — empty, junk, "12abc", zero, negative, a past date,
 * more than an hour — is "present but invalid" (0); the caller still
 * treats the response as rate-limited and uses the 5–10 s default. */
static inline int h2_parse_retry_after_seconds(const uint8_t *value,
                                               size_t valuelen,
                                               int64_t now_unix)
{
    if (value == NULL || valuelen == 0) return 0;
    const char *s = (const char *)value;

    size_t i = 0;
    bool neg = false;
    if (s[0] == '+' || s[0] == '-') {
        neg = (s[0] == '-');
        i = 1;
    }
    if (i < valuelen && s[i] >= '0' && s[i] <= '9') {
        int64_t v = 0;
        for (; i < valuelen; i++) {
            if (s[i] < '0' || s[i] > '9') return 0;      /* not Atoi-clean */
            if (v <= H2_RETRY_AFTER_VALID_MAX_S) v = v * 10 + (s[i] - '0');
        }
        if (neg || v <= 0 || v > H2_RETRY_AFTER_VALID_MAX_S) return 0;
        return (int)v;
    }

    int64_t t = 0;
    if (now_unix > 0 && tl_parse_imf_fixdate(s, valuelen, &t)) {
        const int64_t d = t - now_unix;
        if (d > 0 && d <= H2_RETRY_AFTER_VALID_MAX_S) return (int)d;
    }
    return 0;
}

/* How long to wait before the next /machine/register or /machine/map
 * attempt, or 0 when the response is not a rate limit (the caller's own
 * backoff applies). Upstream direct.go isRateLimitedResponse: 429
 * always; 503 only with a non-empty Retry-After. Valid seconds are
 * honoured up to the 5-min cap; a missing/invalid value on a 429 (or an
 * invalid one on a 503) waits 5 s + rnd % 5 s. While waiting upstream
 * neither advances nor resets its backoff — callers do the same. */
static inline uint32_t h2_rate_limit_wait_ms(int status, bool retry_after_present,
                                             int retry_after_s, uint32_t rnd)
{
    if (!(status == 429 || (status == 503 && retry_after_present))) return 0;
    uint32_t ms = (retry_after_s > 0)
        ? (uint32_t)retry_after_s * 1000u
        : H2_RATE_LIMIT_DEFAULT_MS + rnd % H2_RATE_LIMIT_JITTER_MS;
    return ms > H2_RETRY_AFTER_CAP_MS ? H2_RETRY_AFTER_CAP_MS : ms;
}
