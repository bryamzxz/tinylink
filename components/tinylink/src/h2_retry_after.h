// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// HTTP/2 Retry-After header parser. Header-only so the host test target
// can exercise it without dragging in nghttp2 / esp-tls.

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define H2_RETRY_AFTER_MAX_S 300

/* Parse a Retry-After header value (delta-seconds form per RFC 7231
 * §7.1.3). Returns the parsed seconds clamped into [1, H2_RETRY_AFTER_MAX_S],
 * or 0 if the value is malformed, zero, negative, or in HTTP-date format
 * (which tailscale's control plane does not emit and we deliberately do
 * not support — caller falls back to its own backoff schedule).
 *
 * The 300 s cap is a sanity limit: long-poll silence beyond ~5 min
 * means we miss netmap updates, so we re-check at least that often
 * regardless of what the server says. Protects against buggy emitters
 * sending `Retry-After: 86400`.
 */
static inline int h2_parse_retry_after_seconds(const uint8_t *value,
                                               size_t valuelen)
{
    if (value == NULL || valuelen == 0) return 0;

    /* Stage into a small NUL-terminated buffer for strtol. 7 chars is
     * enough for any plausible value: anything ≥ 5 digits already lands
     * above the cap, so we only need to recognize "is this > 300?" not
     * the exact magnitude. */
    char buf[8] = {0};
    size_t copy = (valuelen < sizeof(buf) - 1) ? valuelen : sizeof(buf) - 1;
    memcpy(buf, value, copy);

    char *end = NULL;
    long s = strtol(buf, &end, 10);
    if (end == buf) return 0;                   /* no leading digits */
    if (s <= 0)     return 0;                   /* zero / negative */
    if (s > H2_RETRY_AFTER_MAX_S) return H2_RETRY_AFTER_MAX_S;
    return (int)s;
}
