// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// TLS sessions across warm resets (round 1.3.8, CONFIG_TINYLINK_TLS_RESUME_RTC).
//
// tls_resume.c keeps the session of the last DERP / control (:443) conn
// in RAM; a reset loses it, and the boot's first connect is a full
// handshake. Each keep also writes the session — mbedTLS's own
// serialization (mbedtls_ssl_session_save: the master secret, the
// ticket, the suite, a digest of the server certificate, behind a
// version / build-configuration header that mbedtls_ssl_session_load
// checks) — into a record in RTC slow memory, which survives a software,
// panic or watchdog reset but not a power-on or an EN-pin reset. The
// first connect to that host:port after such a reset offers it.
//
// What it is not: never flash. A session is a TLS 1.2 master secret; on
// flash (NVS is not encrypted on this device) anyone holding the board
// could read it for as long as it lives, and with it decrypt every
// recorded connection resumed from it — TLS 1.2 resumption has no fresh
// ECDHE, so resumed conns derive their keys from that secret and the two
// randoms. RTC slow memory is on-chip SRAM like the heap the session
// already lives in, and is gone at power-off.
//
// Bounds (the same as the RAM copy, tls_resume.h): one host:port per
// record; the master secret's age, counted on the RTC timer — which keeps
// running through those resets, unlike esp_timer — against
// TLS_RESUME_MAX_AGE_S; a connect that offered it and failed clears it;
// one restore attempt per record per boot. The age is only as good as the
// RTC timer, which esp_clk restarts from 0 whenever its calibration
// register reads 0 (an RTC-domain reset — the bootloader's RTC WDT stage,
// a brown-out, maybe EN) while RTC slow memory can survive: a 23-h-old
// secret would then look seconds old (review, 1.3.8). So a record is used
// only after a software, panic, interrupt-WDT or task-WDT reset
// (tls_resume.c), and never when the RTC timer reads earlier than the
// record's last write (or its birth). Every boot sweeps the records
// first thing (tinylink_bootstat_record, before anything can restart):
// garbage, a record a cold boot cannot use, an expired one — all zeroed,
// master secret included, instead of waiting to be looked up. The gate
// needs the sweep on every boot: a cold boot that restarted before
// sweeping would hand its records to the next, software-reset boot, and
// a record last written before an RTC-timer restart passes the time
// check once the new timer has run past that write (review 138b). The
// checksum is against garbage (after a power-on the bytes are random), not
// against an attacker: writing RTC memory needs code execution already.
//
// Everything here is pure and host-tested (tools/test/test_tls_resume.c);
// RTC_NOINIT_ATTR, the RTC clock and the mbedTLS calls are in
// tls_resume.c.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto/secure_zero.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TLS_RTC_MAGIC    0x544C5302u   /* "TLS" + layout version */
#define TLS_RTC_HOST_MAX 64            /* = TLS_RESUME_HOST_MAX */
#define TLS_RTC_RECS     2             /* the DERP client, the control conn */

/* A serialized TLS 1.2 client session without the peer certificate
 * (CONFIG_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE=n) is ~145 B plus the ticket
 * (~128 B from both servers, 2026-10-29). A longer one is not kept. */
#define TLS_RTC_SESS_MAX 480

typedef struct {
    uint32_t magic;
    uint16_t len;                       /* bytes of sess in use      */
    uint16_t port;
    uint64_t born_rtc_us;               /* the master secret, RTC µs */
    uint64_t saved_rtc_us;              /* this write, RTC µs        */
    char     host[TLS_RTC_HOST_MAX];    /* NUL-terminated            */
    uint8_t  sess[TLS_RTC_SESS_MAX];
    uint32_t check;
} tls_rtc_rec_t;

static inline uint32_t tls_rtc_fnv(uint32_t h, const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    for (size_t i = 0; i < n; i++) {
        h ^= b[i];
        h *= 16777619u;
    }
    return h;
}

static inline uint32_t tls_rtc_check(const tls_rtc_rec_t *r)
{
    uint32_t h = 2166136261u;
    h = tls_rtc_fnv(h, &r->magic, sizeof(r->magic));
    h = tls_rtc_fnv(h, &r->len, sizeof(r->len));
    h = tls_rtc_fnv(h, &r->port, sizeof(r->port));
    h = tls_rtc_fnv(h, &r->born_rtc_us, sizeof(r->born_rtc_us));
    h = tls_rtc_fnv(h, &r->saved_rtc_us, sizeof(r->saved_rtc_us));
    h = tls_rtc_fnv(h, r->host, sizeof(r->host));
    h = tls_rtc_fnv(h, r->sess, r->len <= TLS_RTC_SESS_MAX ? r->len : TLS_RTC_SESS_MAX);
    return h;
}

static inline void tls_rtc_clear(tls_rtc_rec_t *r)
{
    if (r != NULL) tl_secure_zero_inline(r, sizeof(*r));
}

static inline bool tls_rtc_valid(const tls_rtc_rec_t *r)
{
    return r != NULL && r->magic == TLS_RTC_MAGIC && r->len > 0 &&
           r->len <= TLS_RTC_SESS_MAX && memchr(r->host, '\0', sizeof(r->host)) != NULL &&
           r->check == tls_rtc_check(r);
}

/* Fill r for host:port, written at now_rtc_us: header and check around
 * the r->len session bytes the caller serialized into r->sess; the rest
 * of sess (a longer previous session's tail) is zeroed. false (and r
 * cleared) when the host name does not fit, len is out of range or the
 * birth is after now. */
static inline bool tls_rtc_seal(tls_rtc_rec_t *r, const char *host, uint16_t port,
                                uint64_t born_rtc_us, uint64_t now_rtc_us, size_t len)
{
    const size_t hl = host != NULL ? strnlen(host, TLS_RTC_HOST_MAX) : TLS_RTC_HOST_MAX;
    if (hl >= TLS_RTC_HOST_MAX || len == 0 || len > TLS_RTC_SESS_MAX ||
        born_rtc_us > now_rtc_us) {
        tls_rtc_clear(r);
        return false;
    }
    tl_secure_zero_inline(r->sess + len, TLS_RTC_SESS_MAX - len);
    memset(r->host, 0, sizeof(r->host));
    memcpy(r->host, host, hl);
    r->len = (uint16_t)len;
    r->port = port;
    r->born_rtc_us = born_rtc_us;
    r->saved_rtc_us = now_rtc_us;
    r->magic = TLS_RTC_MAGIC;
    r->check = tls_rtc_check(r);
    return true;
}

/* Valid, the RTC timer not behind its last write (nor its birth) — i.e.
 * not restarted since — and the master secret no older than max_age_us
 * at now_rtc_us; *age_us = that age. */
static inline bool tls_rtc_fresh(const tls_rtc_rec_t *r, uint64_t now_rtc_us,
                                 uint64_t max_age_us, uint64_t *age_us)
{
    if (!tls_rtc_valid(r)) return false;
    if (now_rtc_us < r->saved_rtc_us || now_rtc_us < r->born_rtc_us) return false;
    const uint64_t age = now_rtc_us - r->born_rtc_us;
    if (age > max_age_us) return false;
    if (age_us != NULL) *age_us = age;
    return true;
}

/* The record's session for host:port at now_rtc_us, if fresh; *age_us =
 * its age. */
static inline bool tls_rtc_usable(const tls_rtc_rec_t *r, const char *host, uint16_t port,
                                  uint64_t now_rtc_us, uint64_t max_age_us, uint64_t *age_us)
{
    if (!tls_rtc_valid(r) || host == NULL || r->port != port ||
        strncmp(r->host, host, TLS_RTC_HOST_MAX) != 0) {
        return false;
    }
    return tls_rtc_fresh(r, now_rtc_us, max_age_us, age_us);
}

/* Zero every record that cannot be used: garbage / another layout, all of
 * them after a reset that is not a warm one (`warm` false), and any whose
 * master secret is too old or whose RTC time went backwards. Returns how
 * many held a valid record before. */
static inline unsigned tls_rtc_sweep(tls_rtc_rec_t *recs, unsigned n, bool warm,
                                     uint64_t now_rtc_us, uint64_t max_age_us)
{
    unsigned dropped = 0;
    for (unsigned i = 0; i < n; i++) {
        const bool valid = tls_rtc_valid(&recs[i]);
        if (valid && warm && tls_rtc_fresh(&recs[i], now_rtc_us, max_age_us, NULL)) continue;
        dropped += valid;
        tls_rtc_clear(&recs[i]);
    }
    return dropped;
}

/* The record a session for host:port goes to: the one already holding
 * host:port, else an unused one, else the one with the oldest master
 * secret. */
static inline unsigned tls_rtc_pick(const tls_rtc_rec_t *recs, unsigned n,
                                    const char *host, uint16_t port)
{
    unsigned spare = n, oldest = 0;
    for (unsigned i = 0; i < n; i++) {
        if (!tls_rtc_valid(&recs[i])) {
            if (spare == n) spare = i;
            continue;
        }
        if (recs[i].port == port && host != NULL &&
            strncmp(recs[i].host, host, TLS_RTC_HOST_MAX) == 0) {
            return i;
        }
        if (recs[i].born_rtc_us < recs[oldest].born_rtc_us || !tls_rtc_valid(&recs[oldest])) {
            oldest = i;
        }
    }
    return spare != n ? spare : oldest;
}

/* The record holding host:port, or n. */
static inline unsigned tls_rtc_find(const tls_rtc_rec_t *recs, unsigned n,
                                    const char *host, uint16_t port)
{
    for (unsigned i = 0; i < n; i++) {
        if (tls_rtc_valid(&recs[i]) && recs[i].port == port && host != NULL &&
            strncmp(recs[i].host, host, TLS_RTC_HOST_MAX) == 0) {
            return i;
        }
    }
    return n;
}

#ifdef __cplusplus
}
#endif
