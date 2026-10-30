// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Wi-Fi association hint and retry policy (round 1.3.7). The channel of
// the last AP the station joined, kept in RTC slow memory (a software /
// panic / WDT reset) and NVS `tl_state` (any reset), so the connect scan
// starts on that channel; plus what to do after each STA_DISCONNECTED.
//
// Why. On 68 captured boots of 1.3.1–1.3.6 the connect scan walked
// channels 1..11 at ~110 ms each before it saw the AP on 11 (STA start
// 0.37–0.43 s → AP found 1.58–1.69 s). sta.channel makes the driver scan
// that channel first and then 1..N without it (IDF wifi.rst, "Station
// Basic Configuration"), and WIFI_FAST_SCAN ends at the first match: a
// stale channel costs one extra dwell, never a lock-out. bssid_set is
// not used: on the hinted channel the first match is the AP anyway, and a
// replaced AP would turn every attempt into NO_AP_FOUND after a full scan.
// So the record holds no BSSID either — nothing would read it, and on a
// mesh / multi-BSSID network with one SSID on one channel every reconnect
// to another node would have been an NVS write (review, 1.3.7).
//
// The retry. Every one of those boots was a hardware reset (the serial
// DTR pulse) and every one was refused first ("Association refused
// temporarily … comeback time 1100 (TUs)": the AP still held the old PMF
// association and ran an SA Query, +1.13 s). After the comeback the
// 4-way handshake finished in 10–30 ms in 16 boots, in 2.0 s in 30, and
// in 22 the station gave up at exactly 3.0 s with reason 15 raised
// locally (`run -> init (0xf00)`; a deauth from the AP would read 0xfc0).
// The likely source is wpa.c's deauth on the 4th M1 (MAX_EAPOL_RETRIES 3,
// its log compiled out), i.e. the AP re-sent M1 every second and never
// took our M2; CONFIG_TINYLINK_WIFI_DIAG settles it. The driver then
// blacklists the BSSID (libnet80211 cnx_add_to_blacklist): after the
// 0.4–0.6 s backoff the next scan saw the AP at once (its FT-PSK warning
// came first) yet walked every channel for 2.29 s before taking it anyway
// ("no ap found, connect to ap in blacklist") — and that attempt finished
// its handshake in 10–20 ms in 22 of 22 boots, the AP having dropped the
// old association by then. So the first 4-way timeout of a failure
// streak is retried at once with the config re-applied
// (wifi_set_config_process clears the blacklist) — with or without a
// record: the skipped backoff and blacklisted rescan are worth it either
// way. A hint is kept for it: the scan found the AP, the handshake is
// what failed. Any other failure — and a second one — drops the hint
// (scan 1..N) and goes through the backoff ladder as before. A wrong
// passphrase (also reason 15) costs one extra attempt per streak. A
// successful connect, on any channel, rewrites the record.
//
// Everything here is pure and host-tested (tools/test/test_wifi_hint.c);
// the driver calls, RTC_NOINIT_ATTR and NVS are in app_wifi.c.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TL_WIFI_CH_MAX        14     /* 2.4 GHz */
#define TL_WIFI_REASON_4WAY   15     /* WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT */
#define TL_WIFI_REASON_HS     204    /* WIFI_REASON_HANDSHAKE_TIMEOUT */

/* NVS (default partition): the namespace tinylink.c keeps its state in. */
#define TL_WIFI_HINT_NS       "tl_state"
#define TL_WIFI_HINT_KEY      "wifi_ap"

typedef struct {
    uint8_t  channel;        /* 1..14; 0 = none */
    uint32_t ssid_hash;      /* tl_wifi_ssid_hash() of the SSID it was joined on */
} tl_wifi_ap_t;

/* FNV-1a over the SSID bytes (≤ 32): binds a record to the configured
 * network, so re-provisioned credentials never inherit a hint. */
static inline uint32_t tl_wifi_ssid_hash(const uint8_t *ssid, size_t n)
{
    uint32_t h = 2166136261u;
    if (n > 32) n = 32;
    for (size_t i = 0; i < n; i++) {
        h ^= ssid[i];
        h *= 16777619u;
    }
    return h;
}

/* Worth a hint: channel 1..14, this SSID. */
static inline bool tl_wifi_ap_ok(const tl_wifi_ap_t *a, uint32_t ssid_hash)
{
    return a != NULL && a->channel >= 1 && a->channel <= TL_WIFI_CH_MAX &&
           a->ssid_hash == ssid_hash;
}

/* ---- The record: NVS blob and RTC copy ------------------------------- */

/* version ‖ channel ‖ SSID hash (LE32). v1 (with a BSSID, 12 B) was never
 * on a device; its length alone is rejected. */
#define TL_WIFI_AP_REC_V2     2
#define TL_WIFI_AP_BLOB_LEN   6

static inline void tl_wifi_ap_encode(const tl_wifi_ap_t *a, uint8_t b[TL_WIFI_AP_BLOB_LEN])
{
    b[0] = TL_WIFI_AP_REC_V2;
    b[1] = a->channel;
    b[2] = (uint8_t)a->ssid_hash;
    b[3] = (uint8_t)(a->ssid_hash >> 8);
    b[4] = (uint8_t)(a->ssid_hash >> 16);
    b[5] = (uint8_t)(a->ssid_hash >> 24);
}

/* Exactly one v2 record for this SSID, else false (out untouched). */
static inline bool tl_wifi_ap_decode(const uint8_t *b, size_t n, uint32_t ssid_hash,
                                     tl_wifi_ap_t *out)
{
    if (b == NULL || n != TL_WIFI_AP_BLOB_LEN || b[0] != TL_WIFI_AP_REC_V2) return false;
    tl_wifi_ap_t a;
    a.channel   = b[1];
    a.ssid_hash = (uint32_t)b[2] | ((uint32_t)b[3] << 8) | ((uint32_t)b[4] << 16) |
                  ((uint32_t)b[5] << 24);
    if (!tl_wifi_ap_ok(&a, ssid_hash)) return false;
    *out = a;
    return true;
}

/* RTC no-init copy: written at every connect (free), so it is at least
 * as fresh as NVS, which lags by ≤ 60 s and only follows changes. Like
 * tl_bootstat.h it carries a magic and a checksum: after a power-on or
 * an EN-pin reset (the serial DTR pulse — `boots=1 … RTC record
 * restarted` on every captured boot) the bytes are garbage. */
#define TL_WIFI_RTC_MAGIC     0x544C5702u      /* "TLW" + layout version */

typedef struct {
    uint32_t magic;
    uint8_t  rec[TL_WIFI_AP_BLOB_LEN];
    uint32_t check;
} tl_wifi_rtc_t;

static inline uint32_t tl_wifi_rtc_check(const tl_wifi_rtc_t *r)
{
    uint32_t h = 2166136261u;
    for (unsigned k = 0; k < 4; k++) {
        h ^= (r->magic >> (8 * k)) & 0xFFu;
        h *= 16777619u;
    }
    for (unsigned i = 0; i < TL_WIFI_AP_BLOB_LEN; i++) {
        h ^= r->rec[i];
        h *= 16777619u;
    }
    return h;
}

static inline void tl_wifi_rtc_put(tl_wifi_rtc_t *r, const tl_wifi_ap_t *a)
{
    r->magic = TL_WIFI_RTC_MAGIC;
    tl_wifi_ap_encode(a, r->rec);
    r->check = tl_wifi_rtc_check(r);
}

static inline bool tl_wifi_rtc_get(const tl_wifi_rtc_t *r, uint32_t ssid_hash, tl_wifi_ap_t *out)
{
    return r != NULL && r->magic == TL_WIFI_RTC_MAGIC && r->check == tl_wifi_rtc_check(r) &&
           tl_wifi_ap_decode(r->rec, sizeof(r->rec), ssid_hash, out);
}

typedef enum {
    TL_WIFI_HINT_NONE = 0,
    TL_WIFI_HINT_RTC,
    TL_WIFI_HINT_NVS,
} tl_wifi_hint_src_t;

/* The record to boot with: the RTC copy when valid for this SSID, else
 * the NVS one, else none (channel 0). */
static inline tl_wifi_hint_src_t tl_wifi_ap_boot(const tl_wifi_rtc_t *rtc, const uint8_t *nvs,
                                                 size_t nvs_len, uint32_t ssid_hash,
                                                 tl_wifi_ap_t *out)
{
    if (tl_wifi_rtc_get(rtc, ssid_hash, out)) return TL_WIFI_HINT_RTC;
    if (tl_wifi_ap_decode(nvs, nvs_len, ssid_hash, out)) return TL_WIFI_HINT_NVS;
    memset(out, 0, sizeof(*out));
    return TL_WIFI_HINT_NONE;
}

/* ---- NVS: written only on change ------------------------------------- */

/* What NVS holds, mirrored in RAM (loaded at boot, compared before every
 * write) — tl_addr.h's rule: a flash write may erase a 4-KB sector and
 * stall both CPUs, so it happens only when the bytes change, never on
 * the boot path. len 0 = nothing stored. */
typedef struct {
    uint8_t len;
    uint8_t b[TL_WIFI_AP_BLOB_LEN];
} tl_wifi_blob_t;

/* 0 = written, else failed. */
typedef int (*tl_wifi_write_fn)(const uint8_t *b, size_t n, void *ctx);

/* 0 = unchanged (nothing written), 1 = written, -1 = the write failed.
 * The mirror takes the new bytes even when the write fails: a broken NVS
 * costs the next cold boot a full scan, never a write attempt per call. */
static inline int tl_wifi_blob_store(tl_wifi_blob_t *m, const tl_wifi_ap_t *a,
                                     tl_wifi_write_fn write, void *ctx)
{
    uint8_t b[TL_WIFI_AP_BLOB_LEN];
    tl_wifi_ap_encode(a, b);
    if (m->len == sizeof(b) && memcmp(m->b, b, sizeof(b)) == 0) return 0;
    memcpy(m->b, b, sizeof(b));
    m->len = (uint8_t)sizeof(b);
    return write(b, sizeof(b), ctx) == 0 ? 1 : -1;
}

/* ---- Retry policy ---------------------------------------------------- */

typedef struct {
    tl_wifi_ap_t ap;         /* the last AP joined (this boot or the record) */
    bool hint;               /* scan ap.channel first on the next attempt */
    bool joined;             /* STA_CONNECTED seen, no disconnect since */
    bool fast_spent;         /* this failure streak's immediate retry is used */
} tl_wifi_retry_t;

typedef struct {
    bool    now;             /* skip the backoff */
    bool    reapply;         /* esp_wifi_set_config even if the channel is unchanged */
    uint8_t channel;         /* sta.channel for the next attempt; 0 = 1..N */
} tl_wifi_next_t;

static inline void tl_wifi_retry_init(tl_wifi_retry_t *s, const tl_wifi_ap_t *boot,
                                      uint32_t ssid_hash)
{
    memset(s, 0, sizeof(*s));
    if (boot != NULL && tl_wifi_ap_ok(boot, ssid_hash)) {
        s->ap   = *boot;
        s->hint = true;
    }
}

/* sta.channel for the next attempt. */
static inline uint8_t tl_wifi_channel(const tl_wifi_retry_t *s)
{
    return s->hint ? s->ap.channel : 0;
}

/* STA_CONNECTED (the 4-way handshake is done). True when the record
 * changed — a new channel (or SSID) —, i.e. NVS takes it at the next
 * persist; another node of the same network on the same channel is not
 * a change. */
static inline bool tl_wifi_on_connected(tl_wifi_retry_t *s, uint8_t channel, uint32_t ssid_hash)
{
    s->joined     = true;
    s->fast_spent = false;
    const tl_wifi_ap_t a = { channel, ssid_hash };
    if (!tl_wifi_ap_ok(&a, ssid_hash)) return false;      /* keep what we had */
    const bool changed = s->ap.channel != a.channel || s->ap.ssid_hash != a.ssid_hash;
    s->ap   = a;
    s->hint = true;
    return changed;
}

/* STA_DISCONNECTED: how to make the next attempt. */
static inline tl_wifi_next_t tl_wifi_on_disconnected(tl_wifi_retry_t *s, uint16_t reason)
{
    tl_wifi_next_t n = { false, false, 0 };
    const bool was_joined = s->joined;
    s->joined = false;
    if (was_joined) {
        /* A working link went away: the AP is where it just was. */
        n.channel = tl_wifi_channel(s);
        return n;
    }
    const bool handshake = reason == TL_WIFI_REASON_4WAY || reason == TL_WIFI_REASON_HS;
    if (handshake && !s->fast_spent) {
        s->fast_spent = true;
        n.now     = true;
        n.reapply = true;                  /* drop the driver's blacklist entry */
        n.channel = tl_wifi_channel(s);    /* 0 without a record: 1..N */
        return n;
    }
    s->hint = false;                       /* scan 1..N until the next connect */
    return n;
}

/* The reconnect path: whether this attempt needs an esp_wifi_set_config
 * first (`pending` is what the event handler queued). */
static inline bool tl_wifi_needs_config(const tl_wifi_next_t *pending, uint8_t applied_channel)
{
    return pending->reapply || pending->channel != applied_channel;
}

/* After that esp_wifi_set_config: the blacklist clear is done only if it
 * succeeded — on a failure (ESP_ERR_WIFI_STATE…) it stays pending for the
 * next attempt. */
static inline void tl_wifi_config_done(tl_wifi_next_t *pending, bool ok)
{
    if (ok) pending->reapply = false;
}

#ifdef __cplusplus
}
#endif
