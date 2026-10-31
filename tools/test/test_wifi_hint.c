// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// The Wi-Fi association hint and retry policy (main/wifi_hint.h, round
// 1.3.7): the record (validation, NVS blob, RTC copy, which one a boot
// takes), write-only-on-change over a fake NVS that counts flash writes
// across simulated reboots — a mesh's nodes on one channel included —,
// and the retry decisions — the one immediate retry per failure streak
// after a 4-way timeout, record or not, the hint dropped on any other
// failure, a working link keeping it, a failed config re-apply staying
// pending — plus a random walk over a simulated driver that checks the
// invariants (never more than one immediate retry per failure streak,
// never a channel that no connect or record named, every connect
// rewrites the record).

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wifi_hint.h"

static int s_fails;

static void check(const char *name, int ok)
{
    printf("[%s] %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) s_fails++;
}

static const char SSID[]  = "example-ssid";
static const char SSID2[] = "example-ssid-2";

static uint32_t hash_of(const char *s)
{
    return tl_wifi_ssid_hash((const uint8_t *)s, strlen(s));
}

static tl_wifi_ap_t ap_make(uint8_t ch, const char *ssid)
{
    const tl_wifi_ap_t a = { ch, hash_of(ssid) };
    return a;
}

static int ap_eq(const tl_wifi_ap_t *a, const tl_wifi_ap_t *b)
{
    return a->channel == b->channel && a->ssid_hash == b->ssid_hash;
}

/* ---- The record ------------------------------------------------------ */

static void test_hash(void)
{
    check("hash/fnv1a-empty", tl_wifi_ssid_hash((const uint8_t *)"", 0) == 0x811c9dc5u);
    check("hash/fnv1a-a", tl_wifi_ssid_hash((const uint8_t *)"a", 1) == 0xe40c292cu);
    check("hash/ssids-differ", hash_of(SSID) != hash_of(SSID2));
    uint8_t long_ssid[40];
    memset(long_ssid, 'x', sizeof(long_ssid));
    check("hash/capped-at-32", tl_wifi_ssid_hash(long_ssid, 40) == tl_wifi_ssid_hash(long_ssid, 32));
}

static void test_ap_ok(void)
{
    const uint32_t h = hash_of(SSID);
    tl_wifi_ap_t a = ap_make(11, SSID);
    check("ap/ok", tl_wifi_ap_ok(&a, h));
    a.channel = 1;
    int edges = tl_wifi_ap_ok(&a, h);
    a.channel = 14;
    edges = edges && tl_wifi_ap_ok(&a, h);
    check("ap/channels-1-and-14", edges);
    a.channel = 0;
    int bad = !tl_wifi_ap_ok(&a, h);
    a.channel = 15;
    bad = bad && !tl_wifi_ap_ok(&a, h);
    a.channel = 36;
    bad = bad && !tl_wifi_ap_ok(&a, h);
    check("ap/channels-0-15-36-rejected", bad);
    a = ap_make(11, SSID2);
    check("ap/other-ssid-rejected", !tl_wifi_ap_ok(&a, h) && !tl_wifi_ap_ok(NULL, h));
}

static void test_blob(void)
{
    const uint32_t h = hash_of(SSID);
    const tl_wifi_ap_t a = ap_make(6, SSID);
    uint8_t b[TL_WIFI_AP_BLOB_LEN];
    tl_wifi_ap_encode(&a, b);
    check("blob/layout-6-bytes-no-bssid", TL_WIFI_AP_BLOB_LEN == 6 && b[0] == TL_WIFI_AP_REC_V2 &&
                                          b[1] == 6 && b[2] == (uint8_t)h && b[5] == (uint8_t)(h >> 24));
    tl_wifi_ap_t out;
    check("blob/roundtrip", tl_wifi_ap_decode(b, sizeof(b), h, &out) && ap_eq(&out, &a));

    const tl_wifi_ap_t sentinel = ap_make(3, SSID);
    int untouched = 1;
    uint8_t c[TL_WIFI_AP_BLOB_LEN + 1];
    memcpy(c, b, sizeof(b));
    c[TL_WIFI_AP_BLOB_LEN] = 0;
    out = sentinel;
    untouched &= !tl_wifi_ap_decode(c, sizeof(b) - 1, h, &out) && ap_eq(&out, &sentinel);
    untouched &= !tl_wifi_ap_decode(c, sizeof(b) + 1, h, &out) && ap_eq(&out, &sentinel);
    untouched &= !tl_wifi_ap_decode(NULL, sizeof(b), h, &out) && ap_eq(&out, &sentinel);
    check("blob/length-exact-out-untouched", untouched);

    memcpy(c, b, sizeof(b));
    c[0] = 1;                                       /* v1 (never on a device) */
    int rej = !tl_wifi_ap_decode(c, sizeof(b), h, &out);
    memcpy(c, b, sizeof(b));
    c[1] = 0;
    rej = rej && !tl_wifi_ap_decode(c, sizeof(b), h, &out);
    memcpy(c, b, sizeof(b));
    c[1] = 15;
    rej = rej && !tl_wifi_ap_decode(c, sizeof(b), h, &out);
    rej = rej && !tl_wifi_ap_decode(b, sizeof(b), hash_of(SSID2), &out);
    /* A 12-B v1 record (version ‖ channel ‖ BSSID ‖ hash) is not taken. */
    uint8_t v1[12] = { 1, 6, 0x02, 0, 0, 0, 0, 0x0a };
    memcpy(v1 + 8, b + 2, 4);
    rej = rej && !tl_wifi_ap_decode(v1, sizeof(v1), h, &out);
    check("blob/rejects-version-channel-ssid-v1", rej && ap_eq(&out, &sentinel));
}

static void test_rtc(void)
{
    const uint32_t h = hash_of(SSID);
    const tl_wifi_ap_t a = ap_make(11, SSID);
    tl_wifi_rtc_t r;
    tl_wifi_rtc_put(&r, &a);
    tl_wifi_ap_t out;
    check("rtc/roundtrip", tl_wifi_rtc_get(&r, h, &out) && ap_eq(&out, &a));
    check("rtc/other-ssid", !tl_wifi_rtc_get(&r, hash_of(SSID2), &out));

    /* Every single-byte corruption of a field is caught (magic, record,
     * check; the struct's padding carries nothing). */
    int all = 1;
    const size_t fields[][2] = {
        { offsetof(tl_wifi_rtc_t, magic), sizeof(r.magic) },
        { offsetof(tl_wifi_rtc_t, rec), sizeof(r.rec) },
        { offsetof(tl_wifi_rtc_t, check), sizeof(r.check) },
    };
    for (size_t f = 0; f < 3; f++) {
        for (size_t i = 0; i < fields[f][1]; i++) {
            tl_wifi_rtc_t x = r;
            ((uint8_t *)&x)[fields[f][0] + i] ^= 0x5a;
            if (tl_wifi_rtc_get(&x, h, &out)) all = 0;
        }
    }
    check("rtc/any-flipped-byte-rejected", all);

    /* Power-on garbage: 100 000 random records, none taken. */
    srand(1307);
    int taken = 0;
    for (int i = 0; i < 100000; i++) {
        tl_wifi_rtc_t x;
        for (size_t k = 0; k < sizeof(x); k++) ((uint8_t *)&x)[k] = (uint8_t)rand();
        if (i % 2) x.magic = TL_WIFI_RTC_MAGIC;     /* half with the right magic */
        taken += tl_wifi_rtc_get(&x, h, &out);
    }
    check("rtc/power-on-garbage-never-taken", taken == 0);
    check("rtc/null", !tl_wifi_rtc_get(NULL, h, &out));
}

static void test_boot(void)
{
    const uint32_t h = hash_of(SSID);
    const tl_wifi_ap_t rtc_ap = ap_make(11, SSID);
    const tl_wifi_ap_t nvs_ap = ap_make(6, SSID);
    tl_wifi_rtc_t r;
    tl_wifi_rtc_put(&r, &rtc_ap);
    uint8_t nvs[TL_WIFI_AP_BLOB_LEN];
    tl_wifi_ap_encode(&nvs_ap, nvs);
    tl_wifi_ap_t out;

    check("boot/rtc-first", tl_wifi_ap_boot(&r, nvs, sizeof(nvs), h, &out) == TL_WIFI_HINT_RTC &&
                            ap_eq(&out, &rtc_ap));
    tl_wifi_rtc_t bad = r;
    bad.check ^= 1;
    check("boot/nvs-when-rtc-invalid",
          tl_wifi_ap_boot(&bad, nvs, sizeof(nvs), h, &out) == TL_WIFI_HINT_NVS && ap_eq(&out, &nvs_ap));
    tl_wifi_rtc_t other;
    const tl_wifi_ap_t other_ap = ap_make(1, SSID2);
    tl_wifi_rtc_put(&other, &other_ap);
    check("boot/nvs-when-rtc-for-other-ssid",
          tl_wifi_ap_boot(&other, nvs, sizeof(nvs), h, &out) == TL_WIFI_HINT_NVS);
    out = rtc_ap;
    check("boot/none-zeroed", tl_wifi_ap_boot(&bad, nvs, 0, h, &out) == TL_WIFI_HINT_NONE &&
                              out.channel == 0 && out.ssid_hash == 0);
    check("boot/none-nvs-other-ssid",
          tl_wifi_ap_boot(&bad, nvs, sizeof(nvs), hash_of(SSID2), &out) == TL_WIFI_HINT_NONE);
}

/* ---- NVS: written only on change, across reboots ---------------------- */

typedef struct {
    uint8_t b[TL_WIFI_AP_BLOB_LEN];
    size_t  n;
    int     writes;
    int     fail;
} fake_nvs_t;

static int fake_write(const uint8_t *b, size_t n, void *ctx)
{
    fake_nvs_t *f = (fake_nvs_t *)ctx;
    f->writes++;
    if (f->fail) return -1;
    memcpy(f->b, b, n);
    f->n = n;
    return 0;
}

/* A boot: the mirror comes from the fake NVS, as hint_load does. */
static void mirror_load(tl_wifi_blob_t *m, const fake_nvs_t *f)
{
    m->len = (uint8_t)f->n;
    memcpy(m->b, f->b, f->n);
}

static void test_store(void)
{
    fake_nvs_t f;
    memset(&f, 0, sizeof(f));
    tl_wifi_blob_t m;
    memset(&m, 0, sizeof(m));
    const tl_wifi_ap_t a = ap_make(11, SSID);

    check("store/first-write", tl_wifi_blob_store(&m, &a, fake_write, &f) == 1 && f.writes == 1);
    int zero = 1;
    for (int i = 0; i < 1440; i++) zero &= tl_wifi_blob_store(&m, &a, fake_write, &f) == 0;
    check("store/a-day-of-housekeeping-no-write", zero && f.writes == 1);

    /* 100 reboots with the same AP: the mirror is loaded, nothing written. */
    int writes = f.writes;
    for (int boot = 0; boot < 100; boot++) {
        mirror_load(&m, &f);
        for (int i = 0; i < 10; i++) (void)tl_wifi_blob_store(&m, &a, fake_write, &f);
    }
    check("store/100-reboots-no-write", f.writes == writes);

    const tl_wifi_ap_t moved = ap_make(6, SSID);
    const tl_wifi_ap_t back = ap_make(11, SSID);
    int ok = tl_wifi_blob_store(&m, &moved, fake_write, &f) == 1;
    ok = ok && tl_wifi_blob_store(&m, &moved, fake_write, &f) == 0;
    ok = ok && tl_wifi_blob_store(&m, &back, fake_write, &f) == 1;
    check("store/one-write-per-channel-change", ok && f.writes == writes + 2);

    /* A failed write: the mirror still takes the bytes — no write storm. */
    const tl_wifi_ap_t third = ap_make(3, SSID);
    f.fail = 1;
    writes = f.writes;
    ok = tl_wifi_blob_store(&m, &third, fake_write, &f) == -1;
    for (int i = 0; i < 100; i++) ok = ok && tl_wifi_blob_store(&m, &third, fake_write, &f) == 0;
    check("store/failed-write-not-retried", ok && f.writes == writes + 1);

    /* A record for another SSID in NVS is replaced once. */
    fake_nvs_t g;
    memset(&g, 0, sizeof(g));
    const tl_wifi_ap_t other = ap_make(1, SSID2);
    tl_wifi_ap_encode(&other, g.b);
    g.n = TL_WIFI_AP_BLOB_LEN;
    mirror_load(&m, &g);
    check("store/other-ssid-replaced", tl_wifi_blob_store(&m, &a, fake_write, &g) == 1 &&
                                       tl_wifi_blob_store(&m, &a, fake_write, &g) == 0 &&
                                       g.writes == 1);
}

/* Review R1 (1.3.7): a mesh / multi-BSSID network, one SSID on one
 * channel, the station landing on another node at each reconnect, one
 * persist per reconnect. The record holds no BSSID, so the nodes are
 * invisible to it: one write for the one hint change (the first connect),
 * none for the other 99 (the first cut wrote 100). */
static void test_store_mesh(void)
{
    const uint32_t h = hash_of(SSID);
    fake_nvs_t f;
    memset(&f, 0, sizeof(f));
    tl_wifi_blob_t m;
    memset(&m, 0, sizeof(m));
    tl_wifi_retry_t s;
    tl_wifi_retry_init(&s, NULL, h);
    int changed = 0, hint_changes = 0;
    uint8_t last_hint = 0;
    for (int i = 0; i < 100; i++) {             /* node A, B, A, B, … all on channel 6 */
        changed += tl_wifi_on_connected(&s, 6, h);
        if (tl_wifi_channel(&s) != last_hint) {
            hint_changes++;
            last_hint = tl_wifi_channel(&s);
        }
        (void)tl_wifi_blob_store(&m, &s.ap, fake_write, &f);
        (void)tl_wifi_on_disconnected(&s, 200);
    }
    printf("  mesh: 100 reconnects across nodes on channel 6: %d NVS writes, %d hint changes\n",
           f.writes, hint_changes);
    check("store/mesh-nodes-one-channel-one-write", f.writes == 1 && hint_changes == 1 && changed == 1);
}

/* ---- Retry policy ----------------------------------------------------- */

static void test_retry_init(void)
{
    const uint32_t h = hash_of(SSID);
    const tl_wifi_ap_t a = ap_make(11, SSID);
    tl_wifi_retry_t s;
    tl_wifi_retry_init(&s, &a, h);
    check("retry/init-with-record", s.hint && tl_wifi_channel(&s) == 11 && !s.joined);
    tl_wifi_retry_init(&s, NULL, h);
    check("retry/init-without", !s.hint && tl_wifi_channel(&s) == 0 && s.ap.channel == 0);
    const tl_wifi_ap_t other = ap_make(11, SSID2);
    tl_wifi_retry_init(&s, &other, h);
    check("retry/init-other-ssid-ignored", !s.hint && tl_wifi_channel(&s) == 0);
}

/* The hardware-reset boot of the 1.3.x series: hint ch 11, comeback,
 * 4-way timeout, then the immediate retry; if that fails too, the
 * ladder without the hint. */
static void test_retry_hard_reset(void)
{
    const uint32_t h = hash_of(SSID);
    const tl_wifi_ap_t a = ap_make(11, SSID);
    tl_wifi_retry_t s;
    tl_wifi_retry_init(&s, &a, h);

    tl_wifi_next_t n = tl_wifi_on_disconnected(&s, TL_WIFI_REASON_4WAY);
    check("retry/4way-timeout-immediate", n.now && n.reapply && n.channel == 11);
    check("retry/needs-config-for-blacklist", tl_wifi_needs_config(&n, 11));
    n = tl_wifi_on_disconnected(&s, TL_WIFI_REASON_4WAY);
    check("retry/second-timeout-backoff-no-hint", !n.now && !n.reapply && n.channel == 0 && !s.hint);
    check("retry/hint-off-needs-config", tl_wifi_needs_config(&n, 11) && !tl_wifi_needs_config(&n, 0));
    n = tl_wifi_on_disconnected(&s, TL_WIFI_REASON_4WAY);
    check("retry/third-still-no-hint", !n.now && n.channel == 0);
    check("retry/connect-restores-hint", !tl_wifi_on_connected(&s, 11, h) && s.hint &&
                                         tl_wifi_channel(&s) == 11 && s.joined);

    tl_wifi_retry_init(&s, &a, h);
    n = tl_wifi_on_disconnected(&s, TL_WIFI_REASON_HS);
    check("retry/204-also-immediate", n.now && n.channel == 11);
}

static void test_retry_other_failures(void)
{
    const uint32_t h = hash_of(SSID);
    const tl_wifi_ap_t a = ap_make(11, SSID);
    tl_wifi_retry_t s;
    static const uint16_t reasons[] = { 2, 8, 23, 200, 201, 202, 203, 205, 208, 209, 210, 211 };
    int all = 1;
    for (size_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++) {
        tl_wifi_retry_init(&s, &a, h);
        const tl_wifi_next_t n = tl_wifi_on_disconnected(&s, reasons[i]);
        if (n.now || n.reapply || n.channel != 0 || s.hint) {
            printf("  reason %u: now=%d channel=%u hint=%d\n", reasons[i], n.now, n.channel, s.hint);
            all = 0;
        }
    }
    check("retry/any-other-failure-drops-hint", all);

    /* Review R2 (1.3.7): first boot, nothing stored — the immediate retry
     * still happens, as wifi_hint.h now says (the blacklist dropped, no
     * backoff), scanning 1..N; one per streak, then the ladder. */
    tl_wifi_retry_init(&s, NULL, h);
    tl_wifi_next_t n = tl_wifi_on_disconnected(&s, TL_WIFI_REASON_4WAY);
    check("retry/no-record-immediate-too-1..N", n.now && n.reapply && n.channel == 0);
    n = tl_wifi_on_disconnected(&s, TL_WIFI_REASON_4WAY);
    check("retry/no-record-then-ladder", !n.now && !n.reapply && n.channel == 0);
    check("retry/no-record-connect-learns", tl_wifi_on_connected(&s, 6, h) &&
                                            tl_wifi_channel(&s) == 6 && s.ap.ssid_hash == h);
}

static void test_retry_link(void)
{
    const uint32_t h = hash_of(SSID);
    const tl_wifi_ap_t a = ap_make(11, SSID);
    tl_wifi_retry_t s;
    tl_wifi_retry_init(&s, &a, h);
    (void)tl_wifi_on_disconnected(&s, TL_WIFI_REASON_4WAY);     /* spends the fast retry */
    (void)tl_wifi_on_connected(&s, 11, h);

    /* Beacon timeout on a working link: hint kept, the ladder. */
    tl_wifi_next_t n = tl_wifi_on_disconnected(&s, 200);
    check("retry/link-loss-keeps-hint", !n.now && n.channel == 11 && s.hint && !s.joined);
    check("retry/link-loss-no-config", !tl_wifi_needs_config(&n, 11));
    /* A new streak: its first 4-way timeout gets the immediate retry again. */
    n = tl_wifi_on_disconnected(&s, TL_WIFI_REASON_4WAY);
    check("retry/new-streak-immediate-again", n.now && n.channel == 11);

    /* Even a reason-15 deauth on a working link (a failed rekey) is a link
     * loss, not a handshake retry. */
    (void)tl_wifi_on_connected(&s, 11, h);
    n = tl_wifi_on_disconnected(&s, TL_WIFI_REASON_4WAY);
    check("retry/4way-while-joined-is-link-loss", !n.now && n.channel == 11 && !s.fast_spent);

    /* First boot without a record, link learned, then lost: the next
     * attempt needs the config (channel 0 → 6). */
    tl_wifi_retry_init(&s, NULL, h);
    (void)tl_wifi_on_connected(&s, 6, h);
    n = tl_wifi_on_disconnected(&s, 200);
    check("retry/learned-hint-applied-on-reconnect", n.channel == 6 && tl_wifi_needs_config(&n, 0));
}

static void test_retry_connected(void)
{
    const uint32_t h = hash_of(SSID);
    const tl_wifi_ap_t a = ap_make(11, SSID);
    tl_wifi_retry_t s;
    tl_wifi_retry_init(&s, &a, h);
    check("connected/same-channel-unchanged", !tl_wifi_on_connected(&s, 11, h));
    (void)tl_wifi_on_disconnected(&s, 200);
    check("connected/moved-channel-changed", tl_wifi_on_connected(&s, 6, h) && s.ap.channel == 6);
    (void)tl_wifi_on_disconnected(&s, 200);
    const int bad_ch = !tl_wifi_on_connected(&s, 0, h) && s.ap.channel == 6 && s.joined;
    (void)tl_wifi_on_disconnected(&s, 200);
    const int bad_15 = !tl_wifi_on_connected(&s, 15, h) && s.ap.channel == 6;
    check("connected/invalid-channel-keeps-record", bad_ch && bad_15);
}

/* Review L4 (1.3.7): the reconnect path's esp_wifi_set_config can fail
 * (ESP_ERR_WIFI_STATE); the blacklist clear then stays pending until one
 * succeeds — the first cut dropped it before trying. */
static void test_config_pending(void)
{
    const uint32_t h = hash_of(SSID);
    const tl_wifi_ap_t a = ap_make(11, SSID);
    tl_wifi_retry_t s;
    tl_wifi_retry_init(&s, &a, h);
    uint8_t applied = 11;                               /* boot config */
    tl_wifi_next_t pending = tl_wifi_on_disconnected(&s, TL_WIFI_REASON_4WAY);
    int ok = tl_wifi_needs_config(&pending, applied);
    tl_wifi_config_done(&pending, false);               /* set_config failed */
    ok = ok && pending.reapply && tl_wifi_needs_config(&pending, applied);
    tl_wifi_config_done(&pending, true);                /* the next attempt's succeeded */
    ok = ok && !pending.reapply && !tl_wifi_needs_config(&pending, applied);
    check("config/failed-reapply-stays-pending", ok);

    /* Hint off after the second failure: channel 11 → 0 needs a config;
     * once applied, later attempts on 0 need none. */
    tl_wifi_next_t n = tl_wifi_on_disconnected(&s, TL_WIFI_REASON_4WAY);
    pending.reapply = pending.reapply || n.reapply;      /* as app_wifi.c merges */
    pending.channel = n.channel;
    ok = tl_wifi_needs_config(&pending, applied);
    tl_wifi_config_done(&pending, true);
    applied = pending.channel;
    n = tl_wifi_on_disconnected(&s, 205);
    pending.reapply = pending.reapply || n.reapply;
    pending.channel = n.channel;
    check("config/channel-change-once", ok && applied == 0 && !tl_wifi_needs_config(&pending, applied));
}

/* ---- Random walk over a simulated driver ------------------------------ */

/* The AP: its channel, and whether the next 4-way handshake fails. The
 * driver: a scan with any sta.channel finds the AP on its real channel
 * (the hint only orders the scan); an attempt either joins or fails with
 * some reason. Invariants, checked at every step:
 *   - at most one immediate retry per failure streak (between a join or a
 *     link loss and the next join);
 *   - after a failure that was not the immediate retry's grant, the next
 *     attempt scans 1..N (channel 0) until a join;
 *   - a hint is always the channel of the last join or of the boot record;
 *   - a join rewrites the record to the AP joined, whatever channel the
 *     AP moved to meanwhile (3 % of the steps). */
static void test_random_walk(void)
{
    const uint32_t h = hash_of(SSID);
    srand(20261030);
    int violations = 0, joins = 0, fast = 0, moved = 0, max_streak = 0;
    tl_wifi_retry_t s;
    tl_wifi_ap_t real = ap_make(11, SSID);
    tl_wifi_retry_init(&s, &real, h);
    uint8_t named = 11;                 /* last channel a join / the record named */
    int streak_fast = 0, streak_len = 0, must_scan_all = 0;

    for (int step = 0; step < 200000; step++) {
        const int r = rand() % 100;
        if (r < 3) {                    /* the AP changes channel or is replaced */
            real.channel = (uint8_t)(1 + rand() % 13);
            moved++;
            continue;
        }
        if (r < 50 && s.joined) {       /* link loss */
            const tl_wifi_next_t n = tl_wifi_on_disconnected(&s, 200);
            if (n.now || (n.channel != 0 && n.channel != named)) violations++;
            streak_fast = 0;
            streak_len = 0;
            must_scan_all = 0;
            continue;
        }
        if (s.joined) continue;
        /* An attempt. The channel used must be 0 or a named one. */
        const uint8_t ch = tl_wifi_channel(&s);
        if (ch != 0 && ch != named) violations++;
        if (must_scan_all && ch != 0) violations++;
        streak_len++;
        if (streak_len > max_streak) max_streak = streak_len;
        /* Outcome: 30 % a 4-way timeout, 10 % another failure, else a join;
         * the fifth attempt of a streak always joins (AP reachable). */
        const int o = rand() % 100;
        if (streak_len < 5 && o < 40) {
            const uint16_t reason = o < 30 ? TL_WIFI_REASON_4WAY : (uint16_t)(200 + rand() % 12);
            const tl_wifi_next_t n = tl_wifi_on_disconnected(&s, reason);
            if (n.now) {
                fast++;
                if (++streak_fast > 1) violations++;
                if (!n.reapply) violations++;
            } else {
                must_scan_all = 1;
                if (n.channel != 0) violations++;
            }
        } else {
            (void)tl_wifi_on_connected(&s, real.channel, h);
            joins++;
            if (!ap_eq(&s.ap, &real) || tl_wifi_channel(&s) != real.channel) violations++;
            named = real.channel;
            streak_fast = 0;
            streak_len = 0;
            must_scan_all = 0;
        }
    }
    printf("  random walk: %d joins, %d immediate retries, %d AP moves, longest streak %d\n",
           joins, fast, moved, max_streak);
    check("walk/invariants-hold", violations == 0);
    check("walk/coverage", joins > 50000 && fast > 1000 && moved > 1000 && max_streak == 5);
}

int main(void)
{
    test_hash();
    test_ap_ok();
    test_blob();
    test_rtc();
    test_boot();
    test_store();
    test_store_mesh();
    test_retry_init();
    test_retry_hard_reset();
    test_retry_other_failures();
    test_retry_link();
    test_retry_connected();
    test_config_pending();
    test_random_walk();
    if (s_fails) {
        printf("%d FAILED\n", s_fails);
        return 1;
    }
    printf("ALL OK\n");
    return 0;
}
