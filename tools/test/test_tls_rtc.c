// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// TLS sessions across warm resets (tls_rtc.h + tls_resume.c with
// CONFIG_TINYLINK_TLS_RESUME_RTC, round 1.3.8) over a scripted esp_tls, a
// fake RTC timer and a fake mbedTLS session (de)serializer.
//
//  - the record: sealed with a checksum over every field; garbage, a
//    flipped byte, a missing NUL, an oversize length, another host or
//    port, an age past 24 h or an RTC timer behind its birth are never
//    used; pick reuses the record of the same host:port, then an unused
//    one, then the oldest; clear zeroes it;
//  - the glue: every keep writes the session; after a "reset" (RAM slot
//    and heap gone, RTC kept) the first take restores it once — with the
//    master secret's age carried over on the RTC clock — and the resumed
//    handshake keeps going; a failed connect clears it; an expired one is
//    cleared; a session that does not fit is not kept; two servers use
//    two records; a third evicts the oldest; the restore happens once per
//    record per boot; a session mbedTLS refuses to load is dropped;
//  - review 1.3.8: an RTC timer that restarted under the record (reads
//    earlier than its last write) never restores it — the 23-h secret
//    that looked 2 s old; only a warm reset restores, and the boot sweep
//    zeroes everything else (cold boot, expired, garbage) at once; a
//    master secret older than the RTC time is not saved; a seal zeroes the
//    previous session's tail;
//  - review 138b: with the sweep first thing in every boot, a cold boot
//    that restarts before any TLS (no Wi-Fi) does not pass its records on
//    to the software-reset boot after it.

#include "../../components/tinylink/src/tls_resume.c"

#include <stdio.h>

tls_rtc_rec_t s_rtc[TLS_RTC_RECS];
static int64_t s_now = 5000000;   /* esp_timer µs (since this boot) */
/* The RTC timer runs with esp_timer during a boot and keeps running
 * through a warm reset: RTC = base + esp_timer, base moved at each reset. */
static uint64_t s_rtc_base = 5000000000ull;
uint64_t rtc_now_us(void) { return s_rtc_base + (uint64_t)s_now; }
/* The boot's reset reason, as tls_resume.c's ESP side classifies it. */
static bool s_warm = true;
bool rtc_warm_boot(void) { return s_warm; }

struct esp_tls {
    mbedtls_ssl_session cur;
};

static int s_alloc, s_free;
int64_t esp_timer_get_time(void) { return s_now; }

int mbedtls_ct_memcmp(const void *a, const void *b, size_t n) { return memcmp(a, b, n) != 0; }

esp_tls_client_session_t *esp_tls_get_client_session(esp_tls_t *t)
{
    esp_tls_client_session_t *c = calloc(1, sizeof(*c));
    c->saved_session = t->cur;
    if (t->cur.ticket_len) {
        c->saved_session.ticket = malloc(t->cur.ticket_len);
        memcpy(c->saved_session.ticket, t->cur.ticket, t->cur.ticket_len);
    }
    s_alloc++;
    return c;
}

void esp_tls_free_client_session(esp_tls_client_session_t *c)
{
    if (c == NULL) return;
    free(c->saved_session.ticket);
    free(c);
    s_free++;
}

/* Fake serializer: tag, suite, id_len, master, ticket_len, ticket. */
static int s_load_fail, s_load_calls;   /* one calloc'd session per call */
void mbedtls_ssl_session_init(mbedtls_ssl_session *s) { memset(s, 0, sizeof(*s)); }
int mbedtls_ssl_session_save(const mbedtls_ssl_session *s, unsigned char *buf, size_t n,
                             size_t *olen)
{
    const size_t need = 1 + 4 + 4 + 48 + 4 + s->ticket_len;
    *olen = need;
    if (need > n) return MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL;
    uint32_t v;
    buf[0] = 0x5e;
    v = (uint32_t)s->ciphersuite; memcpy(buf + 1, &v, 4);
    v = (uint32_t)s->id_len;      memcpy(buf + 5, &v, 4);
    memcpy(buf + 9, s->master, 48);
    v = (uint32_t)s->ticket_len;  memcpy(buf + 57, &v, 4);
    memcpy(buf + 61, s->ticket, s->ticket_len);
    return 0;
}
int mbedtls_ssl_session_load(mbedtls_ssl_session *s, const unsigned char *buf, size_t n)
{
    s_load_calls++;
    if (s_load_fail || n < 61 || buf[0] != 0x5e) return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    uint32_t v;
    memcpy(&v, buf + 1, 4);  s->ciphersuite = (int)v;
    memcpy(&v, buf + 5, 4);  s->id_len = v;
    memcpy(s->master, buf + 9, 48);
    memcpy(&v, buf + 57, 4); s->ticket_len = v;
    if (61 + s->ticket_len != n) return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    s->ticket = malloc(s->ticket_len);
    memcpy(s->ticket, buf + 61, s->ticket_len);
    return 0;
}

static int s_fails;
static void check(const char *name, int ok)
{
    printf("[%s] %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) s_fails++;
}

static uint8_t s_ticket[128], s_big_ticket[TLS_RTC_SESS_MAX];

static void conn(esp_tls_t *t, uint8_t m, uint8_t *ticket, size_t tlen)
{
    memset(t, 0, sizeof(*t));
    t->cur.ciphersuite = 0xC02F;
    memset(t->cur.master, m, sizeof(t->cur.master));
    t->cur.ticket = ticket;
    t->cur.ticket_len = tlen;
}

/* A warm reset: RAM (slot, heap entry, the once-per-boot flags, esp_timer)
 * gone, RTC memory and the RTC timer kept (advanced by `gap_us`). */
static void new_boot(tls_resume_slot_t *slot, bool warm)
{
    entry_free(*slot);
    *slot = NULL;
    memset(s_rtc_tried, 0, sizeof(s_rtc_tried));
    s_rtc_swept = false;
    s_warm = warm;
}

static void warm_reset(tls_resume_slot_t *slot, uint64_t gap_us)
{
    new_boot(slot, true);
    s_rtc_base += (uint64_t)s_now + gap_us - 1000000;
    s_now = 1000000;
}

static const char kDerp[] = "derp16b.tailscale.com";
static const char kCtl[]  = "controlplane.tailscale.com";

int main(void)
{
    memset(s_ticket, 0x7c, sizeof(s_ticket));
    memset(s_big_ticket, 0x3d, sizeof(s_big_ticket));

    /* --- the record ------------------------------------------------------ */
    tls_rtc_rec_t r;
    memset(&r, 0xa5, sizeof(r));   /* power-on garbage */
    check("rtc_garbage_invalid", !tls_rtc_valid(&r));
    memset(r.sess, 0x42, 100);
    memset(r.sess + 100, 0x77, sizeof(r.sess) - 100);   /* a longer session's tail */
    check("rtc_seal", tls_rtc_seal(&r, kDerp, 443, 1000, 1000, 100) && tls_rtc_valid(&r));
    {
        uint8_t z[TLS_RTC_SESS_MAX - 100] = { 0 };
        check("rtc_seal_zeroes_tail", memcmp(r.sess + 100, z, sizeof(z)) == 0 && r.sess[99] == 0x42);
    }
    uint64_t age = 0;
    check("rtc_usable", tls_rtc_usable(&r, kDerp, 443, 1000 + 5, 10, &age) && age == 5);
    check("rtc_other_port", !tls_rtc_usable(&r, kDerp, 8443, 1005, 10, NULL));
    check("rtc_other_host", !tls_rtc_usable(&r, kCtl, 443, 1005, 10, NULL));
    check("rtc_prefix_host", !tls_rtc_usable(&r, "derp16b", 443, 1005, 10, NULL));
    check("rtc_too_old", !tls_rtc_usable(&r, kDerp, 443, 1011, 10, NULL) &&
                         tls_rtc_usable(&r, kDerp, 443, 1010, 10, NULL));
    check("rtc_clock_restarted", !tls_rtc_usable(&r, kDerp, 443, 999, 10, NULL));
    r.sess[50] ^= 1;
    check("rtc_flipped_session_byte", !tls_rtc_valid(&r));
    r.sess[50] ^= 1;
    r.sess[200] ^= 1;   /* past len: not covered, not used */
    check("rtc_bytes_past_len_ignored", tls_rtc_valid(&r));
    r.born_rtc_us++;
    check("rtc_flipped_birth", !tls_rtc_valid(&r));
    r.born_rtc_us--;
    r.len = TLS_RTC_SESS_MAX + 1;
    check("rtc_oversize_len", !tls_rtc_valid(&r));
    r.len = 100;
    memset(r.host, 'x', sizeof(r.host));
    r.check = tls_rtc_check(&r);
    check("rtc_unterminated_host", !tls_rtc_valid(&r));
    check("rtc_seal_rejects_long_host",
          !tls_rtc_seal(&r, "a-host-name-of-sixty-four-characters-is-one-too-many-for-the-rec",
                        443, 1, 1, 10) && r.magic == 0 && r.len == 0);
    check("rtc_seal_rejects_len", !tls_rtc_seal(&r, kDerp, 443, 1, 1, 0) &&
                                  !tls_rtc_seal(&r, kDerp, 443, 1, 1, TLS_RTC_SESS_MAX + 1));
    check("rtc_seal_rejects_future_birth", !tls_rtc_seal(&r, kDerp, 443, 2, 1, 10));
    /* written at 5000 for a secret born at 1000: the RTC timer reading
     * earlier than the write means it restarted, whatever the birth says */
    tls_rtc_seal(&r, kDerp, 443, 1000, 5000, 10);
    check("rtc_clock_behind_last_write", !tls_rtc_usable(&r, kDerp, 443, 4999, 100000, NULL) &&
                                         tls_rtc_usable(&r, kDerp, 443, 5000, 100000, NULL));
    r.saved_rtc_us++;
    check("rtc_flipped_write_time", !tls_rtc_valid(&r));
    tls_rtc_rec_t recs[2];
    memset(recs, 0xa5, sizeof(recs));
    check("rtc_pick_unused_first", tls_rtc_pick(recs, 2, kDerp, 443) == 0);
    tls_rtc_seal(&recs[1], kDerp, 443, 50, 50, 10);
    check("rtc_pick_same_host", tls_rtc_pick(recs, 2, kDerp, 443) == 1 &&
                                tls_rtc_find(recs, 2, kDerp, 443) == 1);
    check("rtc_pick_spare_for_other", tls_rtc_pick(recs, 2, kCtl, 443) == 0 &&
                                      tls_rtc_find(recs, 2, kCtl, 443) == 2);
    tls_rtc_seal(&recs[0], kCtl, 443, 70, 70, 10);
    check("rtc_pick_evicts_oldest", tls_rtc_pick(recs, 2, "derp1.tailscale.com", 443) == 1);
    tls_rtc_clear(&recs[0]);
    uint8_t zero[sizeof(recs[0])] = { 0 };
    check("rtc_clear_zeroes", memcmp(&recs[0], zero, sizeof(zero)) == 0);
    /* sweep: keeps a fresh record on a warm boot, zeroes garbage, expired,
     * clock-behind and — on a cold boot — everything */
    memset(recs, 0xa5, sizeof(recs));
    memset(recs[1].sess, 0x42, 10);
    tls_rtc_seal(&recs[1], kDerp, 443, 100, 200, 10);
    check("rtc_sweep_warm_keeps_fresh",
          tls_rtc_sweep(recs, 2, true, 300, 1000) == 0 && tls_rtc_valid(&recs[1]) &&
          memcmp(&recs[0], zero, sizeof(zero)) == 0);
    check("rtc_sweep_expired", tls_rtc_sweep(recs, 2, true, 1101, 1000) == 1 &&
                               memcmp(&recs[1], zero, sizeof(zero)) == 0);
    tls_rtc_seal(&recs[1], kDerp, 443, 100, 200, 10);
    check("rtc_sweep_clock_behind", tls_rtc_sweep(recs, 2, true, 150, 1000) == 1 &&
                                    !tls_rtc_valid(&recs[1]));
    tls_rtc_seal(&recs[1], kDerp, 443, 100, 200, 10);
    check("rtc_sweep_cold_boot", tls_rtc_sweep(recs, 2, false, 300, 1000) == 1 &&
                                 memcmp(&recs[1], zero, sizeof(zero)) == 0);

    /* --- the glue -------------------------------------------------------- */
    memset(s_rtc, 0xa5, sizeof(s_rtc));   /* power-on */
    tls_resume_slot_t slot = NULL;
    esp_tls_t t;

    check("glue_poweron_nothing", tls_resume_take(&slot, kDerp, 443) == NULL);
    conn(&t, 0x11, s_ticket, sizeof(s_ticket));
    check("glue_full_kept", tls_resume_keep(&slot, NULL, &t, kDerp, 443) == TLS_RESUME_FULL);
    check("glue_written", tls_rtc_find(s_rtc, TLS_RTC_RECS, kDerp, 443) < TLS_RTC_RECS);
    const int64_t born = slot->born_us;

    s_now = born + 600LL * 1000000;   /* 10 min of uptime, then a panic */
    warm_reset(&slot, 3000000);        /* 3 s to reboot */
    tls_resume_entry_t *e = tls_resume_take(&slot, kDerp, 443);
    check("glue_restored", e != NULL && e->sess->saved_session.master[0] == 0x11 &&
                           e->sess->saved_session.ticket_len == sizeof(s_ticket) &&
                           e->sess->saved_session.ciphersuite == 0xC02F &&
                           strcmp(e->host, kDerp) == 0 && e->port == 443);
    /* 600 s + 3 s old: born_us lands 603 s before now on the new clock */
    check("glue_age_carried", e != NULL && s_now - e->born_us == 603LL * 1000000);
    conn(&t, 0x11, s_ticket, sizeof(s_ticket));
    check("glue_resumed_after_reset", tls_resume_keep(&slot, e, &t, kDerp, 443) == TLS_RESUME_RESUMED);

    /* once per boot: a second empty-slot take does not restore again */
    e = tls_resume_take(&slot, kDerp, 443);
    check("glue_take_ram", e != NULL);
    entry_free(e);
    check("glue_once_per_boot", tls_resume_take(&slot, kDerp, 443) == NULL);

    /* a failed connect clears the RTC copy too */
    conn(&t, 0x22, s_ticket, sizeof(s_ticket));
    tls_resume_keep(&slot, NULL, &t, kDerp, 443);
    e = tls_resume_take(&slot, kDerp, 443);
    tls_resume_keep(&slot, e, NULL, kDerp, 443);
    check("glue_failed_clears", tls_rtc_find(s_rtc, TLS_RTC_RECS, kDerp, 443) == TLS_RTC_RECS);
    warm_reset(&slot, 1000000);
    check("glue_failed_not_restored", tls_resume_take(&slot, kDerp, 443) == NULL);

    /* past 24 h of master-secret age across the reset: cleared, not used */
    conn(&t, 0x33, s_ticket, sizeof(s_ticket));
    tls_resume_keep(&slot, NULL, &t, kDerp, 443);
    warm_reset(&slot, (uint64_t)TLS_RESUME_MAX_AGE_S * 1000000 + 1);
    check("glue_expired_not_restored", tls_resume_take(&slot, kDerp, 443) == NULL &&
          tls_rtc_find(s_rtc, TLS_RTC_RECS, kDerp, 443) == TLS_RTC_RECS);

    /* the RTC timer restarted under the record (born in its future) */
    conn(&t, 0x44, s_ticket, sizeof(s_ticket));
    tls_resume_keep(&slot, NULL, &t, kDerp, 443);
    entry_free(slot);
    slot = NULL;
    memset(s_rtc_tried, 0, sizeof(s_rtc_tried));
    const uint64_t base = s_rtc_base;
    s_rtc_base = 0;   /* a power glitch that restarted the RTC timer, not RTC memory */
    check("glue_rtc_restart_not_restored", tls_resume_take(&slot, kDerp, 443) == NULL);
    s_rtc_base = base;

    /* two servers, two records; a third evicts the oldest */
    conn(&t, 0x55, s_ticket, sizeof(s_ticket));
    tls_resume_slot_t ctl = NULL, other = NULL;
    tls_resume_keep(&slot, NULL, &t, kDerp, 443);
    s_now += 1000000;
    conn(&t, 0x66, s_ticket, sizeof(s_ticket));
    tls_resume_keep(&ctl, NULL, &t, kCtl, 443);
    check("glue_two_records", tls_rtc_find(s_rtc, TLS_RTC_RECS, kDerp, 443) < TLS_RTC_RECS &&
                              tls_rtc_find(s_rtc, TLS_RTC_RECS, kCtl, 443) < TLS_RTC_RECS);
    warm_reset(&ctl, 0);
    entry_free(slot);
    slot = NULL;
    e = tls_resume_take(&ctl, kCtl, 443);
    tls_resume_entry_t *e2 = tls_resume_take(&slot, kDerp, 443);
    check("glue_both_restored", e != NULL && e2 != NULL &&
                                e->sess->saved_session.master[0] == 0x66 &&
                                e2->sess->saved_session.master[0] == 0x55);
    entry_free(e);
    entry_free(e2);
    conn(&t, 0x77, s_ticket, sizeof(s_ticket));
    s_now += 1000000;
    tls_resume_keep(&other, NULL, &t, "derp1.tailscale.com", 443);
    check("glue_third_evicts_oldest",
          tls_rtc_find(s_rtc, TLS_RTC_RECS, kDerp, 443) == TLS_RTC_RECS &&
          tls_rtc_find(s_rtc, TLS_RTC_RECS, kCtl, 443) < TLS_RTC_RECS &&
          tls_rtc_find(s_rtc, TLS_RTC_RECS, "derp1.tailscale.com", 443) < TLS_RTC_RECS);

    /* a session that does not fit a record is not kept in RTC (RAM still) */
    conn(&t, 0x88, s_big_ticket, sizeof(s_big_ticket));
    check("glue_oversize_ram_only",
          tls_resume_keep(&other, NULL, &t, "derp1.tailscale.com", 443) == TLS_RESUME_FULL &&
          other != NULL &&
          tls_rtc_find(s_rtc, TLS_RTC_RECS, "derp1.tailscale.com", 443) == TLS_RTC_RECS);

    /* a record mbedTLS refuses to load: dropped */
    conn(&t, 0x99, s_ticket, sizeof(s_ticket));
    tls_resume_keep(&other, NULL, &t, "derp1.tailscale.com", 443);
    warm_reset(&other, 0);
    s_load_fail = 1;
    const int frees = s_free;
    check("glue_unloadable_dropped",
          tls_resume_take(&other, "derp1.tailscale.com", 443) == NULL &&
          tls_rtc_find(s_rtc, TLS_RTC_RECS, "derp1.tailscale.com", 443) == TLS_RTC_RECS &&
          s_free == frees + 1);
    s_load_fail = 0;

    /* review 1.3.8: the RTC timer restarts from 0 while RTC slow memory
     * keeps the record. A session made at RTC ~4 s and resumed for 23 h
     * keeps born = 4 s; after the restart the RTC reads ~6 s. */
    entry_free(other);
    other = NULL;
    memset(s_rtc, 0xa5, sizeof(s_rtc));
    new_boot(&slot, false);
    s_rtc_base = 0;
    s_now = 4000000;
    conn(&t, 0x11, s_ticket, sizeof(s_ticket));
    tls_resume_keep(&slot, NULL, &t, kDerp, 443);
    for (int h = 1; h <= 23; h++) {
        s_now = 4000000 + (int64_t)h * 3600 * 1000000;
        e = tls_resume_take(&slot, kDerp, 443);
        conn(&t, 0x11, s_ticket, sizeof(s_ticket));
        tls_resume_keep(&slot, e, &t, kDerp, 443);
    }
    new_boot(&slot, true);   /* even if it were classed a warm reset */
    s_rtc_base = 0;
    s_now = 6000000;
    check("glue_rtc_restart_23h_secret_not_restored",
          tls_resume_take(&slot, kDerp, 443) == NULL &&
          tls_rtc_find(s_rtc, TLS_RTC_RECS, kDerp, 443) == TLS_RTC_RECS);

    /* only after a warm reset: a power-on / EN / brown-out / RTC-WDT boot
     * scrubs the record at the boot sweep, master secret included */
    conn(&t, 0x12, s_ticket, sizeof(s_ticket));
    tls_resume_keep(&slot, NULL, &t, kDerp, 443);
    const unsigned ri = tls_rtc_find(s_rtc, TLS_RTC_RECS, kDerp, 443);
    new_boot(&slot, false);
    s_now += 2000000;
    tls_resume_boot();
    uint8_t zrec[sizeof(tls_rtc_rec_t)] = { 0 };
    check("glue_cold_boot_swept", ri < TLS_RTC_RECS && memcmp(&s_rtc[ri], zrec, sizeof(zrec)) == 0 &&
                                  tls_resume_take(&slot, kDerp, 443) == NULL);
    /* the same record after a warm reset survives the sweep and restores */
    conn(&t, 0x13, s_ticket, sizeof(s_ticket));
    tls_resume_keep(&slot, NULL, &t, kDerp, 443);
    warm_reset(&slot, 1000000);
    tls_resume_boot();
    e = tls_resume_take(&slot, kDerp, 443);
    check("glue_warm_boot_restores", e != NULL && e->sess->saved_session.master[0] == 0x13);
    entry_free(e);
    /* an expired record is scrubbed at boot, not when looked up */
    conn(&t, 0x14, s_ticket, sizeof(s_ticket));
    tls_resume_keep(&slot, NULL, &t, kCtl, 443);
    const unsigned ci = tls_rtc_find(s_rtc, TLS_RTC_RECS, kCtl, 443);
    warm_reset(&slot, (uint64_t)TLS_RESUME_MAX_AGE_S * 1000000 + 1);
    tls_resume_boot();
    check("glue_expired_swept_at_boot", ci < TLS_RTC_RECS &&
                                        memcmp(&s_rtc[ci], zrec, sizeof(zrec)) == 0);

    /* a master secret older than the RTC time itself (the timer restarted
     * during this boot): not saved, and the host's old record dropped */
    conn(&t, 0x15, s_ticket, sizeof(s_ticket));
    tls_resume_keep(&slot, NULL, &t, kDerp, 443);
    check("glue_saved", tls_rtc_find(s_rtc, TLS_RTC_RECS, kDerp, 443) < TLS_RTC_RECS);
    e = tls_resume_take(&slot, kDerp, 443);
    s_now += 10LL * 1000000;
    s_rtc_base = (uint64_t)0 - (uint64_t)s_now + 5000000;   /* RTC now reads 5 s */
    conn(&t, 0x15, s_ticket, sizeof(s_ticket));
    e->born_us = s_now - 6LL * 1000000;                      /* 6 s old > 5 s of RTC */
    check("glue_age_beyond_rtc_not_saved",
          tls_resume_keep(&slot, e, &t, kDerp, 443) == TLS_RESUME_RESUMED &&
          tls_rtc_find(s_rtc, TLS_RTC_RECS, kDerp, 443) == TLS_RTC_RECS);
    s_rtc_base = 5000000000ull;

    /* review 138b: every boot sweeps first thing (tinylink_bootstat_record).
     * Epoch A: power-on, a DERP full handshake at 20 s (last write 20 s),
     * up 23 h. Then an RTC-domain reset (timer from 0, RTC memory kept)
     * and boot B finds no Wi-Fi: bringup fails, esp_restart 92 s later,
     * no TLS at all. Boot C is a software reset (warm): by then the new
     * RTC timer (100 s) is past the record's last write, so only the
     * sweep boot B ran at its start keeps the 23-h secret from coming
     * back as "80 s old". */
    entry_free(slot);
    slot = NULL;
    memset(s_rtc, 0, sizeof(s_rtc));
    new_boot(&slot, false);
    s_rtc_base = 0;
    s_now = 0;
    tls_resume_boot();                                   /* boot A, first thing */
    s_now = 20LL * 1000000;
    conn(&t, 0xA5, s_ticket, sizeof(s_ticket));
    tls_resume_keep(&slot, tls_resume_take(&slot, kDerp, 443), &t, kDerp, 443);
    s_now = 23LL * 3600 * 1000000;
    new_boot(&slot, false);                              /* boot B: RTC-domain reset */
    s_rtc_base = 0;
    s_now = 0;
    tls_resume_boot();                                   /* first thing, before any restart */
    s_now = 92LL * 1000000;                              /* no Wi-Fi, esp_restart */
    new_boot(&slot, true);                               /* boot C: ESP_RST_SW */
    s_rtc_base = 92ULL * 1000000;
    s_now = 0;
    tls_resume_boot();
    s_now = 8LL * 1000000;
    check("glue_cold_boot_then_sw_restart_not_restored",
          tls_resume_take(&slot, kDerp, 443) == NULL &&
          tls_rtc_find(s_rtc, TLS_RTC_RECS, kDerp, 443) == TLS_RTC_RECS);

    entry_free(slot);
    entry_free(ctl);
    check("glue_every_session_freed", s_free == s_alloc + s_load_calls);

    if (s_fails) {
        printf("%d FAILED\n", s_fails);
        return 1;
    }
    printf("ALL OK\n");
    return 0;
}
