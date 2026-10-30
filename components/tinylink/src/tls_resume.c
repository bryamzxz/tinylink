// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "tls_resume.h"

#if CONFIG_ESP_TLS_CLIENT_SESSION_TICKETS

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/ssl.h"

#if CONFIG_TINYLINK_TLS_RESUME_RTC
#include "tls_rtc.h"
#ifdef ESP_PLATFORM
#include <sys/lock.h>
#include "esp_attr.h"
#include "esp_rtc_time.h"
#include "esp_system.h"
#endif
#endif

struct tls_resume_entry {
    esp_tls_client_session_t *sess;
    int64_t  born_us;      /* the full handshake that made its master secret */
    uint16_t port;
    char     host[TLS_RESUME_HOST_MAX];
};

static void entry_free(tls_resume_entry_t *e)
{
    if (e == NULL) return;
    esp_tls_free_client_session(e->sess);   /* zeroizes master + ticket */
    free(e);
}

#if CONFIG_TINYLINK_TLS_RESUME_RTC
/* The warm-reset copies (round 1.3.8, tls_rtc.h). s_rtc_lock serialises
 * the DERP supervisor's and the control conn's keeps (two records, one
 * pick); s_rtc_tried makes the restore a once-per-boot, per-record thing
 * — after it the RAM slot is the session, as without the option;
 * s_rtc_swept runs the boot sweep before the first use. */
#ifdef ESP_PLATFORM
static RTC_NOINIT_ATTR tls_rtc_rec_t s_rtc[TLS_RTC_RECS];
static _lock_t s_rtc_lock;
static uint64_t rtc_now_us(void) { return esp_rtc_get_time_us(); }
static void rtc_lock(void)   { _lock_acquire(&s_rtc_lock); }
static void rtc_unlock(void) { _lock_release(&s_rtc_lock); }
/* The resets that keep both RTC slow memory and the RTC timer: esp_restart
 * (ESP_RST_SW), the panic handler's restart (PANIC, and the two WDTs that
 * panic). Not power-on, EN, brown-out, deep sleep, or the RTC / timer-group
 * WDTs (ESP_RST_WDT), which can reset the RTC domain — and with it the RTC
 * timer the master secret's age is counted on. */
static bool rtc_warm_boot(void)
{
    switch (esp_reset_reason()) {
    case ESP_RST_SW:
    case ESP_RST_PANIC:
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
        return true;
    default:
        return false;
    }
}
#else   /* host test: storage, clock, reset kind and lock come from the test */
extern tls_rtc_rec_t s_rtc[TLS_RTC_RECS];
uint64_t rtc_now_us(void);
bool rtc_warm_boot(void);
static void rtc_lock(void)   { }
static void rtc_unlock(void) { }
#endif
static bool s_rtc_tried[TLS_RTC_RECS];
static bool s_rtc_swept;
static const char *RTC_TAG = "tls_resume";

#define MAX_AGE_US ((uint64_t)TLS_RESUME_MAX_AGE_S * 1000000u)

/* Under rtc_lock: the boot's sweep, once. */
static void rtc_sweep_locked(void)
{
    if (s_rtc_swept) return;
    s_rtc_swept = true;
    const bool warm = rtc_warm_boot();
    const unsigned dropped = tls_rtc_sweep(s_rtc, TLS_RTC_RECS, warm, rtc_now_us(), MAX_AGE_US);
    if (dropped > 0) {
        ESP_LOGI(RTC_TAG, "%u RTC session record(s) scrubbed (%s)", dropped,
                 warm ? "expired" : "not a warm reset");
    }
}

void tls_resume_boot(void)
{
    rtc_lock();
    rtc_sweep_locked();
    rtc_unlock();
}

/* The record for host:port, if usable, as a slot entry (once per boot). */
static tls_resume_entry_t *rtc_restore(const char *host, uint16_t port)
{
    rtc_lock();
    rtc_sweep_locked();
    const unsigned i = tls_rtc_find(s_rtc, TLS_RTC_RECS, host, port);
    uint64_t age = 0;
    tls_resume_entry_t *e = NULL;
    esp_tls_client_session_t *s = NULL;
    if (i == TLS_RTC_RECS || s_rtc_tried[i]) goto out;
    s_rtc_tried[i] = true;
    if (!tls_rtc_usable(&s_rtc[i], host, port, rtc_now_us(), MAX_AGE_US, &age)) {
        tls_rtc_clear(&s_rtc[i]);   /* expired, or the RTC timer restarted */
        goto out;
    }
    s = calloc(1, sizeof(*s));
    e = calloc(1, sizeof(*e));
    if (s == NULL || e == NULL) goto fail;
    mbedtls_ssl_session_init(&s->saved_session);
    const int rc = mbedtls_ssl_session_load(&s->saved_session, s_rtc[i].sess, s_rtc[i].len);
    if (rc != 0) {
        ESP_LOGW(RTC_TAG, "RTC session for %s:%u not loadable (-0x%04x) — dropped",
                 host, (unsigned)port, (unsigned)-rc);
        tls_rtc_clear(&s_rtc[i]);
        goto fail;
    }
    e->sess = s;
    e->born_us = esp_timer_get_time() - (int64_t)age;
    e->port = port;
    strcpy(e->host, s_rtc[i].host);   /* NUL inside TLS_RTC_HOST_MAX (tls_rtc_valid) */
    ESP_LOGI(RTC_TAG, "TLS session for %s:%u from RTC memory (master secret %u s old)",
             host, (unsigned)port, (unsigned)(age / 1000000u));
    goto out;
fail:
    esp_tls_free_client_session(s);
    free(e);
    e = NULL;
out:
    rtc_unlock();
    return e;
}

/* Write e's session into its record (or clear the record when it does
 * not serialize into one, or when its age does not fit the RTC timer —
 * a master secret older than the RTC time itself means that timer
 * restarted during this boot, and a birth can only be stored as a time). */
static void rtc_save(const tls_resume_entry_t *e)
{
    rtc_lock();
    rtc_sweep_locked();
    const uint64_t now = rtc_now_us();
    (void)tls_rtc_sweep(s_rtc, TLS_RTC_RECS, true, now, MAX_AGE_US);   /* aged out since */
    const int64_t age_us = esp_timer_get_time() - e->born_us;
    if (age_us < 0 || (uint64_t)age_us > now) {
        const unsigned j = tls_rtc_find(s_rtc, TLS_RTC_RECS, e->host, e->port);
        if (j < TLS_RTC_RECS) tls_rtc_clear(&s_rtc[j]);
        rtc_unlock();
        return;
    }
    const unsigned i = tls_rtc_pick(s_rtc, TLS_RTC_RECS, e->host, e->port);
    tls_rtc_rec_t *r = &s_rtc[i];
    size_t len = 0;
    r->magic = 0;   /* invalid while the bytes change under it */
    if (mbedtls_ssl_session_save(&e->sess->saved_session, r->sess, sizeof(r->sess), &len) != 0 ||
        !tls_rtc_seal(r, e->host, e->port, now - (uint64_t)age_us, now, len)) {
        tls_rtc_clear(r);
    }
    rtc_unlock();
}

static void rtc_drop(const char *host, uint16_t port)
{
    rtc_lock();
    rtc_sweep_locked();
    const unsigned i = tls_rtc_find(s_rtc, TLS_RTC_RECS, host, port);
    if (i < TLS_RTC_RECS) tls_rtc_clear(&s_rtc[i]);
    rtc_unlock();
}
#else
static tls_resume_entry_t *rtc_restore(const char *host, uint16_t port)
{
    (void)host; (void)port;
    return NULL;
}
static void rtc_save(const tls_resume_entry_t *e) { (void)e; }
static void rtc_drop(const char *host, uint16_t port) { (void)host; (void)port; }
#endif /* CONFIG_TINYLINK_TLS_RESUME_RTC */

tls_resume_entry_t *tls_resume_take(tls_resume_slot_t *slot,
                                    const char *host, uint16_t port)
{
    if (slot == NULL || host == NULL) return NULL;
    tls_resume_entry_t *e = __atomic_exchange_n(slot, NULL, __ATOMIC_ACQ_REL);
    if (e == NULL) e = rtc_restore(host, port);   /* after a warm reset */
    if (e == NULL) return NULL;
    const int64_t age_us = esp_timer_get_time() - e->born_us;
    if (e->port != port || strcmp(e->host, host) != 0 ||
        age_us > (int64_t)TLS_RESUME_MAX_AGE_S * 1000000) {
        if (e->port == port && strcmp(e->host, host) == 0) rtc_drop(host, port);   /* too old */
        entry_free(e);
        return NULL;
    }
    return e;
}

void tls_resume_offer(esp_tls_cfg_t *cfg, const tls_resume_entry_t *taken)
{
    if (cfg != NULL && taken != NULL) cfg->client_session = taken->sess;
}

tls_resume_result_t tls_resume_keep(tls_resume_slot_t *slot,
                                    tls_resume_entry_t *taken, esp_tls_t *tls,
                                    const char *host, uint16_t port)
{
    esp_tls_client_session_t *s = NULL;
    if (slot != NULL && host != NULL && tls != NULL &&
        strlen(host) < TLS_RESUME_HOST_MAX) {
        s = esp_tls_get_client_session(tls);
    }
    /* Nothing to resume with: no ticket and no server session ID (a
     * server that issues neither). */
    if (s != NULL && s->saved_session.MBEDTLS_PRIVATE(ticket_len) == 0 &&
        s->saved_session.MBEDTLS_PRIVATE(id_len) == 0) {
        esp_tls_free_client_session(s);
        s = NULL;
    }
    if (s == NULL) {
        entry_free(taken);   /* a failed connect never re-offers it */
        if (host != NULL) rtc_drop(host, port);   /* nor after a reset */
        return TLS_RESUME_NONE;
    }

    /* An abbreviated handshake reuses the offered master secret; a full
     * one derives a fresh one. Server-independent (unlike the session ID
     * echo, which only Go's full handshakes leave empty). */
    const bool resumed = taken != NULL &&
        mbedtls_ct_memcmp(taken->sess->saved_session.MBEDTLS_PRIVATE(master),
                          s->saved_session.MBEDTLS_PRIVATE(master),
                          sizeof(s->saved_session.MBEDTLS_PRIVATE(master))) == 0;
    tls_resume_entry_t *e = taken;
    if (e == NULL) {
        e = calloc(1, sizeof(*e));
        if (e == NULL) {
            esp_tls_free_client_session(s);
            return TLS_RESUME_NONE;
        }
    } else {
        esp_tls_free_client_session(e->sess);
    }
    e->sess = s;
    if (!resumed) e->born_us = esp_timer_get_time();
    e->port = port;
    strcpy(e->host, host);   /* length checked above */
    rtc_save(e);             /* before the slot owns it: e is ours here */
    entry_free(__atomic_exchange_n(slot, e, __ATOMIC_ACQ_REL));
    return resumed ? TLS_RESUME_RESUMED : TLS_RESUME_FULL;
}

#endif /* CONFIG_ESP_TLS_CLIENT_SESSION_TICKETS */
