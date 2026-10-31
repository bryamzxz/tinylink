// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// TLS 1.2 session resumption slot (tls_resume.c, round 1.3.5, D9) over a
// scripted esp_tls: what the control (:443) and DERP connects offer and
// keep.
//
//  - a full handshake's session is kept; the next connect to the same
//    host:port takes it and offers it (cfg.client_session);
//  - resumed is told from full by the master secret (an abbreviated
//    handshake reuses it), not by the session ID; a resumed handshake
//    keeps the fresh ticket but the master secret's age; a full one
//    restarts the age;
//  - never offered to another host or port, nor past 24 h; a connect that
//    fails after taking it drops it (the next one is a full handshake);
//    sessions without a ticket or ID, oversize host names and a failed
//    session export keep nothing;
//  - every session the fake esp_tls handed out is freed exactly once.

#include "../../components/tinylink/src/tls_resume.c"

#include <stdio.h>

struct esp_tls {
    mbedtls_ssl_session cur;   /* the conn's session after its handshake */
    bool                fail;  /* esp_tls_get_client_session fails */
};

static int s_alloc, s_free;
static int64_t s_now = 5000000;

esp_tls_client_session_t *esp_tls_get_client_session(esp_tls_t *t)
{
    if (t->fail) return NULL;
    esp_tls_client_session_t *c = calloc(1, sizeof(*c));
    if (c == NULL) return NULL;
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

int64_t esp_timer_get_time(void) { return s_now; }

int mbedtls_ct_memcmp(const void *a, const void *b, size_t n)
{
    return memcmp(a, b, n) != 0;
}

static int s_fails;

static void check(const char *name, int ok)
{
    printf("[%s] %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) s_fails++;
}

static uint8_t s_ticket_a[128], s_ticket_b[160];

/* The conn after a handshake: master secret `m` (one byte repeated),
 * ticket a or b (or none). */
static void conn(esp_tls_t *t, uint8_t m, int ticket)
{
    memset(t, 0, sizeof(*t));
    memset(t->cur.master, m, sizeof(t->cur.master));
    if (ticket == 1) { t->cur.ticket = s_ticket_a; t->cur.ticket_len = sizeof(s_ticket_a); }
    if (ticket == 2) { t->cur.ticket = s_ticket_b; t->cur.ticket_len = sizeof(s_ticket_b); }
}

static const char kDerp[] = "derp16b.tailscale.com";

int main(void)
{
    memset(s_ticket_a, 0xa1, sizeof(s_ticket_a));
    memset(s_ticket_b, 0xb2, sizeof(s_ticket_b));
    tls_resume_slot_t slot = NULL;
    esp_tls_t t;
    esp_tls_cfg_t cfg;

    check("resume_empty_slot", tls_resume_take(&slot, kDerp, 443) == NULL);
    check("resume_null_guards", tls_resume_take(NULL, kDerp, 443) == NULL &&
          tls_resume_take(&slot, NULL, 443) == NULL &&
          tls_resume_keep(NULL, NULL, &t, kDerp, 443) == TLS_RESUME_NONE);

    /* first connect: full handshake, its session kept */
    conn(&t, 0x11, 1);
    check("resume_full_kept",
          tls_resume_keep(&slot, NULL, &t, kDerp, 443) == TLS_RESUME_FULL && slot != NULL &&
          slot->sess->saved_session.ticket_len == sizeof(s_ticket_a));
    const int64_t born = slot->born_us;

    /* reconnect an hour later: taken (slot empty meanwhile), offered */
    s_now += 3600LL * 1000000;
    tls_resume_entry_t *e = tls_resume_take(&slot, kDerp, 443);
    memset(&cfg, 0, sizeof(cfg));
    tls_resume_offer(&cfg, e);
    check("resume_take_offer", e != NULL && slot == NULL && cfg.client_session == e->sess &&
          cfg.client_session->saved_session.master[0] == 0x11);

    /* the server resumed it (same master secret) and sent a new ticket */
    conn(&t, 0x11, 2);
    check("resume_resumed",
          tls_resume_keep(&slot, e, &t, kDerp, 443) == TLS_RESUME_RESUMED && slot == e &&
          slot->sess->saved_session.ticket_len == sizeof(s_ticket_b) &&
          slot->born_us == born);

    /* the master secret ages from its full handshake, not from the last
     * resumption: still offered at 23 h 59 min, never at 24 h + 1 s */
    s_now = born + (TLS_RESUME_MAX_AGE_S - 60) * 1000000LL;
    e = tls_resume_take(&slot, kDerp, 443);
    check("resume_offered_under_24h", e != NULL);
    conn(&t, 0x11, 1);
    check("resume_resumed_again", tls_resume_keep(&slot, e, &t, kDerp, 443) == TLS_RESUME_RESUMED);
    s_now = born + (TLS_RESUME_MAX_AGE_S + 1) * 1000000LL;
    int f0 = s_free;
    check("resume_dropped_past_24h",
          tls_resume_take(&slot, kDerp, 443) == NULL && slot == NULL && s_free == f0 + 1);

    /* the ticket was rejected: a full handshake, its session (new master
     * secret) kept with a fresh age */
    conn(&t, 0x22, 1);
    tls_resume_keep(&slot, NULL, &t, kDerp, 443);
    s_now += 1000000;
    e = tls_resume_take(&slot, kDerp, 443);
    conn(&t, 0x33, 1);
    check("resume_rejected_is_full",
          e != NULL && tls_resume_keep(&slot, e, &t, kDerp, 443) == TLS_RESUME_FULL &&
          slot->sess->saved_session.master[0] == 0x33 && slot->born_us == s_now);

    /* another relay (home region change) or port: never offered, freed */
    f0 = s_free;
    check("resume_other_host_dropped",
          tls_resume_take(&slot, "derp1.tailscale.com", 443) == NULL && slot == NULL &&
          s_free == f0 + 1);
    conn(&t, 0x44, 1);
    tls_resume_keep(&slot, NULL, &t, kDerp, 443);
    f0 = s_free;
    check("resume_other_port_dropped",
          tls_resume_take(&slot, kDerp, 8443) == NULL && slot == NULL && s_free == f0 + 1);

    /* a connect that took it and failed: dropped, the next one is full */
    conn(&t, 0x55, 1);
    tls_resume_keep(&slot, NULL, &t, kDerp, 443);
    e = tls_resume_take(&slot, kDerp, 443);
    f0 = s_free;
    check("resume_failed_connect_drops",
          e != NULL && tls_resume_keep(&slot, e, NULL, kDerp, 443) == TLS_RESUME_NONE &&
          slot == NULL && s_free == f0 + 1 && tls_resume_take(&slot, kDerp, 443) == NULL);

    /* nothing to resume with: no ticket, no session ID */
    conn(&t, 0x66, 0);
    check("resume_no_ticket_kept_nothing",
          tls_resume_keep(&slot, NULL, &t, kDerp, 443) == TLS_RESUME_NONE && slot == NULL);
    conn(&t, 0x66, 0);
    t.cur.id_len = 32;                        /* a server-side session cache */
    check("resume_session_id_kept",
          tls_resume_keep(&slot, NULL, &t, kDerp, 443) == TLS_RESUME_FULL && slot != NULL);

    /* the export failed (heap): the offered one is not kept either */
    e = tls_resume_take(&slot, kDerp, 443);
    conn(&t, 0x66, 1);
    t.fail = true;
    f0 = s_free;
    check("resume_export_failure",
          tls_resume_keep(&slot, e, &t, kDerp, 443) == TLS_RESUME_NONE && slot == NULL &&
          s_free == f0 + 1);

    /* a host name the slot cannot hold is never resumed */
    char longhost[TLS_RESUME_HOST_MAX + 8];
    memset(longhost, 'h', sizeof(longhost) - 1);
    longhost[sizeof(longhost) - 1] = '\0';
    conn(&t, 0x77, 1);
    check("resume_long_host_not_kept",
          tls_resume_keep(&slot, NULL, &t, longhost, 443) == TLS_RESUME_NONE && slot == NULL);
    longhost[TLS_RESUME_HOST_MAX - 1] = '\0';  /* 63 chars: fits */
    check("resume_63_char_host_kept",
          tls_resume_keep(&slot, NULL, &t, longhost, 443) == TLS_RESUME_FULL &&
          (e = tls_resume_take(&slot, longhost, 443)) != NULL);
    tls_resume_keep(&slot, e, NULL, longhost, 443);   /* a failed connect: dropped */

    check("resume_str", strcmp(tls_resume_str(TLS_RESUME_RESUMED), "resumed") == 0 &&
          strcmp(tls_resume_str(TLS_RESUME_FULL), "full") == 0 &&
          strcmp(tls_resume_str(TLS_RESUME_NONE), "no ticket") == 0);

    /* a slot left holding a session is emptied by a take for another
     * server; then every session the fake handed out was freed once */
    conn(&t, 0x88, 1);
    tls_resume_keep(&slot, NULL, &t, kDerp, 443);
    (void)tls_resume_take(&slot, "controlplane.test", 443);
    check("resume_every_session_freed_once", slot == NULL && s_alloc > 0 && s_alloc == s_free);

    if (s_fails == 0) printf("\nALL OK\n");
    return s_fails ? 1 : 0;
}
