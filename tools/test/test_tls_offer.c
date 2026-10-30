// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// The TLS ClientHello offer (tls_offer.c, round 1.3.8) over a scripted
// esp_tls: what the DERP / control / /key connects offer and when they
// fall back.
//
//  - ECDHE-RSA only (0xC02F, 0xC030, 0-terminated) unless the server
//    needed the full offer within TLS_OFFER_MEMO_S, or the session being
//    offered was negotiated under a non-RSA suite (full: a Go server only
//    resumes a session whose suite is listed); NULL list = mbedTLS's
//    default (full) offer;
//  - the fallback fires only after the RSA offer and only on a TLS
//    handshake failure (not a timeout, not a TCP failure): the esp_tls is
//    destroyed and replaced, the retry carries the full offer and no
//    session; a failed esp_tls_init ends it;
//  - only a successful full retry is remembered, per host:port, for 6 h;
//    oversize host names are not remembered;
//  - the connect sequence of derp_client.c / ts2021_client.c end to end.

#include "../../components/tinylink/src/tls_offer.c"

#include <stdio.h>
#include <stdlib.h>

struct esp_tls {
    esp_tls_last_error_t err;
    int                  id;
};

static int64_t s_now = 1000000;
static int s_inits, s_destroys, s_init_fail;
static esp_tls_t *s_live[8];

int64_t esp_timer_get_time(void) { return s_now; }

esp_tls_t *esp_tls_init(void)
{
    if (s_init_fail) return NULL;
    esp_tls_t *t = calloc(1, sizeof(*t));
    t->id = ++s_inits;
    s_live[t->id % 8] = t;
    return t;
}

int esp_tls_conn_destroy(esp_tls_t *t)
{
    if (t != NULL) {
        s_live[t->id % 8] = NULL;
        free(t);
        s_destroys++;
    }
    return 0;
}

esp_err_t esp_tls_get_error_handle(esp_tls_t *t, esp_tls_error_handle_t *h)
{
    if (t == NULL || h == NULL) return ESP_ERR_INVALID_ARG;
    *h = &t->err;
    return ESP_OK;
}

static int s_fails;

static void check(const char *name, int ok)
{
    printf("[%s] %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) s_fails++;
}

static bool is_rsa_list(const int *l)
{
    return l != NULL && l[0] == 0xC02F && l[1] == 0xC030 && l[2] == 0;
}

/* A scripted server: answers the RSA offer with `rsa_rc`/`rsa_err`, the
 * full one with `full_rc`. One "dial" as the callers do it. */
typedef struct {
    int rsa_rc, rsa_err, full_rc;
    int dials, rsa_dials, full_dials;
    bool last_had_session;
} server_t;

static int dial(server_t *sv, esp_tls_t *t, const esp_tls_cfg_t *cfg)
{
    sv->dials++;
    sv->last_had_session = cfg->client_session != NULL;
    if (cfg->ciphersuites_list != NULL) {
        sv->rsa_dials++;
        if (sv->rsa_rc != 1) t->err.last_error = sv->rsa_err;
        return sv->rsa_rc;
    }
    sv->full_dials++;
    return sv->full_rc;
}

/* derp_client.c / ts2021_client.c open_tls, minus resumption. */
static int connect_like_derp(server_t *sv, tls_offer_memo_t *memo, const char *host,
                             uint16_t port, esp_tls_client_session_t *sess,
                             tls_offer_t *used, esp_tls_t **out)
{
    esp_tls_cfg_t cfg = { .common_name = host, .client_session = sess };
    *used = tls_offer_apply(&cfg, memo, host, port);
    esp_tls_t *t = esp_tls_init();
    int rc = dial(sv, t, &cfg);
    if (rc != 1 && tls_offer_fallback(*used, &t, &cfg, host, port)) {
        *used = TLS_OFFER_FULL;
        rc = dial(sv, t, &cfg);
        tls_offer_note(memo, host, port, rc == 1);
    }
    *out = t;
    return rc;
}

int main(void)
{
    tls_offer_memo_t memo = { 0 };
    const char *H = "derp16b.tailscale.com";

    /* --- pick ------------------------------------------------------------ */
    check("pick: fresh memo -> RSA", tls_offer_pick(&memo, H, 443, 0, s_now) == TLS_OFFER_RSA);
    check("pick: NULL memo -> RSA", tls_offer_pick(NULL, H, 443, 0, s_now) == TLS_OFFER_RSA);
    check("pick: NULL host -> full", tls_offer_pick(&memo, NULL, 443, 0, s_now) == TLS_OFFER_FULL);
    check("pick: ECDSA session -> full",
          tls_offer_pick(&memo, H, 443, 0xC02B /* ECDHE-ECDSA-AES128-GCM */, s_now) == TLS_OFFER_FULL);
    check("pick: RSA session -> RSA", tls_offer_pick(&memo, H, 443, 0xC02F, s_now) == TLS_OFFER_RSA);
    check("pick: RSA-256 session -> RSA", tls_offer_pick(&memo, H, 443, 0xC030, s_now) == TLS_OFFER_RSA);
    tls_offer_note(&memo, H, 443, true);
    check("note: remembered", strcmp(memo.host, H) == 0 && memo.port == 443 &&
                              memo.until_us == s_now + (int64_t)TLS_OFFER_MEMO_S * 1000000);
    check("pick: remembered host -> full", tls_offer_pick(&memo, H, 443, 0, s_now) == TLS_OFFER_FULL);
    check("pick: remembered, other port -> RSA", tls_offer_pick(&memo, H, 8443, 0, s_now) == TLS_OFFER_RSA);
    check("pick: remembered, other host -> RSA",
          tls_offer_pick(&memo, "derp17.tailscale.com", 443, 0, s_now) == TLS_OFFER_RSA);
    check("pick: remembered, 1 us before expiry -> full",
          tls_offer_pick(&memo, H, 443, 0, memo.until_us - 1) == TLS_OFFER_FULL);
    check("pick: remembered, at expiry -> RSA",
          tls_offer_pick(&memo, H, 443, 0, memo.until_us) == TLS_OFFER_RSA);
    memset(&memo, 0, sizeof(memo));
    tls_offer_note(&memo, H, 443, false);
    check("note: failed retry not remembered", memo.host[0] == '\0');
    char big[TLS_OFFER_HOST_MAX + 8];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    tls_offer_note(&memo, big, 443, true);
    check("note: oversize host not remembered", memo.host[0] == '\0');
    tls_offer_note(NULL, H, 443, true);   /* must not crash */

    /* --- apply ----------------------------------------------------------- */
    {
        esp_tls_cfg_t cfg = { 0 };
        check("apply: RSA list", tls_offer_apply(&cfg, &memo, H, 443) == TLS_OFFER_RSA &&
                                 is_rsa_list(cfg.ciphersuites_list));
        esp_tls_client_session_t s = { .saved_session = { .ciphersuite = 0xC02B } };
        cfg.client_session = &s;
        check("apply: ECDSA session -> NULL list",
              tls_offer_apply(&cfg, &memo, H, 443) == TLS_OFFER_FULL && cfg.ciphersuites_list == NULL);
        s.saved_session.ciphersuite = 0xC02F;
        check("apply: RSA session -> RSA list",
              tls_offer_apply(&cfg, &memo, H, 443) == TLS_OFFER_RSA && is_rsa_list(cfg.ciphersuites_list));
    }

    /* --- fallback -------------------------------------------------------- */
    {
        esp_tls_client_session_t s = { 0 };
        esp_tls_cfg_t cfg = { .ciphersuites_list = (const int *)1, .client_session = &s };
        esp_tls_t *t = esp_tls_init();
        t->err.last_error = ESP_ERR_MBEDTLS_SSL_HANDSHAKE_FAILED;
        check("fallback: not after the full offer",
              !tls_offer_fallback(TLS_OFFER_FULL, &t, &cfg, H, 443) && t != NULL &&
              cfg.client_session == &s);
        t->err.last_error = ESP_ERR_ESP_TLS_CONNECTION_TIMEOUT;
        check("fallback: not on a timeout", !tls_offer_fallback(TLS_OFFER_RSA, &t, &cfg, H, 443));
        t->err.last_error = 0;   /* a TCP connect failure leaves no TLS error */
        check("fallback: not on a TCP failure", !tls_offer_fallback(TLS_OFFER_RSA, &t, &cfg, H, 443));
        const int destroys = s_destroys;
        t->err.last_error = ESP_ERR_MBEDTLS_SSL_HANDSHAKE_FAILED;
        const bool fb = tls_offer_fallback(TLS_OFFER_RSA, &t, &cfg, H, 443);
        check("fallback: handshake failure -> retry", fb && t != NULL);
        check("fallback: old conn destroyed, new one clean",
              s_destroys == destroys + 1 && t->err.last_error == 0);
        check("fallback: full offer, no session",
              cfg.ciphersuites_list == NULL && cfg.client_session == NULL);
        t->err.last_error = ESP_ERR_MBEDTLS_SSL_HANDSHAKE_FAILED;
        s_init_fail = 1;
        check("fallback: esp_tls_init failure -> no retry",
              !tls_offer_fallback(TLS_OFFER_RSA, &t, &cfg, H, 443) && t == NULL);
        s_init_fail = 0;
        esp_tls_t *null_tls = NULL;
        check("fallback: NULL conn", !tls_offer_fallback(TLS_OFFER_RSA, &null_tls, &cfg, H, 443));
        check("fallback: NULL pointer", !tls_offer_fallback(TLS_OFFER_RSA, NULL, &cfg, H, 443));
    }

    /* --- connect sequences ----------------------------------------------- */
    {
        memset(&memo, 0, sizeof(memo));
        server_t ts = { .rsa_rc = 1, .full_rc = 1 };   /* Tailscale: both chains */
        tls_offer_t used;
        esp_tls_t *t;
        int rc = connect_like_derp(&ts, &memo, H, 443, NULL, &used, &t);
        check("seq tailscale: one RSA dial", rc == 1 && used == TLS_OFFER_RSA && ts.dials == 1 &&
                                             ts.rsa_dials == 1 && memo.host[0] == '\0');
        esp_tls_conn_destroy(t);

        server_t ec = { .rsa_rc = -1, .rsa_err = ESP_ERR_MBEDTLS_SSL_HANDSHAKE_FAILED, .full_rc = 1 };
        esp_tls_client_session_t s = { .saved_session = { .ciphersuite = 0xC02F } };
        rc = connect_like_derp(&ec, &memo, "headscale.example", 443, &s, &used, &t);
        check("seq ecdsa-only: RSA refused, full retry wins",
              rc == 1 && used == TLS_OFFER_FULL && ec.rsa_dials == 1 && ec.full_dials == 1 &&
              !ec.last_had_session);
        check("seq ecdsa-only: remembered", strcmp(memo.host, "headscale.example") == 0);
        esp_tls_conn_destroy(t);
        rc = connect_like_derp(&ec, &memo, "headscale.example", 443, NULL, &used, &t);
        check("seq ecdsa-only: next connect goes full directly",
              rc == 1 && used == TLS_OFFER_FULL && ec.rsa_dials == 1 && ec.full_dials == 2);
        esp_tls_conn_destroy(t);
        s_now = memo.until_us;
        rc = connect_like_derp(&ec, &memo, "headscale.example", 443, NULL, &used, &t);
        check("seq ecdsa-only: after 6 h the RSA offer is tried again",
              rc == 1 && ec.rsa_dials == 2 && ec.full_dials == 3);
        esp_tls_conn_destroy(t);

        memset(&memo, 0, sizeof(memo));
        server_t down = { .rsa_rc = -1, .rsa_err = ESP_ERR_MBEDTLS_SSL_HANDSHAKE_FAILED, .full_rc = -1 };
        rc = connect_like_derp(&down, &memo, H, 443, NULL, &used, &t);
        check("seq both fail: two dials, nothing remembered",
              rc == -1 && down.dials == 2 && memo.host[0] == '\0');
        esp_tls_conn_destroy(t);

        server_t slow = { .rsa_rc = 0, .rsa_err = ESP_ERR_ESP_TLS_CONNECTION_TIMEOUT, .full_rc = 1 };
        rc = connect_like_derp(&slow, &memo, H, 443, NULL, &used, &t);
        check("seq timeout: no retry", rc == 0 && slow.dials == 1 && used == TLS_OFFER_RSA);
        esp_tls_conn_destroy(t);
    }

    int leaks = 0;
    for (int i = 0; i < 8; i++) leaks += s_live[i] != NULL;
    check("every esp_tls destroyed", leaks == 0 && s_inits == s_destroys);

    if (s_fails) {
        printf("%d FAILED\n", s_fails);
        return 1;
    }
    printf("ALL OK\n");
    return 0;
}
