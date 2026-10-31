// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "tls_offer.h"

#include <stdio.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509.h"

static const char *TAG = "tls_offer";

/* AES-128-GCM first: what both servers pick from the full offer today
 * (ECDHE-ECDSA-AES128-GCM-SHA256 since 1.3.2), AES on the accelerator. */
static const int s_rsa_suites[] = {
    TLS_OFFER_ECDHE_RSA_AES128_GCM,
    TLS_OFFER_ECDHE_RSA_AES256_GCM,
    0,
};

static int session_suite(const esp_tls_cfg_t *cfg)
{
#if CONFIG_ESP_TLS_CLIENT_SESSION_TICKETS
    if (cfg->client_session != NULL) {
        return cfg->client_session->saved_session.MBEDTLS_PRIVATE(ciphersuite);
    }
#endif
    (void)cfg;
    return 0;
}

tls_offer_t tls_offer_apply(esp_tls_cfg_t *cfg, const tls_offer_memo_t *memo,
                            const char *host, uint16_t port)
{
    const tls_offer_t o = tls_offer_pick(memo, host, port, session_suite(cfg),
                                         esp_timer_get_time());
    cfg->ciphersuites_list = o == TLS_OFFER_RSA ? s_rsa_suites : NULL;
    return o;
}

/* The X.509 verdict of the failed handshake. esp-tls's own capture
 * (esp_tls_flags) needs mbedtls_ssl_get_peer_cert, which is NULL with
 * KEEP_PEER_CERTIFICATE=n, so read it from the SSL context, which esp-tls
 * keeps until esp_tls_conn_destroy. 0xFFFFFFFF = none: no certificate
 * verified yet (an alert before it) — or the bundle callback rejected the
 * top certificate (x509_crt_verify sets every flag on a callback error). */
static uint32_t verify_result(esp_tls_t *tls)
{
    const mbedtls_ssl_context *ssl = (const mbedtls_ssl_context *)esp_tls_get_ssl_context(tls);
    return ssl != NULL ? mbedtls_ssl_get_verify_result(ssl) : 0xFFFFFFFFu;
}

bool tls_offer_fallback(tls_offer_t o, esp_tls_t **tls, esp_tls_cfg_t *cfg,
                        const char *host, uint16_t port)
{
    if (o != TLS_OFFER_RSA || tls == NULL || *tls == NULL) return false;
    esp_tls_error_handle_t h = NULL;
    if (esp_tls_get_error_handle(*tls, &h) != ESP_OK || h == NULL ||
        h->last_error != ESP_ERR_MBEDTLS_SSL_HANDSHAKE_FAILED) {
        return false;
    }
    /* Which failures the full offer can fix (review, 1.3.8). The server's
     * alert (no suite in common), a chain the bundle does not anchor, dates
     * or key / usage policy: the RSA chain is a separate set of
     * certificates — its own issuance, renewals and hierarchy — so the
     * ECDSA one may pass. Not a name mismatch: both chains name the server
     * the connect asked for, so a leaf for another name means another
     * server answered (a stale cached address, which the caller retries
     * by name) or an impostor — a second, slower handshake would only
     * delay that. An impostor with the right name and an unanchored chain
     * still costs the retry: it is the verdict an RSA hierarchy change
     * would produce, and it fails the same way. */
    const uint32_t vr = verify_result(*tls);
    if (vr != 0xFFFFFFFFu && (vr & MBEDTLS_X509_BADCERT_CN_MISMATCH) != 0) {
        ESP_LOGW(TAG, "%s:%u: certificate for another name (verify flags 0x%x) "
                      "— no full-offer retry",
                 host != NULL ? host : "?", (unsigned)port, (unsigned)vr);
        return false;
    }
    ESP_LOGW(TAG, "%s:%u refused the RSA offer (mbedTLS -0x%04x, verify flags 0x%x) "
                  "— retrying with the full offer",
             host != NULL ? host : "?", (unsigned)port,
             (unsigned)-h->esp_tls_error_code, (unsigned)vr);
    esp_tls_conn_destroy(*tls);
    *tls = esp_tls_init();
    cfg->ciphersuites_list = NULL;
#if CONFIG_ESP_TLS_CLIENT_SESSION_TICKETS
    cfg->client_session = NULL;
#endif
    return *tls != NULL;
}

void tls_offer_note(tls_offer_memo_t *memo, const char *host, uint16_t port, bool ok)
{
    if (memo == NULL || host == NULL || !ok) return;
    const size_t n = strnlen(host, sizeof(memo->host));
    if (n >= sizeof(memo->host)) return;
    memcpy(memo->host, host, n);
    memo->host[n] = '\0';
    memo->port = port;
    memo->until_us = esp_timer_get_time() + (int64_t)TLS_OFFER_MEMO_S * 1000000;
    ESP_LOGI(TAG, "%s:%u takes the full offer for the next %d h", host, (unsigned)port,
             TLS_OFFER_MEMO_S / 3600);
}
