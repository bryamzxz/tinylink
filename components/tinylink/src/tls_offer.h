// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// The TLS ClientHello's cipher-suite offer: ECDHE-RSA first (round 1.3.8).
//
// Both Tailscale servers this firmware dials over TLS hold two
// certificates and pick one from the ClientHello (Go's autocert
// supportsECDSA: an ECDHE-ECDSA suite offered → the ECDSA certificate).
// openssl s_client, 2026-10-30, derp16b and controlplane alike:
//
//   offer with ECDSA (mbedTLS default)    offer ECDHE-RSA only
//   leaf P-256    ← YE2/YE1 (P-384)        leaf RSA-2048 ← YR2 (RSA-2048)
//   YE2   P-384   ← Root YE (P-384)        YR2           ← Root YR (RSA-4096)
//   Root YE P-384 ← ISRG X2 (P-384)        Root YR       ← ISRG X1 (bundle)
//   X2    P-384   ← ISRG X1 (bundle, RSA)  ServerKeyExchange rsa_pkcs1_sha256
//   ServerKeyExchange ecdsa_secp256r1      ECDHE X25519 in both
//
// The client verifies every signature above. With ECDSA that is three
// P-384 ECDSA verifies, one P-256 (the ServerKeyExchange) and one
// RSA-4096 (the X1 cross-sign); with RSA it is two RSA-2048 and two
// RSA-4096 verifies, each a public-exponent (65537) exponentiation —
// 17 modular multiplications, on the RSA accelerator — instead of two
// scalar multiplications per ECDSA verify in software. The measured
// costs per primitive are in the CHANGELOG (CONFIG_TINYLINK_BENCH_TLS).
// The chain is still verified in full against the same bundle (ISRG
// Root X1 is in the common-CA set) by the same callback; the ECDHE is
// the same X25519, the records the same AES-128-GCM, so forward secrecy
// and record protection do not change. What changes is the server
// authentication: RSA-2048 (≈ 112-bit) instead of P-256 (≈ 128-bit),
// the strength Let's Encrypt issues for RSA and NIST SP 800-57 accepts
// through 2030 — the CHANGELOG has the argument.
//
// A server that refuses the RSA offer (an ECDSA-only certificate, a
// chain the bundle does not anchor) fails the TLS handshake; the
// connect then dials once more at once with the full mbedTLS offer and
// no session, and remembers for TLS_OFFER_MEMO_S that this host:port
// needs it. A connect that offers a saved session offers the suite
// family the session was negotiated under (a Go server only resumes a
// session whose suite the ClientHello lists).

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "esp_tls.h"
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* IANA ids (= mbedTLS's ssl_ciphersuites.h). */
#define TLS_OFFER_ECDHE_RSA_AES128_GCM 0xC02F
#define TLS_OFFER_ECDHE_RSA_AES256_GCM 0xC030

#define TLS_OFFER_HOST_MAX 64

/* A server that needed the full offer is asked with it directly for 6 h,
 * so a one-off handshake failure (a reset mid-handshake that the full
 * retry got past) does not pin the slow path for the whole uptime. */
#define TLS_OFFER_MEMO_S (6 * 3600)

typedef enum {
    TLS_OFFER_FULL = 0,   /* mbedTLS's default list (ECDSA + RSA suites) */
    TLS_OFFER_RSA,        /* ECDHE-RSA with AES-GCM only               */
} tls_offer_t;

/* The server (one per caller: the DERP client, the control conn) that
 * refused the RSA offer and took the full one. Zero-init = none. */
typedef struct {
    char     host[TLS_OFFER_HOST_MAX];
    uint16_t port;
    int64_t  until_us;
} tls_offer_memo_t;

static inline bool tls_offer_is_rsa_suite(int id)
{
    return id == TLS_OFFER_ECDHE_RSA_AES128_GCM || id == TLS_OFFER_ECDHE_RSA_AES256_GCM;
}

/* The offer for a connect to host:port at now_us, offering a session
 * negotiated under `session_suite` (0 = no session). memo may be NULL. */
static inline tls_offer_t tls_offer_pick(const tls_offer_memo_t *memo,
                                         const char *host, uint16_t port,
                                         int session_suite, int64_t now_us)
{
#if !CONFIG_TINYLINK_TLS_RSA_FIRST
    (void)memo; (void)host; (void)port; (void)session_suite; (void)now_us;
    return TLS_OFFER_FULL;
#else
    if (host == NULL) return TLS_OFFER_FULL;
    if (session_suite != 0 && !tls_offer_is_rsa_suite(session_suite)) return TLS_OFFER_FULL;
    if (memo != NULL && memo->host[0] != '\0' && memo->port == port &&
        now_us < memo->until_us && strcmp(memo->host, host) == 0) {
        return TLS_OFFER_FULL;
    }
    return TLS_OFFER_RSA;
#endif
}

/* Picks the offer for cfg (its client_session already set by
 * tls_resume_offer, or NULL) and sets cfg->ciphersuites_list. */
tls_offer_t tls_offer_apply(esp_tls_cfg_t *cfg, const tls_offer_memo_t *memo,
                            const char *host, uint16_t port);

/* After a connect with offer `o` failed: true when it was the RSA offer
 * and the TLS handshake itself failed (esp-tls's
 * ESP_ERR_MBEDTLS_SSL_HANDSHAKE_FAILED: an alert, no common suite, a
 * chain the bundle does not anchor — not a TCP failure or a timeout).
 * Then *tls has been replaced by a fresh esp_tls (NULL if that failed:
 * false), cfg carries the full offer and no session, and the caller
 * dials again at once and reports the result to tls_offer_note. */
bool tls_offer_fallback(tls_offer_t o, esp_tls_t **tls, esp_tls_cfg_t *cfg,
                        const char *host, uint16_t port);

/* The full-offer retry's result: success remembers host:port for
 * TLS_OFFER_MEMO_S. memo may be NULL. */
void tls_offer_note(tls_offer_memo_t *memo, const char *host, uint16_t port, bool ok);

/* "RSA" / "full", for the connect logs. */
static inline const char *tls_offer_str(tls_offer_t o)
{
    return o == TLS_OFFER_RSA ? "RSA" : "full";
}

#ifdef __cplusplus
}
#endif
