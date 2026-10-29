// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// TLS 1.2 session resumption for the control (:443) and DERP conns
// (round 1.3.5, D9): one saved session per slot, in RAM only — the
// ticket and its master secret are never written to flash, and they die
// with the boot.
//
// A reconnect that offers the saved session and is accepted skips the
// server's certificate chain (no X.509 parse, no chain verify, no ECDSA
// / RSA signature checks) and the ECDHE: the abbreviated handshake is
// ClientHello → ServerHello + [NewSessionTicket] + ChangeCipherSpec +
// Finished → ChangeCipherSpec + Finished. A server that does not accept
// it (unknown ticket key, another backend, expired) answers with a full
// handshake in the same connection, verified exactly as without
// resumption (same esp_tls_cfg_t, same crt_bundle_attach callback);
// mbedtls takes the full path whenever ServerHello does not echo the
// session ID it generated for the ticket. A session only ever comes from
// a handshake that completed under MBEDTLS_SSL_VERIFY_REQUIRED, i.e. one
// whose chain was verified in this boot.
//
// Bounds: a slot holds a session for one host:port (a session for
// another server is freed, never offered); a session whose master secret
// is older than TLS_RESUME_MAX_AGE_S is dropped (TLS 1.2 resumption
// reuses the master secret — a resumed conn has fresh keys but no fresh
// ECDHE — so this caps how long one master secret keeps deriving
// connection keys); a connect that offered a session and failed drops
// it, so the next one is a full handshake. Freed sessions are zeroized
// by mbedtls_ssl_session_free.
//
// Measured 2026-10-29 with openssl s_client -tls1_2 and with mbedTLS
// 3.6.7's ssl_client2 (the IDF v5.5.6 library, built for the host):
// controlplane.tailscale.com and derp16b.tailscale.com issue a ticket on
// a full handshake (ServerHello session ID empty, ~128-B ticket) and
// resume it (session ID echoed, a fresh ticket sent). controlplane is 8
// A records (TTL 60 s) whose ticket keys are per address: resumed 3/3 on
// the issuing address, 0/7 on the others — so a control reconnect
// resumes only when lwIP's resolver (one address per name, kept for the
// TTL) hands out the same address. derp16b is one address (TTL 600 s).
//
// Callers own their slot (one control conn, one DERP client); take/keep
// still exchange the slot pointer atomically, so even two concurrent
// connects on one slot cannot free a session the other is using.

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_tls.h"
#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 24 h — the rotation period of Go's automatic session-ticket keys
 * (crypto/tls), which serve both servers: one full handshake a day per
 * server costs nothing; reconnects in between resume. */
#define TLS_RESUME_MAX_AGE_S (24 * 3600)

/* DERP host names are TL_DERP_HOSTNAME_LEN (64) at most; the control host
 * is a Kconfig string. A longer name is simply never resumed. */
#define TLS_RESUME_HOST_MAX 64

typedef enum {
    TLS_RESUME_NONE = 0,   /* no session kept (failed, or none issued) */
    TLS_RESUME_FULL,       /* full handshake; its session is kept      */
    TLS_RESUME_RESUMED,    /* abbreviated handshake on the saved one   */
} tls_resume_result_t;

typedef struct tls_resume_entry tls_resume_entry_t;
typedef tls_resume_entry_t *tls_resume_slot_t;   /* zero-init = empty */

#if CONFIG_ESP_TLS_CLIENT_SESSION_TICKETS

/* Detach the slot's session for a connect to host:port; NULL when there
 * is none, or it belongs to another server or is too old (then freed).
 * Pass the result to tls_resume_offer before the handshake and to
 * tls_resume_keep after it — always, also on failure. */
tls_resume_entry_t *tls_resume_take(tls_resume_slot_t *slot,
                                    const char *host, uint16_t port);

/* cfg->client_session = the taken session (no-op for NULL). */
void tls_resume_offer(esp_tls_cfg_t *cfg, const tls_resume_entry_t *taken);

/* After the handshake: tls = the connected esp_tls (NULL = the connect
 * failed). Keeps the conn's session (a resumed one carries the fresh
 * ticket) in the slot, frees `taken`. */
tls_resume_result_t tls_resume_keep(tls_resume_slot_t *slot,
                                    tls_resume_entry_t *taken, esp_tls_t *tls,
                                    const char *host, uint16_t port);

#else  /* tickets compiled out: every handshake is a full one */

static inline tls_resume_entry_t *tls_resume_take(tls_resume_slot_t *slot,
                                                  const char *host, uint16_t port)
{
    (void)slot; (void)host; (void)port;
    return NULL;
}
static inline void tls_resume_offer(esp_tls_cfg_t *cfg, const tls_resume_entry_t *taken)
{
    (void)cfg; (void)taken;
}
static inline tls_resume_result_t tls_resume_keep(tls_resume_slot_t *slot,
                                                  tls_resume_entry_t *taken,
                                                  esp_tls_t *tls,
                                                  const char *host, uint16_t port)
{
    (void)slot; (void)taken; (void)tls; (void)host; (void)port;
    return TLS_RESUME_NONE;
}

#endif

/* "resumed" / "full" / "no ticket", for the one-line connect logs. */
static inline const char *tls_resume_str(tls_resume_result_t r)
{
    return r == TLS_RESUME_RESUMED ? "resumed" :
           r == TLS_RESUME_FULL    ? "full"    : "no ticket";
}

#ifdef __cplusplus
}
#endif
