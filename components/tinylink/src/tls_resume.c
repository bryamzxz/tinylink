// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "tls_resume.h"

#if CONFIG_ESP_TLS_CLIENT_SESSION_TICKETS

#include <stdlib.h>
#include <string.h>

#include "esp_timer.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/ssl.h"

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

tls_resume_entry_t *tls_resume_take(tls_resume_slot_t *slot,
                                    const char *host, uint16_t port)
{
    if (slot == NULL || host == NULL) return NULL;
    tls_resume_entry_t *e = __atomic_exchange_n(slot, NULL, __ATOMIC_ACQ_REL);
    if (e == NULL) return NULL;
    const int64_t age_us = esp_timer_get_time() - e->born_us;
    if (e->port != port || strcmp(e->host, host) != 0 ||
        age_us > (int64_t)TLS_RESUME_MAX_AGE_S * 1000000) {
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
    entry_free(__atomic_exchange_n(slot, e, __ATOMIC_ACQ_REL));
    return resumed ? TLS_RESUME_RESUMED : TLS_RESUME_FULL;
}

#endif /* CONFIG_ESP_TLS_CLIENT_SESSION_TICKETS */
