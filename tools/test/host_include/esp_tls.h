/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host-only stand-in for ESP-IDF's esp_tls.h: the handful of types and
 * calls ts2021_client.c / tls_resume.c use. The tests that build them on
 * the host (test_ts2021.c, test_tls_resume.c) define the functions over
 * an in-memory byte stream / scripted sessions. */
#pragma once

#include <stddef.h>
#include <sys/types.h>

#include "esp_err.h"
#include "mbedtls/ssl.h"

typedef struct esp_tls esp_tls_t;

#if CONFIG_ESP_TLS_CLIENT_SESSION_TICKETS
typedef struct esp_tls_client_session {
    mbedtls_ssl_session saved_session;
} esp_tls_client_session_t;
#endif

typedef struct {
    esp_err_t (*crt_bundle_attach)(void *conf);
    int timeout_ms;
    const char *common_name;
#if CONFIG_ESP_TLS_CLIENT_SESSION_TICKETS
    esp_tls_client_session_t *client_session;
#endif
} esp_tls_cfg_t;

typedef struct esp_tls_last_error {
    esp_err_t last_error;
    int       esp_tls_error_code;
    int       esp_tls_flags;
} esp_tls_last_error_t;
typedef esp_tls_last_error_t *esp_tls_error_handle_t;

esp_tls_t *esp_tls_init(void);
int esp_tls_conn_http_new_sync(const char *url, const esp_tls_cfg_t *cfg,
                               esp_tls_t *tls);
int esp_tls_conn_new_sync(const char *hostname, int hostlen, int port,
                          const esp_tls_cfg_t *cfg, esp_tls_t *tls);
ssize_t esp_tls_conn_read(esp_tls_t *tls, void *data, size_t datalen);
ssize_t esp_tls_conn_write(esp_tls_t *tls, const void *data, size_t datalen);
ssize_t esp_tls_get_bytes_avail(esp_tls_t *tls);
int esp_tls_conn_destroy(esp_tls_t *tls);
esp_err_t esp_tls_get_conn_sockfd(esp_tls_t *tls, int *sockfd);
esp_err_t esp_tls_plain_tcp_connect(const char *host, int hostlen, int port,
                                    const esp_tls_cfg_t *cfg,
                                    esp_tls_error_handle_t error_handle,
                                    int *sockfd);
#if CONFIG_ESP_TLS_CLIENT_SESSION_TICKETS
esp_tls_client_session_t *esp_tls_get_client_session(esp_tls_t *tls);
void esp_tls_free_client_session(esp_tls_client_session_t *client_session);
#endif
