/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host-only stand-in for ESP-IDF's esp_tls.h: the handful of types and
 * calls ts2021_client.c uses. The test that builds ts2021_client.c on
 * the host (test_ts2021.c) defines the functions over an in-memory
 * byte stream. */
#pragma once

#include <stddef.h>
#include <sys/types.h>

#include "esp_err.h"

typedef struct esp_tls esp_tls_t;

typedef struct {
    esp_err_t (*crt_bundle_attach)(void *conf);
    int timeout_ms;
} esp_tls_cfg_t;

esp_tls_t *esp_tls_init(void);
int esp_tls_conn_http_new_sync(const char *url, const esp_tls_cfg_t *cfg,
                               esp_tls_t *tls);
ssize_t esp_tls_conn_read(esp_tls_t *tls, void *data, size_t datalen);
ssize_t esp_tls_conn_write(esp_tls_t *tls, const void *data, size_t datalen);
int esp_tls_conn_destroy(esp_tls_t *tls);
esp_err_t esp_tls_get_conn_sockfd(esp_tls_t *tls, int *sockfd);
