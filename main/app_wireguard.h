// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define APP_WG_ALLOWED_IP_MAX 32

typedef struct {
    char allowed_ip[APP_WG_ALLOWED_IP_MAX];
} app_wireguard_peer_info_t;

esp_err_t app_wireguard_start(void);

esp_err_t app_wireguard_wait_up(uint32_t timeout_ms);

esp_err_t app_wireguard_get_peer(app_wireguard_peer_info_t *out);

#ifdef __cplusplus
}
#endif
