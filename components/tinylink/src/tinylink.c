// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "tinylink.h"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

static const char k_version[] =
    STR(TINYLINK_VERSION_MAJOR) "."
    STR(TINYLINK_VERSION_MINOR) "."
    STR(TINYLINK_VERSION_PATCH);

const char *tinylink_version_string(void)
{
    return k_version;
}

/* M2 — ts2021 Noise IK handshake. TODO. */
esp_err_t tinylink_ts2021_handshake(tinylink_ts2021_ctx_t *ctx)
{
    (void)ctx;
    return ESP_ERR_NOT_SUPPORTED;
}

/* M3 — MapResponse parser. TODO. */
esp_err_t tinylink_map_response_parse(const uint8_t *buf, size_t len,
                                      tinylink_map_response_t *out)
{
    (void)buf;
    (void)len;
    (void)out;
    return ESP_ERR_NOT_SUPPORTED;
}

/* M4 — DISCO ping over WG UDP socket. TODO. */
esp_err_t tinylink_disco_send_ping(tinylink_disco_ctx_t *ctx)
{
    (void)ctx;
    return ESP_ERR_NOT_SUPPORTED;
}

/* M5 — DERP relay fallback. TODO. */
esp_err_t tinylink_derp_connect(tinylink_derp_ctx_t *ctx, const char *region)
{
    (void)ctx;
    (void)region;
    return ESP_ERR_NOT_SUPPORTED;
}

/* M6 — production hardening hooks. TODO. */
esp_err_t tinylink_harden_apply_defaults(void)
{
    return ESP_ERR_NOT_SUPPORTED;
}
