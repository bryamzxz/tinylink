// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include "esp_err.h"

#include "tinylink.h"
#include "ts2021_client.h"

#ifdef __cplusplus
extern "C" {
#endif

/* POST /machine/register over the Noise channel and parse the response.
 * - auth_key: tskey-auth-... from NVS namespace "tl_creds", or NULL to
 *   send no Auth (a node control already authorized; see
 *   register_build_body).
 * - http_status: the answer's HTTP status, 0 when the request got none
 *   (transport failure, buffer busy, bad args).
 * Returns:
 *   ESP_OK            -> MachineAuthorized=true.
 *   ESP_ERR_NOT_FINISHED -> MachineAuthorized=false (operator must approve).
 *                       Caller should retry on a slow cadence.
 *   ESP_ERR_INVALID_STATE -> NodeKeyExpired=true (or the control buffer
 *                       is busy: http_status 0).
 *   any other err     -> hard failure.
 */
esp_err_t register_emit(ts2021_conn_t *conn,
                        const tinylink_keys_t *keys,
                        const char *auth_key, int *http_status);

#ifdef __cplusplus
}
#endif
