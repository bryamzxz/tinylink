// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include <stdint.h>

#include "esp_err.h"

#define CONTROL_KEY_LEN 32

#ifdef __cplusplus
extern "C" {
#endif

/* Bootstrap the control plane public key.
 * - First call: HTTPS GET https://<host>/key?v=100, parse the JSON
 *   "publicKey" ("nlpub:<64 hex>"), persist the 32 raw bytes to NVS
 *   namespace "tl_pin", key "control_pub".
 * - Subsequent calls: read from NVS, return cached pin. If we see a
 *   different value on the wire later, the caller should treat that as
 *   a hard failure (possible MITM) — that check happens in
 *   tinylink_register() after the handshake completes.
 */
esp_err_t control_key_get(uint8_t out_pub[CONTROL_KEY_LEN]);

/* Refresh: forces a re-fetch and overwrites the pin. Use only after a
 * controlled key rotation event. */
esp_err_t control_key_refresh(uint8_t out_pub[CONTROL_KEY_LEN]);

#ifdef __cplusplus
}
#endif
