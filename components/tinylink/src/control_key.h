// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include <stdint.h>

#include "esp_err.h"

#define CONTROL_KEY_LEN 32

#ifdef __cplusplus
extern "C" {
#endif

/* Resolve the control plane public key. Resolution order:
 *
 *   1. NVS namespace "tl_pin", blob "control_pub" — if present, used
 *      directly. The operator already accepted this key.
 *   2. CONFIG_TINYLINK_CONTROL_PUB_FALLBACK_HEX — if non-empty (must
 *      be exactly 64 hex chars), installed into NVS as the pin
 *      without any network round-trip. Eliminates the TOFU MITM
 *      window. Production firmware should ship this.
 *   3. HTTPS GET https://<host>/key?v=100 (TOFU). Legacy first-boot
 *      flow, logged as a WARN since it's vulnerable to a MITM during
 *      the initial fetch. Suitable for development only.
 *
 * Subsequent calls take path 1 (cached pin). If the control plane
 * later presents a key that disagrees with the pin, the caller treats
 * that as a hard failure (possible MITM) — that check happens in
 * tinylink_register() after the handshake completes.
 */
esp_err_t control_key_get(uint8_t out_pub[CONTROL_KEY_LEN]);

/* Force-refresh the pin from /key?v=100. If
 * CONFIG_TINYLINK_CONTROL_PUB_FALLBACK_HEX is set, the fetched key
 * MUST match it; otherwise the refresh is refused and the existing
 * NVS pin is left intact (returns ESP_ERR_INVALID_RESPONSE). Use only
 * after a controlled key rotation event. */
esp_err_t control_key_refresh(uint8_t out_pub[CONTROL_KEY_LEN]);

#ifdef __cplusplus
}
#endif
