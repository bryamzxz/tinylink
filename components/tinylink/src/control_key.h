// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include <stdbool.h>
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
 *   3. HTTPS GET https://<host>/key?v=<TINYLINK_CAPVER> (TOFU, on
 *      esp_tls). Legacy first-boot flow, logged as a WARN since it's
 *      vulnerable to a MITM during the initial fetch. Suitable for
 *      development only.
 *
 * Subsequent calls take path 1 (cached pin). If the control plane
 * later presents a key that disagrees with the pin, the caller treats
 * that as a hard failure (possible MITM) — that check happens in
 * tinylink_register() after the handshake completes.
 */
esp_err_t control_key_get(uint8_t out_pub[CONTROL_KEY_LEN]);

/* True when the key control_key_get returned was pinned before this
 * boot's network activity — path 1 or 2 — and false after a TOFU fetch
 * (path 3) or before any call. Gates ts2021 over plain HTTP :80 (round
 * 1.3.5): there the server is authenticated by Noise IK against this key
 * alone, so a key whose only evidence is this boot's TLS fetch keeps the
 * whole boot on TLS; the next boot loads it from NVS as a pin. */
bool control_key_pinned(void);

#ifdef __cplusplus
}
#endif
