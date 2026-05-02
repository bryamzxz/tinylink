// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TINYLINK_VERSION_MAJOR 0
#define TINYLINK_VERSION_MINOR 1
#define TINYLINK_VERSION_PATCH 0

#define TINYLINK_KEY_LEN 32

/* The three Curve25519 identities a Tailscale node carries. They are
 * persisted in the encrypted NVS namespace "tl_keys" so they survive
 * reboots and re-authentications. */
typedef struct {
    uint8_t machine_priv[TINYLINK_KEY_LEN]; /* ts2021 Noise IK static (M1)  */
    uint8_t machine_pub[TINYLINK_KEY_LEN];
    uint8_t node_priv[TINYLINK_KEY_LEN];    /* WireGuard static (M2+)       */
    uint8_t node_pub[TINYLINK_KEY_LEN];
    uint8_t disco_priv[TINYLINK_KEY_LEN];   /* DISCO box (M3+)              */
    uint8_t disco_pub[TINYLINK_KEY_LEN];
} tinylink_keys_t;

/* One-time setup: load or generate node identities, fetch + pin the control
 * plane public key. Must be called after WiFi is up so that:
 *   1. esp_random() / esp_fill_random() return CSPRNG output (the RF
 *      subsystem seeds the entropy pool).
 *   2. DNS/TLS to controlplane.tailscale.com is reachable.
 */
esp_err_t tinylink_init(void);

/* Run the ts2021 Noise IK handshake and POST /machine/register. Reads the
 * Tailscale auth key from NVS namespace "tl_creds", key "auth_key".
 * Blocks until either MachineAuthorized=true (returns ESP_OK) or a hard
 * failure (returns an esp_err_t describing the failure). The caller is
 * expected to retry on transient failures; tinylink_register() does not
 * retry internally.
 */
esp_err_t tinylink_register(void);

/* Read-only view of the current node identities, useful for debugging and
 * for M2+ which needs the NodeKey for the WireGuard data plane. The output
 * struct is filled even if tinylink_register() has not been called yet —
 * identities are stable from tinylink_init() onward. */
esp_err_t tinylink_get_keys(tinylink_keys_t *out);

const char *tinylink_version_string(void);

#ifdef __cplusplus
}
#endif
