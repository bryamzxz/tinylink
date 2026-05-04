// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include <stdbool.h>
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

/* M2 — fetch one MapResponse from the control plane and bring up the
 * WireGuard data plane against the first peer it announces. Internally:
 *   1. Open a fresh ts2021 Noise channel.
 *   2. POST /machine/map with `Stream:false`; parse the single
 *      MapResponse.
 *   3. Translate the netmap into a `wireguard_config_t` and call
 *      `esp_wireguard_init` + `esp_wireguard_connect`.
 *
 * Returns ESP_OK once the WG netif is up. Note: this only means the
 * device is *trying* to handshake; whether the peer is reachable is a
 * separate poll via the underlying `esp_wireguardif_peer_is_up`. The
 * long-poll `Stream:true` form, which keeps the netmap fresh, lands
 * with the M3 DISCO loop.
 */
esp_err_t tinylink_dataplane_start(void);

/* Spawn the long-poll MapRequest task. After this returns ESP_OK a
 * dedicated FreeRTOS task is running `POST /machine/map` with
 * `Stream:true`; each non-KeepAlive MapResponse refreshes the in-memory
 * netmap and (if the peer endpoint moved) reconfigures the WG peer.
 *
 * The task supervises its own ts2021 connection: on stream EOF or
 * transport error, it closes the connection, sleeps the configured
 * retry backoff, and re-opens. Callable only after a successful
 * `tinylink_dataplane_start()` so the WG netif already exists.
 */
esp_err_t tinylink_long_poll_start(void);

/* M3 first cut — spawn the TMP117 telemetry task. The task initializes
 * the I²C bus + sensor, then sends one JSON datagram per
 * `CONFIG_TINYLINK_TELEMETRY_PERIOD_MS` to the configured destination
 * over UDP. The destination is expected to be reachable through the
 * WireGuard netif (usually a `100.x.y.z` tailnet address on the home
 * peer).
 *
 * If `CONFIG_TINYLINK_TELEMETRY_ENABLE=n` the call is a no-op so
 * boards that ship without a TMP117 still build and run.
 */
esp_err_t tinylink_telemetry_start(void);

/* M4 — best-effort STUN binding probe to discover the device's public
 * AddrPort. Result is cached and uploaded to the control plane via
 * Hostinfo.Endpoints on the next MapRequest, so peers learn an address
 * they can try to dial directly even before DERP-mediated CallMeMaybe
 * (M5) is wired up. Failure is non-fatal; the device just operates
 * without a reflexive endpoint advertised, exactly like the pre-M4
 * baseline. Safe to call only after WiFi is up. */
esp_err_t tinylink_stun_probe(void);

/* Read-only accessor for the cached STUN result. Returns true and
 * fills *addr_v4 / *port if a successful probe has run; returns false
 * otherwise. mapreq.c queries this when building the HostInfo block. */
bool tinylink_get_public_endpoint(uint8_t addr_v4[4], uint16_t *port);

const char *tinylink_version_string(void);

#ifdef __cplusplus
}
#endif
