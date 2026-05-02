// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// WireGuard runtime: owns the BSD UDP socket, runs the handshake +
// transport state machines on top of wg_handshake/wg_transport, and
// dispatches incoming datagrams via wg_demux. This is the module that
// step 6 swaps wg_dataplane.c onto.
//
// Architectural note: the UDP socket lives here. DISCO (step 7) and
// STUN (M4) reuse the same socket via wg_demux_classify, so neither
// has to bind its own port (a step we avoided to bypass the
// trombik-component patching strategy). The RX task delivers WG
// transport plaintext to a callback the netif glue will register.

#pragma once

#ifdef ESP_PLATFORM

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#include "wg_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Callback invoked from the RX task once a WG transport packet has
 * been authenticated and decrypted. The plaintext is the inner IP
 * datagram; the callee owns nothing — must copy if it needs to retain
 * the bytes past callback return. */
typedef void (*wg_netif_rx_cb_t)(const uint8_t *plaintext, size_t len,
                                 void *user);

struct wg_netif_peer_config {
    uint8_t  peer_static_pub[WG_KEY_LEN];   /* WG static public of the peer */
    uint8_t  preshared_key[WG_KEY_LEN];     /* zero if no PSK */
    uint32_t peer_endpoint_v4_be;           /* big-endian (network) IPv4 */
    uint16_t peer_endpoint_port;            /* host order */
};

struct wg_netif_local_config {
    uint8_t  static_priv[WG_KEY_LEN];
    uint8_t  static_pub [WG_KEY_LEN];
    uint16_t bind_port;            /* 0 = let the kernel pick (ephemeral) */
};

/* Initialize the runtime. Allocates the UDP socket, binds, and spawns
 * the RX task in the suspended-equivalent state (state machine starts
 * at WG_NETIF_IDLE). Idempotent — safe to call once at startup. */
esp_err_t wg_netif_init(const struct wg_netif_local_config *local);

/* Configure the peer and kick off the handshake. Sends one
 * MessageInitiation, schedules retries on timeout (up to ~90 s per WG
 * spec), and transitions to UP once a valid MessageResponse arrives.
 * If wg_netif_init has not been called this returns ESP_ERR_INVALID_STATE. */
esp_err_t wg_netif_start(const struct wg_netif_peer_config *peer);

/* Update the peer endpoint without renegotiating keys, if there's a
 * live session. This is what hot-update from MapResponse calls when
 * the peer has roamed. */
esp_err_t wg_netif_update_peer_endpoint(uint32_t v4_be, uint16_t port);

/* Encrypt and send a plaintext IP packet through the tunnel. Returns
 * ESP_ERR_INVALID_STATE if no transport session is up yet. */
esp_err_t wg_netif_send_plaintext(const uint8_t *pkt, size_t len);

/* Hook a delivery callback for inbound plaintext IP packets. Step 6
 * registers the esp_netif input function here. */
void wg_netif_set_rx_callback(wg_netif_rx_cb_t cb, void *user);

/* Returns true once the handshake has produced transport keys and we
 * can send/receive. */
bool wg_netif_is_up(void);

/* Tear down. Closes the socket, stops the RX task, scrubs key
 * material. Safe to call from any state. */
void wg_netif_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* ESP_PLATFORM */
