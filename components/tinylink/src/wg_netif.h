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
    uint8_t  peer_disco_pub[WG_KEY_LEN];    /* peer's DiscoKey; used to gate
                                             * WG endpoint roaming via DISCO
                                             * direct-path observation. Only
                                             * DISCO frames sealed by THIS
                                             * key trigger
                                             * peer_endpoint_{v4_be,port}
                                             * updates — frames from other
                                             * peers in the netmap (e.g.
                                             * a laptop with its own NodeKey)
                                             * are valid DISCO but must NOT
                                             * roam our WG transport target. */
    bool     has_peer_disco_pub;            /* false → roaming permissive
                                             * (fall back to legacy behavior:
                                             * any direct DISCO ping/pong
                                             * src is accepted). */
    uint8_t  preshared_key[WG_KEY_LEN];     /* zero if no PSK */
    uint32_t peer_endpoint_v4_be;           /* big-endian (network) IPv4 */
    uint16_t peer_endpoint_port;            /* host order */
};

struct wg_netif_local_config {
    uint8_t  static_priv[WG_KEY_LEN];
    uint8_t  static_pub [WG_KEY_LEN];
    /* DISCO NaCl-box keys. Used by the RX task to decrypt inbound DISCO
     * pings on the shared UDP socket and reply with a sealed pong over
     * the same path the ping arrived on. Without this the direct-UDP
     * path stays cold even after STUN advertises a correct AddrPort —
     * peers probe with DISCO before sending real WG transport. */
    uint8_t  disco_priv [WG_KEY_LEN];
    uint8_t  disco_pub  [WG_KEY_LEN];
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

/* Callback invoked from the RX task when a STUN datagram (request or
 * response, classified by `wg_demux_classify` via the magic cookie at
 * offset 4) arrives on the shared UDP socket. Dispatch lets the
 * orchestration layer (tinylink.c) implement periodic STUN re-probes
 * over the live WG socket without taking ownership of recvfrom — which
 * would race with the RX task. The buffer is owned by the RX task;
 * the callee must copy what it needs before returning.
 *
 * Setting cb=NULL (the default) restores the prior "drop on receive"
 * behavior. */
typedef void (*wg_netif_stun_cb_t)(const uint8_t *buf, size_t len, void *user);
void wg_netif_set_stun_callback(wg_netif_stun_cb_t cb, void *user);

/* Returns true once the handshake has produced transport keys and we
 * can send/receive. */
bool wg_netif_is_up(void);

/* Inject a wire-shaped WG datagram from a DERP-relayed source. Used
 * by the supervisor task to feed inbound packets through the same
 * demux + handler path the UDP RX task uses. `src_node_pub` must
 * match the active peer's static public key — packets from anyone
 * else are dropped (we'd never have a session with them).
 *
 * Returns ESP_OK if the packet was classified and dispatched. Returns
 * ESP_ERR_INVALID_STATE before init, ESP_ERR_INVALID_ARG on null
 * inputs, ESP_ERR_INVALID_RESPONSE on src_node_pub mismatch. Packets
 * the demux classifies as initiator-only (HANDSHAKE_INIT) or as
 * already-handled-elsewhere (DISCO) are silently dropped — same
 * policy as the UDP RX task. */
esp_err_t wg_netif_inject_packet(const uint8_t *src_node_pub,
                                 const uint8_t *buf, size_t len);

/* Tear down. Closes the socket, stops the RX task, scrubs key
 * material. Safe to call from any state. */
void wg_netif_stop(void);

/* Cumulative count of outbound plaintext frames dropped because the
 * TX queue was full when wg_netif_send_plaintext tried to enqueue. A
 * non-zero value indicates the encrypt-then-send pipeline can't keep
 * up with lwIP's TX rate (or the worker task is starving — check task
 * priority + WiFi RF stalls). Read-only, monotonically increasing. */
uint64_t wg_netif_get_tx_drops(void);

/* Returns the bound UDP socket descriptor, or -1 if wg_netif has not
 * been initialized yet. Exposed so STUN can run on the same socket the
 * data plane uses — that way the public AddrPort the STUN response
 * advertises matches the NAT mapping that WG keepalives keep alive,
 * and inbound transport from peers actually reaches us. Caller MUST
 * NOT close the socket; it remains owned by wg_netif. */
int wg_netif_get_socket(void);

/* Returns true once wg_netif_start has spawned the RX task. Boot-time
 * STUN must run before this flips so a synchronous recvfrom on the
 * shared socket doesn't race against the RX task's recvfrom (only one
 * of the two would receive a given datagram). */
bool wg_netif_rx_running(void);

#ifdef __cplusplus
}
#endif

#endif /* ESP_PLATFORM */
