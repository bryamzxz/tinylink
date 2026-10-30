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

struct pbuf;

/* Callback invoked once a WG transport packet has been authenticated and
 * decrypted, from the RX task or (DERP-relayed) the DERP task, with no
 * wg lock and no lwIP core lock held. `p` is a single PBUF_RAM pbuf
 * (p->len == p->tot_len, word-aligned payload) holding the inner IP
 * datagram — the AEAD wrote it there directly (round 1.3.3, C1-S). The
 * callee takes ownership: it hands `p` to lwIP or frees it. */
typedef void (*wg_netif_rx_cb_t)(struct pbuf *p, void *user);

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
    /* Tailnet (inner) IPv4 of this node and of the peer, network order:
     * src/dst of the TSMP disco-key advertisement sent after every
     * completed handshake (capver 144). 0 = unknown → no advertisement. */
    uint32_t self_tailnet_v4_be;
    uint32_t peer_tailnet_v4_be;
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

/* Apply a peer identity change reported by control (headscale sends it
 * as a PeersChangedPatch: every tailscaled restart rotates the DiscoKey,
 * a re-login rotates the NodeKey). `disco_pub` NULL = unchanged. A new
 * DiscoKey re-arms the DISCO pre-filter, the relayed-DISCO gate and the
 * cached NaCl shared key; a new static key also restarts the session
 * with a cold handshake. Computes X25519 (~20 ms, 2.7 KiB frame) in the
 * caller's task, outside the locks — call it from the long-poll task. */
esp_err_t wg_netif_update_peer_keys(const uint8_t static_pub[WG_KEY_LEN],
                                    const uint8_t *disco_pub);

/* The peer's tailnet IPv4 (network order) changed — the destination of
 * the TSMP disco advert (round 1.3.9). With the session up the advert
 * goes again at once: the one after the last handshake carried the old
 * address, which the peer drops. Long-poll task. */
esp_err_t wg_netif_update_peer_tailnet(uint32_t v4_be);

/* Path events that can unblock a pending handshake (round 1.3.2, B7).
 * While an INIT is unanswered (cold handshake or rekey), the SAME INIT
 * is re-sent — not a new attempt, so REKEY_TIMEOUT pacing is untouched:
 *   RELAY_UP        — the DERP relay just logged in: send it via DERP
 *                     (its copy queued at build time was declined).
 *   CALL_ME_MAYBE   — the WG peer sent a CallMeMaybe: it is punching
 *                     towards us, so send it direct (and via DERP while
 *                     the direct path is not valid, wg_path.h).
 * A solicited DISCO pong that changes the path does the same direct
 * re-send inside wg_netif.
 * No-op when nothing is pending. Takes hs_lock and g.lock briefly; the
 * DERP copy goes through the TX worker, so it is safe to call from the
 * DERP task (it never holds a DERP lock into wg_netif). */
typedef enum {
    WG_NETIF_KICK_RELAY_UP,
    WG_NETIF_KICK_CALL_ME_MAYBE,
} wg_netif_kick_t;
void wg_netif_handshake_kick(wg_netif_kick_t why);

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

/* Callback invoked from the RX task when the WG transport has been
 * silent (no successful decrypt) for WG_RX_STALE_THRESHOLD_MS AND we
 * have a registered probe handler — and, since round 1.3.6, when the
 * current endpoint failed a ping (DERP only) and at the DERP-only
 * re-probes (10 s, doubling to 60 s, while data goes out; wg_path.h).
 * Tinylink's handler iterates the latest known peer endpoints and sends
 * DISCO pings to all of them; if the peer responds from a different
 * AddrPort, the existing roaming in handle_disco_direct swaps
 * g.peer.peer_endpoint to the live one BEFORE the next
 * rekey/cold-handshake INIT goes out — so the INIT lands on a working
 * address instead of hammering a stale NAT mapping.
 *
 * Mirrors the upstream tailscale model (wgengine/magicsock/endpoint.go:
 * setBestAddrLocked + addrForSendLocked): DISCO ping/pong, not WG
 * handshake, is the canonical path-liveness signal. Rotating to the
 * next endpoint blindly is strictly worse than asking "which of these
 * is alive right now?" — that's what this callback enables.
 *
 * Throttled internally to WG_PATH_PROBE_COOLDOWN_MS so the probe rate
 * is bounded even when the stale condition persists (e.g. peer offline
 * for an extended window). Setting cb=NULL disables. */
typedef void (*wg_netif_path_stale_cb_t)(void *user);
void wg_netif_set_path_stale_callback(wg_netif_path_stale_cb_t cb, void *user);

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

/* Relay callback for the encrypted WG transport frame when the direct
 * UDP path is not confirmed. Invoked by the TX worker per the path
 * selection (round 1.3.6, wg_path.h): INSTEAD of sendto while the direct
 * path failed its ping, or WireGuard failed there while DISCO answered
 * (DERP only); AFTER it (a redundant copy) while the direct path is
 * unconfirmed; and after a sendto that returns errno != 0. Since round
 * 1.3.2 (B7) also for handshake INITs while the direct path is not valid
 * (`packet` is then a 148-B MessageInitiation); since 1.3.6 also for the
 * recent direct-only frames re-sent when a lapse of the direct path is
 * confirmed. The relay is responsible for shipping the bytes to the peer
 * via an alternate transport (e.g. DERP); the WG bytes are already
 * encrypted with the session keys (or are a public handshake message),
 * so the relay just carries opaque ciphertext.
 *
 * Arguments:
 *   dst_node_pub:  the peer's WG static public key (also their NodeKey
 *                  in Tailscale's model). Stable across the lifetime
 *                  of the netif, sourced from the peer config passed
 *                  to wg_netif_start.
 *   packet:        encrypted WG transport frame bytes (data message
 *                  type 0x04 + key idx + counter + ciphertext + tag).
 *   len:           packet length.
 *
 * Returns ESP_OK to mean "relay accepted the bytes for transmission".
 * Returns ESP_ERR_INVALID_STATE if the relay isn't currently usable
 * (e.g. underlying TLS conn not up) — the TX worker treats this the
 * same as no callback registered and falls back to direct sendto.
 * Other non-OK returns are logged but otherwise treated identically.
 *
 * The callback may be invoked from the TX worker context — must not
 * call back into wg_netif_send_plaintext or block longer than ~100 ms.
 *
 * `best_effort` (round 1.3.2) marks a redundant copy — B7's DERP copy
 * of a handshake INIT, or the DERP half of the dual send while the
 * direct path is unproven: the callee must not block at all and may
 * decline (ESP_ERR_TIMEOUT) when the relay cannot take it at once. A
 * relay the TX worker depends on (DERP only, the re-sent frames, sendto
 * errno, and since 1.3.8 an INIT whose only copy is the DERP one or that
 * a DERP login queued behind its re-send) passes false and may wait for
 * the relay's write lock and send buffer.
 *
 * cb=NULL (the default) disables all relay paths; the TX worker only
 * does direct UDP sendto. */
typedef esp_err_t (*wg_netif_relay_fn)(const uint8_t *dst_node_pub,
                                       const uint8_t *packet,
                                       size_t len,
                                       bool best_effort,
                                       void *user);
void wg_netif_set_relay_callback(wg_netif_relay_fn cb, void *user);

/* Is the relay connected right now (round 1.3.8)? An INIT is held behind
 * a re-send of the frames its keypair change would cost only while it is
 * (wg_path_init_route); with the relay down it goes as in 1.3.7. Called
 * with wg_netif's handshake lock held: must not block. NULL (the
 * default): connected whenever a relay callback is registered. */
typedef bool (*wg_netif_relay_up_fn)(void *user);
void wg_netif_set_relay_state_callback(wg_netif_relay_up_fn cb, void *user);

/* Cumulative count of WG transport frames that the TX worker shipped
 * via the relay callback (DERP fallback) instead of — or in addition
 * to — direct sendto. Not counted (round 1.3.2, B7): DERP copies of
 * handshake INITs and the DERP half of the dual send after a
 * DERP-completed handshake; a failed dual-send relay does count in
 * relay_errors (it is a relay failure). Two-counter split:
 *
 *   _stale: relay used because the direct path failed its ping, or
 *           WireGuard failed there while DISCO answered (DERP only, 1.3.6;
 *           until 1.3.5: no decrypt in WG_RX_STALE_THRESHOLD_MS).
 *           Direct sendto skipped on success.
 *   _errno: relay used because sendto returned errno != 0. Reactive
 *           route; direct sendto was attempted first.
 *
 * Both counters increment only on relay success; relay failures count
 * separately via wg_netif_get_relay_errors(). Read-only. */
uint64_t wg_netif_get_relayed_stale(void);
uint64_t wg_netif_get_relayed_errno(void);
uint64_t wg_netif_get_relay_errors(void);

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

/* /stats snapshot (M16). */
typedef struct {
    int      state;                  /* wg_netif_state_t */
    uint32_t rekeys;
    uint32_t cold_handshakes;
    uint32_t rx_stale_events;
    uint32_t roams;
    uint32_t disco_adverts;          /* TSMP disco-key adverts sent (capver 144) */
    uint64_t tx_drops;
    uint64_t relayed_stale;
    uint64_t relay_errors;
    int64_t  last_transport_recv_us;
    int64_t  last_handshake_completed_us;
    /* Path selection (round 1.3.6, wg_path.h). */
    uint8_t  path_mode;              /* wg_path_mode_t: 0 dual, 1 direct, 2 DERP only */
    uint32_t path_lapses;            /* direct → dual */
    uint32_t path_deaths;            /* dual → DERP only */
    uint32_t path_confirms;          /* → direct (pong) */
    uint32_t path_doubts;            /* lapse answered by DISCO, not WireGuard */
    uint32_t path_silences;          /* ...nor WireGuard in a 2nd window: DERP only */
    uint32_t path_undelivered;       /* ...WireGuard answered via DERP only: DERP only */
    uint32_t silent_rekeys;          /* rekeys the silences started */
    uint32_t doubt_rekeys;           /* rekeys the doubts' tests started (1.3.8) */
    uint32_t rescued;                /* direct-only frames re-sent via DERP */
    uint32_t late_responses;         /* answers to replaced INITs (dropped) */
} wg_netif_stats_t;

void wg_netif_get_stats(wg_netif_stats_t *out);

/* Copy the active WG peer's DiscoKey into out (WG_KEY_LEN bytes) and
 * return true if one is known (has_peer_disco_pub). Returns false (and
 * leaves out untouched) when no peer DiscoKey is configured yet — the
 * caller should then treat all DISCO senders as permissive, matching
 * the direct-path roaming gate. Exposed so the DERP-relayed DISCO
 * handler in tinylink.c can apply the same knownPeerDiscoKey gate the
 * direct UDP path applies in handle_disco_direct, instead of acting on
 * a PING/CallMeMaybe sealed by any tailnet node's DiscoKey. */
bool wg_netif_get_peer_disco_pub(uint8_t out[WG_KEY_LEN]);

/* The same, with the cached NaCl box key K for it (round 1.3.7, B2):
 * *k_valid false (k untouched) when there is none — no DiscoKey, or a
 * low-order one. Copied under one lock, so pub and k always belong
 * together. k is a secret: the caller scrubs it. */
bool wg_netif_get_peer_disco_k(uint8_t pub[WG_KEY_LEN], uint8_t k[WG_KEY_LEN],
                               bool *k_valid);

/* The live WG target (network-order v4 + port), which also moves on its
 * own (roam on authenticated packets, pong roam). False before start. */
bool wg_netif_get_peer_endpoint(uint32_t *v4_be, uint16_t *port);

/* True while the session is up and a transport packet authenticated
 * within the RX-stale window (WG_RX_STALE_THRESHOLD_MS). */
bool wg_netif_path_alive(void);

#ifdef __cplusplus
}
#endif

#endif /* ESP_PLATFORM */
