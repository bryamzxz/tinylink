// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// DERP HTTP-upgrade client. Opens a TLS connection to a DERP server,
// performs the HTTP/1.1 GET /derp + Upgrade: DERP dance, and runs the
// login frame exchange (server FrameServerKey → our FrameClientInfo →
// server FrameServerInfo).
//
// On success the underlying TLS conn is left open inside derp_client_t
// for subsequent send/recv loops (M5 step 2b / 3). M5 step 2a (this
// commit) only proves the connect + login path works end-to-end with
// a real production DERP server; the recv loop is not yet wired.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_tls.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "derp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    esp_tls_t        *tls;                /* owned: closed by derp_client_close */
    bool              connected;
    uint8_t           server_pub[DERP_KEY_LEN];
    int               server_version;     /* parsed from FrameServerInfo JSON */
    /* Serializes writes between the recv-loop's auto-pongs and any
     * external sender (e.g. magicsock relay). Held across one full
     * frame write so DERP framing on the wire stays intact. */
    SemaphoreHandle_t write_lock;
} derp_client_t;

/* Open a TLS connection to server_host:port, complete the HTTP
 * Upgrade dance, and run the DERP login handshake against the server.
 * On ESP_OK the conn is fully established and stashed in *out — the
 * caller owns it and must release with derp_client_close().
 *
 * Identity is the device's NodePrivate/NodePublic (the same WireGuard
 * key the control plane already knows about). Memory budget for the
 * login: 1 esp-tls (~12 KiB transient heap during TLS handshake) +
 * ~512 B stack scratch. */
esp_err_t derp_client_connect_login(derp_client_t *out,
                                    const char *server_host, uint16_t port,
                                    const uint8_t client_priv[DERP_KEY_LEN],
                                    const uint8_t client_pub[DERP_KEY_LEN]);

/* Close the TLS conn and zero the struct. Safe to call on an
 * already-closed or never-connected client. */
void derp_client_close(derp_client_t *c);

/* Drive the recv loop on top of an already-logged-in client. Wraps
 * derp_run_loop with esp_tls read/write callbacks. Internally answers
 * FramePing with FramePong; invokes cb on every relayed event.
 *
 * frame_buf must persist across the call and hold at least 40 bytes
 * (32 src key + 8 ping). Sized for typical WG packets, ~1600 B is
 * comfortable. Returns:
 *   ESP_OK                     cb returned non-zero (caller stop)
 *   ESP_ERR_INVALID_RESPONSE   server FrameRestarting (supervisor must
 *                              honor evt.restart_reconnect_ms)
 *   ESP_ERR_INVALID_STATE      not connected
 *   ESP_FAIL                   I/O error or protocol violation */
esp_err_t derp_client_run(derp_client_t *c,
                          uint8_t *frame_buf, size_t frame_cap,
                          derp_event_cb_t cb, void *cb_ctx);

/* Send one DERP FrameSendPacket relaying `packet` to peer `dst_pub`.
 * Atomic on the wire: holds c->write_lock across header + payload, so
 * concurrent calls (and the recv-loop's pongs) cannot interleave.
 *
 * Used by the M5 step 3 magicsock fallback when the direct UDP path
 * to a peer fails (ENETUNREACH, no recent reply). plen must be ≤
 * DERP_MAX_PACKET; in practice WG packets are < 1500 B.
 *
 * Returns ESP_OK on success, ESP_ERR_INVALID_STATE if not connected,
 * ESP_ERR_INVALID_ARG / ESP_ERR_INVALID_SIZE on misuse, ESP_FAIL on
 * transport error (caller should drop the conn and reconnect). */
esp_err_t derp_client_send_packet(derp_client_t *c,
                                  const uint8_t dst_pub[DERP_KEY_LEN],
                                  const uint8_t *packet, size_t plen);

#ifdef __cplusplus
}
#endif
