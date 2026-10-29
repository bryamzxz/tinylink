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

/* Largest frame payload staged into ONE write (round 1.3.2, B8): a dst
 * key plus a packet the size of wg_netif's 1 536-B buffers — every
 * WireGuard / DISCO packet tinylink relays. Bigger payloads still go out
 * correctly, as header / key / packet writes under the same lock. */
#define DERP_TX_STAGE_MAX (DERP_KEY_LEN + 1536)

typedef struct {
    esp_tls_t        *tls;                /* owned: closed by derp_client_close */
    bool              connected;
    uint8_t           server_pub[DERP_KEY_LEN];
    int               server_version;     /* parsed from FrameServerInfo JSON */
    /* Serializes writes between the recv-loop's auto-pongs and any
     * external sender (e.g. magicsock relay). Held across one full
     * frame write so DERP framing on the wire stays intact. Created on
     * the first connect and never deleted (derp_client_close takes it
     * while destroying the TLS context, so a cross-task sender can never
     * touch a freed conn) — zero-initialise the struct before first use. */
    SemaphoreHandle_t write_lock;
    /* Set from any task to make the recv loop's next TLS poll fail with
     * DERP_ERR_READ_ABORTED (≤ one SO_RCVTIMEO), so the supervisor drops
     * and reconnects — used when the device's IP changes. Cleared by
     * derp_client_connect_login. */
    volatile bool     abort_reads;
    /* One outgoing frame, header + payload back to back, so a send is
     * ONE esp_tls write = one TLS record (≤ MBEDTLS_SSL_OUT_CONTENT_LEN,
     * 2 KiB) = one TCP segment with TCP_NODELAY. It used to be three
     * writes (header, dst key, packet): three records, and Nagle held the
     * last two until the first was ACKed — ~1 RTT per relayed packet.
     * Guarded by write_lock, like the wire itself. */
    uint8_t           tx_stage[DERP_FRAME_HDR_LEN + DERP_TX_STAGE_MAX];
} derp_client_t;

/* Returned through tls_io by the read adapter when abort_reads is set.
 * Outside the mbedtls error space; distinct from TLS_IO_ERR_IDLE_TIMEOUT. */
#define DERP_ERR_READ_ABORTED (-0x10002)

/* Open a TLS connection to server_host:port, complete the HTTP
 * Upgrade dance, and run the DERP login handshake against the server.
 * On ESP_OK the conn is fully established and stashed in *out — the
 * caller owns it and must release with derp_client_close().
 *
 * server_v4 (round 1.3.5, tl_addr.h): the node's IPv4 from the DERP map
 * (NULL or 0.0.0.0 = none). When given it is dialed first, with a 3-s
 * budget, and the certificate is still verified against server_host
 * (the SNI and mbedtls' hostname check are server_host's); if that
 * fails for any reason, server_host is resolved and dialed in the same
 * call, as without an address. The TLS session is resumed by
 * server_host:port either way.
 *
 * Identity is the device's NodePrivate/NodePublic (the same WireGuard
 * key the control plane already knows about). Memory budget for the
 * login: 1 esp-tls (~12 KiB transient heap during TLS handshake) +
 * ~512 B stack scratch. */
esp_err_t derp_client_connect_login(derp_client_t *out,
                                    const char *server_host, uint16_t port,
                                    const uint8_t server_v4[4],
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
 * concurrent calls (and the recv-loop's pongs) cannot interleave; up to
 * DERP_TX_STAGE_MAX of payload it is a single TLS record.
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

/* Same frame, never blocking (round 1.3.2), for redundant copies — B7's
 * DERP copies of a handshake INIT and the DERP half of the dual send,
 * both made while the direct path may be fine. Declines with
 * ESP_ERR_TIMEOUT when another writer holds the lock or the socket is
 * not writable right now (select() with a zero timeout: lwIP reports
 * writable only above TCP_SNDLOWAT ≈ 2.9 KB free, more than one frame +
 * TLS record needs, so the write cannot block). A half-open DERP conn
 * can then never park the wg_tx task — the blocking variant above can
 * wait out 4 × 30 s of send timeouts. Other returns as above. */
esp_err_t derp_client_try_send_packet(derp_client_t *c,
                                      const uint8_t dst_pub[DERP_KEY_LEN],
                                      const uint8_t *packet, size_t plen);

#ifdef __cplusplus
}
#endif
