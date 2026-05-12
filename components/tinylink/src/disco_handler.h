// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// DISCO inbound handler — bridges a relayed DERP packet to a sealed
// Pong reply when the frame is a Ping addressed to our DiscoKey.
//
// This is the M3 step 2 minimum: enough wiring to make
// `tailscale ping <tinylink>` from a remote peer return a Pong via
// DERP, without yet implementing CallMeMaybe-driven direct path
// probing or WG-level ICMP forwarding.
//
// Pure-C codec orchestration (decrypt → parse → encode → seal). No
// I/O, no FreeRTOS, host-testable. Network egress is the caller's
// responsibility (typically derp_client_send_packet to the peer's
// NodePublic, which DERP routes to the right destination).

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "disco.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum sealed-Pong wire length. Inner Pong = 1 (type) + 1 (ver) +
 * 12 (txid) + 16 (addr) + 2 (port) = 32. Sealed wire = 78 (overhead)
 * + 32 = 110. Round up to 128 for caller comfort. */
#define DISCO_HANDLER_REPLY_MAX 128

/* Decide what to do with an incoming DISCO-magic-prefixed payload that
 * arrived over DERP (or any other transport — function is wire-agnostic).
 *
 * Steps:
 *   1. disco_looks_like(frame). If false → 0.
 *   2. disco_open(frame) using my_disco_priv. Failure → 0 (logged via
 *      out_type = -1 sentinel? no — out_type only set on success).
 *   3. disco_parse(plaintext). Failure → 0.
 *   4. Switch on parsed type:
 *        PING → build Pong inner (echoes txid; src = zeroed sentinel),
 *               seal it back to the sender's DiscoKey, return wire len.
 *        PONG / CALLMEMAYBE → no reply (this PR doesn't probe), 0.
 *
 * out_reply / out_cap: receives the sealed Pong wire bytes if the input
 *   was a Ping. The caller passes these straight to
 *   derp_client_send_packet(supervisor, peer_node_pub, out_reply, ret).
 *   Buffer must be at least DISCO_HANDLER_REPLY_MAX bytes.
 *
 * Optional outputs (may be NULL — useful for logging):
 *   out_type            : parsed disco_msg_type_t when decrypt+parse succeed.
 *   out_peer_disco_pub  : sender's DiscoKey from the cleartext header.
 *   out_txid            : 12-byte TxID of the Ping (only meaningful when
 *                         we actually replied).
 *
 * Returns:
 *   > 0  bytes of sealed Pong written to out_reply (Ping path).
 *   = 0  no reply needed (non-DISCO bytes, decrypt fail, non-Ping type,
 *        or build/seal failure).
 *
 * Notes on the Pong's src_addr/src_port: upstream magicsock sets these
 * to a `derpFakeAddr` sentinel (127.3.3.40:<region>) so the ping
 * originator can label the path "via DERP". For this minimum cut we
 * zero both fields — the originator still accepts the Pong by TxID
 * match; it just shows the path as "via DERP" without a region tag.
 */
size_t disco_handle_recv(uint8_t *out_reply, size_t out_cap,
                         const uint8_t *frame, size_t frame_len,
                         const uint8_t my_disco_priv[DISCO_KEY_LEN],
                         const uint8_t my_disco_pub[DISCO_KEY_LEN],
                         disco_msg_type_t *out_type,
                         uint8_t out_peer_disco_pub[DISCO_KEY_LEN],
                         uint8_t out_txid[DISCO_TXID_LEN]);

/* Same as disco_handle_recv but uses a precomputed shared key for the
 * inbound open (skipping the per-frame X25519+HSalsa20). my_disco_priv
 * is still required for sealing the outbound Pong reply on the Ping
 * path. Caller is responsible for invalidating shared_k whenever the
 * peer DiscoKey or our disco_priv changes. */
size_t disco_handle_recv_with_shared(uint8_t *out_reply, size_t out_cap,
                                     const uint8_t *frame, size_t frame_len,
                                     const uint8_t shared_k[DISCO_KEY_LEN],
                                     const uint8_t my_disco_priv[DISCO_KEY_LEN],
                                     const uint8_t my_disco_pub[DISCO_KEY_LEN],
                                     disco_msg_type_t *out_type,
                                     uint8_t out_peer_disco_pub[DISCO_KEY_LEN],
                                     uint8_t out_txid[DISCO_TXID_LEN]);

#ifdef __cplusplus
}
#endif
