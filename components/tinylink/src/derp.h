// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Tailscale DERP wire codec — Designated Encrypted Relay for Packets.
//
// DERP is the fallback transport magicsock falls back to when a direct
// UDP path between two peers is impossible (double-NATed, IPv6-only,
// blocked, etc.). It is also the channel over which DISCO CallMeMaybe
// frames travel before any direct path exists.
//
// This module implements only the stateless wire codec (port of
// tailscale/tailscale: derp/derp.go):
//   - frame header read/write
//   - per-frame-type encoders/decoders for the subset a leaf client
//     needs (login handshake, packet relay, ping/pong, KeepAlive,
//     NotePreferred, PeerGone, Restarting)
//
// Network I/O (TLS upgrade dance, frame loop) lives in derp_client
// when it lands. The codec here is host-testable and has no platform
// deps beyond the in-tree NaCl crypto wrapper.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tls_io.h"   /* tls_io_read_fn / tls_io_write_fn for derp_run_loop */

#ifdef __cplusplus
extern "C" {
#endif

#define DERP_MAGIC_LEN          8
#define DERP_KEY_LEN            32
#define DERP_NONCE_LEN          24
#define DERP_TAG_LEN            16
#define DERP_FRAME_HDR_LEN      5    /* 1 byte type + 4 byte BE32 length */
#define DERP_PROTOCOL_VERSION   2
#define DERP_PING_LEN           8
#define DERP_MAX_PACKET         (64 * 1024)

/* Magic bytes at the start of FrameServerKey: "DERP🔑" UTF-8.
 * Verified against tailscale/tailscale: derp/derp.go:32. */
extern const uint8_t DERP_MAGIC[DERP_MAGIC_LEN];

/* The subset of frame types this codec covers. Numeric values match
 * upstream derp.FrameType literals. */
typedef enum {
    DERP_FRAME_SERVER_KEY     = 0x01, /* magic + server pub */
    DERP_FRAME_CLIENT_INFO    = 0x02, /* clientPub + nonce + box(json) */
    DERP_FRAME_SERVER_INFO    = 0x03, /* nonce + box(json) */
    DERP_FRAME_SEND_PACKET    = 0x04, /* dstPub + packet */
    DERP_FRAME_RECV_PACKET    = 0x05, /* v2: srcPub + packet */
    DERP_FRAME_KEEPALIVE      = 0x06, /* empty */
    DERP_FRAME_NOTE_PREFERRED = 0x07, /* 1 byte (0x01 if home) */
    DERP_FRAME_PEER_GONE      = 0x08, /* peerPub + reason byte */
    DERP_FRAME_PEER_PRESENT   = 0x09, /* peerPub + opt 18 B addrport + opt flags */
    DERP_FRAME_PING           = 0x12, /* 8 byte payload */
    DERP_FRAME_PONG           = 0x13, /* 8 byte payload */
    DERP_FRAME_HEALTH         = 0x14, /* error message text */
    DERP_FRAME_RESTARTING     = 0x15, /* 2 BE32: reconnect_ms, total_ms */
} derp_frame_type_t;

typedef enum {
    DERP_PEER_GONE_DISCONNECTED  = 0x00,
    DERP_PEER_GONE_NOT_HERE      = 0x01,
    DERP_PEER_GONE_MESH_BROKE    = 0xf0,
} derp_peer_gone_reason_t;

/* ------------------------------------------------------------------ */
/* Frame header                                                        */
/* ------------------------------------------------------------------ */

/* Write a 5-byte frame header into out. Returns DERP_FRAME_HDR_LEN. */
size_t derp_write_frame_header(uint8_t out[DERP_FRAME_HDR_LEN],
                               derp_frame_type_t type, uint32_t len);

/* Parse a frame header from buf. Returns 0 on success, -1 on short
 * input. Does NOT validate the type or length against any whitelist. */
int derp_read_frame_header(const uint8_t *buf, size_t buflen,
                           derp_frame_type_t *out_type,
                           uint32_t *out_len);

/* ------------------------------------------------------------------ */
/* Login handshake                                                     */
/* ------------------------------------------------------------------ */

/* FrameServerKey payload = magic[8] || serverPub[32] || future.
 * On success, returns 0 and copies serverPub to out_server_pub.
 * Bytes after offset 40 are reserved for forward-compat and ignored. */
int derp_parse_server_key(const uint8_t *payload, size_t plen,
                          uint8_t out_server_pub[DERP_KEY_LEN]);

/* Build FrameClientInfo payload (NOT including the 5-byte frame
 * header). Layout: clientPub[32] || nonce[24] || nacl_box(json).
 *
 * The JSON we send is fixed by ClientInfo defaults for a leaf node:
 *   {"version":2,"CanAckPings":true}
 *
 * (No MeshKey: we're not a mesh peer. IsProber omitted: we're a
 * regular client.)
 *
 * out_cap must hold DERP_KEY_LEN + DERP_NONCE_LEN + DERP_TAG_LEN +
 * len(json) bytes. The fixed JSON is 32 bytes, so 32+24+16+32 = 104
 * bytes is enough.
 *
 * Returns the number of payload bytes written, 0 on failure. */
size_t derp_build_client_info(uint8_t *out, size_t out_cap,
                              const uint8_t client_pub[DERP_KEY_LEN],
                              const uint8_t client_priv[DERP_KEY_LEN],
                              const uint8_t server_pub[DERP_KEY_LEN],
                              const uint8_t nonce[DERP_NONCE_LEN]);

/* FrameServerInfo payload = nonce[24] || box(json).
 *
 * Authenticates the server's reply with our client_priv against the
 * server_pub we just learned from FrameServerKey. Decrypts the box
 * into an internal scratch buffer, then opportunistically scans for
 * "version":N in the plaintext (server_info JSON is small — typically
 * <100 bytes). Out_version receives the parsed integer, or 0 if not
 * present.
 *
 * Returns 0 on success (box opened cleanly), negative on bad arg /
 * short input / AEAD failure. */
int derp_parse_server_info(const uint8_t *payload, size_t plen,
                           const uint8_t client_priv[DERP_KEY_LEN],
                           const uint8_t server_pub[DERP_KEY_LEN],
                           int *out_version);

/* ------------------------------------------------------------------ */
/* Packet relay                                                        */
/* ------------------------------------------------------------------ */

/* FrameSendPacket payload = dstPub[32] || packet[plen].
 * Straight memcpy + magic; returns bytes written or 0 if out_cap too
 * small / packet too large (> DERP_MAX_PACKET). */
size_t derp_build_send_packet(uint8_t *out, size_t out_cap,
                              const uint8_t dst_pub[DERP_KEY_LEN],
                              const uint8_t *packet, size_t plen);

/* FrameRecvPacket (v2) payload = srcPub[32] || packet.
 * On success, copies srcPub and sets *out_packet to the packet data
 * inside the original payload buffer (no copy). Returns 0, or -1 on
 * short payload. The caller must not mutate or free the payload while
 * out_packet is in use. */
int derp_parse_recv_packet(const uint8_t *payload, size_t plen,
                           uint8_t out_src_pub[DERP_KEY_LEN],
                           const uint8_t **out_packet, size_t *out_len);

/* ------------------------------------------------------------------ */
/* Liveness & control                                                  */
/* ------------------------------------------------------------------ */

/* Both Ping and Pong carry an 8-byte opaque payload that's echoed
 * back: client receives Ping → must reply with Pong carrying the same
 * payload, so the server can match RTT samples. */
int derp_parse_ping_or_pong(const uint8_t *payload, size_t plen,
                            uint8_t out_data[DERP_PING_LEN]);

/* FrameNotePreferred payload is a single byte: 0x01 = "this DERP is
 * my home node", 0x00 = not. Always succeeds. */
size_t derp_build_note_preferred(uint8_t out[1], bool is_home);

/* FramePeerGone payload = peerPub[32] || reason[1]. The reason byte
 * is optional in older servers; if missing, defaults to
 * DERP_PEER_GONE_DISCONNECTED. */
int derp_parse_peer_gone(const uint8_t *payload, size_t plen,
                         uint8_t out_peer_pub[DERP_KEY_LEN],
                         uint8_t *out_reason);

/* FrameRestarting payload = reconnect_ms[BE32] || total_ms[BE32]:
 * server is gracefully shutting down and asks the client to reconnect
 * after `reconnect_ms`, giving up entirely after `total_ms`. */
int derp_parse_restarting(const uint8_t *payload, size_t plen,
                          uint32_t *out_reconnect_ms,
                          uint32_t *out_total_ms);

/* ------------------------------------------------------------------ */
/* Recv loop (M5 step 2b)                                              */
/* ------------------------------------------------------------------ */

typedef enum {
    DERP_EVT_RECV_PACKET    = 1,   /* WG packet from peer (most common) */
    DERP_EVT_PEER_PRESENT   = 2,
    DERP_EVT_PEER_GONE      = 3,
    DERP_EVT_HEALTH         = 4,
    DERP_EVT_RESTARTING     = 5,
    DERP_EVT_KEEPALIVE      = 6,
} derp_event_kind_t;

/* Borrowed pointers — only valid for the duration of the cb call.
 * Callers that need to keep the bytes must memcpy. */
typedef struct {
    derp_event_kind_t kind;
    const uint8_t    *src_pub;             /* RECV_PACKET / PEER_PRESENT / PEER_GONE: 32 B */
    const uint8_t    *data;                /* RECV_PACKET payload, HEALTH text */
    size_t            data_len;
    uint8_t           peer_gone_reason;
    uint32_t          restart_reconnect_ms;
    uint32_t          restart_total_ms;
} derp_event_t;

/* Return non-zero from the callback to stop the loop cleanly. */
typedef int (*derp_event_cb_t)(const derp_event_t *evt, void *ctx);

/* Atomically write one DERP frame (5-byte header + payload). The
 * implementation MUST serialize concurrent calls from different
 * threads — this is the sole synchronization point shared by the
 * recv loop's pongs and any external sender (e.g. magicsock relay).
 * Returns 0 on success, negative on transport failure. */
typedef int (*derp_send_frame_fn)(void *ctx, derp_frame_type_t type,
                                  const uint8_t *payload, size_t plen);

/* Run the recv loop. Reads frames via rd, internally answers
 * FramePing by calling send(PONG, payload), and invokes cb on every
 * event the loop deems interesting.
 *
 * frame_buf must hold a single frame's payload. We cap accepted
 * payload length at frame_cap; oversized frames are fatal (we cannot
 * skip-without-reading through the tls_io abstraction).
 *
 * `max_idle` is threaded to every tls_io_read_full call: the number of
 * consecutive zero-progress WANT_READ polls (one SO_RCVTIMEO period
 * each on target) tolerated before the stream is declared dead and the
 * loop returns -1 so the supervisor reconnects. The DERP server sends
 * a keepalive frame roughly every minute, so the caller should budget
 * ≥2 keepalive intervals. 0 = unlimited (hosts tests / legacy).
 *
 * Return values:
 *    0  cb returned non-zero — caller-driven termination
 *   -1  read/write failure, idle timeout, or oversized frame
 *   -2  server FrameRestarting — supervisor must honor restart timing
 *   -3  bad frame parse
 *   -4  unexpected post-login frame (ServerKey / ServerInfo)
 *   -5  bad arg / capacity too small */
int derp_run_loop(tls_io_read_fn rd, derp_send_frame_fn send, void *io_ctx,
                  uint8_t *frame_buf, size_t frame_cap,
                  derp_event_cb_t cb, void *cb_ctx, uint32_t max_idle);

#ifdef __cplusplus
}
#endif
