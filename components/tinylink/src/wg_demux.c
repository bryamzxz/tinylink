// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "wg_demux.h"

#include <string.h>

/* WG message type bytes (also defined in wg_proto.h, redeclared here so
 * this file stays free of WG protocol headers and remains
 * self-contained for the host KAT). */
#define MSG_INITIATION    1
#define MSG_RESPONSE      2
#define MSG_COOKIE_REPLY  3
#define MSG_TRANSPORT     4

/* DISCO v1 magic prefix per Tailscale's disco/disco.go (const Magic =
 * "TS💬", 6 bytes: 0x54 0x53 0xf0 0x9f 0x92 0xac). Cited from
 * tailscale/tailscale: disco/disco.go line 35. */
static const uint8_t DISCO_V1_MAGIC[6] = {
    0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac
};

/* Hard-coded sizes. Off-by-one or short reads must NOT escalate to
 * downstream parsers; the demuxer is the gatekeeper. */
#define WG_INIT_LEN       148
#define WG_RESP_LEN        92
#define WG_COOKIE_LEN      64
#define WG_TRANSPORT_MIN   32   /* 16 B header + 16 B AEAD tag, empty payload */
/* STUN per RFC 5389 §6: 20-byte header (msg_type 2 + length 2 + magic 4 +
 * txid 12). The 4-byte magic cookie at offset 4 is what reliably tells
 * STUN apart from anything else multiplexed on the same UDP socket — in
 * our case, both DISCO (own magic at offset 0) and WG transport
 * (msg_type byte that could collide with STUN's class+method on a
 * first-byte-only check). */
#define STUN_HEADER_MIN    20
#define STUN_MAGIC_OFF      4
static const uint8_t STUN_MAGIC[4] = { 0x21, 0x12, 0xa4, 0x42 };
/* magic(6) + senderDiscoPub(32) + nonce(24) + AEAD tag(16) + msgType(1) +
 * msgVer(1) = 80 bytes — the smallest disco datagram that could possibly
 * decrypt and parse to a known message type. Anything shorter is junk. */
#define DISCO_HEADER_MIN   (sizeof(DISCO_V1_MAGIC) + 32 + 24 + 16 + 2)

/* STUN by magic cookie at offset 4 — catches binding requests (msg_type
 * 0x0001, byte 0 = 0x00) and binding success/error responses (0x0101 /
 * 0x0111, byte 0 = 0x01). */
static int is_stun(const uint8_t *buf, size_t len)
{
    return len >= STUN_HEADER_MIN &&
           memcmp(buf + STUN_MAGIC_OFF, STUN_MAGIC, sizeof(STUN_MAGIC)) == 0;
}

wg_demux_kind_t wg_demux_classify(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0) return WG_DEMUX_DISCARD;

    /* One switch on the first byte (round 1.3.2, B21) instead of a
     * 6-byte DISCO memcmp + a STUN memcmp ahead of every WG packet.
     * The partition is exact: the DISCO magic starts with 0x54 ('T');
     * every STUN message has its top two bits zero and every method we
     * (or TURN) can see is below 0x80, so its first byte is 0x00 or 0x01
     * (RFC 5389 §6: 0b00 M11..M7 C1); WG types are 0x01..0x04.
     *
     * Only 0x01 is shared: a STUN response (0x0101) must win over the WG
     * MSG_RESPONSE size check, so the magic is checked first there.
     * Until 1.3.1 the STUN magic was checked for EVERY first byte, so a
     * WG transport datagram whose receiver index happened to read
     * 21 12 a4 42 (2^-32 per handshake — our own random local index)
     * was routed to the STUN handler for the whole session; types
     * 0x02..0x04 no longer look at offset 4.
     *
     * WG message format mandates reserved[3] all zero — we don't
     * enforce that here (the cheap check is on the caller side / parser
     * side), but we DO enforce exact size for fixed-length types so a
     * truncated / padded packet doesn't reach downstream parsers. */
    switch (buf[0]) {
    case 0x54:   /* DISCO_V1_MAGIC[0] */
        if (len >= sizeof(DISCO_V1_MAGIC) &&
            memcmp(buf, DISCO_V1_MAGIC, sizeof(DISCO_V1_MAGIC)) == 0) {
            return (len < DISCO_HEADER_MIN) ? WG_DEMUX_DISCARD : WG_DEMUX_DISCO;
        }
        return WG_DEMUX_DISCARD;
    case 0x00:   /* STUN request / indication */
        return is_stun(buf, len) ? WG_DEMUX_STUN : WG_DEMUX_DISCARD;
    case MSG_INITIATION:   /* == STUN success / error response class */
        if (is_stun(buf, len)) return WG_DEMUX_STUN;
        return (len == WG_INIT_LEN) ? WG_DEMUX_HANDSHAKE_INIT : WG_DEMUX_DISCARD;
    case MSG_RESPONSE:
        return (len == WG_RESP_LEN) ? WG_DEMUX_HANDSHAKE_RESP : WG_DEMUX_DISCARD;
    case MSG_COOKIE_REPLY:
        return (len == WG_COOKIE_LEN) ? WG_DEMUX_HANDSHAKE_COOKIE : WG_DEMUX_DISCARD;
    case MSG_TRANSPORT:
        return (len >= WG_TRANSPORT_MIN) ? WG_DEMUX_TRANSPORT : WG_DEMUX_DISCARD;
    default:
        return WG_DEMUX_DISCARD;
    }
}
