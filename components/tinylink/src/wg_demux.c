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

/* DISCO v1 magic prefix per Tailscale's disco/disco.go. Used in step 7;
 * declared here so the demuxer can already shed DISCO traffic to its
 * own bucket before the parser exists. Verified at
 * /home/bryam/dev/tailscale/disco/disco.go before integration. */
static const uint8_t DISCO_V1_MAGIC[8] = {
    0x01, 0x05, 0xfe, 0x16, 0x76, 0x46, 0x90, 0x80
};

/* Hard-coded sizes. Off-by-one or short reads must NOT escalate to
 * downstream parsers; the demuxer is the gatekeeper. */
#define WG_INIT_LEN       148
#define WG_RESP_LEN        92
#define WG_COOKIE_LEN      64
#define WG_TRANSPORT_MIN   32   /* 16 B header + 16 B AEAD tag, empty payload */
#define STUN_FIRST_TWO     2
#define DISCO_HEADER_MIN   (sizeof(DISCO_V1_MAGIC) + 32 + 24 + 16)
                                /* magic + sender DiscoPub + nonce + tag */

wg_demux_kind_t wg_demux_classify(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len == 0) return WG_DEMUX_DISCARD;

    /* DISCO check first: the magic is 8 bytes long, and starts with
     * 0x01 — the same as MessageInitiation's first byte. So we MUST
     * check the magic before we'd otherwise accept it as a 148-byte
     * handshake init. */
    if (len >= sizeof(DISCO_V1_MAGIC) &&
        memcmp(buf, DISCO_V1_MAGIC, sizeof(DISCO_V1_MAGIC)) == 0) {
        if (len < DISCO_HEADER_MIN) return WG_DEMUX_DISCARD;
        return WG_DEMUX_DISCO;
    }

    /* WG types are identified by a single byte. WG message format
     * mandates reserved[3] all zero — we don't enforce that here (the
     * cheap check is on the caller side / parser side), but we DO
     * enforce exact size for fixed-length types so a truncated /
     * padded packet doesn't reach downstream parsers. */
    switch (buf[0]) {
    case MSG_INITIATION:
        return (len == WG_INIT_LEN) ? WG_DEMUX_HANDSHAKE_INIT : WG_DEMUX_DISCARD;
    case MSG_RESPONSE:
        return (len == WG_RESP_LEN) ? WG_DEMUX_HANDSHAKE_RESP : WG_DEMUX_DISCARD;
    case MSG_COOKIE_REPLY:
        return (len == WG_COOKIE_LEN) ? WG_DEMUX_HANDSHAKE_COOKIE : WG_DEMUX_DISCARD;
    case MSG_TRANSPORT:
        return (len >= WG_TRANSPORT_MIN) ? WG_DEMUX_TRANSPORT : WG_DEMUX_DISCARD;
    default:
        break;
    }

    /* STUN binding request: first 2 bits of msg_type are 00 (per
     * RFC 5389 §6: "two zero bits at the start of every STUN msg
     * allow STUN to be multiplexed with other protocols"). The
     * binding-request method has class+method = 0x0001 in the first
     * 16 bits. We only need to recognize "looks like STUN" cheaply
     * here; the actual STUN parser does the rest. */
    if (len >= STUN_FIRST_TWO && buf[0] == 0x00 && buf[1] == 0x01) {
        return WG_DEMUX_STUN;
    }

    return WG_DEMUX_DISCARD;
}
