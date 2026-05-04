/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for the DERP wire codec (derp.c). Covers:
 *   - Frame header read/write roundtrip + golden vectors lifted from
 *     /home/bryam/dev/tailscale/derp/derp_test.go::TestWriteFrameHeader.
 *   - FrameServerKey: magic verification, key extraction, magic tamper
 *     rejection, short-input rejection, forward-compat tail tolerance.
 *   - FrameClientInfo: build with two real Curve25519 keypairs, then
 *     SERVER-side decrypt verifies the boxed JSON is authenticated and
 *     parses to the expected fixed payload.
 *   - FrameServerInfo: build a synthetic server reply (we have both
 *     keys), parse it back, verify the version field is extracted.
 *   - FrameSendPacket: build, then parse via FrameRecvPacket roundtrip
 *     (the wire layouts of the two are functionally symmetric for the
 *     codec — just dst vs. src semantics).
 *   - FrameRecvPacket: zero-byte packet + max-size accept; parser
 *     surfaces a no-copy pointer.
 *   - FramePing/Pong: payload roundtrip, short-payload rejection.
 *   - FrameNotePreferred: home/non-home byte.
 *   - FramePeerGone: with reason byte, without reason byte (older
 *     server fallback to DISCONNECTED), short rejection.
 *   - FrameRestarting: BE32 pair roundtrip, short rejection.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "derp.h"
#include "crypto/curve25519.h"
#include "crypto/nacl_box.h"

/* esp_fill_random stub for nacl_box on host. Mirrors the pattern in
 * test_disco.c — deterministic xorshift, never tested for crypto
 * randomness here. */
static uint64_t s_rng_state = 0xCAFEBABEDEADBEEFULL;
void esp_fill_random(void *buf, size_t len)
{
    uint8_t *out = (uint8_t *)buf;
    for (size_t i = 0; i < len; i++) {
        s_rng_state ^= s_rng_state << 13;
        s_rng_state ^= s_rng_state >> 7;
        s_rng_state ^= s_rng_state << 17;
        out[i] = (uint8_t)s_rng_state;
    }
}

static int fails = 0;

static int ok(const char *name, int condition) {
    if (condition) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL\n", name);
    return 1;
}

static int eq_bytes(const char *name, const uint8_t *a, const uint8_t *b, size_t n) {
    if (memcmp(a, b, n) == 0) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL\n  got:  ", name);
    for (size_t i = 0; i < n; i++) printf("%02x", a[i]);
    printf("\n  want: ");
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
    return 1;
}

static int eq_u32(const char *name, uint32_t got, uint32_t want) {
    if (got == want) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL got=%u want=%u\n", name, got, want);
    return 1;
}

/* Helper: derive a Curve25519 keypair from a deterministic 32-byte seed.
 * Same shape as the test_disco helper. The byte 0x37 of the seed is the
 * RFC 7748 §5 clamping mask reserved for the private key, but for KAT
 * purposes we just clamp ourselves to keep the curve operations valid. */
static void make_keypair(const char *seed_label,
                         uint8_t priv[32], uint8_t pub[32])
{
    memset(priv, 0, 32);
    size_t len = strlen(seed_label);
    if (len > 32) len = 32;
    memcpy(priv, seed_label, len);
    /* curve25519_derive_pub does the RFC 7748 §5 clamping internally
     * and computes pub = priv * basepoint. */
    curve25519_derive_pub(pub, priv);
}

/* ------------------------------------------------------------------ */
/* Frame header                                                       */
/* ------------------------------------------------------------------ */

static void test_frame_header_roundtrip(void) {
    /* Lifted from /home/bryam/dev/tailscale/derp/derp_test.go
     * TestWriteFrameHeader: FrameSendPacket + length 0x400 → bytes
     * {0x04, 0x00, 0x00, 0x04, 0x00}. */
    uint8_t hdr[DERP_FRAME_HDR_LEN];
    size_t n = derp_write_frame_header(hdr, DERP_FRAME_SEND_PACKET, 0x400);
    fails += ok("hdr/write/len", n == DERP_FRAME_HDR_LEN);
    const uint8_t want_send[DERP_FRAME_HDR_LEN] = {0x04, 0x00, 0x00, 0x04, 0x00};
    fails += eq_bytes("hdr/write/send-packet", hdr, want_send, DERP_FRAME_HDR_LEN);

    /* TestWriteFrameHeader: FrameRecvPacket + 0xFFFFFFFF → {0x05, ff,ff,ff,ff}. */
    n = derp_write_frame_header(hdr, DERP_FRAME_RECV_PACKET, 0xFFFFFFFFu);
    const uint8_t want_recv[DERP_FRAME_HDR_LEN] = {0x05, 0xff, 0xff, 0xff, 0xff};
    fails += eq_bytes("hdr/write/recv-packet-max", hdr, want_recv, DERP_FRAME_HDR_LEN);

    /* Read-side roundtrip. */
    derp_frame_type_t got_type;
    uint32_t got_len;
    fails += ok("hdr/read/rc", derp_read_frame_header(want_recv, sizeof(want_recv),
                                                     &got_type, &got_len) == 0);
    fails += ok("hdr/read/type", got_type == DERP_FRAME_RECV_PACKET);
    fails += eq_u32("hdr/read/len", got_len, 0xFFFFFFFFu);

    fails += ok("hdr/read/short", derp_read_frame_header(want_recv, 4, &got_type, &got_len) == -1);
    fails += ok("hdr/read/null", derp_read_frame_header(NULL, 5, &got_type, &got_len) == -1);
}

/* ------------------------------------------------------------------ */
/* FrameServerKey                                                     */
/* ------------------------------------------------------------------ */

static void test_server_key(void) {
    uint8_t srv_priv[32], srv_pub[32];
    make_keypair("derp-server-key-test", srv_priv, srv_pub);

    uint8_t payload[DERP_MAGIC_LEN + DERP_KEY_LEN + 4]; /* +tail */
    memcpy(payload, DERP_MAGIC, DERP_MAGIC_LEN);
    memcpy(payload + DERP_MAGIC_LEN, srv_pub, DERP_KEY_LEN);
    payload[DERP_MAGIC_LEN + DERP_KEY_LEN]     = 0xCA;  /* future bytes */
    payload[DERP_MAGIC_LEN + DERP_KEY_LEN + 1] = 0xFE;
    payload[DERP_MAGIC_LEN + DERP_KEY_LEN + 2] = 0xBA;
    payload[DERP_MAGIC_LEN + DERP_KEY_LEN + 3] = 0xBE;

    uint8_t out_pub[DERP_KEY_LEN];
    fails += ok("srvkey/parse-rc", derp_parse_server_key(payload, sizeof(payload), out_pub) == 0);
    fails += eq_bytes("srvkey/extract-pub", out_pub, srv_pub, DERP_KEY_LEN);

    /* Forward-compat: still parses if there's no tail. */
    fails += ok("srvkey/parse-no-tail",
                derp_parse_server_key(payload, DERP_MAGIC_LEN + DERP_KEY_LEN, out_pub) == 0);

    /* Tamper: corrupt magic byte 0 → reject. */
    uint8_t bad[sizeof(payload)];
    memcpy(bad, payload, sizeof(payload));
    bad[0] ^= 0x01;
    fails += ok("srvkey/tamper-magic-rejected",
                derp_parse_server_key(bad, sizeof(bad), out_pub) == -1);

    /* Short input. */
    fails += ok("srvkey/short-rejected",
                derp_parse_server_key(payload, DERP_MAGIC_LEN + DERP_KEY_LEN - 1, out_pub) == -1);
    fails += ok("srvkey/null-rejected",
                derp_parse_server_key(NULL, 100, out_pub) == -1);
}

/* ------------------------------------------------------------------ */
/* FrameClientInfo + FrameServerInfo handshake                         */
/* ------------------------------------------------------------------ */

static void test_client_info_handshake(void) {
    uint8_t cli_priv[32], cli_pub[32];
    uint8_t srv_priv[32], srv_pub[32];
    make_keypair("derp-client-info-cli", cli_priv, cli_pub);
    make_keypair("derp-client-info-srv", srv_priv, srv_pub);

    uint8_t nonce[DERP_NONCE_LEN];
    for (int i = 0; i < DERP_NONCE_LEN; i++) nonce[i] = (uint8_t)(0x10 + i);

    uint8_t payload[256];
    size_t n = derp_build_client_info(payload, sizeof(payload),
                                      cli_pub, cli_priv, srv_pub, nonce);
    /* JSON is fixed at 32 bytes; payload = 32 + 24 + 16 + 32 = 104. */
    fails += ok("clientinfo/build-len", n == 32 + 24 + 16 + 32);
    fails += eq_bytes("clientinfo/clientpub", payload, cli_pub, 32);
    fails += eq_bytes("clientinfo/nonce", payload + 32, nonce, 24);

    /* Server-side: open the box with srv_priv against cli_pub. */
    const size_t boxlen = n - 32 - 24;
    const size_t ptlen  = boxlen - DERP_TAG_LEN;
    uint8_t pt[64];
    fails += ok("clientinfo/server-decrypts",
                nacl_box_open(pt, payload + 32 + 24, boxlen,
                              nonce, cli_pub, srv_priv) == 0);

    /* Verify the JSON the server sees matches our fixed payload. */
    static const char want_json[] = "{\"version\":2,\"CanAckPings\":true}";
    fails += ok("clientinfo/json-len", ptlen == sizeof(want_json) - 1);
    fails += eq_bytes("clientinfo/json-bytes", pt, (const uint8_t *)want_json, ptlen);

    /* out_cap underflow is rejected. */
    fails += ok("clientinfo/cap-too-small",
                derp_build_client_info(payload, 100, cli_pub, cli_priv, srv_pub, nonce) == 0);

    /* Now build a synthetic FrameServerInfo and roundtrip-parse it.
     * Server signs with srv_priv against cli_pub; we open it with
     * cli_priv against srv_pub — exactly the flow the device runs. */
    static const char srv_json[] = "{\"version\":2,\"TokenBucketBytesPerSecond\":1048576}";
    const size_t srv_jlen = sizeof(srv_json) - 1;
    uint8_t srv_payload[DERP_NONCE_LEN + DERP_TAG_LEN + 96];

    uint8_t srv_nonce[DERP_NONCE_LEN];
    for (int i = 0; i < DERP_NONCE_LEN; i++) srv_nonce[i] = (uint8_t)(0xA0 ^ i);
    memcpy(srv_payload, srv_nonce, DERP_NONCE_LEN);
    fails += ok("serverinfo/seal",
                nacl_box(srv_payload + DERP_NONCE_LEN,
                         (const uint8_t *)srv_json, srv_jlen,
                         srv_nonce, cli_pub, srv_priv) == 0);
    const size_t srv_total = DERP_NONCE_LEN + DERP_TAG_LEN + srv_jlen;

    int ver = -1;
    fails += ok("serverinfo/parse-rc",
                derp_parse_server_info(srv_payload, srv_total,
                                       cli_priv, srv_pub, &ver) == 0);
    fails += ok("serverinfo/parse-version", ver == 2);

    /* Tamper: flip a byte inside the box → reject. */
    uint8_t bad[sizeof(srv_payload)];
    memcpy(bad, srv_payload, srv_total);
    bad[DERP_NONCE_LEN + DERP_TAG_LEN + 5] ^= 0xFF;
    fails += ok("serverinfo/tamper-rejected",
                derp_parse_server_info(bad, srv_total, cli_priv, srv_pub, &ver) == -1);

    /* Wrong key (use a different server pub) → reject. */
    uint8_t other_priv[32], other_pub[32];
    make_keypair("derp-other", other_priv, other_pub);
    fails += ok("serverinfo/wrong-key-rejected",
                derp_parse_server_info(srv_payload, srv_total,
                                       cli_priv, other_pub, &ver) == -1);
}

/* ------------------------------------------------------------------ */
/* FrameSendPacket / FrameRecvPacket                                  */
/* ------------------------------------------------------------------ */

static void test_send_recv_packet(void) {
    uint8_t dst_pub[32];
    for (int i = 0; i < 32; i++) dst_pub[i] = (uint8_t)(0xC0 + i);

    static const uint8_t pkt[] = {
        0x01, 0x02, 0x03, 0x04, 0xDE, 0xAD, 0xBE, 0xEF,
        0xFE, 0xED, 0xFA, 0xCE, 0xBA, 0xAD, 0xF0, 0x0D
    };
    uint8_t buf[64];
    size_t n = derp_build_send_packet(buf, sizeof(buf), dst_pub, pkt, sizeof(pkt));
    fails += ok("send/build-len", n == 32 + sizeof(pkt));
    fails += eq_bytes("send/dst-pub", buf, dst_pub, 32);
    fails += eq_bytes("send/packet-bytes", buf + 32, pkt, sizeof(pkt));

    /* zero-byte packet still produces a 32-byte payload (no crash). */
    n = derp_build_send_packet(buf, sizeof(buf), dst_pub, NULL, 0);
    fails += ok("send/zero-packet-len", n == 32);

    /* over-cap rejection */
    fails += ok("send/cap-too-small",
                derp_build_send_packet(buf, 32, dst_pub, pkt, sizeof(pkt)) == 0);

    /* parse the same payload as a RecvPacket — the wire layout of the
     * payload area is symmetric (dst pub = src pub from the receiver's
     * pov). */
    uint8_t src_pub[32];
    const uint8_t *out_pkt = NULL;
    size_t out_len = 0;
    fails += ok("recv/parse-rc",
                derp_parse_recv_packet(buf, 32 + sizeof(pkt),
                                       src_pub, &out_pkt, &out_len) == 0);
    fails += eq_bytes("recv/src-pub", src_pub, dst_pub, 32);
    fails += ok("recv/len", out_len == sizeof(pkt));
    fails += eq_bytes("recv/packet-bytes", out_pkt, pkt, sizeof(pkt));
    /* recv hands back a pointer INSIDE the original buffer — no copy. */
    fails += ok("recv/no-copy-pointer", out_pkt == buf + 32);

    /* short payload (no key) → reject */
    fails += ok("recv/short-rejected",
                derp_parse_recv_packet(buf, 31, src_pub, &out_pkt, &out_len) == -1);

    /* zero-byte packet payload — valid, len=0 */
    fails += ok("recv/zero-packet",
                derp_parse_recv_packet(buf, 32, src_pub, &out_pkt, &out_len) == 0);
    fails += ok("recv/zero-packet-len", out_len == 0);
}

/* ------------------------------------------------------------------ */
/* Ping/Pong                                                          */
/* ------------------------------------------------------------------ */

static void test_ping_pong(void) {
    const uint8_t ping_data[DERP_PING_LEN] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE
    };
    uint8_t out[DERP_PING_LEN];
    fails += ok("ping/parse-rc",
                derp_parse_ping_or_pong(ping_data, DERP_PING_LEN, out) == 0);
    fails += eq_bytes("ping/echoed-bytes", out, ping_data, DERP_PING_LEN);

    /* Same parser handles Pong (8-byte echo). */
    fails += ok("pong/parse-rc",
                derp_parse_ping_or_pong(ping_data, DERP_PING_LEN, out) == 0);

    /* Short rejection. */
    fails += ok("ping/short-rejected",
                derp_parse_ping_or_pong(ping_data, 7, out) == -1);
}

/* ------------------------------------------------------------------ */
/* FrameNotePreferred                                                  */
/* ------------------------------------------------------------------ */

static void test_note_preferred(void) {
    uint8_t b[1];
    fails += ok("notepref/build-home-len", derp_build_note_preferred(b, true) == 1);
    fails += ok("notepref/build-home-byte", b[0] == 0x01);
    fails += ok("notepref/build-away-len", derp_build_note_preferred(b, false) == 1);
    fails += ok("notepref/build-away-byte", b[0] == 0x00);
}

/* ------------------------------------------------------------------ */
/* FramePeerGone                                                       */
/* ------------------------------------------------------------------ */

static void test_peer_gone(void) {
    uint8_t peer_pub[32];
    for (int i = 0; i < 32; i++) peer_pub[i] = (uint8_t)(0x90 + i);

    /* Modern server sends key + reason byte. */
    uint8_t payload[33];
    memcpy(payload, peer_pub, 32);
    payload[32] = (uint8_t)DERP_PEER_GONE_NOT_HERE;

    uint8_t out_pub[32];
    uint8_t reason = 0;
    fails += ok("peergone/parse-rc",
                derp_parse_peer_gone(payload, sizeof(payload), out_pub, &reason) == 0);
    fails += eq_bytes("peergone/peer-pub", out_pub, peer_pub, 32);
    fails += ok("peergone/reason-not-here",
                reason == (uint8_t)DERP_PEER_GONE_NOT_HERE);

    /* Older server omits the reason byte — defaults to DISCONNECTED. */
    fails += ok("peergone/parse-no-reason",
                derp_parse_peer_gone(payload, 32, out_pub, &reason) == 0);
    fails += ok("peergone/reason-defaults-disconnected",
                reason == (uint8_t)DERP_PEER_GONE_DISCONNECTED);

    /* Short. */
    fails += ok("peergone/short-rejected",
                derp_parse_peer_gone(payload, 31, out_pub, &reason) == -1);
}

/* ------------------------------------------------------------------ */
/* FrameRestarting                                                     */
/* ------------------------------------------------------------------ */

static void test_restarting(void) {
    /* reconnect_ms = 1500 (BE 00 00 05 dc), total_ms = 30000 (BE 00 00 75 30) */
    uint8_t payload[8] = {
        0x00, 0x00, 0x05, 0xdc,
        0x00, 0x00, 0x75, 0x30
    };
    uint32_t reconn = 0, total = 0;
    fails += ok("restart/parse-rc",
                derp_parse_restarting(payload, sizeof(payload), &reconn, &total) == 0);
    fails += eq_u32("restart/reconnect-ms", reconn, 1500);
    fails += eq_u32("restart/total-ms", total, 30000);

    fails += ok("restart/short-rejected",
                derp_parse_restarting(payload, 7, &reconn, &total) == -1);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(void) {
    test_frame_header_roundtrip();
    test_server_key();
    test_client_info_handshake();
    test_send_recv_packet();
    test_ping_pong();
    test_note_preferred();
    test_peer_gone();
    test_restarting();

    if (fails) {
        printf("\n[FAIL] %d assertion(s) failed\n", fails);
        return 1;
    }
    printf("\n[PASS] all derp assertions passed\n");
    return 0;
}
