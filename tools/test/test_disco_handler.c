/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for disco_handler.c — the M3 step 2 wiring that turns an
 * inbound DISCO Ping (received via the DERP supervisor) into a sealed
 * Pong reply ready to ship back over derp_client_send_packet.
 *
 * Coverage:
 *   - Ping→Pong roundtrip: peer encodes a Ping, our handler emits
 *     wire bytes that the peer can disco_open and disco_parse to find
 *     a Pong with the matching TxID.
 *   - Pong → no reply (we don't bounce Pongs).
 *   - CallMeMaybe → no reply (M5 step 3 territory).
 *   - Non-DISCO bytes → no reply (cheap magic-prefix gate).
 *   - Wrong recipient (sealed to a different DiscoKey) → no reply.
 *   - Tampered ciphertext → no reply.
 *   - out_cap < DISCO_HANDLER_REPLY_MAX → no reply (defensive arg check).
 *   - The reply's src_addr/src_port are zeroed (this commit's choice;
 *     locks the wire shape so a future change to use the DERP sentinel
 *     surfaces here as a test update).
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "disco.h"
#include "disco_handler.h"
#include "crypto/curve25519.h"

/* Deterministic xorshift random — same shape as test_disco.c. The
 * handler calls esp_fill_random for the Pong nonce; the seed here
 * is fixed so the resulting wire bytes are reproducible. */
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
    printf("[%s] FAIL\n", name);
    return 1;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static void make_keypair(const char *seed_label,
                         uint8_t priv[32], uint8_t pub[32])
{
    memset(priv, 0, 32);
    size_t len = strlen(seed_label);
    if (len > 32) len = 32;
    memcpy(priv, seed_label, len);
    curve25519_derive_pub(pub, priv);
}

/* Build a wire-format DISCO Ping sealed from `peer` to `me`. Mirrors
 * what an actual remote magicsock would send through DERP. */
static size_t make_ping_wire(uint8_t *out, size_t out_cap,
                             const uint8_t txid[DISCO_TXID_LEN],
                             const uint8_t peer_priv[32],
                             const uint8_t peer_pub[32],
                             const uint8_t my_pub[32])
{
    disco_ping_t p = {0};
    memcpy(p.txid, txid, DISCO_TXID_LEN);

    uint8_t inner[256];
    size_t  inner_len = disco_encode_ping(inner, sizeof(inner), &p);
    if (inner_len == 0) return 0;

    uint8_t nonce[DISCO_NONCE_LEN];
    for (int i = 0; i < DISCO_NONCE_LEN; i++) nonce[i] = (uint8_t)(0xb0 + i);

    return disco_seal(out, out_cap, inner, inner_len,
                      nonce, peer_pub, my_pub, peer_priv);
}

/* ------------------------------------------------------------------ */
/* Ping → Pong roundtrip                                              */
/* ------------------------------------------------------------------ */

static void test_ping_to_pong(void) {
    uint8_t me_priv[32], me_pub[32];
    uint8_t peer_priv[32], peer_pub[32];
    make_keypair("disco-handler-me",   me_priv,   me_pub);
    make_keypair("disco-handler-peer", peer_priv, peer_pub);

    uint8_t txid[DISCO_TXID_LEN];
    for (int i = 0; i < DISCO_TXID_LEN; i++) txid[i] = (uint8_t)(0x40 + i);

    uint8_t wire[512];
    size_t  wire_len = make_ping_wire(wire, sizeof(wire),
                                      txid, peer_priv, peer_pub, me_pub);
    fails += ok("ping/wire-built", wire_len > 0);

    uint8_t reply[DISCO_HANDLER_REPLY_MAX];
    disco_msg_type_t got_type = (disco_msg_type_t)0xff;
    uint8_t got_peer_pub[DISCO_KEY_LEN] = {0};
    uint8_t got_txid[DISCO_TXID_LEN] = {0};

    size_t reply_len = disco_handle_recv(reply, sizeof(reply),
                                         wire, wire_len,
                                         me_priv, me_pub,
                                         &got_type, got_peer_pub, got_txid);
    fails += ok("ping/reply-emitted", reply_len > 0);
    fails += ok("ping/observed-type-ping", got_type == DISCO_TYPE_PING);
    fails += eq_bytes("ping/peer-disco-pub-extracted",
                      got_peer_pub, peer_pub, DISCO_KEY_LEN);
    fails += eq_bytes("ping/txid-extracted", got_txid, txid, DISCO_TXID_LEN);

    /* The reply must be a valid sealed DISCO frame addressed back to
     * the peer. Open it from the peer's perspective. */
    uint8_t pt[256];
    uint8_t reply_sender_pub[DISCO_KEY_LEN] = {0};
    size_t  pt_len = disco_open(pt, sizeof(pt), reply_sender_pub,
                                reply, reply_len, peer_priv);
    fails += ok("pong/peer-can-decrypt", pt_len > 0);
    fails += eq_bytes("pong/sealed-by-us", reply_sender_pub, me_pub, DISCO_KEY_LEN);

    disco_msg_t parsed;
    fails += ok("pong/parse-ok", disco_parse(pt, pt_len, &parsed) == 0);
    fails += ok("pong/type-pong", parsed.type == DISCO_TYPE_PONG);
    fails += eq_bytes("pong/txid-echoed",
                      parsed.u.pong.txid, txid, DISCO_TXID_LEN);

    /* This commit zeros src_addr/src_port. If a future change starts
     * filling them with a DERP sentinel (127.3.3.40:<region>) this
     * assertion will fail and force an explicit update. */
    uint8_t zero_addr[16] = {0};
    fails += eq_bytes("pong/src-addr-zero", parsed.u.pong.src_addr,
                      zero_addr, 16);
    fails += ok("pong/src-port-zero", parsed.u.pong.src_port == 0);
}

/* ------------------------------------------------------------------ */
/* No-reply paths                                                     */
/* ------------------------------------------------------------------ */

static void test_pong_no_reply(void) {
    uint8_t me_priv[32], me_pub[32];
    uint8_t peer_priv[32], peer_pub[32];
    make_keypair("disco-pong-me",   me_priv,   me_pub);
    make_keypair("disco-pong-peer", peer_priv, peer_pub);

    /* Encode a Pong from peer to us. */
    disco_pong_t pong = {0};
    for (int i = 0; i < DISCO_TXID_LEN; i++) pong.txid[i] = (uint8_t)i;
    uint8_t inner[64];
    size_t inner_len = disco_encode_pong(inner, sizeof(inner), &pong);

    uint8_t nonce[DISCO_NONCE_LEN] = {0};
    for (int i = 0; i < DISCO_NONCE_LEN; i++) nonce[i] = (uint8_t)(0x10 + i);
    uint8_t wire[256];
    size_t wire_len = disco_seal(wire, sizeof(wire), inner, inner_len,
                                 nonce, peer_pub, me_pub, peer_priv);

    uint8_t reply[DISCO_HANDLER_REPLY_MAX];
    disco_msg_type_t got_type = (disco_msg_type_t)0xff;
    uint8_t got_txid[DISCO_TXID_LEN] = {0xff};
    size_t reply_len = disco_handle_recv(reply, sizeof(reply),
                                         wire, wire_len,
                                         me_priv, me_pub,
                                         &got_type, NULL, got_txid);
    fails += ok("pong-in/no-reply", reply_len == 0);
    fails += ok("pong-in/observed-type", got_type == DISCO_TYPE_PONG);
    fails += ok("pong-in/txid-extracted",
                memcmp(got_txid, pong.txid, DISCO_TXID_LEN) == 0);
}

static void test_callmemaybe_no_reply(void) {
    uint8_t me_priv[32], me_pub[32];
    uint8_t peer_priv[32], peer_pub[32];
    make_keypair("disco-cmm-me",   me_priv,   me_pub);
    make_keypair("disco-cmm-peer", peer_priv, peer_pub);

    disco_call_me_maybe_t cmm = {0};
    cmm.n = 1;
    /* IPv4 1.2.3.4:5678 in v4-mapped IPv6 form: ::ffff:1.2.3.4 */
    cmm.endpoints[0].addr[10] = 0xff;
    cmm.endpoints[0].addr[11] = 0xff;
    cmm.endpoints[0].addr[12] = 1;
    cmm.endpoints[0].addr[13] = 2;
    cmm.endpoints[0].addr[14] = 3;
    cmm.endpoints[0].addr[15] = 4;
    cmm.endpoints[0].port = 5678;

    uint8_t inner[256];
    size_t inner_len = disco_encode_call_me_maybe(inner, sizeof(inner), &cmm);

    uint8_t nonce[DISCO_NONCE_LEN] = {0};
    for (int i = 0; i < DISCO_NONCE_LEN; i++) nonce[i] = (uint8_t)(0x20 + i);
    uint8_t wire[256];
    size_t wire_len = disco_seal(wire, sizeof(wire), inner, inner_len,
                                 nonce, peer_pub, me_pub, peer_priv);

    uint8_t reply[DISCO_HANDLER_REPLY_MAX];
    disco_msg_type_t got_type = (disco_msg_type_t)0xff;
    size_t reply_len = disco_handle_recv(reply, sizeof(reply),
                                         wire, wire_len,
                                         me_priv, me_pub,
                                         &got_type, NULL, NULL);
    fails += ok("cmm-in/no-reply", reply_len == 0);
    fails += ok("cmm-in/observed-type", got_type == DISCO_TYPE_CALLMEMAYBE);
}

static void test_non_disco_bytes(void) {
    uint8_t me_priv[32], me_pub[32];
    make_keypair("disco-nodisco-me", me_priv, me_pub);

    /* Random WG-like bytes — no DISCO magic. The handler must short-
     * circuit before any AEAD work so this is cheap on the hot path. */
    uint8_t wire[200];
    for (size_t i = 0; i < sizeof(wire); i++) wire[i] = (uint8_t)(i ^ 0x5a);

    uint8_t reply[DISCO_HANDLER_REPLY_MAX];
    disco_msg_type_t got_type = (disco_msg_type_t)0xff;
    size_t reply_len = disco_handle_recv(reply, sizeof(reply),
                                         wire, sizeof(wire),
                                         me_priv, me_pub,
                                         &got_type, NULL, NULL);
    fails += ok("non-disco/no-reply", reply_len == 0);
    /* out_type stays untouched on the magic-fail path. */
    fails += ok("non-disco/type-untouched", got_type == (disco_msg_type_t)0xff);
}

static void test_wrong_recipient(void) {
    uint8_t me_priv[32], me_pub[32];
    uint8_t peer_priv[32], peer_pub[32];
    uint8_t other_priv[32], other_pub[32];
    make_keypair("disco-wrong-me",    me_priv,    me_pub);
    make_keypair("disco-wrong-peer",  peer_priv,  peer_pub);
    make_keypair("disco-wrong-other", other_priv, other_pub);

    /* peer seals a Ping addressed to OTHER, not us. */
    uint8_t txid[DISCO_TXID_LEN];
    for (int i = 0; i < DISCO_TXID_LEN; i++) txid[i] = (uint8_t)(0x77 + i);
    uint8_t wire[256];
    size_t wire_len = make_ping_wire(wire, sizeof(wire), txid,
                                     peer_priv, peer_pub, other_pub);

    uint8_t reply[DISCO_HANDLER_REPLY_MAX];
    size_t reply_len = disco_handle_recv(reply, sizeof(reply),
                                         wire, wire_len,
                                         me_priv, me_pub,
                                         NULL, NULL, NULL);
    fails += ok("wrong-recipient/no-reply", reply_len == 0);
}

static void test_tampered_ciphertext(void) {
    uint8_t me_priv[32], me_pub[32];
    uint8_t peer_priv[32], peer_pub[32];
    make_keypair("disco-tamper-me",   me_priv,   me_pub);
    make_keypair("disco-tamper-peer", peer_priv, peer_pub);

    uint8_t txid[DISCO_TXID_LEN];
    for (int i = 0; i < DISCO_TXID_LEN; i++) txid[i] = (uint8_t)(0x33 + i);
    uint8_t wire[256];
    size_t wire_len = make_ping_wire(wire, sizeof(wire), txid,
                                     peer_priv, peer_pub, me_pub);
    /* Flip a byte deep in the box payload (past magic + sender_pub +
     * nonce = 6 + 32 + 24 = 62). */
    wire[80] ^= 0x01;

    uint8_t reply[DISCO_HANDLER_REPLY_MAX];
    size_t reply_len = disco_handle_recv(reply, sizeof(reply),
                                         wire, wire_len,
                                         me_priv, me_pub,
                                         NULL, NULL, NULL);
    fails += ok("tampered/no-reply", reply_len == 0);
}

static void test_bad_args(void) {
    uint8_t me_priv[32], me_pub[32];
    make_keypair("disco-bad-me", me_priv, me_pub);
    uint8_t wire[200];
    uint8_t reply[DISCO_HANDLER_REPLY_MAX];

    fails += ok("bad/null-out-reply",
        disco_handle_recv(NULL, sizeof(reply), wire, sizeof(wire),
                          me_priv, me_pub, NULL, NULL, NULL) == 0);
    fails += ok("bad/null-frame",
        disco_handle_recv(reply, sizeof(reply), NULL, sizeof(wire),
                          me_priv, me_pub, NULL, NULL, NULL) == 0);
    fails += ok("bad/null-priv",
        disco_handle_recv(reply, sizeof(reply), wire, sizeof(wire),
                          NULL, me_pub, NULL, NULL, NULL) == 0);
    fails += ok("bad/cap-too-small",
        disco_handle_recv(reply, DISCO_HANDLER_REPLY_MAX - 1,
                          wire, sizeof(wire),
                          me_priv, me_pub, NULL, NULL, NULL) == 0);
}

int main(void) {
    test_ping_to_pong();
    test_pong_no_reply();
    test_callmemaybe_no_reply();
    test_non_disco_bytes();
    test_wrong_recipient();
    test_tampered_ciphertext();
    test_bad_args();

    if (fails) {
        printf("\n[FAIL] %d disco_handler assertion(s) failed\n", fails);
        return 1;
    }
    printf("\n[PASS] all disco_handler assertions passed\n");
    return 0;
}
