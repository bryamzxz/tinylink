/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for the DISCO codec (disco.c). Covers:
 *   - Inner-payload encode + parse roundtrip for Ping, Pong, CallMeMaybe.
 *   - Optional Ping NodeKey + PMTU padding handling.
 *   - Wire frame seal + open with two real Curve25519 keypairs.
 *   - Tamper detection (corrupt one byte → open must fail).
 *   - Wrong-recipient rejection.
 *   - Magic-prefix and short-frame rejection.
 *   - Out-cap underflow protection on encoders.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "disco.h"
#include "crypto/curve25519.h"
#include "crypto/nacl_box.h"

/* Stub esp_fill_random — deterministic xorshift, mirrors the pattern
 * used by test_wg_handshake.c. We never test cryptographic randomness
 * here; we only need reproducible keypairs and nonces. */
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

static void hexdump(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

static int ok(const char *name, int condition) {
    if (condition) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL\n", name);
    return 1;
}

static int eq_bytes(const char *name, const uint8_t *a, const uint8_t *b, size_t n) {
    if (memcmp(a, b, n) == 0) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL\n  got:  ", name); hexdump(a, n); printf("\n  want: ");
    hexdump(b, n); printf("\n");
    return 1;
}

/* ------------------------------------------------------------------ */
/* Inner-encoder roundtrips                                           */
/* ------------------------------------------------------------------ */

static void test_ping_basic(void) {
    disco_ping_t in = {0};
    for (int i = 0; i < DISCO_TXID_LEN; i++) in.txid[i] = (uint8_t)(0xa0 + i);

    uint8_t buf[256];
    size_t n = disco_encode_ping(buf, sizeof(buf), &in);
    fails += ok("ping/encode-len-no-key",
                n == DISCO_INNER_HDR_LEN + DISCO_TXID_LEN);
    fails += ok("ping/encode-type-byte", buf[0] == DISCO_TYPE_PING);
    fails += ok("ping/encode-ver-byte", buf[1] == 0x00);

    disco_msg_t parsed;
    fails += ok("ping/parse-ok", disco_parse(buf, n, &parsed) == 0);
    fails += ok("ping/parse-type", parsed.type == DISCO_TYPE_PING);
    fails += eq_bytes("ping/parse-txid", parsed.u.ping.txid, in.txid, DISCO_TXID_LEN);
    fails += ok("ping/parse-no-nodekey", parsed.u.ping.has_node_key == false);
    fails += ok("ping/parse-no-padding", parsed.u.ping.padding == 0);
}

static void test_ping_with_nodekey_and_padding(void) {
    disco_ping_t in = {0};
    for (int i = 0; i < DISCO_TXID_LEN; i++) in.txid[i] = (uint8_t)(i * 3);
    for (int i = 0; i < DISCO_NODEKEY_LEN; i++) in.node_key[i] = (uint8_t)(0xc0 ^ i);
    in.has_node_key = true;
    in.padding      = 19;

    uint8_t buf[256];
    size_t n = disco_encode_ping(buf, sizeof(buf), &in);
    fails += ok("ping+nk+pad/len",
                n == DISCO_INNER_HDR_LEN + DISCO_TXID_LEN + DISCO_NODEKEY_LEN + 19);

    /* Padding must be all zero. */
    int padding_ok = 1;
    for (size_t i = 0; i < 19; i++) {
        if (buf[n - 19 + i] != 0) padding_ok = 0;
    }
    fails += ok("ping+nk+pad/zero-padding", padding_ok);

    disco_msg_t parsed;
    fails += ok("ping+nk+pad/parse", disco_parse(buf, n, &parsed) == 0);
    fails += ok("ping+nk+pad/has-key", parsed.u.ping.has_node_key);
    fails += eq_bytes("ping+nk+pad/key", parsed.u.ping.node_key, in.node_key,
                      DISCO_NODEKEY_LEN);
    fails += ok("ping+nk+pad/padding-count", parsed.u.ping.padding == 19);
}

static void test_pong_roundtrip(void) {
    disco_pong_t in = {0};
    for (int i = 0; i < DISCO_TXID_LEN; i++) in.txid[i] = (uint8_t)(0x10 + i);
    /* IPv4 192.0.2.5 in IPv4-mapped IPv6 form: ::ffff:c000:0205 */
    in.src_addr[10] = 0xff; in.src_addr[11] = 0xff;
    in.src_addr[12] = 0xc0; in.src_addr[13] = 0x00;
    in.src_addr[14] = 0x02; in.src_addr[15] = 0x05;
    in.src_port = 41641;

    uint8_t buf[64];
    size_t n = disco_encode_pong(buf, sizeof(buf), &in);
    fails += ok("pong/len", n == DISCO_INNER_HDR_LEN + DISCO_TXID_LEN + 16 + 2);
    fails += ok("pong/type-byte", buf[0] == DISCO_TYPE_PONG);
    /* Big-endian port encoding: 41641 = 0xa2a9 → bytes a2 a9 */
    fails += ok("pong/port-be-hi", buf[n - 2] == 0xa2);
    fails += ok("pong/port-be-lo", buf[n - 1] == 0xa9);

    disco_msg_t parsed;
    fails += ok("pong/parse-ok", disco_parse(buf, n, &parsed) == 0);
    fails += eq_bytes("pong/parse-txid", parsed.u.pong.txid, in.txid, DISCO_TXID_LEN);
    fails += eq_bytes("pong/parse-addr", parsed.u.pong.src_addr, in.src_addr, 16);
    fails += ok("pong/parse-port", parsed.u.pong.src_port == 41641);
}

static void test_call_me_maybe_variants(void) {
    /* Empty CallMeMaybe — zero endpoints. */
    {
        disco_call_me_maybe_t in = {0};
        uint8_t buf[64];
        size_t n = disco_encode_call_me_maybe(buf, sizeof(buf), &in);
        fails += ok("cmm/0-len", n == DISCO_INNER_HDR_LEN);

        disco_msg_t parsed;
        fails += ok("cmm/0-parse", disco_parse(buf, n, &parsed) == 0);
        fails += ok("cmm/0-count", parsed.u.cmm.n == 0);
    }
    /* Three endpoints. */
    {
        disco_call_me_maybe_t in = {0};
        in.n = 3;
        for (size_t i = 0; i < 3; i++) {
            for (int j = 0; j < 16; j++) in.endpoints[i].addr[j] = (uint8_t)((i+1) * 10 + j);
            in.endpoints[i].port = (uint16_t)(40000 + i);
        }
        uint8_t buf[128];
        size_t n = disco_encode_call_me_maybe(buf, sizeof(buf), &in);
        fails += ok("cmm/3-len", n == DISCO_INNER_HDR_LEN + DISCO_AP_LEN * 3);

        disco_msg_t parsed;
        fails += ok("cmm/3-parse", disco_parse(buf, n, &parsed) == 0);
        fails += ok("cmm/3-count", parsed.u.cmm.n == 3);
        for (size_t i = 0; i < 3; i++) {
            char name[32];
            snprintf(name, sizeof(name), "cmm/3-ep%zu-addr", i);
            fails += eq_bytes(name, parsed.u.cmm.endpoints[i].addr,
                              in.endpoints[i].addr, 16);
            snprintf(name, sizeof(name), "cmm/3-ep%zu-port", i);
            fails += ok(name, parsed.u.cmm.endpoints[i].port == in.endpoints[i].port);
        }
    }
    /* Misaligned remainder (rem % 18 != 0) — must error. */
    {
        uint8_t buf[DISCO_INNER_HDR_LEN + 17] = {0};
        buf[0] = DISCO_TYPE_CALLMEMAYBE;
        disco_msg_t parsed;
        fails += ok("cmm/misaligned-rejects",
                    disco_parse(buf, sizeof(buf), &parsed) == -1);
    }
}

static void test_encoder_capacity_underflow(void) {
    disco_ping_t pin = {0};
    fails += ok("encode/ping-tight-zero",
                disco_encode_ping(NULL, 0, &pin) == 0);
    uint8_t small[5];
    fails += ok("encode/ping-too-small",
                disco_encode_ping(small, sizeof(small), &pin) == 0);

    disco_pong_t po = {0};
    uint8_t small2[10];
    fails += ok("encode/pong-too-small",
                disco_encode_pong(small2, sizeof(small2), &po) == 0);

    disco_call_me_maybe_t c = {0}; c.n = 4;
    uint8_t small3[20];
    fails += ok("encode/cmm-too-small",
                disco_encode_call_me_maybe(small3, sizeof(small3), &c) == 0);
}

/* ------------------------------------------------------------------ */
/* Frame seal + open                                                  */
/* ------------------------------------------------------------------ */

static void test_seal_open_ping(void) {
    /* Two real keypairs. */
    uint8_t alice_priv[32], alice_pub[32];
    uint8_t bob_priv[32],   bob_pub[32];
    fails += ok("seal/alice-keygen", curve25519_keypair(alice_priv, alice_pub) == 0);
    fails += ok("seal/bob-keygen",   curve25519_keypair(bob_priv,   bob_pub)   == 0);

    /* Build a Ping inner. */
    disco_ping_t pi = {0};
    for (int i = 0; i < DISCO_TXID_LEN; i++) pi.txid[i] = (uint8_t)(0xe0 + i);
    pi.has_node_key = true;
    for (int i = 0; i < DISCO_NODEKEY_LEN; i++) pi.node_key[i] = (uint8_t)(i * 7);

    uint8_t pt[128];
    size_t plen = disco_encode_ping(pt, sizeof(pt), &pi);
    fails += ok("seal/ping-encoded", plen == DISCO_INNER_HDR_LEN + DISCO_TXID_LEN + DISCO_NODEKEY_LEN);

    /* Random nonce. */
    uint8_t nonce[DISCO_NONCE_LEN];
    esp_fill_random(nonce, sizeof(nonce));

    /* Alice → Bob. */
    uint8_t wire[256];
    size_t wlen = disco_seal(wire, sizeof(wire), pt, plen, nonce,
                             alice_pub, bob_pub, alice_priv);
    fails += ok("seal/wire-len", wlen == DISCO_OVERHEAD + plen);
    fails += ok("seal/has-magic", memcmp(wire, DISCO_MAGIC, DISCO_MAGIC_LEN) == 0);
    fails += eq_bytes("seal/sender-pub-in-header",
                      wire + DISCO_MAGIC_LEN, alice_pub, DISCO_KEY_LEN);
    fails += ok("seal/looks-like", disco_looks_like(wire, wlen));

    /* Bob opens. */
    uint8_t pt_out[128];
    uint8_t sender_out[DISCO_KEY_LEN];
    size_t got = disco_open(pt_out, sizeof(pt_out), sender_out,
                            wire, wlen, bob_priv);
    fails += ok("open/plaintext-len", got == plen);
    fails += eq_bytes("open/plaintext-bytes", pt_out, pt, plen);
    fails += eq_bytes("open/sender-pub-recovered", sender_out, alice_pub, DISCO_KEY_LEN);

    /* And parse the recovered plaintext. */
    disco_msg_t parsed;
    fails += ok("open/parse", disco_parse(pt_out, got, &parsed) == 0);
    fails += ok("open/parse-type", parsed.type == DISCO_TYPE_PING);
    fails += eq_bytes("open/parse-txid", parsed.u.ping.txid, pi.txid, DISCO_TXID_LEN);
    fails += eq_bytes("open/parse-nodekey", parsed.u.ping.node_key, pi.node_key,
                      DISCO_NODEKEY_LEN);
}

static void test_seal_open_pong(void) {
    uint8_t alice_priv[32], alice_pub[32];
    uint8_t bob_priv[32],   bob_pub[32];
    curve25519_keypair(alice_priv, alice_pub);
    curve25519_keypair(bob_priv,   bob_pub);

    disco_pong_t po = {0};
    for (int i = 0; i < DISCO_TXID_LEN; i++) po.txid[i] = (uint8_t)(0x55 ^ i);
    po.src_addr[10] = 0xff; po.src_addr[11] = 0xff;
    po.src_addr[12] = 198;  po.src_addr[13] = 51;
    po.src_addr[14] = 100;  po.src_addr[15] = 7;
    po.src_port = 12345;

    uint8_t pt[64];
    size_t plen = disco_encode_pong(pt, sizeof(pt), &po);

    uint8_t nonce[DISCO_NONCE_LEN]; esp_fill_random(nonce, sizeof(nonce));
    uint8_t wire[256];
    size_t wlen = disco_seal(wire, sizeof(wire), pt, plen, nonce,
                             alice_pub, bob_pub, alice_priv);
    fails += ok("pong-seal/len", wlen == DISCO_OVERHEAD + plen);

    uint8_t pt_out[64], sender_out[32];
    size_t got = disco_open(pt_out, sizeof(pt_out), sender_out,
                            wire, wlen, bob_priv);
    fails += ok("pong-open/len", got == plen);

    disco_msg_t parsed;
    fails += ok("pong-open/parse", disco_parse(pt_out, got, &parsed) == 0);
    fails += ok("pong-open/parse-port", parsed.u.pong.src_port == 12345);
    fails += eq_bytes("pong-open/parse-addr", parsed.u.pong.src_addr,
                      po.src_addr, 16);
}

/* ------------------------------------------------------------------ */
/* Tamper / wrong-recipient / short-frame rejection                   */
/* ------------------------------------------------------------------ */

static void test_tamper_detection(void) {
    uint8_t alice_priv[32], alice_pub[32];
    uint8_t bob_priv[32],   bob_pub[32];
    curve25519_keypair(alice_priv, alice_pub);
    curve25519_keypair(bob_priv,   bob_pub);

    disco_pong_t po = {0};
    for (int i = 0; i < DISCO_TXID_LEN; i++) po.txid[i] = (uint8_t)i;
    uint8_t pt[64];
    size_t plen = disco_encode_pong(pt, sizeof(pt), &po);

    uint8_t nonce[DISCO_NONCE_LEN]; esp_fill_random(nonce, sizeof(nonce));
    uint8_t wire[256];
    size_t wlen = disco_seal(wire, sizeof(wire), pt, plen, nonce,
                             alice_pub, bob_pub, alice_priv);

    /* Flip one byte in the ciphertext region. Open must reject. */
    uint8_t bad[256]; memcpy(bad, wire, wlen);
    bad[DISCO_OVERHEAD + 5] ^= 0x01;   /* index past the AEAD tag, in plaintext bytes */
    uint8_t pt_out[64], sender_out[32];
    fails += ok("tamper/ct-flip-rejects",
                disco_open(pt_out, sizeof(pt_out), sender_out,
                           bad, wlen, bob_priv) == 0);

    /* Flip a byte inside the AEAD tag — also rejects. */
    memcpy(bad, wire, wlen);
    bad[DISCO_MAGIC_LEN + DISCO_KEY_LEN + DISCO_NONCE_LEN] ^= 0x80;
    fails += ok("tamper/tag-flip-rejects",
                disco_open(pt_out, sizeof(pt_out), sender_out,
                           bad, wlen, bob_priv) == 0);

    /* Flip the magic — rejects (bad header). */
    memcpy(bad, wire, wlen);
    bad[0] ^= 0xFF;
    fails += ok("tamper/magic-flip-rejects",
                disco_open(pt_out, sizeof(pt_out), sender_out,
                           bad, wlen, bob_priv) == 0);
}

static void test_wrong_recipient(void) {
    uint8_t alice_priv[32], alice_pub[32];
    uint8_t bob_priv[32],   bob_pub[32];
    uint8_t carol_priv[32], carol_pub[32];
    curve25519_keypair(alice_priv, alice_pub);
    curve25519_keypair(bob_priv,   bob_pub);
    curve25519_keypair(carol_priv, carol_pub);

    disco_pong_t po = {0};
    uint8_t pt[64]; size_t plen = disco_encode_pong(pt, sizeof(pt), &po);

    uint8_t nonce[DISCO_NONCE_LEN]; esp_fill_random(nonce, sizeof(nonce));
    uint8_t wire[256];
    size_t wlen = disco_seal(wire, sizeof(wire), pt, plen, nonce,
                             alice_pub, bob_pub, alice_priv);

    /* Carol can't decrypt a frame addressed to Bob. */
    uint8_t pt_out[64], sender_out[32];
    fails += ok("wrong-recipient/rejects",
                disco_open(pt_out, sizeof(pt_out), sender_out,
                           wire, wlen, carol_priv) == 0);
    /* Bob still can. */
    fails += ok("wrong-recipient/bob-still-opens",
                disco_open(pt_out, sizeof(pt_out), sender_out,
                           wire, wlen, bob_priv) == plen);

    (void)carol_pub;
}

static void test_short_and_bad_magic(void) {
    uint8_t key[32]; esp_fill_random(key, 32);
    uint8_t out[64], sender[32];

    /* Too short for header alone. */
    uint8_t small[10] = {0};
    memcpy(small, DISCO_MAGIC, DISCO_MAGIC_LEN);
    fails += ok("short/header-only",
                disco_open(out, sizeof(out), sender, small, sizeof(small), key) == 0);
    fails += ok("short/looks-like-false",
                disco_looks_like(small, sizeof(small)) == false);

    /* Right-sized prefix but wrong magic. */
    uint8_t junk[DISCO_OVERHEAD + 2] = {0};
    junk[0] = 0x99;
    fails += ok("magic/bad-rejects",
                disco_open(out, sizeof(out), sender, junk, sizeof(junk), key) == 0);
}

static void test_call_me_maybe_seal_open(void) {
    uint8_t alice_priv[32], alice_pub[32];
    uint8_t bob_priv[32],   bob_pub[32];
    curve25519_keypair(alice_priv, alice_pub);
    curve25519_keypair(bob_priv,   bob_pub);

    disco_call_me_maybe_t cmm = {0};
    cmm.n = 2;
    /* IPv6 endpoints. */
    for (int j = 0; j < 16; j++) cmm.endpoints[0].addr[j] = (uint8_t)(0x20 + j);
    cmm.endpoints[0].port = 41641;
    for (int j = 0; j < 16; j++) cmm.endpoints[1].addr[j] = (uint8_t)(0x40 ^ j);
    cmm.endpoints[1].port = 51820;

    uint8_t pt[128];
    size_t plen = disco_encode_call_me_maybe(pt, sizeof(pt), &cmm);

    uint8_t nonce[DISCO_NONCE_LEN]; esp_fill_random(nonce, sizeof(nonce));
    uint8_t wire[256];
    size_t wlen = disco_seal(wire, sizeof(wire), pt, plen, nonce,
                             alice_pub, bob_pub, alice_priv);

    uint8_t pt_out[128], sender[32];
    size_t got = disco_open(pt_out, sizeof(pt_out), sender, wire, wlen, bob_priv);
    fails += ok("cmm-seal-open/len", got == plen);

    disco_msg_t parsed;
    fails += ok("cmm-seal-open/parse", disco_parse(pt_out, got, &parsed) == 0);
    fails += ok("cmm-seal-open/n", parsed.u.cmm.n == 2);
    fails += ok("cmm-seal-open/port0", parsed.u.cmm.endpoints[0].port == 41641);
    fails += ok("cmm-seal-open/port1", parsed.u.cmm.endpoints[1].port == 51820);
    fails += eq_bytes("cmm-seal-open/addr0", parsed.u.cmm.endpoints[0].addr,
                      cmm.endpoints[0].addr, 16);
}

/* Equivalence test: disco_open_with_shared on a precomputed K must
 * produce the same plaintext + sender pubkey as disco_open with the
 * fresh-DH path. Locks in the refactor so a future change to
 * nacl_box_open_after_shared cannot diverge from nacl_box_open. */
static void test_open_with_shared(void) {
    uint8_t alice_priv[32], alice_pub[32];
    uint8_t bob_priv[32],   bob_pub[32];
    fails += ok("shared/alice-keygen",
                curve25519_keypair(alice_priv, alice_pub) == 0);
    fails += ok("shared/bob-keygen",
                curve25519_keypair(bob_priv, bob_pub) == 0);

    /* Encode a Ping inner. */
    disco_ping_t pi = {0};
    for (int i = 0; i < DISCO_TXID_LEN; i++) pi.txid[i] = (uint8_t)(0xa0 + i);
    uint8_t pt[64];
    size_t plen = disco_encode_ping(pt, sizeof(pt), &pi);

    uint8_t nonce[DISCO_NONCE_LEN];
    for (int i = 0; i < DISCO_NONCE_LEN; i++) nonce[i] = (uint8_t)(0x77 + i);

    uint8_t wire[256];
    size_t wlen = disco_seal(wire, sizeof(wire), pt, plen, nonce,
                             alice_pub, bob_pub, alice_priv);
    fails += ok("shared/seal-ok", wlen > 0);

    /* Compute K = HSalsa20(X25519(bob_priv, alice_pub), 0^16). */
    uint8_t k[32];
    fails += ok("shared/compute-ok",
                nacl_box_compute_shared(k, alice_pub, bob_priv) == 0);

    /* Open with K vs open with priv must agree. */
    uint8_t pt1[64], sender1[32];
    uint8_t pt2[64], sender2[32];
    size_t got1 = disco_open(pt1, sizeof(pt1), sender1,
                             wire, wlen, bob_priv);
    size_t got2 = disco_open_with_shared(pt2, sizeof(pt2), sender2,
                                         wire, wlen, k);
    fails += ok("shared/lens-equal",     got1 == got2 && got1 == plen);
    fails += eq_bytes("shared/pt-equal", pt1, pt2, plen);
    fails += eq_bytes("shared/sender-equal",
                      sender1, sender2, DISCO_KEY_LEN);
    fails += eq_bytes("shared/pt-matches-orig", pt1, pt, plen);

    /* Tamper: flip one byte of the ciphertext. Both opens must fail. */
    wire[wlen - 1] ^= 0x01;
    got1 = disco_open(pt1, sizeof(pt1), sender1, wire, wlen, bob_priv);
    got2 = disco_open_with_shared(pt2, sizeof(pt2), sender2, wire, wlen, k);
    fails += ok("shared/tamper-disco_open-fail",         got1 == 0);
    fails += ok("shared/tamper-disco_open_with_shared-fail", got2 == 0);
}

int main(void) {
    test_ping_basic();
    test_ping_with_nodekey_and_padding();
    test_pong_roundtrip();
    test_call_me_maybe_variants();
    test_encoder_capacity_underflow();
    test_seal_open_ping();
    test_seal_open_pong();
    test_tamper_detection();
    test_wrong_recipient();
    test_short_and_bad_magic();
    test_call_me_maybe_seal_open();
    test_open_with_shared();

    if (fails == 0) printf("\nALL OK\n");
    else printf("\n%d FAIL(S)\n", fails);
    return fails ? 1 : 0;
}
