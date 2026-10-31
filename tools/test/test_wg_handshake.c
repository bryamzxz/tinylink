/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for WG handshake initiator-side construction. Step 3a
 * coverage:
 *
 *   1. Initial constants (INITIAL_CHAIN_KEY, INITIAL_HASH) computed
 *      lazily by wg_proto.c match the formulas from the WG whitepaper
 *      (Algorithm 1) when computed end-to-end via the same BLAKE2s.
 *   2. mac1_key derivation matches BLAKE2s(LABEL_MAC1 || peer_pub).
 *   3. wg_handshake_create_initiation produces a structurally valid
 *      148-byte MessageInitiation: type, reserved, sender_index,
 *      mac2-zero, ephemeral matches state, and the encrypted fields /
 *      mac1 are non-zero (with overwhelming probability).
 *
 *   4. Per-peer cache (round 1.3.2, B11): an INIT built on a cached
 *      state (no static-static DH, no mac1-key BLAKE2s) is byte-identical
 *      to one built from scratch, for a fixed ephemeral (the xorshift
 *      seed below) and timestamp (recovered by the simulated responder);
 *      identity changes recompute the cache; a scrubbed state refuses
 *      responses.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wg_proto.h"
#include "wg_handshake.h"
#include "wg_path.h"

#include "crypto/blake2s.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/curve25519.h"
#include "crypto/hkdf_blake2s.h"

/* Host-side stub for esp_fill_random. curve25519.c uses it internally
 * for ephemeral keygen on-target; off-target we ship our own. A
 * deterministic xorshift gives reproducible test runs but advances on
 * each call, so two consecutive curve25519_keypair() calls still
 * produce distinct keys (which the test asserts). */
static uint64_t s_rng_state = 0x9E3779B97F4A7C15ULL;
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
static int check(const char *name, const uint8_t *got, const uint8_t *want, size_t n) {
    if (memcmp(got, want, n) == 0) {
        printf("[%s] OK\n", name);
        return 0;
    }
    printf("[%s] FAIL\n  got:  ", name); hexdump(got, n); printf("\n  want: ");
    hexdump(want, n); printf("\n");
    return 1;
}
static int is_all_zero(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) if (b[i]) return 0;
    return 1;
}

static void test_initial_constants(void) {
    /* Compute INITIAL_CHAIN_KEY independently and compare to the
     * cached one from wg_proto.c. */
    uint8_t expected_ck[32];
    blake2s_state st;
    blake2s_init(&st, 32);
    blake2s_update(&st, WG_CONSTRUCTION, sizeof(WG_CONSTRUCTION));
    blake2s_final(&st, expected_ck, 32);
    fails += check("initial_chain_key-vs-blake2s",
                   wg_initial_chain_key(), expected_ck, 32);

    /* Compute INITIAL_HASH independently. */
    uint8_t expected_h[32];
    blake2s_init(&st, 32);
    blake2s_update(&st, expected_ck, 32);
    blake2s_update(&st, WG_IDENTIFIER, sizeof(WG_IDENTIFIER));
    blake2s_final(&st, expected_h, 32);
    fails += check("initial_hash-vs-blake2s",
                   wg_initial_hash(), expected_h, 32);

    /* Idempotency: second call returns the same pointer (or at least
     * the same bytes — we don't promise pointer identity). */
    fails += check("initial_chain_key-idempotent",
                   wg_initial_chain_key(), expected_ck, 32);
}

static void test_mac1_key(void) {
    /* Pick a fixed peer pub. */
    uint8_t peer_pub[32];
    for (int i = 0; i < 32; i++) peer_pub[i] = (uint8_t)(i * 11 + 5);

    uint8_t expected[32];
    blake2s_state st;
    blake2s_init(&st, 32);
    blake2s_update(&st, WG_LABEL_MAC1, sizeof(WG_LABEL_MAC1));
    blake2s_update(&st, peer_pub, 32);
    blake2s_final(&st, expected, 32);

    uint8_t got[32];
    wg_mac1_key(got, peer_pub);
    fails += check("mac1_key-vs-blake2s", got, expected, 32);
}

static void test_create_initiation_shape(void) {
    /* Generate a real X25519 keypair for the local identity (any valid
     * pair; the test doesn't care which). */
    uint8_t local_priv[32], local_pub[32];
    if (curve25519_keypair(local_priv, local_pub) != 0) {
        printf("[init/keypair-local] FAIL: keypair returned non-zero\n");
        fails++;
        return;
    }
    /* Same for the peer. */
    uint8_t peer_priv[32], peer_pub[32];
    if (curve25519_keypair(peer_priv, peer_pub) != 0) {
        printf("[init/keypair-peer] FAIL\n");
        fails++;
        return;
    }
    uint8_t psk[32] = {0};

    struct wg_handshake_state st;
    if (wg_handshake_init(&st, local_priv, local_pub, peer_pub, psk) != 0) {
        printf("[init/handshake-init] FAIL\n");
        fails++;
        return;
    }

    struct wg_msg_initiation msg;
    const uint32_t test_index = 0xDEADBEEF;
    if (wg_handshake_create_initiation(&st, test_index, &msg) != 0) {
        printf("[init/create-initiation] FAIL: returned non-zero\n");
        fails++;
        return;
    }

    /* Header sanity. */
    if (msg.message_type != WG_MSG_INITIATION) {
        printf("[init/message-type] FAIL: %u != 1\n", msg.message_type); fails++;
    } else { printf("[init/message-type] OK\n"); }

    if (msg.reserved[0] || msg.reserved[1] || msg.reserved[2]) {
        printf("[init/reserved-zero] FAIL\n"); fails++;
    } else { printf("[init/reserved-zero] OK\n"); }

    if (msg.sender_index != test_index) {
        printf("[init/sender-index] FAIL: %x != %x\n", msg.sender_index, test_index);
        fails++;
    } else { printf("[init/sender-index] OK\n"); }

    /* The state's local_index field should match what we passed. */
    if (st.local_index != test_index) {
        printf("[init/state-local-index] FAIL\n"); fails++;
    } else { printf("[init/state-local-index] OK\n"); }

    /* The state's ephemeral_pub should match what landed in the message. */
    if (memcmp(msg.ephemeral, st.ephemeral_pub, 32) != 0) {
        printf("[init/ephemeral-mirror] FAIL\n"); fails++;
    } else { printf("[init/ephemeral-mirror] OK\n"); }

    /* mac2 must be exactly zero. */
    if (!is_all_zero(msg.mac2, sizeof(msg.mac2))) {
        printf("[init/mac2-zero] FAIL\n"); fails++;
    } else { printf("[init/mac2-zero] OK\n"); }

    /* These fields will be all-zero only with negligible probability
     * (random ephemeral, AEAD output, keyed BLAKE2s). If any are zero,
     * something is wrong. */
    if (is_all_zero(msg.ephemeral, sizeof(msg.ephemeral))) {
        printf("[init/ephemeral-nonzero] FAIL\n"); fails++;
    } else { printf("[init/ephemeral-nonzero] OK\n"); }

    if (is_all_zero(msg.encrypted_static, sizeof(msg.encrypted_static))) {
        printf("[init/encrypted-static-nonzero] FAIL\n"); fails++;
    } else { printf("[init/encrypted-static-nonzero] OK\n"); }

    if (is_all_zero(msg.encrypted_timestamp, sizeof(msg.encrypted_timestamp))) {
        printf("[init/encrypted-timestamp-nonzero] FAIL\n"); fails++;
    } else { printf("[init/encrypted-timestamp-nonzero] OK\n"); }

    if (is_all_zero(msg.mac1, sizeof(msg.mac1))) {
        printf("[init/mac1-nonzero] FAIL\n"); fails++;
    } else { printf("[init/mac1-nonzero] OK\n"); }

    /* Two consecutive initiations on the same state must produce
     * distinct messages: distinct ephemerals → distinct
     * encrypted_static / encrypted_timestamp / mac1. */
    struct wg_msg_initiation msg2;
    if (wg_handshake_create_initiation(&st, test_index + 1, &msg2) != 0) {
        printf("[init/second-create] FAIL\n"); fails++; return;
    }
    if (memcmp(msg.ephemeral, msg2.ephemeral, 32) == 0) {
        printf("[init/ephemeral-distinct] FAIL\n"); fails++;
    } else { printf("[init/ephemeral-distinct] OK\n"); }
    if (memcmp(msg.encrypted_static, msg2.encrypted_static,
               sizeof(msg.encrypted_static)) == 0) {
        printf("[init/encrypted-static-distinct] FAIL\n"); fails++;
    } else { printf("[init/encrypted-static-distinct] OK\n"); }

    /* mac1 over msg with the wrong key must NOT match — sanity check
     * that mac1_key isn't being ignored. */
    uint8_t wrong_peer_pub[32];
    for (int i = 0; i < 32; i++) wrong_peer_pub[i] = peer_pub[i] ^ 0xAA;
    uint8_t wrong_key[32];
    wg_mac1_key(wrong_key, wrong_peer_pub);
    uint8_t bogus_mac[16];
    /* Recompute mac1 area length using offsetof would require header;
     * the field starts at byte 116 of a 148-byte msg, so 116 is the
     * span. Hardcode it here. */
    wg_keyed_mac16(bogus_mac, wrong_key, (const uint8_t *)&msg, 116);
    if (memcmp(bogus_mac, msg.mac1, 16) == 0) {
        printf("[init/mac1-key-sensitive] FAIL\n"); fails++;
    } else { printf("[init/mac1-key-sensitive] OK\n"); }

    wg_handshake_scrub(&st);
}

/* --- Simulated responder for end-to-end tests --------------------- */

/* Replays the responder side of Noise IKpsk2 starting from a received
 * MessageInitiation, so we can validate that the initiator's processing
 * of the resulting MessageResponse derives matching transport keys.
 * Roughly mirrors WireGuard whitepaper §5.4.4. Test-only code. */
struct sim_responder {
    /* Identity. */
    uint8_t  static_priv[32];
    uint8_t  static_pub[32];

    /* Outputs after process_initiation + create_response. */
    uint8_t  initiator_static_pub_recovered[32];
    uint8_t  timestamp_recovered[WG_TAI64N_LEN];
    uint32_t remote_sender_index;
    uint8_t  send_key[32];   /* responder-side: encrypts resp→init */
    uint8_t  recv_key[32];   /* responder-side: decrypts init→resp */

    /* Live Noise state (mirrors the initiator's chain_key/hash exactly). */
    uint8_t  chain_key[32];
    uint8_t  hash[32];
};

static int sim_resp_process_initiation_and_build_response(
        struct sim_responder *r,
        const struct wg_msg_initiation *init_msg,
        struct wg_msg_response *out_resp,
        uint32_t responder_sender_index,
        const uint8_t preshared_key[32])
{
    uint8_t key[32];
    uint8_t dh[32];
    uint8_t *const timestamp_recovered = r->timestamp_recovered;
    uint8_t nonce[CHACHA20POLY1305_NONCE_LEN] = {0};

    /* --- Mirror initiator's prefix mixing (§5.4.3 lines 1–3). --- */
    memcpy(r->chain_key, wg_initial_chain_key(), 32);
    memcpy(r->hash,      wg_initial_hash(),      32);
    wg_mix_hash(r->hash, r->static_pub, 32);

    /* Initiator-ephemeral mixed in (line 4–5). */
    wg_mix_chain_only(r->chain_key, init_msg->ephemeral, 32);
    wg_mix_hash(r->hash, init_msg->ephemeral, 32);

    /* DH(S_priv_responder, E_pub_initiator) → (C, k). */
    if (curve25519_dh(dh, r->static_priv, init_msg->ephemeral) != 0) return -1;
    {
        uint8_t new_ck[32];
        noise_hkdf2(r->chain_key, dh, 32, new_ck, key);
        memcpy(r->chain_key, new_ck, 32);
    }

    /* Decrypt encrypted_static into Spub_initiator. */
    if (chacha20poly1305_decrypt(r->initiator_static_pub_recovered,
                                 init_msg->encrypted_static,
                                 sizeof(init_msg->encrypted_static),
                                 r->hash, 32, key, nonce) != 0) {
        return -2;
    }
    wg_mix_hash(r->hash, init_msg->encrypted_static,
                sizeof(init_msg->encrypted_static));

    /* (C, k) = KDF2(C, DH(S_priv_responder, S_pub_initiator)). */
    if (curve25519_dh(dh, r->static_priv,
                      r->initiator_static_pub_recovered) != 0) return -3;
    {
        uint8_t new_ck[32];
        noise_hkdf2(r->chain_key, dh, 32, new_ck, key);
        memcpy(r->chain_key, new_ck, 32);
    }

    /* Decrypt encrypted_timestamp. We don't enforce monotonicity in
     * this test — just need to verify the tag. */
    if (chacha20poly1305_decrypt(timestamp_recovered,
                                 init_msg->encrypted_timestamp,
                                 sizeof(init_msg->encrypted_timestamp),
                                 r->hash, 32, key, nonce) != 0) {
        return -4;
    }
    wg_mix_hash(r->hash, init_msg->encrypted_timestamp,
                sizeof(init_msg->encrypted_timestamp));

    r->remote_sender_index = init_msg->sender_index;

    /* --- Build MessageResponse (§5.4.4). --- */
    uint8_t e_priv[32], e_pub[32];
    if (curve25519_keypair(e_priv, e_pub) != 0) return -5;

    memset(out_resp, 0, sizeof(*out_resp));
    memcpy(out_resp->ephemeral, e_pub, 32);

    /* C = KDF1(C, E_pub_responder), H = H(H || E_pub_responder). */
    wg_mix_chain_only(r->chain_key, e_pub, 32);
    wg_mix_hash(r->hash, e_pub, 32);

    /* C = KDF1(C, DH(E_priv_resp, E_pub_init)). */
    if (curve25519_dh(dh, e_priv, init_msg->ephemeral) != 0) return -6;
    wg_mix_chain_only(r->chain_key, dh, 32);

    /* C = KDF1(C, DH(E_priv_resp, S_pub_init)). */
    if (curve25519_dh(dh, e_priv,
                      r->initiator_static_pub_recovered) != 0) return -7;
    wg_mix_chain_only(r->chain_key, dh, 32);

    /* (C, T, K) = KDF3(C, PSK). H = H(H || T). */
    {
        uint8_t new_ck[32], tau[32];
        noise_hkdf3(r->chain_key, preshared_key, 32, new_ck, tau, key);
        memcpy(r->chain_key, new_ck, 32);
        wg_mix_hash(r->hash, tau, 32);
    }

    /* AEAD-encrypt empty payload. The 16-byte tag is encrypted_nothing. */
    chacha20poly1305_encrypt(out_resp->encrypted_nothing,
                             NULL, 0,
                             r->hash, 32,
                             key, nonce);
    wg_mix_hash(r->hash, out_resp->encrypted_nothing,
                sizeof(out_resp->encrypted_nothing));

    /* Header. */
    out_resp->message_type   = WG_MSG_RESPONSE;
    out_resp->sender_index   = responder_sender_index;
    out_resp->receiver_index = init_msg->sender_index;

    /* mac1 over msg up to mac1 field, keyed with
     * BLAKE2s(LABEL_MAC1 || S_pub_initiator). */
    uint8_t mac1_key[32];
    wg_mac1_key(mac1_key, r->initiator_static_pub_recovered);
    wg_keyed_mac16(out_resp->mac1, mac1_key,
                   (const uint8_t *)out_resp,
                   offsetof(struct wg_msg_response, mac1));

    /* (T_init→resp, T_resp→init) = KDF2(C, ""). On responder's side:
     *   send_key = T_resp→init = second slot.
     *   recv_key = T_init→resp = first slot. */
    noise_hkdf2(r->chain_key, NULL, 0, r->recv_key, r->send_key);

    /* Scrub. */
    memset(key, 0, sizeof(key));
    memset(dh, 0, sizeof(dh));
    memset(e_priv, 0, sizeof(e_priv));
    memset(mac1_key, 0, sizeof(mac1_key));
    return 0;
}

static void test_full_handshake_roundtrip(void) {
    /* Build identities for both ends. */
    uint8_t init_priv[32], init_pub[32];
    uint8_t resp_priv[32], resp_pub[32];
    if (curve25519_keypair(init_priv, init_pub) != 0 ||
        curve25519_keypair(resp_priv, resp_pub) != 0) {
        printf("[full/keypairs] FAIL\n"); fails++; return;
    }
    uint8_t psk[32] = {0};

    /* Initiator builds MessageInitiation. */
    struct wg_handshake_state ist;
    if (wg_handshake_init(&ist, init_priv, init_pub, resp_pub, psk) != 0) {
        printf("[full/init-handshake-init] FAIL\n"); fails++; return;
    }
    struct wg_msg_initiation init_msg;
    if (wg_handshake_create_initiation(&ist, 0xCAFEBABE, &init_msg) != 0) {
        printf("[full/init-create] FAIL\n"); fails++; return;
    }

    /* Simulated responder processes and builds MessageResponse. */
    struct sim_responder rsim;
    memcpy(rsim.static_priv, resp_priv, 32);
    memcpy(rsim.static_pub,  resp_pub,  32);
    struct wg_msg_response resp_msg;
    int rc = sim_resp_process_initiation_and_build_response(
                &rsim, &init_msg, &resp_msg, 0xFEEDF00D, psk);
    if (rc != 0) {
        printf("[full/sim-responder] FAIL: rc=%d\n", rc); fails++; return;
    }
    /* Sanity: responder should have recovered initiator's static pub. */
    fails += check("full/spub-recovered",
                   rsim.initiator_static_pub_recovered, init_pub, 32);

    /* Initiator processes the response and derives transport keys. */
    uint8_t init_send[32], init_recv[32];
    uint32_t remote_idx = 0;
    if (wg_handshake_process_response(&ist, &resp_msg, init_send,
                                      init_recv, &remote_idx) != 0) {
        printf("[full/process-response] FAIL\n"); fails++; return;
    }
    if (remote_idx != 0xFEEDF00D) {
        printf("[full/remote-index] FAIL\n"); fails++;
    } else { printf("[full/remote-index] OK\n"); }

    /* The whole point of the handshake: both sides agree on transport
     * keys, with init→resp and resp→init crossed. */
    fails += check("full/init-send==resp-recv", init_send, rsim.recv_key, 32);
    fails += check("full/init-recv==resp-send", init_recv, rsim.send_key, 32);

    /* Tamper detection: flip a bit in the responder's encrypted_nothing
     * tag. Initiator must reject. */
    {
        struct wg_handshake_state ist2;
        wg_handshake_init(&ist2, init_priv, init_pub, resp_pub, psk);
        struct wg_msg_initiation init_msg2;
        wg_handshake_create_initiation(&ist2, 0xCAFEBABE, &init_msg2);

        struct sim_responder rsim2;
        memcpy(rsim2.static_priv, resp_priv, 32);
        memcpy(rsim2.static_pub,  resp_pub,  32);
        struct wg_msg_response resp_msg2;
        sim_resp_process_initiation_and_build_response(
            &rsim2, &init_msg2, &resp_msg2, 0xFEEDF00D, psk);
        resp_msg2.encrypted_nothing[0] ^= 0x01;

        uint8_t s[32], r[32]; uint32_t ri;
        if (wg_handshake_process_response(&ist2, &resp_msg2, s, r, &ri) == 0) {
            printf("[full/tamper-tag] FAIL: accepted bad tag\n"); fails++;
        } else { printf("[full/tamper-tag] OK\n"); }
    }

    /* Bad mac1 (tag and everything else intact): rejected before any DH. */
    {
        struct wg_handshake_state istm;
        wg_handshake_init(&istm, init_priv, init_pub, resp_pub, psk);
        struct wg_msg_initiation init_msgm;
        wg_handshake_create_initiation(&istm, 0xCAFEBABE, &init_msgm);
        struct sim_responder rsimm;
        memcpy(rsimm.static_priv, resp_priv, 32);
        memcpy(rsimm.static_pub,  resp_pub,  32);
        struct wg_msg_response resp_m;
        sim_resp_process_initiation_and_build_response(
            &rsimm, &init_msgm, &resp_m, 0xFEEDF00D, psk);
        resp_m.mac1[3] ^= 0x40;
        uint8_t s[32], r[32]; uint32_t ri;
        if (wg_handshake_process_response(&istm, &resp_m, s, r, &ri) == 0) {
            printf("[full/bad-mac1] FAIL: accepted\n"); fails++;
        } else { printf("[full/bad-mac1] OK\n"); }
    }

    /* A forged response (right receiver index, valid mac1 — anyone who
     * knows our public key can compute it — garbage ephemeral) must not
     * poison the in-flight handshake: the genuine response that arrives
     * after it is still accepted and yields the same keys. */
    {
        struct wg_handshake_state istf;
        wg_handshake_init(&istf, init_priv, init_pub, resp_pub, psk);
        struct wg_msg_initiation init_msgf;
        wg_handshake_create_initiation(&istf, 0xCAFEBABE, &init_msgf);
        struct sim_responder rsimf;
        memcpy(rsimf.static_priv, resp_priv, 32);
        memcpy(rsimf.static_pub,  resp_pub,  32);
        struct wg_msg_response genuine;
        sim_resp_process_initiation_and_build_response(
            &rsimf, &init_msgf, &genuine, 0xFEEDF00D, psk);

        struct wg_msg_response forged = genuine;
        uint8_t junk_priv[32], junk_pub[32];
        curve25519_keypair(junk_priv, junk_pub);
        memcpy(forged.ephemeral, junk_pub, 32);
        uint8_t mk[32];
        wg_mac1_key(mk, init_pub);
        wg_keyed_mac16(forged.mac1, mk, (const uint8_t *)&forged,
                       offsetof(struct wg_msg_response, mac1));

        uint8_t s[32], r[32]; uint32_t ri;
        if (wg_handshake_process_response(&istf, &forged, s, r, &ri) == 0) {
            printf("[full/forged-rejected] FAIL: accepted\n"); fails++;
        } else { printf("[full/forged-rejected] OK\n"); }
        ri = 0;
        if (wg_handshake_process_response(&istf, &genuine, s, r, &ri) != 0 ||
            ri != 0xFEEDF00D) {
            printf("[full/genuine-after-forged] FAIL\n"); fails++;
        } else {
            printf("[full/genuine-after-forged] OK\n");
            fails += check("full/genuine-after-forged-keys", s, rsimf.recv_key, 32);
        }
    }

    /* Tamper detection: wrong receiver_index. Initiator must reject
     * before doing any crypto. */
    {
        struct wg_handshake_state ist3;
        wg_handshake_init(&ist3, init_priv, init_pub, resp_pub, psk);
        struct wg_msg_initiation init_msg3;
        wg_handshake_create_initiation(&ist3, 0xCAFEBABE, &init_msg3);

        struct sim_responder rsim3;
        memcpy(rsim3.static_priv, resp_priv, 32);
        memcpy(rsim3.static_pub,  resp_pub,  32);
        struct wg_msg_response resp_msg3;
        sim_resp_process_initiation_and_build_response(
            &rsim3, &init_msg3, &resp_msg3, 0xFEEDF00D, psk);
        resp_msg3.receiver_index = 0xDEAD0000;

        uint8_t s[32], r[32]; uint32_t ri;
        if (wg_handshake_process_response(&ist3, &resp_msg3, s, r, &ri) == 0) {
            printf("[full/wrong-receiver-index] FAIL: accepted\n"); fails++;
        } else { printf("[full/wrong-receiver-index] OK\n"); }
    }

    /* Tamper detection: wrong message_type. */
    {
        struct wg_handshake_state ist4;
        wg_handshake_init(&ist4, init_priv, init_pub, resp_pub, psk);
        struct wg_msg_initiation init_msg4;
        wg_handshake_create_initiation(&ist4, 0xCAFEBABE, &init_msg4);

        struct sim_responder rsim4;
        memcpy(rsim4.static_priv, resp_priv, 32);
        memcpy(rsim4.static_pub,  resp_pub,  32);
        struct wg_msg_response resp_msg4;
        sim_resp_process_initiation_and_build_response(
            &rsim4, &init_msg4, &resp_msg4, 0xFEEDF00D, psk);
        resp_msg4.message_type = WG_MSG_INITIATION;

        uint8_t s[32], r[32]; uint32_t ri;
        if (wg_handshake_process_response(&ist4, &resp_msg4, s, r, &ri) == 0) {
            printf("[full/wrong-msg-type] FAIL: accepted\n"); fails++;
        } else { printf("[full/wrong-msg-type] OK\n"); }
    }

    /* Tamper detection: non-zero reserved bytes. Must be rejected before
     * any crypto runs (mirrors wg_transport_decrypt's reserved check). */
    {
        struct wg_handshake_state ist5;
        wg_handshake_init(&ist5, init_priv, init_pub, resp_pub, psk);
        struct wg_msg_initiation init_msg5;
        wg_handshake_create_initiation(&ist5, 0xCAFEBABE, &init_msg5);

        struct sim_responder rsim5;
        memcpy(rsim5.static_priv, resp_priv, 32);
        memcpy(rsim5.static_pub,  resp_pub,  32);
        struct wg_msg_response resp_msg5;
        sim_resp_process_initiation_and_build_response(
            &rsim5, &init_msg5, &resp_msg5, 0xFEEDF00D, psk);
        resp_msg5.reserved[1] = 0x01;

        uint8_t s[32], r[32]; uint32_t ri;
        if (wg_handshake_process_response(&ist5, &resp_msg5, s, r, &ri) == 0) {
            printf("[full/reserved-nonzero] FAIL: accepted\n"); fails++;
        } else { printf("[full/reserved-nonzero] OK\n"); }
    }

    wg_handshake_scrub(&ist);
}

/* --- Per-peer cache (B11) ------------------------------------------ */

/* The pre-1.3.2 INIT construction, written out from the whitepaper
 * (§5.4.2) with the static-static DH and the mac1 key computed afresh
 * for this one message — what wg_handshake_init + create_initiation did
 * on every attempt before the cache. */
static void ref_build_initiation(const uint8_t lpriv[32], const uint8_t lpub[32],
                                 const uint8_t ppub[32],
                                 const uint8_t eph_priv[32], const uint8_t eph_pub[32],
                                 const uint8_t ts[WG_TAI64N_LEN], uint32_t idx,
                                 struct wg_msg_initiation *out)
{
    uint8_t ck[32], h[32], key[32], dh[32], mk[32];
    uint8_t nonce[CHACHA20POLY1305_NONCE_LEN] = {0};
    memset(out, 0, sizeof(*out));
    memcpy(ck, wg_initial_chain_key(), 32);
    memcpy(h,  wg_initial_hash(),      32);
    wg_mix_hash(h, ppub, 32);
    memcpy(out->ephemeral, eph_pub, 32);
    wg_mix_chain_only(ck, eph_pub, 32);
    wg_mix_hash(h, eph_pub, 32);
    curve25519_dh(dh, eph_priv, ppub);
    wg_mix_key(ck, dh, 32, key);
    chacha20poly1305_encrypt(out->encrypted_static, lpub, 32, h, 32, key, nonce);
    wg_mix_hash(h, out->encrypted_static, sizeof(out->encrypted_static));
    curve25519_dh(dh, lpriv, ppub);                     /* static-static, fresh */
    wg_mix_key(ck, dh, 32, key);
    chacha20poly1305_encrypt(out->encrypted_timestamp, ts, WG_TAI64N_LEN,
                             h, 32, key, nonce);
    out->message_type = WG_MSG_INITIATION;
    out->sender_index = idx;
    wg_mac1_key(mk, ppub);                              /* mac1 key, fresh */
    wg_keyed_mac16(out->mac1, mk, (const uint8_t *)out,
                   offsetof(struct wg_msg_initiation, mac1));
}

/* Build an INIT on *st with the RNG at `seed`, recover its timestamp via
 * the simulated responder, rebuild it with ref_build_initiation from the
 * same ephemeral + timestamp and compare all 148 bytes. Leaves the
 * responder's MessageResponse in *resp for the caller. */
static void check_init_vs_ref(const char *name, struct wg_handshake_state *st,
                              const uint8_t lpriv[32], const uint8_t lpub[32],
                              const uint8_t rpriv[32], const uint8_t rpub[32],
                              uint64_t seed, uint32_t idx,
                              struct sim_responder *rsim,
                              struct wg_msg_response *resp)
{
    char tag[96];
    struct wg_msg_initiation got, want;
    s_rng_state = seed;
    if (wg_handshake_create_initiation(st, idx, &got) != 0) {
        printf("[%s/create] FAIL\n", name); fails++; return;
    }
    uint8_t eph_priv[32], eph_pub[32];
    s_rng_state = seed;                       /* same draw as inside create */
    curve25519_keypair(eph_priv, eph_pub);

    memcpy(rsim->static_priv, rpriv, 32);
    memcpy(rsim->static_pub,  rpub,  32);
    static const uint8_t psk[32] = {0};
    if (sim_resp_process_initiation_and_build_response(rsim, &got, resp,
                                                       0x5EED0000u ^ idx, psk) != 0) {
        printf("[%s/responder] FAIL\n", name); fails++; return;
    }
    ref_build_initiation(lpriv, lpub, rpub, eph_priv, eph_pub,
                         rsim->timestamp_recovered, idx, &want);
    snprintf(tag, sizeof(tag), "%s/bytes-vs-uncached", name);
    fails += check(tag, (const uint8_t *)&got, (const uint8_t *)&want, sizeof(got));
}

static void test_cached_identity(void) {
    uint8_t a_priv[32], a_pub[32];     /* local */
    uint8_t b_priv[32], b_pub[32];     /* peer  */
    uint8_t c_priv[32], c_pub[32];     /* peer after a re-login */
    uint8_t d_priv[32], d_pub[32];     /* regenerated local key */
    curve25519_keypair(a_priv, a_pub);
    curve25519_keypair(b_priv, b_pub);
    curve25519_keypair(c_priv, c_pub);
    curve25519_keypair(d_priv, d_pub);
    static const uint8_t psk[32] = {0};

    struct wg_handshake_state st;
    memset(&st, 0, sizeof(st));
    struct sim_responder rsim;
    struct wg_msg_response resp;
    uint8_t s[32], r[32];
    uint32_t ri = 0;

    /* Cold: first INIT computes the cache. */
    if (wg_handshake_init(&st, a_priv, a_pub, b_pub, psk) != 0) {
        printf("[cache/init-cold] FAIL\n"); fails++; return;
    }
    uint8_t ss_want[32];
    curve25519_dh(ss_want, a_priv, b_pub);
    fails += check("cache/static-dh-computed", st.static_static_dh, ss_want, 32);
    check_init_vs_ref("cache/cold", &st, a_priv, a_pub, b_priv, b_pub,
                      0x1111222233334444ULL, 0x01020304u, &rsim, &resp);
    if (wg_handshake_process_response(&st, &resp, s, r, &ri) != 0) {
        printf("[cache/cold-response] FAIL\n"); fails++;
    } else {
        fails += check("cache/cold-keys", s, rsim.recv_key, 32);
    }

    /* Session up: live material goes, the cache stays; a scrubbed state
     * refuses even the genuine response it just accepted. */
    wg_handshake_scrub_live(&st);
    fails += check("cache/static-dh-kept", st.static_static_dh, ss_want, 32);
    if (wg_handshake_process_response(&st, &resp, s, r, &ri) == 0) {
        printf("[cache/scrubbed-refuses] FAIL: accepted\n"); fails++;
    } else { printf("[cache/scrubbed-refuses] OK\n"); }

    /* Rekey towards the same peer: cached path, same bytes as uncached. */
    if (wg_handshake_init(&st, a_priv, a_pub, b_pub, psk) != 0 || !st.identity_valid) {
        printf("[cache/init-rekey] FAIL\n"); fails++; return;
    }
    check_init_vs_ref("cache/rekey", &st, a_priv, a_pub, b_priv, b_pub,
                      0x5555666677778888ULL, 0x0A0B0C0Du, &rsim, &resp);
    if (wg_handshake_process_response(&st, &resp, s, r, &ri) != 0) {
        printf("[cache/rekey-response] FAIL\n"); fails++;
    } else {
        fails += check("cache/rekey-keys", s, rsim.recv_key, 32);
        fails += check("cache/rekey-keys-recv", r, rsim.send_key, 32);
    }

    /* Retry without a response in between (state armed, not scrubbed). */
    wg_handshake_init(&st, a_priv, a_pub, b_pub, psk);
    check_init_vs_ref("cache/retry", &st, a_priv, a_pub, b_priv, b_pub,
                      0x0123456789ABCDEFULL, 0x11111111u, &rsim, &resp);

    /* Peer re-login (new static key): cache recomputed for C. */
    wg_handshake_init(&st, a_priv, a_pub, c_pub, psk);
    curve25519_dh(ss_want, a_priv, c_pub);
    fails += check("cache/peer-change-recomputed", st.static_static_dh, ss_want, 32);
    check_init_vs_ref("cache/peer-change", &st, a_priv, a_pub, c_priv, c_pub,
                      0x2222333344445555ULL, 0x22222222u, &rsim, &resp);
    if (wg_handshake_process_response(&st, &resp, s, r, &ri) != 0) {
        printf("[cache/peer-change-response] FAIL\n"); fails++;
    } else { printf("[cache/peer-change-response] OK\n"); }

    /* Local key regenerated: recomputed again (static DH and the mac1 key
     * the response is checked with both depend on it). */
    wg_handshake_init(&st, d_priv, d_pub, c_pub, psk);
    curve25519_dh(ss_want, d_priv, c_pub);
    fails += check("cache/local-change-recomputed", st.static_static_dh, ss_want, 32);
    check_init_vs_ref("cache/local-change", &st, d_priv, d_pub, c_priv, c_pub,
                      0x3333444455556666ULL, 0x33333333u, &rsim, &resp);
    if (wg_handshake_process_response(&st, &resp, s, r, &ri) != 0) {
        printf("[cache/local-change-response] FAIL\n"); fails++;
    } else { printf("[cache/local-change-response] OK\n"); }

    /* A new PSK is an identity change too. */
    uint8_t psk2[32];
    memset(psk2, 0x5a, sizeof(psk2));
    uint8_t mk_before[32];
    memcpy(mk_before, st.mac1_key, 32);
    wg_handshake_init(&st, d_priv, d_pub, c_pub, psk2);
    fails += check("cache/psk-change-copied", st.preshared_key, psk2, 32);
    fails += check("cache/psk-change-mac1-same-peer", st.mac1_key, mk_before, 32);

    /* Low-order peer key: init fails, state wiped (no stale cache), and
     * the next valid identity computes cleanly. */
    static const uint8_t low_order[32] = {0};
    if (wg_handshake_init(&st, a_priv, a_pub, low_order, psk) == 0 ||
        st.identity_valid || st.armed) {
        printf("[cache/low-order-wipes] FAIL\n"); fails++;
    } else { printf("[cache/low-order-wipes] OK\n"); }
    if (wg_handshake_init(&st, a_priv, a_pub, b_pub, psk) != 0) {
        printf("[cache/after-low-order] FAIL\n"); fails++;
    } else {
        check_init_vs_ref("cache/after-low-order", &st, a_priv, a_pub, b_priv, b_pub,
                          0x7777888899990000ULL, 0x44444444u, &rsim, &resp);
    }

    /* Full scrub drops the cache. */
    wg_handshake_scrub(&st);
    if (st.identity_valid || !is_all_zero(st.static_static_dh, 32)) {
        printf("[cache/scrub-drops-cache] FAIL\n"); fails++;
    } else { printf("[cache/scrub-drops-cache] OK\n"); }
}

/* Round 1.3.6, late answers. wg_netif replaces the INIT in flight on a
 * path event (B7b) only once it is WG_INIT_FRESH_AFTER_MS old — 1 s until
 * 1.3.5, when answers arriving later were refused on the sensor. An
 * answer 2 s after its INIT now finds it; past the bound the INIT is
 * replaced, the old answer is refused (its Noise state is gone — keeping
 * it was rejected, see wg_netif.c) and the new INIT's answer completes. */
static void test_late_response(void) {
    uint8_t ipriv[32], ipub[32], rpriv[32], rpub[32], psk[32] = {0};
    if (curve25519_keypair(ipriv, ipub) != 0 || curve25519_keypair(rpriv, rpub) != 0) {
        printf("[late/keypairs] FAIL\n"); fails++; return;
    }
    struct sim_responder r;
    memcpy(r.static_priv, rpriv, 32);
    memcpy(r.static_pub, rpub, 32);
    const int64_t t_init = 10000000;   /* µs */

    /* A pong 1.5 s after the INIT: re-send, not replace; the answer at
     * 2 s completes the handshake. */
    struct wg_handshake_state st;
    struct wg_msg_initiation i1;
    struct wg_msg_response a1;
    uint8_t sk[32], rk[32];
    uint32_t ridx = 0;
    int good = wg_handshake_init(&st, ipriv, ipub, rpub, psk) == 0 &&
               wg_handshake_create_initiation(&st, 0x11111111, &i1) == 0 &&
               sim_resp_process_initiation_and_build_response(&r, &i1, &a1, 0xA1, psk) == 0;
    good &= !wg_init_fresh_due(t_init + 1500000, t_init);
    good &= wg_handshake_process_response(&st, &a1, sk, rk, &ridx) == 0 && ridx == 0xA1;
    printf("[late/young-init-kept-answer-taken] %s\n", good ? "OK" : "FAIL");
    fails += !good;

    /* A pong 3 s after: a new INIT replaces it; the first INIT's answer
     * is refused, the second's taken. */
    struct wg_msg_initiation i2, i3;
    struct wg_msg_response a2, a3;
    good = wg_handshake_init(&st, ipriv, ipub, rpub, psk) == 0 &&
           wg_handshake_create_initiation(&st, 0x22222222, &i2) == 0 &&
           sim_resp_process_initiation_and_build_response(&r, &i2, &a2, 0xA2, psk) == 0;
    good &= wg_init_fresh_due(t_init + 3000000, t_init);
    good &= wg_handshake_init(&st, ipriv, ipub, rpub, psk) == 0 &&
            wg_handshake_create_initiation(&st, 0x33333333, &i3) == 0;
    good &= wg_handshake_process_response(&st, &a2, sk, rk, &ridx) != 0;
    printf("[late/replaced-init-answer-refused] %s\n", good ? "OK" : "FAIL");
    fails += !good;
    good = sim_resp_process_initiation_and_build_response(&r, &i3, &a3, 0xA3, psk) == 0 &&
           wg_handshake_process_response(&st, &a3, sk, rk, &ridx) == 0 && ridx == 0xA3;
    printf("[late/new-init-answer-taken] %s\n", good ? "OK" : "FAIL");
    fails += !good;
    /* Even with the old answer's index rewritten to the new INIT's and its
     * mac1 recomputed, it was sealed for another ephemeral: refused by the
     * AEAD (the index check is not the only guard). */
    wg_handshake_init(&st, ipriv, ipub, rpub, psk);
    wg_handshake_create_initiation(&st, 0x44444444, &i3);
    a2.receiver_index = 0x44444444;
    uint8_t mk[WG_HASH_LEN];
    wg_mac1_key(mk, ipub);
    wg_keyed_mac16(a2.mac1, mk, (const uint8_t *)&a2, offsetof(struct wg_msg_response, mac1));
    good = wg_handshake_process_response(&st, &a2, sk, rk, &ridx) != 0;
    printf("[late/old-answer-new-index-refused] %s\n", good ? "OK" : "FAIL");
    fails += !good;
    wg_handshake_scrub(&st);
}

int main(void) {
    test_initial_constants();
    test_mac1_key();
    test_create_initiation_shape();
    test_full_handshake_roundtrip();
    test_cached_identity();
    test_late_response();
    if (fails == 0) printf("\nALL OK\n");
    return fails ? 1 : 0;
}
