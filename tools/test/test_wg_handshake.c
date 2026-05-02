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
 * Step 3b will add a byte-exact KAT once we expose a test hook that
 * lets us inject a fixed ephemeral keypair and timestamp.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wg_proto.h"
#include "wg_handshake.h"

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
    uint8_t timestamp_recovered[WG_TAI64N_LEN];
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
    memset(timestamp_recovered, 0, sizeof(timestamp_recovered));
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

    wg_handshake_scrub(&ist);
}

int main(void) {
    test_initial_constants();
    test_mac1_key();
    test_create_initiation_shape();
    test_full_handshake_roundtrip();
    if (fails == 0) printf("\nALL OK\n");
    return fails ? 1 : 0;
}
