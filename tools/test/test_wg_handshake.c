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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wg_proto.h"
#include "wg_handshake.h"

#include "crypto/blake2s.h"
#include "crypto/curve25519.h"

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

int main(void) {
    test_initial_constants();
    test_mac1_key();
    test_create_initiation_shape();
    if (fails == 0) printf("\nALL OK\n");
    return fails ? 1 : 0;
}
