// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Host-side known-answer test for the placeholder TweetNaCl-derived
// X25519. Run with:
//   make -C tools/test test_curve25519
//
// Vectors: RFC 7748 §5.2 (single scalarmult) and §6.1 (DH round-trip).
//
// Note: the host build replaces esp_fill_random() with a fake symbol so
// curve25519_keypair() compiles; we only exercise curve25519_scalarmult
// in this test, where the entropy source is irrelevant.

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../../components/tinylink/src/crypto/curve25519.h"

/* Stub esp_fill_random for the host build. Not exercised by these tests. */
void esp_fill_random(void *buf, size_t len) { memset(buf, 0, len); }

static int hex_decode(const char *hex, uint8_t out[32])
{
    if (strlen(hex) != 64) return -1;
    for (size_t i = 0; i < 32; i++) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static void print_hex(const uint8_t *buf)
{
    for (size_t i = 0; i < 32; i++) printf("%02x", buf[i]);
}

static int check(const char *label,
                 const char *scalar_hex, const char *u_hex,
                 const char *expected_hex)
{
    uint8_t scalar[32], u[32], expected[32], got[32];
    if (hex_decode(scalar_hex, scalar) != 0 ||
        hex_decode(u_hex, u) != 0 ||
        hex_decode(expected_hex, expected) != 0) {
        printf("[%s] hex decode failed\n", label);
        return 1;
    }
    if (curve25519_scalarmult(got, scalar, u) != 0) {
        printf("[%s] scalarmult returned -1 (low-order)?\n", label);
        return 1;
    }
    if (memcmp(got, expected, 32) != 0) {
        printf("[%s] FAIL\n  got:      ", label); print_hex(got);
        printf("\n  expected: ");                  print_hex(expected);
        printf("\n");
        return 1;
    }
    printf("[%s] OK\n", label);
    return 0;
}

int main(void)
{
    int fails = 0;

    /* RFC 7748 §5.2 — first single-scalarmult test vector. */
    fails += check("rfc7748-5.2-a",
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

    /* RFC 7748 §5.2 — second single-scalarmult test vector. */
    fails += check("rfc7748-5.2-b",
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

    /* RFC 7748 §6.1 — DH round-trip.
     * Alice's priv -> Bob's pub == Bob's priv -> Alice's pub == K. */
    const char *alice_priv =
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const char *alice_pub =
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const char *bob_priv =
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const char *bob_pub =
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const char *expected_K =
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    fails += check("rfc7748-6.1-alice-to-bob", alice_priv, bob_pub, expected_K);
    fails += check("rfc7748-6.1-bob-to-alice", bob_priv, alice_pub, expected_K);

    if (fails == 0) {
        printf("\nALL OK\n");
        return 0;
    }
    printf("\n%d FAILURES\n", fails);
    return 1;
}
