/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for the ChaCha20-Poly1305 AEAD against RFC 8439 §2.8.2.
 * This is the integration test that actually exercises the AEAD glue
 * (where most CVEs live): pad16(AAD), pad16(ciphertext), LE u64
 * length encoding, constant-time tag check.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "chacha20poly1305.h"

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

/* RFC 8439 §2.8.2 */
static const uint8_t key[32] = {
    0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
    0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
    0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
    0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
};
static const uint8_t nonce[12] = {
    0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,
    0x44,0x45,0x46,0x47,
};
static const uint8_t aad[12] = {
    0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,
    0xc4,0xc5,0xc6,0xc7,
};
static const uint8_t plaintext[] =
    "Ladies and Gentlemen of the class of '99: If I could offer you "
    "only one tip for the future, sunscreen would be it.";
static const uint8_t expected_ct[114] = {
    0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,
    0x7b,0x86,0xaf,0xbc,0x53,0xef,0x7e,0xc2,
    0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,
    0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,
    0x3d,0xbe,0xa4,0x5e,0x8c,0xa9,0x67,0x12,
    0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
    0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,
    0x05,0xd6,0xa5,0xb6,0x7e,0xcd,0x3b,0x36,
    0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,
    0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,
    0xfa,0xb3,0x24,0xe4,0xfa,0xd6,0x75,0x94,
    0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
    0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,
    0xe5,0x76,0xd2,0x65,0x86,0xce,0xc6,0x4b,
    0x61,0x16,
};
static const uint8_t expected_tag[16] = {
    0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,
    0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91,
};

int main(void) {
    const size_t mlen = sizeof(plaintext) - 1;
    if (mlen != sizeof(expected_ct)) {
        printf("[plaintext-len] FAIL: %zu vs %zu\n", mlen, sizeof(expected_ct));
        return 1;
    }
    int fails = 0;

    /* Encrypt and check both ciphertext and tag against the spec. */
    uint8_t out[114 + 16];
    chacha20poly1305_encrypt(out, plaintext, mlen, aad, sizeof(aad), key, nonce);
    fails += check("rfc8439-2.8.2-ct",  out,        expected_ct,  mlen);
    fails += check("rfc8439-2.8.2-tag", out + mlen, expected_tag, 16);

    /* Decrypt and check round-trip. */
    uint8_t pt[114];
    int rc = chacha20poly1305_decrypt(pt, out, mlen + 16, aad, sizeof(aad), key, nonce);
    if (rc != 0) {
        printf("[rfc8439-2.8.2-decrypt] FAIL: rc=%d\n", rc);
        fails++;
    } else {
        fails += check("rfc8439-2.8.2-decrypt", pt, plaintext, mlen);
    }

    /* Tamper detection: flip one bit in ciphertext, decrypt must fail. */
    uint8_t tampered[114 + 16];
    memcpy(tampered, out, sizeof(tampered));
    tampered[0] ^= 0x01;
    rc = chacha20poly1305_decrypt(pt, tampered, mlen + 16, aad, sizeof(aad), key, nonce);
    if (rc == 0) {
        printf("[tamper-ct-flip] FAIL: decrypt accepted modified ciphertext\n");
        fails++;
    } else {
        printf("[tamper-ct-flip] OK\n");
    }

    /* Tamper detection: flip one bit in tag, decrypt must fail. */
    memcpy(tampered, out, sizeof(tampered));
    tampered[mlen] ^= 0x01;
    rc = chacha20poly1305_decrypt(pt, tampered, mlen + 16, aad, sizeof(aad), key, nonce);
    if (rc == 0) {
        printf("[tamper-tag-flip] FAIL: decrypt accepted modified tag\n");
        fails++;
    } else {
        printf("[tamper-tag-flip] OK\n");
    }

    /* Tamper detection: flip one bit in AAD, decrypt must fail. */
    uint8_t bad_aad[12];
    memcpy(bad_aad, aad, sizeof(bad_aad));
    bad_aad[0] ^= 0x01;
    rc = chacha20poly1305_decrypt(pt, out, mlen + 16, bad_aad, sizeof(bad_aad), key, nonce);
    if (rc == 0) {
        printf("[tamper-aad-flip] FAIL: decrypt accepted modified AAD\n");
        fails++;
    } else {
        printf("[tamper-aad-flip] OK\n");
    }

    /* Empty plaintext + empty AAD edge case (still produces a tag). */
    uint8_t empty_out[16];
    chacha20poly1305_encrypt(empty_out, NULL, 0, NULL, 0, key, nonce);
    uint8_t empty_pt[1] = {0xAA};
    rc = chacha20poly1305_decrypt(empty_pt, empty_out, 16, NULL, 0, key, nonce);
    if (rc != 0) {
        printf("[empty-roundtrip] FAIL: decrypt rc=%d\n", rc);
        fails++;
    } else {
        printf("[empty-roundtrip] OK\n");
    }

    if (fails == 0) printf("\nALL OK\n");
    return fails ? 1 : 0;
}
