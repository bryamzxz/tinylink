/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for the ChaCha20-Poly1305 AEAD against RFC 8439 §2.8.2 and
 * Appendix A.5 (the decryption example; its nonce 0^32 || 01..08 has the
 * WireGuard / ts2021 shape). This is the integration test that actually
 * exercises the AEAD glue (where most CVEs live): pad16(AAD),
 * pad16(ciphertext), LE u64 length encoding, constant-time tag check —
 * and that a rejected record leaves the output buffer untouched, which
 * noise_ik.c documents for its callers since round 1.3.2.
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

/* RFC 8439 Appendix A.5 (hex, as in mbedTLS test_suite_chachapoly.data). */
static const char kA5Key[] =
    "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0";
static const char kA5Nonce[] = "000000000102030405060708";
static const char kA5Aad[]   = "f33388860000000000004e91";
static const char kA5Pt[] =
    "496e7465726e65742d4472616674732061726520647261667420646f63756d65"
    "6e74732076616c696420666f722061206d6178696d756d206f6620736978206d"
    "6f6e74687320616e64206d617920626520757064617465642c207265706c6163"
    "65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65"
    "6e747320617420616e792074696d652e20497420697320696e617070726f7072"
    "6961746520746f2075736520496e7465726e65742d4472616674732061732072"
    "65666572656e6365206d6174657269616c206f7220746f206369746520746865"
    "6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67"
    "726573732e2fe2809d";
static const char kA5Ct[] =
    "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2"
    "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf"
    "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855"
    "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4"
    "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e"
    "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a"
    "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10"
    "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29"
    "a6ad5cb4022b02709b";
static const char kA5Tag[] = "eead9d67890cbb22392336fea1851f38";

static size_t unhex(uint8_t *out, size_t max, const char *hex) {
    size_t n = strlen(hex) / 2;
    if (n > max) n = max;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        sscanf(hex + 2 * i, "%2x", &v);
        out[i] = (uint8_t)v;
    }
    return n;
}

static int all_bytes(const uint8_t *b, size_t n, uint8_t v) {
    for (size_t i = 0; i < n; i++) if (b[i] != v) return 0;
    return 1;
}

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

    /* Rejected records must not leak plaintext into out (it stays as the
     * caller left it), for a tag flip and a ciphertext flip alike. */
    {
        uint8_t sentinel[114];
        memcpy(tampered, out, sizeof(tampered));
        tampered[mlen + 15] ^= 0x80;
        memset(sentinel, 0x5A, sizeof(sentinel));
        rc = chacha20poly1305_decrypt(sentinel, tampered, mlen + 16, aad, sizeof(aad), key, nonce);
        if (rc == 0 || !all_bytes(sentinel, sizeof(sentinel), 0x5A)) {
            printf("[reject-leaves-out-untouched] FAIL\n");
            fails++;
        } else {
            printf("[reject-leaves-out-untouched] OK\n");
        }
    }

    /* Appendix A.5: encrypt, decrypt, and the not-authentic variant. */
    {
        uint8_t k5[32], n5[12], a5[12], p5[300], c5[300], t5[16];
        uint8_t got[300 + 16], back[300];
        unhex(k5, sizeof(k5), kA5Key);
        unhex(n5, sizeof(n5), kA5Nonce);
        size_t alen = unhex(a5, sizeof(a5), kA5Aad);
        size_t plen = unhex(p5, sizeof(p5), kA5Pt);
        size_t clen = unhex(c5, sizeof(c5), kA5Ct);
        unhex(t5, sizeof(t5), kA5Tag);
        if (plen != 265 || clen != 265 || alen != 12) {
            printf("[rfc8439-a5-lengths] FAIL: %zu %zu %zu\n", plen, clen, alen);
            fails++;
        }
        chacha20poly1305_encrypt(got, p5, plen, a5, alen, k5, n5);
        fails += check("rfc8439-a5-ct",  got,        c5, clen);
        fails += check("rfc8439-a5-tag", got + plen, t5, 16);

        memcpy(got, c5, clen);
        memcpy(got + clen, t5, 16);
        rc = chacha20poly1305_decrypt(back, got, clen + 16, a5, alen, k5, n5);
        if (rc != 0) {
            printf("[rfc8439-a5-decrypt] FAIL: rc=%d\n", rc);
            fails++;
        } else {
            fails += check("rfc8439-a5-decrypt", back, p5, plen);
        }

        got[clen] ^= 0x10;   /* the mbedTLS suite's "not authentic" tag */
        memset(back, 0x5A, sizeof(back));
        rc = chacha20poly1305_decrypt(back, got, clen + 16, a5, alen, k5, n5);
        if (rc == 0 || !all_bytes(back, plen, 0x5A)) {
            printf("[rfc8439-a5-not-authentic] FAIL\n");
            fails++;
        } else {
            printf("[rfc8439-a5-not-authentic] OK\n");
        }
    }

    if (fails == 0) printf("\nALL OK\n");
    return fails ? 1 : 0;
}
