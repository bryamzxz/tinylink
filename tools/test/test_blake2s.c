// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Host-side known-answer test for the vendored BLAKE2s. Run with:
//   make -C tools/test test_blake2s
//
// Vectors: RFC 7693 Appendix A and the official BLAKE2 test suite at
// https://github.com/BLAKE2/BLAKE2/blob/master/testvectors/blake2s-kat.txt

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "../../components/tinylink/src/crypto/blake2s.h"

static int hex_decode(const char *hex, uint8_t *out, size_t out_size)
{
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > out_size) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return (int)(hex_len / 2);
}

static void print_hex(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
}

static int run_one(const char *label,
                   const char *in_hex, const char *key_hex,
                   const char *expected_hex)
{
    uint8_t in[256];
    uint8_t key[32];
    uint8_t expected[32];
    uint8_t got[32];

    int in_len = hex_decode(in_hex, in, sizeof(in));
    int key_len = (key_hex == NULL) ? 0 : hex_decode(key_hex, key, sizeof(key));
    int exp_len = hex_decode(expected_hex, expected, sizeof(expected));
    if (in_len < 0 || key_len < 0 || exp_len != 32) {
        printf("[%s] hex decode failed\n", label);
        return 1;
    }
    if (blake2s(got, 32, in, (size_t)in_len,
                (key_len == 0) ? NULL : key, (size_t)key_len) != 0) {
        printf("[%s] blake2s() returned non-zero\n", label);
        return 1;
    }
    if (memcmp(got, expected, 32) != 0) {
        printf("[%s] FAIL\n  got:      ", label); print_hex(got, 32);
        printf("\n  expected: ");                  print_hex(expected, 32);
        printf("\n");
        return 1;
    }
    printf("[%s] OK\n", label);
    return 0;
}

int main(void)
{
    int fails = 0;

    /* RFC 7693 Appendix A: "abc" (no key). */
    fails += run_one("rfc7693-abc",
        "616263",   /* "abc" */
        NULL,
        "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");

    /* BLAKE2s KAT: empty input, empty key. Expected from the BLAKE2 test
     * vectors — first line of blake2s-kat.txt with key length 0. */
    fails += run_one("kat-empty-nokey",
        "",
        NULL,
        "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");

    /* BLAKE2s KAT with the canonical 32-byte key and empty input.
     * Key = 0x00..0x1f (32 bytes). */
    fails += run_one("kat-empty-key32",
        "",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49");

    /* BLAKE2s KAT: input = 0x00 (single byte), no key. */
    fails += run_one("kat-1byte-nokey",
        "00",
        NULL,
        "e34d74dbaf4ff4c6abd871cc220451d2ea2648846c7757fbaac82fe51ad64bea");

    /* The whole blake2s-kat.txt (keyed: key 00..1f, input 00..i-1 for
     * i = 0..255) and the same inputs unkeyed, folded into one BLAKE2s
     * of the 256 concatenated digests — every length across the block
     * boundaries (round 1.3.3, C9, rewrote the compression function).
     * Expected values from Python's hashlib.blake2s, whose keyed digests
     * are the KAT file's lines (first and last checked below). */
    {
        uint8_t in[256], key[32], d[32], first[32], last[32];
        static uint8_t cat_k[256 * 32], cat_u[256 * 32];
        for (int i = 0; i < 256; i++) in[i] = (uint8_t)i;
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
        int bad = 0;
        for (int i = 0; i < 256; i++) {
            bad |= blake2s(cat_k + 32 * i, 32, in, (size_t)i, key, 32) != 0;
            bad |= blake2s(cat_u + 32 * i, 32, in, (size_t)i, NULL, 0) != 0;
        }
        hex_decode("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49", first, 32);
        hex_decode("3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd", last, 32);
        bad |= memcmp(cat_k, first, 32) != 0 || memcmp(cat_k + 255 * 32, last, 32) != 0;
        uint8_t want[32];
        blake2s(d, 32, cat_k, sizeof(cat_k), NULL, 0);
        hex_decode("2582f7b18a91f66ef22aa9455384ada69b2590306a6470ee8588df75ee982f02", want, 32);
        bad |= memcmp(d, want, 32) != 0;
        printf("[blake2s-kat.txt keyed 0..255 (digest of digests)] %s\n", bad ? "FAIL" : "OK");
        fails += bad;
        blake2s(d, 32, cat_u, sizeof(cat_u), NULL, 0);
        hex_decode("6d86d20a9d486cc270bc10f4523a3e811f7f88636204b0a9a76277823b30b672", want, 32);
        bad = memcmp(d, want, 32) != 0;
        printf("[unkeyed 0..255 (digest of digests)] %s\n", bad ? "FAIL" : "OK");
        fails += bad;
    }

    if (fails == 0) {
        printf("\nALL OK\n");
        return 0;
    }
    printf("\n%d FAILURES\n", fails);
    return 1;
}
