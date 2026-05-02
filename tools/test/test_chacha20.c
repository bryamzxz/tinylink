/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for ChaCha20 against RFC 8439 §2.4.2 (the "sunscreen"
 * vector). Counter starts at 1 (state[12]=1 set explicitly after
 * chacha20_init since the lifted API zeros it). The §2.4.2 nonce has
 * its first 4 bytes zero, so leaving state[13]=0 (set by chacha20_init)
 * matches the spec without us touching it.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "chacha20.h"

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

/* RFC 8439 §2.4.2 */
static const uint8_t key[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
};
/* nonce 12 bytes: 00 00 00 00 00 00 00 4a 00 00 00 00.
 * First 4 bytes are zero → state[13] = 0 (chacha20_init default).
 * Lower 8 bytes packed as LE u64 → 0x000000004a000000. */
static const uint64_t nonce_lo64 = 0x000000004a000000ULL;
static const uint8_t plaintext[] =
    "Ladies and Gentlemen of the class of '99: If I could offer you "
    "only one tip for the future, sunscreen would be it.";
static const uint8_t expected_ct[114] = {
    0x6e,0x2e,0x35,0x9a,0x25,0x68,0xf9,0x80,
    0x41,0xba,0x07,0x28,0xdd,0x0d,0x69,0x81,
    0xe9,0x7e,0x7a,0xec,0x1d,0x43,0x60,0xc2,
    0x0a,0x27,0xaf,0xcc,0xfd,0x9f,0xae,0x0b,
    0xf9,0x1b,0x65,0xc5,0x52,0x47,0x33,0xab,
    0x8f,0x59,0x3d,0xab,0xcd,0x62,0xb3,0x57,
    0x16,0x39,0xd6,0x24,0xe6,0x51,0x52,0xab,
    0x8f,0x53,0x0c,0x35,0x9f,0x08,0x61,0xd8,
    0x07,0xca,0x0d,0xbf,0x50,0x0d,0x6a,0x61,
    0x56,0xa3,0x8e,0x08,0x8a,0x22,0xb6,0x5e,
    0x52,0xbc,0x51,0x4d,0x16,0xcc,0xf8,0x06,
    0x81,0x8c,0xe9,0x1a,0xb7,0x79,0x37,0x36,
    0x5a,0xf9,0x0b,0xbf,0x74,0xa3,0x5b,0xe6,
    0xb4,0x0b,0x8e,0xed,0xf2,0x78,0x5e,0x42,
    0x87,0x4d,
};

int main(void) {
    const size_t mlen = sizeof(plaintext) - 1;  /* drop NUL */
    if (mlen != sizeof(expected_ct)) {
        printf("[plaintext-len] FAIL: %zu vs %zu\n", mlen, sizeof(expected_ct));
        return 1;
    }
    int fails = 0;

    uint8_t ct[114];
    struct chacha20_ctx ctx;
    chacha20_init(&ctx, key, nonce_lo64);
    ctx.state[12] = 1;  /* RFC §2.4.2 starts at counter=1 */
    chacha20(&ctx, ct, plaintext, (uint32_t)mlen);
    fails += check("rfc8439-2.4.2-encrypt", ct, expected_ct, mlen);

    /* Round-trip: decrypt by re-XOR with same keystream. */
    uint8_t pt[114];
    chacha20_init(&ctx, key, nonce_lo64);
    ctx.state[12] = 1;
    chacha20(&ctx, pt, ct, (uint32_t)mlen);
    fails += check("rfc8439-2.4.2-decrypt", pt, plaintext, mlen);

    if (fails == 0) printf("\nALL OK\n");
    return fails ? 1 : 0;
}
