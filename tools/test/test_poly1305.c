/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for poly1305-donna against RFC 8439 §2.5.2.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "poly1305_donna.h"

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

/* RFC 8439 §2.5.2 */
static const uint8_t key[32] = {
    0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
    0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
    0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
    0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b,
};
static const char msg[] = "Cryptographic Forum Research Group";  /* 34 bytes */
static const uint8_t expected_tag[16] = {
    0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
    0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9,
};

int main(void) {
    int fails = 0;

    poly1305_context ctx;
    uint8_t tag[16];

    /* One-shot. */
    poly1305_init(&ctx, key);
    poly1305_update(&ctx, (const unsigned char *)msg, 34);
    poly1305_finish(&ctx, tag);
    fails += check("rfc8439-2.5.2-oneshot", tag, expected_tag, 16);

    /* Streamed in awkward chunks to exercise leftover handling. */
    poly1305_init(&ctx, key);
    poly1305_update(&ctx, (const unsigned char *)msg,      7);
    poly1305_update(&ctx, (const unsigned char *)msg + 7,  9);
    poly1305_update(&ctx, (const unsigned char *)msg + 16, 1);
    poly1305_update(&ctx, (const unsigned char *)msg + 17, 17);
    poly1305_finish(&ctx, tag);
    fails += check("rfc8439-2.5.2-streamed", tag, expected_tag, 16);

    if (fails == 0) printf("\nALL OK\n");
    return fails ? 1 : 0;
}
