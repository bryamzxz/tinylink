/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for poly1305-donna against RFC 8439 §2.5.2 and the eleven
 * Appendix A.3 vectors (as shipped in mbedTLS's test_suite_poly1305.data;
 * #5–#11 hit the final-reduction / carry edge cases). nacl_box.c moved
 * from mbedtls_poly1305_mac() onto this code in round 1.3.2.
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

/* RFC 8439 Appendix A.3: key, tag, message (hex). */
static const struct {
    const char *name, *key, *tag, *msg;
} kA3[] = {
    { "a3-1",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "00000000000000000000000000000000",
      "0000000000000000000000000000000000000000000000000000000000000000"
          "0000000000000000000000000000000000000000000000000000000000000000" },
    { "a3-2",
      "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
      "36e5f6b5c5e06070f0efca96227a863e",
      "416e79207375626d697373696f6e20746f20746865204945544620696e74656e"
          "6465642062792074686520436f6e7472696275746f7220666f72207075626c69"
          "636174696f6e20617320616c6c206f722070617274206f6620616e2049455446"
          "20496e7465726e65742d4472616674206f722052464320616e6420616e792073"
          "746174656d656e74206d6164652077697468696e2074686520636f6e74657874"
          "206f6620616e204945544620616374697669747920697320636f6e7369646572"
          "656420616e20224945544620436f6e747269627574696f6e222e205375636820"
          "73746174656d656e747320696e636c756465206f72616c2073746174656d656e"
          "747320696e20494554462073657373696f6e732c2061732077656c6c20617320"
          "7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361"
          "74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c"
          "207768696368206172652061646472657373656420746f" },
    { "a3-3",
      "36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000",
      "f3477e7cd95417af89a6b8794c310cf0",
      "416e79207375626d697373696f6e20746f20746865204945544620696e74656e"
          "6465642062792074686520436f6e7472696275746f7220666f72207075626c69"
          "636174696f6e20617320616c6c206f722070617274206f6620616e2049455446"
          "20496e7465726e65742d4472616674206f722052464320616e6420616e792073"
          "746174656d656e74206d6164652077697468696e2074686520636f6e74657874"
          "206f6620616e204945544620616374697669747920697320636f6e7369646572"
          "656420616e20224945544620436f6e747269627574696f6e222e205375636820"
          "73746174656d656e747320696e636c756465206f72616c2073746174656d656e"
          "747320696e20494554462073657373696f6e732c2061732077656c6c20617320"
          "7772697474656e20616e6420656c656374726f6e696320636f6d6d756e696361"
          "74696f6e73206d61646520617420616e792074696d65206f7220706c6163652c"
          "207768696368206172652061646472657373656420746f" },
    { "a3-4",
      "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
      "4541669a7eaaee61e708dc7cbcc5eb62",
      "2754776173206272696c6c69672c20616e642074686520736c6974687920746f"
          "7665730a446964206779726520616e642067696d626c6520696e207468652077"
          "6162653a0a416c6c206d696d737920776572652074686520626f726f676f7665"
          "732c0a416e6420746865206d6f6d65207261746873206f757467726162652e" },
    { "a3-5",
      "0200000000000000000000000000000000000000000000000000000000000000",
      "03000000000000000000000000000000",
      "ffffffffffffffffffffffffffffffff" },
    { "a3-6",
      "02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
      "03000000000000000000000000000000",
      "02000000000000000000000000000000" },
    { "a3-7",
      "0100000000000000000000000000000000000000000000000000000000000000",
      "05000000000000000000000000000000",
      "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff"
          "11000000000000000000000000000000" },
    { "a3-8",
      "0100000000000000000000000000000000000000000000000000000000000000",
      "00000000000000000000000000000000",
      "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe"
          "01010101010101010101010101010101" },
    { "a3-9",
      "0200000000000000000000000000000000000000000000000000000000000000",
      "faffffffffffffffffffffffffffffff",
      "fdffffffffffffffffffffffffffffff" },
    { "a3-10",
      "0100000000000000040000000000000000000000000000000000000000000000",
      "14000000000000005500000000000000",
      "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000"
          "0000000000000000000000000000000001000000000000000000000000000000" },
    { "a3-11",
      "0100000000000000040000000000000000000000000000000000000000000000",
      "13000000000000000000000000000000",
      "e33594d7505e43b900000000000000003394d7505e4379cd0100000000000000"
          "00000000000000000000000000000000" },
};

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

    /* Appendix A.3, one-shot and fed one byte at a time. */
    for (size_t v = 0; v < sizeof(kA3) / sizeof(kA3[0]); v++) {
        uint8_t k[32], want[16], m[512];
        char name[48];
        unhex(k, sizeof(k), kA3[v].key);
        unhex(want, sizeof(want), kA3[v].tag);
        size_t mlen = unhex(m, sizeof(m), kA3[v].msg);

        poly1305_init(&ctx, k);
        poly1305_update(&ctx, m, mlen);
        poly1305_finish(&ctx, tag);
        snprintf(name, sizeof(name), "rfc8439-%s-oneshot", kA3[v].name);
        fails += check(name, tag, want, 16);

        poly1305_init(&ctx, k);
        for (size_t i = 0; i < mlen; i++) poly1305_update(&ctx, m + i, 1);
        poly1305_finish(&ctx, tag);
        snprintf(name, sizeof(name), "rfc8439-%s-bytewise", kA3[v].name);
        fails += check(name, tag, want, 16);
    }

    if (fails == 0) printf("\nALL OK\n");
    return fails ? 1 : 0;
}
