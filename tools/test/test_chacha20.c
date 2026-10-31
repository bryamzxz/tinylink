/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KATs for ChaCha20 (crypto/chacha20.c):
 *  - RFC 8439 §2.3.2 (block function), §2.4.2 (the "sunscreen" vector),
 *    A.1 #1–#5 (keystream blocks) and A.2 #1–#3 (encryption), the
 *    multi-block ones at every in/out alignment 0..3 and in place;
 *  - HChaCha20, draft-irtf-cfrg-xchacha-03 §2.2.1;
 *  - differential: 5 000 random (key, nonce, counter, length, in/out
 *    offset, in-place) trials and block-aligned streaming against the
 *    1.3.2 implementation (ref/chacha20_132.c, compiled as ref_*), which
 *    the round-1.3.3 rewrite (C4) replaced.
 * The lifted API zeroes state[12] (counter) and state[13] (first nonce
 * word); vectors with a non-zero counter / nonce word set them after
 * chacha20_init. The host build runs the C rotate; the Xtensa `ssai` /
 * `src` path is checked on the compiled firmware objects (round 1.3.3
 * notes) and on the device by CONFIG_TINYLINK_BENCH_AEAD's KAT.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "chacha20.h"

/* ref/chacha20_ref.c: the 1.3.2 code under ref_* names. */
void ref_chacha20_init(struct chacha20_ctx *ctx, const uint8_t *key, uint64_t nonce);
void ref_chacha20(struct chacha20_ctx *ctx, uint8_t *out, const uint8_t *in, uint32_t len);
void ref_hchacha20(uint8_t *out, const uint8_t *nonce, const uint8_t *key);

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

static int hex2bin(uint8_t *out, const char *hex) {
    size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return (int)n;
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* RFC 8439 framing on top of the WG-shaped API: 12-byte nonce n,
 * 32-bit initial block counter. */
static void cc_setup(struct chacha20_ctx *ctx, const uint8_t key[32],
                     const uint8_t n12[12], uint32_t counter) {
    chacha20_init(ctx, key, (uint64_t)le32(n12 + 4) | ((uint64_t)le32(n12 + 8) << 32));
    ctx->state[12] = counter;
    ctx->state[13] = le32(n12);
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

/* RFC 8439 A.1 / A.2 (and §2.3.2): key, nonce, counter, plaintext
 * (NULL = 64 zero bytes, i.e. the keystream block), ciphertext. */
struct cc_vec {
    const char *name, *key, *nonce;
    uint32_t counter;
    const char *pt, *ct;
};

static const char a2_2_pt[] =
    "Any submission to the IETF intended by the Contributor for publication as all or part "
    "of an IETF Internet-Draft or RFC and any statement made within the context of an IETF "
    "activity is considered an \"IETF Contribution\". Such statements include oral statements "
    "in IETF sessions, as well as written and electronic communications made at any time or "
    "place, which are addressed to";
static const char a2_3_pt[] =
    "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\n"
    "All mimsy were the borogoves,\nAnd the mome raths outgrabe.";

static const struct cc_vec vecs[] = {
    { "rfc8439-2.3.2-block",
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "000000090000004a00000000", 1, NULL,
      "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
      "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e" },
    { "rfc8439-a.1-1",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "000000000000000000000000", 0, NULL,
      "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
      "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586" },
    { "rfc8439-a.1-2",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "000000000000000000000000", 1, NULL,
      "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
      "29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f" },
    { "rfc8439-a.1-3",
      "0000000000000000000000000000000000000000000000000000000000000001",
      "000000000000000000000000", 1, NULL,
      "3aeb5224ecf849929b9d828db1ced4dd832025e8018b8160b82284f3c949aa5a"
      "8eca00bbb4a73bdad192b5c42f73f2fd4e273644c8b36125a64addeb006c13a0" },
    { "rfc8439-a.1-4",
      "00ff000000000000000000000000000000000000000000000000000000000000",
      "000000000000000000000000", 2, NULL,
      "72d54dfbf12ec44b362692df94137f328fea8da73990265ec1bbbea1ae9af0ca"
      "13b25aa26cb4a648cb9b9d1be65b2c0924a66c54d545ec1b7374f4872e99f096" },
    { "rfc8439-a.1-5",
      "0000000000000000000000000000000000000000000000000000000000000000",
      "000000000000000000000002", 0, NULL,
      "c2c64d378cd536374ae204b9ef933fcd1a8b2288b3dfa49672ab765b54ee27c7"
      "8a970e0e955c14f3a88e741b97c286f75f8fc299e8148362fa198a39531bed6d" },
    { "rfc8439-a.2-2",
      "0000000000000000000000000000000000000000000000000000000000000001",
      "000000000000000000000002", 1, a2_2_pt,
      "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec"
      "2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d"
      "4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e527950"
      "42bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85a"
      "d00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259d"
      "c4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b"
      "0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6c"
      "cc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0b"
      "c39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f"
      "5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e6"
      "98ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab"
      "7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221" },
    { "rfc8439-a.2-3",
      "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0",
      "000000000000000000000002", 42, a2_3_pt,
      "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf"
      "166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553eb"
      "f39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f77"
      "04c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1" },
};

/* One vector at a given in/out byte offset (in place when inplace). */
static int run_vec(const struct cc_vec *v, unsigned in_off, unsigned out_off, int inplace) {
    uint8_t k[32], n[12], want[400];
    uint8_t inbuf[400 + 8] __attribute__((aligned(4)));
    uint8_t outbuf[400 + 8] __attribute__((aligned(4)));
    hex2bin(k, v->key);
    hex2bin(n, v->nonce);
    const size_t len = (size_t)hex2bin(want, v->ct);
    if (v->pt && strlen(v->pt) != len) {
        printf("[%s] FAIL: plaintext %zu B vs ciphertext %zu B\n", v->name, strlen(v->pt), len);
        return 1;
    }
    uint8_t *in = inbuf + in_off;
    uint8_t *out = inplace ? in : outbuf + out_off;
    if (v->pt) memcpy(in, v->pt, len); else memset(in, 0, len);
    struct chacha20_ctx ctx;
    cc_setup(&ctx, k, n, v->counter);
    chacha20(&ctx, out, in, (uint32_t)len);
    if (memcmp(out, want, len) != 0) {
        printf("[%s in+%u out+%u%s] FAIL\n  got:  ", v->name, in_off, out_off, inplace ? " in-place" : "");
        hexdump(out, len); printf("\n  want: "); hexdump(want, len); printf("\n");
        return 1;
    }
    /* The counter advanced by one per (possibly partial) block. */
    if (ctx.state[12] != v->counter + (uint32_t)((len + 63) / 64)) {
        printf("[%s counter] FAIL: %u\n", v->name, (unsigned)ctx.state[12]);
        return 1;
    }
    return 0;
}

static uint64_t rng_s = 0x9e3779b97f4a7c15ULL;
static uint32_t rnd(void) {
    rng_s ^= rng_s << 13; rng_s ^= rng_s >> 7; rng_s ^= rng_s << 17;
    return (uint32_t)(rng_s >> 16);
}

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

    /* RFC 8439 §2.3.2, A.1, A.2: aligned, then the multi-block ones at
     * every in/out alignment (fused aligned path, keystream + unaligned
     * XOR path, byte tail) and in place. */
    for (size_t i = 0; i < sizeof(vecs) / sizeof(vecs[0]); i++) {
        int f = run_vec(&vecs[i], 0, 0, 0);
        if (vecs[i].pt) {
            for (unsigned a = 0; a < 4; a++) {
                for (unsigned b = 0; b < 4; b++) f += run_vec(&vecs[i], a, b, 0);
                f += run_vec(&vecs[i], a, 0, 1);
            }
        }
        printf("[%s%s] %s\n", vecs[i].name, vecs[i].pt ? " (16 alignments + in place)" : "",
               f ? "FAIL" : "OK");
        fails += f != 0;
    }
    {   /* A.2 #1: 64 zero bytes, key 0, nonce 0, counter 0 = A.1 #1 */
        uint8_t z[64] = {0}, k0[32] = {0}, n0[12] = {0}, want[64];
        hex2bin(want, vecs[1].ct);
        cc_setup(&ctx, k0, n0, 0);
        chacha20(&ctx, z, z, 64);
        fails += check("rfc8439-a.2-1", z, want, 64);
    }

    /* HChaCha20 (draft-irtf-cfrg-xchacha-03 §2.2.1). */
    {
        uint8_t n16[16], want[32], got[32];
        hex2bin(n16, "000000090000004a0000000031415927");
        hex2bin(want, "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc");
        hchacha20(got, n16, key);
        fails += check("hchacha20-xchacha-2.2.1", got, want, 32);
    }

    /* Differential vs 1.3.2: random key / nonce / counter (incl. the
     * 2^32 wrap) / length 0..1600 / in and out offsets 0..3 / in place. */
    {
        static uint8_t in[1608] __attribute__((aligned(4)));
        static uint8_t o1[1608] __attribute__((aligned(4)));
        static uint8_t o2[1608] __attribute__((aligned(4)));
        int bad = 0;
        for (int t = 0; t < 5000 && !bad; t++) {
            uint8_t k[32];
            for (int i = 0; i < 32; i++) k[i] = (uint8_t)rnd();
            const uint64_t nonce = ((uint64_t)rnd() << 32) | rnd();
            const uint32_t len = rnd() % 1601;
            const unsigned ia = rnd() & 3, oa = rnd() & 3;
            const int inplace = (rnd() & 7) == 0;
            uint32_t ctr = rnd();
            if ((t & 15) == 1) ctr = 0xFFFFFFFFu - (rnd() & 7);
            const uint32_t w13 = (t & 3) ? 0 : rnd();
            for (uint32_t i = 0; i < len + 4; i++) in[i] = (uint8_t)rnd();
            struct chacha20_ctx a, b;
            chacha20_init(&a, k, nonce);
            ref_chacha20_init(&b, k, nonce);
            a.state[12] = b.state[12] = ctr;
            a.state[13] = b.state[13] = w13;
            if (inplace) {
                memcpy(o1 + ia, in + ia, len);
                memcpy(o2 + ia, in + ia, len);
                chacha20(&a, o1 + ia, o1 + ia, len);
                ref_chacha20(&b, o2 + ia, o2 + ia, len);
                bad = memcmp(o1 + ia, o2 + ia, len) != 0;
            } else {
                chacha20(&a, o1 + oa, in + ia, len);
                ref_chacha20(&b, o2 + oa, in + ia, len);
                bad = memcmp(o1 + oa, o2 + oa, len) != 0;
            }
            if (memcmp(&a, &b, sizeof(a)) != 0) bad = 1;
            if (bad) printf("  mismatch: trial %d len %u in+%u out+%u inplace %d ctr %08x\n",
                            t, (unsigned)len, ia, oa, inplace, (unsigned)ctr);
        }
        printf("[diff-vs-1.3.2: 5000 random lengths/alignments/counters] %s\n", bad ? "FAIL" : "OK");
        fails += bad;

        /* Streaming: block-aligned pieces continue the keystream. */
        bad = 0;
        for (int t = 0; t < 200 && !bad; t++) {
            uint8_t k[32];
            for (int i = 0; i < 32; i++) k[i] = (uint8_t)rnd();
            const uint64_t nonce = ((uint64_t)rnd() << 32) | rnd();
            const uint32_t len = 64 * (1 + rnd() % 24);
            for (uint32_t i = 0; i < len; i++) in[i] = (uint8_t)rnd();
            struct chacha20_ctx a, b;
            chacha20_init(&a, k, nonce);
            ref_chacha20_init(&b, k, nonce);
            ref_chacha20(&b, o2, in, len);
            for (uint32_t off = 0; off < len;) {
                uint32_t n = 64 * (1 + rnd() % 4);
                if (n > len - off) n = len - off;
                chacha20(&a, o1 + off, in + off, n);
                off += n;
            }
            bad = memcmp(o1, o2, len) != 0 || a.state[12] != b.state[12];
        }
        printf("[diff-vs-1.3.2: streaming in block-aligned pieces] %s\n", bad ? "FAIL" : "OK");
        fails += bad;

        uint8_t n16[16], h1[32], h2[32];
        bad = 0;
        for (int t = 0; t < 500 && !bad; t++) {
            uint8_t k[32];
            for (int i = 0; i < 32; i++) k[i] = (uint8_t)rnd();
            for (int i = 0; i < 16; i++) n16[i] = (uint8_t)rnd();
            hchacha20(h1, n16, k);
            ref_hchacha20(h2, n16, k);
            bad = memcmp(h1, h2, 32) != 0;
        }
        printf("[diff-vs-1.3.2: hchacha20 x500] %s\n", bad ? "FAIL" : "OK");
        fails += bad;
    }

    if (fails == 0) printf("\nALL OK\n");
    return fails ? 1 : 0;
}
