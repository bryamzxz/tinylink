// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// HPACK (hpack.c, round 1.3.4 D1): RFC 7541 Appendix C.1-C.6 (integers,
// literals, requests and responses with and without Huffman, dynamic
// table sizes after every block, C.5/C.6 with a 256-byte table), each
// block also fed byte by byte and split at random points; every Huffman
// symbol and the §5.2 padding / EOS rules against an independent copy of
// Appendix B (explicit codes, not hpack.c's canonical tables); malformed
// blocks; the device configuration (table 0: insertions evict, dynamic
// references fail); the capture caps; field-name / value checks; the
// encoder (C.2.2 bytes, static name indices); a fixed-seed round-trip
// fuzz against an in-test reference encoder with its own dynamic-table
// model (indexing, eviction, size updates, Huffman); and a fixed-seed
// garbage fuzz (run it under `make asan`).
//
// The Appendix C hex below was cross-checked with nghttp2's inflater
// (same header lists and table sizes) when this test was written.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hpack.h"

static int s_fails;

static void check(const char *name, int ok)
{
    printf("[%s] %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) s_fails++;
}

static size_t unhex(const char *h, uint8_t *o)
{
    size_t n = strlen(h) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned x;
        sscanf(h + 2 * i, "%2x", &x);
        o[i] = (uint8_t)x;
    }
    return n;
}

/* ---- RFC 7541 Appendix C ---------------------------------------------- */

typedef struct { const char *hex; const char *hdrs; unsigned table_size; } vec_t;

static const vec_t C2[] = {
  { "400a637573746f6d2d6b65790d637573746f6d2d686561646572", "custom-key: custom-header\n", 55 },
  { "040c2f73616d706c652f70617468", ":path: /sample/path\n", 0 },
  { "100870617373776f726406736563726574", "password: secret\n", 0 },
  { "82", ":method: GET\n", 0 },
};
static const vec_t C3[] = {
  { "828684410f7777772e6578616d706c652e636f6d",
    ":method: GET\n:scheme: http\n:path: /\n:authority: www.example.com\n", 57 },
  { "828684be58086e6f2d6361636865",
    ":method: GET\n:scheme: http\n:path: /\n:authority: www.example.com\ncache-control: no-cache\n", 110 },
  { "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
    ":method: GET\n:scheme: https\n:path: /index.html\n:authority: www.example.com\ncustom-key: custom-value\n", 164 },
};
static const vec_t C4[] = {
  { "828684418cf1e3c2e5f23a6ba0ab90f4ff",
    ":method: GET\n:scheme: http\n:path: /\n:authority: www.example.com\n", 57 },
  { "828684be5886a8eb10649cbf",
    ":method: GET\n:scheme: http\n:path: /\n:authority: www.example.com\ncache-control: no-cache\n", 110 },
  { "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf",
    ":method: GET\n:scheme: https\n:path: /index.html\n:authority: www.example.com\ncustom-key: custom-value\n", 164 },
};
static const vec_t C5[] = {
  { "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d",
    ":status: 302\ncache-control: private\ndate: Mon, 21 Oct 2013 20:13:21 GMT\nlocation: https://www.example.com\n", 222 },
  { "4803333037c1c0bf",
    ":status: 307\ncache-control: private\ndate: Mon, 21 Oct 2013 20:13:21 GMT\nlocation: https://www.example.com\n", 222 },
  { "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
    ":status: 200\ncache-control: private\ndate: Mon, 21 Oct 2013 20:13:22 GMT\nlocation: https://www.example.com\ncontent-encoding: gzip\nset-cookie: foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1\n", 215 },
};
static const vec_t C6[] = {
  { "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3",
    ":status: 302\ncache-control: private\ndate: Mon, 21 Oct 2013 20:13:21 GMT\nlocation: https://www.example.com\n", 222 },
  { "4883640effc1c0bf",
    ":status: 307\ncache-control: private\ndate: Mon, 21 Oct 2013 20:13:21 GMT\nlocation: https://www.example.com\n", 222 },
  { "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
    ":status: 200\ncache-control: private\ndate: Mon, 21 Oct 2013 20:13:22 GMT\nlocation: https://www.example.com\ncontent-encoding: gzip\nset-cookie: foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1\n", 215 },
};

/* "name: value\n" per field, from the captures. */
typedef struct {
    char   buf[4096];
    size_t len;
    int    fields;
    int    cut;
    uint8_t flags[64];
} collect_t;

static int collect(void *ctx, const hpack_field_t *f)
{
    collect_t *c = ctx;
    if (f->flags & (HPACK_F_NAME_CUT | HPACK_F_VALUE_CUT)) c->cut++;
    if (c->fields < 64) c->flags[c->fields] = f->flags;
    c->fields++;
    if (c->len + f->name_len + f->value_len + 3 < sizeof(c->buf)) {
        memcpy(c->buf + c->len, f->name, f->name_len);
        c->len += f->name_len;
        memcpy(c->buf + c->len, ": ", 2);
        c->len += 2;
        memcpy(c->buf + c->len, f->value, f->value_len);
        c->len += f->value_len;
        c->buf[c->len++] = '\n';
    }
    c->buf[c->len] = 0;
    return 0;
}

static uint32_t s_rng = 0x1234567u;
static uint32_t rnd(void)
{
    s_rng ^= s_rng << 13; s_rng ^= s_rng >> 17; s_rng ^= s_rng << 5;
    return s_rng;
}

/* mode 0: whole block; 1: byte by byte; 2: random splits */
static int decode_block(hpack_dec_t *d, const uint8_t *in, size_t len, int mode,
                        collect_t *c)
{
    memset(c, 0, sizeof(*c));
    hpack_dec_begin(d);
    size_t off = 0;
    while (off < len) {
        size_t n = len - off;
        if (mode == 1) n = 1;
        else if (mode == 2) n = 1 + rnd() % n;
        int rc = hpack_dec_feed(d, in + off, n, collect, c);
        if (rc != HPACK_OK) return rc;
        off += n;
    }
    return hpack_dec_end(d);
}

static void run_seq(const char *name, const vec_t *v, int n, uint32_t tsize)
{
    static uint8_t tab[4096];
    for (int mode = 0; mode < 3; mode++) {
        hpack_dec_t d;
        hpack_dec_init(&d, tab, sizeof(tab), tsize);
        int ok = 1;
        for (int i = 0; i < n; i++) {
            uint8_t in[512];
            size_t len = unhex(v[i].hex, in);
            collect_t c;
            int rc = decode_block(&d, in, len, mode, &c);
            if (rc != HPACK_OK || strcmp(c.buf, v[i].hdrs) != 0 || c.cut ||
                d.size != v[i].table_size) {
                ok = 0;
                printf("  %s[%d] mode %d: rc %d size %u\n%s", name, i, mode, rc,
                       (unsigned)d.size, c.buf);
            }
        }
        char nm[64];
        snprintf(nm, sizeof(nm), "%s_%s", name,
                 mode == 0 ? "block" : mode == 1 ? "bytewise" : "split");
        check(nm, ok);
    }
}

static void test_appendix_c(void)
{
    for (int i = 0; i < 4; i++) {
        char nm[32];
        snprintf(nm, sizeof(nm), "c2_%d", i + 1);
        run_seq(nm, &C2[i], 1, 4096);
    }
    run_seq("c3_requests", C3, 3, 4096);
    run_seq("c4_requests_huffman", C4, 3, 4096);
    run_seq("c5_responses_t256", C5, 3, 256);
    run_seq("c6_responses_huffman_t256", C6, 3, 256);
}

/* C.1 integers + size-update decoding of the same values. */
static void test_integers(void)
{
    uint8_t b[8];
    size_t n = hpack_put_int(b, sizeof(b), 0x00, 5, 10);
    check("c1_1_int10_prefix5", n == 1 && b[0] == 0x0a);
    n = hpack_put_int(b, sizeof(b), 0x00, 5, 1337);
    check("c1_2_int1337_prefix5", n == 3 && b[0] == 0x1f && b[1] == 0x9a && b[2] == 0x0a);
    n = hpack_put_int(b, sizeof(b), 0x00, 8, 42);
    check("c1_3_int42_prefix8", n == 1 && b[0] == 0x2a);
    n = hpack_put_int(b, sizeof(b), 0x00, 5, 31);
    check("int31_prefix5_boundary", n == 2 && b[0] == 0x1f && b[1] == 0x00);
    check("int_no_room", hpack_put_int(b, 2, 0x00, 5, 1337) == 0);

    hpack_dec_t d;
    static uint8_t tab[4096];
    hpack_dec_init(&d, tab, sizeof(tab), 4096);
    const uint8_t up[] = { 0x3f, 0x9a, 0x0a };   /* size update to 1337 */
    collect_t c;
    int rc = decode_block(&d, up, sizeof(up), 1, &c);
    check("size_update_1337_decoded", rc == HPACK_OK && d.size_limit == 1337 && c.fields == 0);
    const uint8_t up2[] = { 0x3f, 0xe1, 0x1f, 0x20 };   /* 4000, then 0, in one block */
    rc = decode_block(&d, up2, sizeof(up2), 0, &c);
    check("size_updates_back_to_back", rc == HPACK_OK && d.size_limit == 0);
}

/* ---- Huffman ------------------------------------------------------------ */

/* RFC 7541 Appendix B: (bits, code) for symbols 0..256. */
static const struct { uint8_t bits; uint32_t code; } kHuff[257] = {
    {13, 0x1ff8}, {23, 0x7fffd8}, {28, 0xfffffe2}, {28, 0xfffffe3},
    {28, 0xfffffe4}, {28, 0xfffffe5}, {28, 0xfffffe6}, {28, 0xfffffe7},
    {28, 0xfffffe8}, {24, 0xffffea}, {30, 0x3ffffffc}, {28, 0xfffffe9},
    {28, 0xfffffea}, {30, 0x3ffffffd}, {28, 0xfffffeb}, {28, 0xfffffec},
    {28, 0xfffffed}, {28, 0xfffffee}, {28, 0xfffffef}, {28, 0xffffff0},
    {28, 0xffffff1}, {28, 0xffffff2}, {30, 0x3ffffffe}, {28, 0xffffff3},
    {28, 0xffffff4}, {28, 0xffffff5}, {28, 0xffffff6}, {28, 0xffffff7},
    {28, 0xffffff8}, {28, 0xffffff9}, {28, 0xffffffa}, {28, 0xffffffb},
    {6, 0x14}, {10, 0x3f8}, {10, 0x3f9}, {12, 0xffa}, {13, 0x1ff9}, {6, 0x15},
    {8, 0xf8}, {11, 0x7fa}, {10, 0x3fa}, {10, 0x3fb}, {8, 0xf9}, {11, 0x7fb},
    {8, 0xfa}, {6, 0x16}, {6, 0x17}, {6, 0x18}, {5, 0x0}, {5, 0x1}, {5, 0x2},
    {6, 0x19}, {6, 0x1a}, {6, 0x1b}, {6, 0x1c}, {6, 0x1d}, {6, 0x1e},
    {6, 0x1f}, {7, 0x5c}, {8, 0xfb}, {15, 0x7ffc}, {6, 0x20}, {12, 0xffb},
    {10, 0x3fc}, {13, 0x1ffa}, {6, 0x21}, {7, 0x5d}, {7, 0x5e}, {7, 0x5f},
    {7, 0x60}, {7, 0x61}, {7, 0x62}, {7, 0x63}, {7, 0x64}, {7, 0x65},
    {7, 0x66}, {7, 0x67}, {7, 0x68}, {7, 0x69}, {7, 0x6a}, {7, 0x6b},
    {7, 0x6c}, {7, 0x6d}, {7, 0x6e}, {7, 0x6f}, {7, 0x70}, {7, 0x71},
    {7, 0x72}, {8, 0xfc}, {7, 0x73}, {8, 0xfd}, {13, 0x1ffb}, {19, 0x7fff0},
    {13, 0x1ffc}, {14, 0x3ffc}, {6, 0x22}, {15, 0x7ffd}, {5, 0x3}, {6, 0x23},
    {5, 0x4}, {6, 0x24}, {5, 0x5}, {6, 0x25}, {6, 0x26}, {6, 0x27}, {5, 0x6},
    {7, 0x74}, {7, 0x75}, {6, 0x28}, {6, 0x29}, {6, 0x2a}, {5, 0x7},
    {6, 0x2b}, {7, 0x76}, {6, 0x2c}, {5, 0x8}, {5, 0x9}, {6, 0x2d}, {7, 0x77},
    {7, 0x78}, {7, 0x79}, {7, 0x7a}, {7, 0x7b}, {15, 0x7ffe}, {11, 0x7fc},
    {14, 0x3ffd}, {13, 0x1ffd}, {28, 0xffffffc}, {20, 0xfffe6},
    {22, 0x3fffd2}, {20, 0xfffe7}, {20, 0xfffe8}, {22, 0x3fffd3},
    {22, 0x3fffd4}, {22, 0x3fffd5}, {23, 0x7fffd9}, {22, 0x3fffd6},
    {23, 0x7fffda}, {23, 0x7fffdb}, {23, 0x7fffdc}, {23, 0x7fffdd},
    {23, 0x7fffde}, {24, 0xffffeb}, {23, 0x7fffdf}, {24, 0xffffec},
    {24, 0xffffed}, {22, 0x3fffd7}, {23, 0x7fffe0}, {24, 0xffffee},
    {23, 0x7fffe1}, {23, 0x7fffe2}, {23, 0x7fffe3}, {23, 0x7fffe4},
    {21, 0x1fffdc}, {22, 0x3fffd8}, {23, 0x7fffe5}, {22, 0x3fffd9},
    {23, 0x7fffe6}, {23, 0x7fffe7}, {24, 0xffffef}, {22, 0x3fffda},
    {21, 0x1fffdd}, {20, 0xfffe9}, {22, 0x3fffdb}, {22, 0x3fffdc},
    {23, 0x7fffe8}, {23, 0x7fffe9}, {21, 0x1fffde}, {23, 0x7fffea},
    {22, 0x3fffdd}, {22, 0x3fffde}, {24, 0xfffff0}, {21, 0x1fffdf},
    {22, 0x3fffdf}, {23, 0x7fffeb}, {23, 0x7fffec}, {21, 0x1fffe0},
    {21, 0x1fffe1}, {22, 0x3fffe0}, {21, 0x1fffe2}, {23, 0x7fffed},
    {22, 0x3fffe1}, {23, 0x7fffee}, {23, 0x7fffef}, {20, 0xfffea},
    {22, 0x3fffe2}, {22, 0x3fffe3}, {22, 0x3fffe4}, {23, 0x7ffff0},
    {22, 0x3fffe5}, {22, 0x3fffe6}, {23, 0x7ffff1}, {26, 0x3ffffe0},
    {26, 0x3ffffe1}, {20, 0xfffeb}, {19, 0x7fff1}, {22, 0x3fffe7},
    {23, 0x7ffff2}, {22, 0x3fffe8}, {25, 0x1ffffec}, {26, 0x3ffffe2},
    {26, 0x3ffffe3}, {26, 0x3ffffe4}, {27, 0x7ffffde}, {27, 0x7ffffdf},
    {26, 0x3ffffe5}, {24, 0xfffff1}, {25, 0x1ffffed}, {19, 0x7fff2},
    {21, 0x1fffe3}, {26, 0x3ffffe6}, {27, 0x7ffffe0}, {27, 0x7ffffe1},
    {26, 0x3ffffe7}, {27, 0x7ffffe2}, {24, 0xfffff2}, {21, 0x1fffe4},
    {21, 0x1fffe5}, {26, 0x3ffffe8}, {26, 0x3ffffe9}, {28, 0xffffffd},
    {27, 0x7ffffe3}, {27, 0x7ffffe4}, {27, 0x7ffffe5}, {20, 0xfffec},
    {24, 0xfffff3}, {20, 0xfffed}, {21, 0x1fffe6}, {22, 0x3fffe9},
    {21, 0x1fffe7}, {21, 0x1fffe8}, {23, 0x7ffff3}, {22, 0x3fffea},
    {22, 0x3fffeb}, {25, 0x1ffffee}, {25, 0x1ffffef}, {24, 0xfffff4},
    {24, 0xfffff5}, {26, 0x3ffffea}, {23, 0x7ffff4}, {26, 0x3ffffeb},
    {27, 0x7ffffe6}, {26, 0x3ffffec}, {26, 0x3ffffed}, {27, 0x7ffffe7},
    {27, 0x7ffffe8}, {27, 0x7ffffe9}, {27, 0x7ffffea}, {27, 0x7ffffeb},
    {28, 0xffffffe}, {27, 0x7ffffec}, {27, 0x7ffffed}, {27, 0x7ffffee},
    {27, 0x7ffffef}, {27, 0x7fffff0}, {26, 0x3ffffee}, {30, 0x3fffffff},
};

/* Appendix B encoder with EOS-prefix padding; `eos` appends the EOS
 * symbol itself (a decoding error), `pad_bits` forces extra padding. */
static size_t huff_enc(const uint8_t *s, size_t n, uint8_t *out, int eos, int pad_byte)
{
    uint64_t acc = 0;
    unsigned nb = 0;
    size_t o = 0;
    for (size_t i = 0; i <= n; i++) {
        unsigned sym;
        if (i < n) sym = s[i];
        else if (eos) sym = 256;
        else break;
        acc = (acc << kHuff[sym].bits) | kHuff[sym].code;
        nb += kHuff[sym].bits;
        while (nb >= 8) {
            out[o++] = (uint8_t)(acc >> (nb - 8));
            nb -= 8;
        }
    }
    if (nb) out[o++] = (uint8_t)((acc << (8 - nb)) | (0xffu >> nb));
    if (pad_byte) out[o++] = 0xff;
    return o;
}

/* A literal-without-indexing field "x: <huffman value>" block. */
static size_t huff_field(const uint8_t *val, size_t n, uint8_t *blk, int eos, int pad_byte)
{
    uint8_t enc[512];
    size_t el = huff_enc(val, n, enc, eos, pad_byte);
    size_t o = 0;
    blk[o++] = 0x00;
    blk[o++] = 0x01;
    blk[o++] = 'x';
    o += hpack_put_int(blk + o, 8, 0x80, 7, (uint32_t)el);
    memcpy(blk + o, enc, el);
    return o + el;
}

static void test_huffman(void)
{
    hpack_dec_t d;
    collect_t c;
    uint8_t blk[600];
    int bad = 0;
    for (int sym = 0; sym < 256; sym++) {
        uint8_t v = (uint8_t)sym;
        size_t n = huff_field(&v, 1, blk, 0, 0);
        hpack_dec_init(&d, NULL, 0, 0);
        int rc = decode_block(&d, blk, n, 0, &c);
        if (rc != HPACK_OK || c.fields != 1 || c.len != 5 || (uint8_t)c.buf[3] != v) bad++;
    }
    check("huffman_every_symbol", bad == 0);

    bad = 0;
    for (int t = 0; t < 3000; t++) {
        uint8_t v[200];
        size_t vl = rnd() % sizeof(v);
        for (size_t i = 0; i < vl; i++) v[i] = (uint8_t)(t & 1 ? rnd() : 0x20 + rnd() % 95);
        size_t n = huff_field(v, vl, blk, 0, 0);
        hpack_dec_init(&d, NULL, 0, 0);
        int rc = decode_block(&d, blk, n, (int)(t % 3), &c);
        size_t cap = vl < HPACK_VALUE_CAP ? vl : HPACK_VALUE_CAP;
        if (rc != HPACK_OK || c.fields != 1 || memcmp(c.buf + 3, v, cap) != 0 ||
            (vl > HPACK_VALUE_CAP) != (c.cut == 1)) bad++;
    }
    check("huffman_random_strings_3000", bad == 0);

    const uint8_t hi[] = { 'h', 'i' };
    size_t n = huff_field(hi, 2, blk, 1, 0);
    hpack_dec_init(&d, NULL, 0, 0);
    check("huffman_eos_rejected", decode_block(&d, blk, n, 0, &c) == HPACK_ERR);
    n = huff_field(hi, 2, blk, 0, 1);
    hpack_dec_init(&d, NULL, 0, 0);
    check("huffman_padding_over_7_bits_rejected", decode_block(&d, blk, n, 0, &c) == HPACK_ERR);
    /* "00000000" is 8 × 5 bits = 5 whole bytes: an extra 0xff is exactly
     * 8 bits of padding, one too many. */
    const uint8_t zeros[] = "00000000";
    n = huff_field(zeros, 8, blk, 0, 1);
    hpack_dec_init(&d, NULL, 0, 0);
    check("huffman_padding_exactly_8_bits_rejected", decode_block(&d, blk, n, 0, &c) == HPACK_ERR);
    n = huff_field(zeros, 8, blk, 0, 0);
    hpack_dec_init(&d, NULL, 0, 0);
    check("huffman_no_padding_ok", decode_block(&d, blk, n, 0, &c) == HPACK_OK && c.len == 12);
    /* "a" = 00011 (5 bits) + 111 padding = 0x1f; flip a padding bit. */
    const uint8_t bad_pad[] = { 0x00, 0x01, 'x', 0x81, 0x1e };
    hpack_dec_init(&d, NULL, 0, 0);
    check("huffman_padding_not_eos_prefix_rejected",
          decode_block(&d, bad_pad, sizeof(bad_pad), 0, &c) == HPACK_ERR);
    const uint8_t ok_pad[] = { 0x00, 0x01, 'x', 0x81, 0x1f };
    hpack_dec_init(&d, NULL, 0, 0);
    check("huffman_padding_7_ones_ok",
          decode_block(&d, ok_pad, sizeof(ok_pad), 0, &c) == HPACK_OK && c.len == 5 &&
          c.buf[3] == 'a');
    const uint8_t empty_h[] = { 0x00, 0x01, 'x', 0x80 };
    hpack_dec_init(&d, NULL, 0, 0);
    check("huffman_empty_string_ok",
          decode_block(&d, empty_h, sizeof(empty_h), 0, &c) == HPACK_OK && c.fields == 1);
}

/* ---- malformed / device configuration ----------------------------------- */

static void test_malformed(void)
{
    hpack_dec_t d;
    collect_t c;
    static uint8_t tab[4096];
#define REJ(name, ...) do { \
        const uint8_t b_[] = { __VA_ARGS__ }; \
        hpack_dec_init(&d, tab, sizeof(tab), 4096); \
        check(name, decode_block(&d, b_, sizeof(b_), 0, &c) == HPACK_ERR); \
    } while (0)
    REJ("index_0_rejected", 0x80);
    REJ("dynamic_index_past_table_rejected", 0xbe);
    REJ("literal_name_index_past_table_rejected", 0x7f, 0x00, 0x01, 'a');
    REJ("size_update_above_max_rejected", 0x3f, 0xe2, 0x1f);          /* 4097 */
    REJ("size_update_after_field_rejected", 0x82, 0x20);
    REJ("int_over_31_bits_rejected", 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f);
    REJ("int_too_many_bytes_rejected", 0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00);
    REJ("string_over_64k_rejected", 0x00, 0x7f, 0x82, 0x80, 0x04);   /* 65 665 */
    REJ("block_ends_mid_int", 0xff);
    REJ("block_ends_mid_string", 0x00, 0x05, 'a', 'b');
    REJ("block_ends_before_value", 0x04);
#undef REJ
    /* A size update in a later block, after a field in an earlier one. */
    hpack_dec_init(&d, tab, sizeof(tab), 4096);
    const uint8_t f1[] = { 0x82 }, f2[] = { 0x20, 0x82 };
    int rc1 = decode_block(&d, f1, 1, 0, &c);
    int rc2 = decode_block(&d, f2, 2, 0, &c);
    check("size_update_at_next_block_start_ok", rc1 == HPACK_OK && rc2 == HPACK_OK);
}

static void test_device_table_zero(void)
{
    /* What tinylink runs: SETTINGS_HEADER_TABLE_SIZE 0, no storage. */
    hpack_dec_t d;
    collect_t c;
    uint8_t in[512];
    hpack_dec_init(&d, NULL, 0, 0);
    size_t n = unhex(C3[0].hex, in);   /* inserts :authority — evicted at once */
    int rc = decode_block(&d, in, n, 0, &c);
    check("t0_insert_evicts", rc == HPACK_OK && strcmp(c.buf, C3[0].hdrs) == 0 &&
                              d.count == 0 && d.size == 0);
    n = unhex(C3[1].hex, in);          /* references dynamic index 62 */
    check("t0_dynamic_reference_rejected", decode_block(&d, in, n, 0, &c) == HPACK_ERR);
    hpack_dec_init(&d, NULL, 0, 0);
    const uint8_t z[] = { 0x20, 0x88 }, one[] = { 0x21 };
    rc = decode_block(&d, z, sizeof(z), 0, &c);
    check("t0_size_update_0_ok", rc == HPACK_OK && c.fields == 1 && strcmp(c.buf, ":status: 200\n") == 0);
    hpack_dec_init(&d, NULL, 0, 0);
    check("t0_size_update_1_rejected", decode_block(&d, one, 1, 0, &c) == HPACK_ERR);
    /* C.5 / C.6 responses on the device configuration: the first block
     * decodes, the second (dynamic references) is refused. */
    hpack_dec_init(&d, NULL, 0, 0);
    n = unhex(C6[0].hex, in);
    rc = decode_block(&d, in, n, 2, &c);
    check("t0_c6_1_decodes", rc == HPACK_OK && strcmp(c.buf, C6[0].hdrs) == 0);
    n = unhex(C6[1].hex, in);
    check("t0_c6_2_rejected", decode_block(&d, in, n, 0, &c) == HPACK_ERR);
}

static void test_caps_and_flags(void)
{
    hpack_dec_t d;
    collect_t c;
    static uint8_t tab[4096];
    uint8_t blk[300];
    size_t o = 0;
    blk[o++] = 0x00;
    blk[o++] = 40;                                   /* 40-char name */
    for (int i = 0; i < 40; i++) blk[o++] = 'a' + i % 26;
    blk[o++] = 100;                                  /* 100-char value */
    for (int i = 0; i < 100; i++) blk[o++] = '0' + i % 10;
    hpack_dec_init(&d, NULL, 0, 0);
    hpack_field_t got;
    memset(&got, 0, sizeof(got));
    int rc = decode_block(&d, blk, o, 1, &c);
    check("cap_cut_reported", rc == HPACK_OK && c.fields == 1 && c.cut == 1 &&
          (c.flags[0] & HPACK_F_NAME_CUT) && (c.flags[0] & HPACK_F_VALUE_CUT));
    check("cap_prefix_kept", c.len == HPACK_NAME_CAP + 2 + HPACK_VALUE_CAP + 1 &&
          c.buf[0] == 'a' && c.buf[HPACK_NAME_CAP + 2] == '0');
    blk[0] = 0x40;                                   /* same, incremental */
    hpack_dec_init(&d, tab, sizeof(tab), 4096);
    check("cap_cut_entry_unsupported",
          decode_block(&d, blk, o, 0, &c) == HPACK_ERR_UNSUPPORTED);

#define FLAGS(name, want, ...) do { \
        const uint8_t b_[] = { __VA_ARGS__ }; \
        hpack_dec_init(&d, NULL, 0, 0); \
        int r_ = decode_block(&d, b_, sizeof(b_), 0, &c); \
        check(name, r_ == HPACK_OK && c.fields == 1 && \
                    (c.flags[0] & 0x1c) == (want)); \
    } while (0)
    FLAGS("flags_clean", 0, 0x00, 0x02, 'a', '-', 0x01, 'v');
    FLAGS("flags_pseudo_ok", 0, 0x00, 0x07, ':', 's', 't', 'a', 't', 'u', 's', 0x03, '2', '0', '0');
    FLAGS("flags_uppercase_name", HPACK_F_NAME_UPPER, 0x00, 0x02, 'A', 'b', 0x00);
    FLAGS("flags_space_in_name", HPACK_F_NAME_BAD, 0x00, 0x03, 'a', ' ', 'b', 0x00);
    FLAGS("flags_colon_inside_name", HPACK_F_NAME_BAD, 0x00, 0x03, 'a', ':', 'b', 0x00);
    FLAGS("flags_lone_colon", HPACK_F_NAME_BAD, 0x00, 0x01, ':', 0x00);
    FLAGS("flags_empty_name", HPACK_F_NAME_BAD, 0x00, 0x00, 0x01, 'v');
    FLAGS("flags_obs_text_name", HPACK_F_NAME_BAD, 0x00, 0x01, 0xe9, 0x00);
    FLAGS("flags_leading_space", HPACK_F_VALUE_BAD, 0x00, 0x01, 'a', 0x02, ' ', 'v');
    FLAGS("flags_trailing_tab", HPACK_F_VALUE_BAD, 0x00, 0x01, 'a', 0x02, 'v', '\t');
    FLAGS("flags_cr_in_value", HPACK_F_VALUE_BAD, 0x00, 0x01, 'a', 0x03, 'v', '\r', 'w');
    FLAGS("flags_nul_in_value", HPACK_F_VALUE_BAD, 0x00, 0x01, 'a', 0x01, 0x00);
    FLAGS("flags_obs_text_value_ok", 0, 0x00, 0x01, 'a', 0x02, 0xe9, 'x');
    FLAGS("flags_inner_space_ok", 0, 0x00, 0x01, 'a', 0x03, 'v', ' ', 'w');
#undef FLAGS
    const uint8_t never[] = { 0x10, 0x01, 'a', 0x01, 'b' };
    hpack_dec_init(&d, NULL, 0, 0);
    rc = decode_block(&d, never, sizeof(never), 0, &c);
    check("flags_never_indexed", rc == HPACK_OK && (c.flags[0] & HPACK_F_NEVER_INDEX));
}

/* ---- encoder -------------------------------------------------------------- */

static void test_encoder(void)
{
    uint8_t out[128], want[64];
    size_t n = hpack_put_field(out, sizeof(out), ":path", 5, "/sample/path", 12);
    size_t wl = unhex(C2[1].hex, want);
    check("enc_c2_2_bytes", n == wl && memcmp(out, want, wl) == 0);
    n = hpack_put_field(out, sizeof(out), "content-type", 12, "application/json", 16);
    check("enc_static_index_31", n == 2 + 1 + 16 && out[0] == 0x0f && out[1] == 0x10 &&
                                 out[2] == 16);
    n = hpack_put_field(out, sizeof(out), "custom-key", 10, "custom-header", 13);
    check("enc_new_name", n == 1 + 1 + 10 + 1 + 13 && out[0] == 0x00 && out[1] == 10);
    check("enc_no_room", hpack_put_field(out, 20, "custom-key", 10, "custom-header", 13) == 0);
    check("enc_static_names", hpack_static_name_index(":authority", 10) == 1 &&
          hpack_static_name_index(":method", 7) == 2 && hpack_static_name_index(":path", 5) == 4 &&
          hpack_static_name_index(":scheme", 7) == 6 &&
          hpack_static_name_index("content-length", 14) == 28 &&
          hpack_static_name_index("retry-after", 11) == 53 &&
          hpack_static_name_index("www-authenticate", 16) == 61 &&
          hpack_static_name_index("x-nope", 6) == 0);

    /* The request block h2_core builds, back through the decoder. */
    uint8_t blk[256];
    size_t o = 0;
    blk[o++] = 0x20;
    o += hpack_put_field(blk + o, sizeof(blk) - o, ":method", 7, "POST", 4);
    o += hpack_put_field(blk + o, sizeof(blk) - o, ":scheme", 7, "https", 5);
    o += hpack_put_field(blk + o, sizeof(blk) - o, ":path", 5, "/machine/map", 12);
    o += hpack_put_field(blk + o, sizeof(blk) - o, ":authority", 10, "controlplane.tailscale.com", 26);
    o += hpack_put_field(blk + o, sizeof(blk) - o, "content-type", 12, "application/json", 16);
    o += hpack_put_field(blk + o, sizeof(blk) - o, "content-length", 14, "612", 3);
    hpack_dec_t d;
    collect_t c;
    hpack_dec_init(&d, NULL, 0, 0);
    int rc = decode_block(&d, blk, o, 1, &c);
    check("enc_request_roundtrip", rc == HPACK_OK && strcmp(c.buf,
          ":method: POST\n:scheme: https\n:path: /machine/map\n"
          ":authority: controlplane.tailscale.com\ncontent-type: application/json\n"
          "content-length: 612\n") == 0);
}

/* ---- round-trip fuzz with a reference encoder and table model ------------ */

typedef struct { char n[40]; char v[60]; uint8_t nl, vl; } ent_t;
typedef struct { ent_t e[128]; int count; uint32_t size, limit; } model_t;

static void model_evict(model_t *m, uint32_t limit)
{
    while (m->count > 0 && m->size > limit) {
        ent_t *e = &m->e[m->count - 1];
        m->size -= 32u + e->nl + e->vl;
        m->count--;
    }
}

static void model_insert(model_t *m, const ent_t *x)
{
    uint32_t s = 32u + x->nl + x->vl;
    if (s > m->limit) { model_evict(m, 0); return; }
    model_evict(m, m->limit - s);
    memmove(&m->e[1], &m->e[0], sizeof(ent_t) * (size_t)m->count);
    m->e[0] = *x;
    m->count++;
    m->size += s;
}

static size_t enc_str(uint8_t *o, const char *s, size_t n, int huff)
{
    if (!huff) {
        size_t h = hpack_put_int(o, 8, 0x00, 7, (uint32_t)n);
        memcpy(o + h, s, n);
        return h + n;
    }
    uint8_t tmp[256];
    size_t el = huff_enc((const uint8_t *)s, n, tmp, 0, 0);
    size_t h = hpack_put_int(o, 8, 0x80, 7, (uint32_t)el);
    memcpy(o + h, tmp, el);
    return h + el;
}

static void test_roundtrip_fuzz(void)
{
    static uint8_t tab[4096];
    static const char *names[] = { "custom-key", ":status", "date", "x-a", "cache-control",
                                   "retry-after", "set-cookie", "location", "content-type" };
    int bad = 0, blocks = 0;
    for (int conn = 0; conn < 300; conn++) {
        const uint32_t max = (conn % 3 == 0) ? 0 : (conn % 3 == 1) ? 256 : 4096;
        hpack_dec_t d;
        hpack_dec_init(&d, tab, sizeof(tab), max);
        model_t m;
        memset(&m, 0, sizeof(m));
        m.limit = max;
        for (int b = 0; b < 12; b++, blocks++) {
            uint8_t blk[4096];
            size_t o = 0;
            char want[4096];
            size_t wl = 0;
            if (rnd() % 4 == 0) {                         /* size update(s) */
                uint32_t v = max ? rnd() % (max + 1) : 0;
                o += hpack_put_int(blk + o, 8, 0x20, 5, v);
                m.limit = v;
                model_evict(&m, v);
            }
            int nf = 1 + (int)(rnd() % 8);
            for (int f = 0; f < nf; f++) {
                ent_t x;
                memset(&x, 0, sizeof(x));
                const int kind = (int)(rnd() % 5);
                if (kind == 0 && m.count > 0) {           /* indexed dynamic */
                    int j = (int)(rnd() % (unsigned)m.count);
                    o += hpack_put_int(blk + o, 8, 0x80, 7, (uint32_t)(HPACK_STATIC_LEN + 1 + j));
                    x = m.e[j];
                } else if (kind == 1) {                   /* indexed static */
                    o += hpack_put_int(blk + o, 8, 0x80, 7, 8);   /* :status 200 */
                    strcpy(x.n, ":status"); x.nl = 7; strcpy(x.v, "200"); x.vl = 3;
                } else {                                  /* literals */
                    const char *nm = names[rnd() % (sizeof(names) / sizeof(names[0]))];
                    x.nl = (uint8_t)strlen(nm);
                    memcpy(x.n, nm, x.nl);
                    x.vl = (uint8_t)(rnd() % 50);
                    for (int i = 0; i < x.vl; i++) x.v[i] = (char)('a' + rnd() % 26);
                    const uint8_t first = kind == 2 ? 0x40 : kind == 3 ? 0x00 : 0x10;
                    const uint8_t prefix = kind == 2 ? 6 : 4;
                    int name_idx = 0;
                    if (rnd() % 2) {
                        for (int j = 0; j < m.count && !name_idx; j++)
                            if (m.e[j].nl == x.nl && memcmp(m.e[j].n, x.n, x.nl) == 0)
                                name_idx = HPACK_STATIC_LEN + 1 + j;
                        if (!name_idx) name_idx = (int)hpack_static_name_index(x.n, x.nl);
                    }
                    o += hpack_put_int(blk + o, 8, first, prefix, (uint32_t)name_idx);
                    if (!name_idx) o += enc_str(blk + o, x.n, x.nl, (int)(rnd() % 2));
                    o += enc_str(blk + o, x.v, x.vl, (int)(rnd() % 2));
                    if (kind == 2) model_insert(&m, &x);
                }
                memcpy(want + wl, x.n, x.nl); wl += x.nl;
                memcpy(want + wl, ": ", 2); wl += 2;
                memcpy(want + wl, x.v, x.vl); wl += x.vl;
                want[wl++] = '\n';
            }
            want[wl] = 0;
            collect_t c;
            int rc = decode_block(&d, blk, o, (int)(rnd() % 3), &c);
            if (rc != HPACK_OK || strcmp(c.buf, want) != 0 || d.size != m.size ||
                d.count != (uint16_t)m.count) {
                if (bad < 3) printf("  block %d: rc %d size %u/%u\n", blocks, rc,
                                    (unsigned)d.size, (unsigned)m.size);
                bad++;
                break;
            }
        }
    }
    char nm[64];
    snprintf(nm, sizeof(nm), "roundtrip_fuzz_%d_blocks", blocks);
    check(nm, bad == 0);
}

/* ---- garbage fuzz ---------------------------------------------------------- */

static void test_garbage_fuzz(void)
{
    static uint8_t tab[4096];
    int outcomes[4] = { 0 };
    for (int t = 0; t < 200000; t++) {
        uint8_t b[64];
        size_t n = 1 + rnd() % sizeof(b);
        for (size_t i = 0; i < n; i++) b[i] = (uint8_t)rnd();
        if (t & 1) b[0] &= 0x3f;                   /* more literals */
        hpack_dec_t d;
        hpack_dec_init(&d, (t % 4) ? tab : NULL, (t % 4) ? sizeof(tab) : 0,
                       (t % 4) ? 4096 : 0);
        collect_t c;
        int rc = decode_block(&d, b, n, (int)(t % 3), &c);
        if (rc == HPACK_OK) outcomes[0]++;
        else if (rc == HPACK_ERR) outcomes[1]++;
        else if (rc == HPACK_ERR_UNSUPPORTED) outcomes[2]++;
        else outcomes[3]++;
        if (d.used > d.tab_cap || d.size > d.size_limit) outcomes[3]++;
    }
    printf("  garbage: %d ok, %d rejected, %d unsupported\n", outcomes[0], outcomes[1], outcomes[2]);
    check("garbage_fuzz_200000", outcomes[3] == 0 && outcomes[0] > 0 && outcomes[1] > 0);
}

int main(void)
{
    test_appendix_c();
    test_integers();
    test_huffman();
    test_malformed();
    test_device_table_zero();
    test_caps_and_flags();
    test_encoder();
    test_roundtrip_fuzz();
    test_garbage_fuzz();
    if (s_fails == 0) printf("\nALL OK\n");
    return s_fails ? 1 : 0;
}
