// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// The early WPA2 PSK (main/wifi_psk.h, round 1.3.8): the SHA-1
// compressions against FIPS 180 digests and a plain byte-oriented
// SHA-1, the PSK against the IEEE 802.11-2020 J.4.1 vectors, RFC 6070
// and edge vectors computed with OpenSSL (Python hashlib), a random
// cross-check against a straight RFC 8018 PBKDF2 over that reference
// HMAC, the input bounds the driver's own choice of path implies, the
// hex digits the driver reads back (hostap's hexstr2bin round trip), the
// scrub and the hand-off between the deriving task and the connect.
// tools/qemu_crypto runs this suite on the ESP32 and adds the comparison
// with the IDF's own pbkdf2_sha1 (psk_qemu.c).

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wifi_psk.h"

static int s_fails;

static void check(const char *name, int ok)
{
    printf("[%s] %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) s_fails++;
}

static int unhex(const char *s, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(s + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

/* ---- Reference: byte-oriented SHA-1 / HMAC / PBKDF2 ------------------- */

typedef struct {
    uint32_t h[5];
    uint8_t  buf[64];
    size_t   n;
    uint64_t total;
} ref_sha1_t;

static uint32_t rol(uint32_t x, unsigned n) { return (x << n) | (x >> (32 - n)); }

static void ref_block(uint32_t h[5], const uint8_t b[64])
{
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t)b[4 * i] << 24 | (uint32_t)b[4 * i + 1] << 16 |
               (uint32_t)b[4 * i + 2] << 8 | b[4 * i + 3];
    }
    for (int i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (bb & c) | (~bb & d);           k = 0x5A827999u; }
        else if (i < 40) { f = bb ^ c ^ d;                     k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (bb & c) | (bb & d) | (c & d);  k = 0x8F1BBCDCu; }
        else             { f = bb ^ c ^ d;                     k = 0xCA62C1D6u; }
        const uint32_t t = rol(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol(bb, 30); bb = a; a = t;
    }
    h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e;
}

static void ref_init(ref_sha1_t *s)
{
    memset(s, 0, sizeof(*s));
    tl_sha1_iv(s->h);
}

static void ref_update(ref_sha1_t *s, const uint8_t *p, size_t n)
{
    s->total += n;
    while (n--) {
        s->buf[s->n++] = *p++;
        if (s->n == 64) { ref_block(s->h, s->buf); s->n = 0; }
    }
}

static void ref_final(ref_sha1_t *s, uint8_t out[20])
{
    const uint64_t bits = s->total * 8;
    const uint8_t one = 0x80, zero = 0;
    ref_update(s, &one, 1);
    while (s->n != 56) ref_update(s, &zero, 1);
    uint8_t len[8];
    for (int i = 0; i < 8; i++) len[i] = (uint8_t)(bits >> (56 - 8 * i));
    ref_update(s, len, 8);
    for (int i = 0; i < 20; i++) out[i] = (uint8_t)(s->h[i >> 2] >> (24 - 8 * (i & 3)));
}

static void ref_sha1(const uint8_t *p, size_t n, uint8_t out[20])
{
    ref_sha1_t s;
    ref_init(&s);
    ref_update(&s, p, n);
    ref_final(&s, out);
}

static void ref_hmac(const uint8_t *k, size_t kn, const uint8_t *m, size_t mn, uint8_t out[20])
{
    uint8_t key[64] = {0}, pad[64], inner[20];
    if (kn > 64) ref_sha1(k, kn, key); else memcpy(key, k, kn);
    ref_sha1_t s;
    for (int i = 0; i < 64; i++) pad[i] = key[i] ^ 0x36;
    ref_init(&s); ref_update(&s, pad, 64); ref_update(&s, m, mn); ref_final(&s, inner);
    for (int i = 0; i < 64; i++) pad[i] = key[i] ^ 0x5C;
    ref_init(&s); ref_update(&s, pad, 64); ref_update(&s, inner, 20); ref_final(&s, out);
}

static void ref_pbkdf2(const uint8_t *p, size_t pn, const uint8_t *salt, size_t sn,
                       unsigned iter, uint8_t *out, size_t outn)
{
    for (uint32_t blk = 1; outn > 0; blk++) {
        uint8_t msg[64 + 4], u[20], t[20];
        memcpy(msg, salt, sn);
        msg[sn] = (uint8_t)(blk >> 24); msg[sn + 1] = (uint8_t)(blk >> 16);
        msg[sn + 2] = (uint8_t)(blk >> 8); msg[sn + 3] = (uint8_t)blk;
        ref_hmac(p, pn, msg, sn + 4, u);
        memcpy(t, u, 20);
        for (unsigned j = 1; j < iter; j++) {
            ref_hmac(p, pn, u, 20, u);
            for (int i = 0; i < 20; i++) t[i] ^= u[i];
        }
        const size_t n = outn < 20 ? outn : 20;
        memcpy(out, t, n);
        out += n;
        outn -= n;
    }
}

/* hostap src/utils/common.c hexstr2bin — what wpa.c feeds the
 * 64-character password through. */
static int hex2num(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hexstr2bin(const char *hex, uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        const int a = hex2num(hex[2 * i]), b = hex2num(hex[2 * i + 1]);
        if (a < 0 || b < 0) return -1;
        buf[i] = (uint8_t)(a << 4 | b);
    }
    return 0;
}

static uint32_t s_seed = 0x13801380u;

static uint32_t rnd(void)
{
    s_seed ^= s_seed << 13; s_seed ^= s_seed >> 17; s_seed ^= s_seed << 5;
    return s_seed;
}

/* ---- SHA-1 compressions ----------------------------------------------- */

static void digest_bytes(const uint32_t st[5], uint8_t out[20])
{
    for (int i = 0; i < 20; i++) out[i] = (uint8_t)(st[i >> 2] >> (24 - 8 * (i & 3)));
}

/* SHA-1 of a message of ≤ 55 bytes through tl_sha1_compress. */
static void one_block_sha1(const char *msg, uint8_t out[20])
{
    const size_t n = strlen(msg);
    uint32_t w[16] = {0}, st[5];
    tl_psk_load(w, (const uint8_t *)msg, n);
    w[n >> 2] |= 0x80u << (24 - 8 * (n & 3));
    w[15] = (uint32_t)n * 8;
    tl_sha1_iv(st);
    tl_sha1_compress(st, w);
    digest_bytes(st, out);
}

static void test_sha1(void)
{
    uint8_t got[20], want[20];
    one_block_sha1("abc", got);
    unhex("a9993e364706816aba3e25717850c26c9cd0d89d", want, 20);
    check("sha1/fips-abc", memcmp(got, want, 20) == 0);
    one_block_sha1("", got);
    unhex("da39a3ee5e6b4b0d3255bfef95601890afd80709", want, 20);
    check("sha1/empty", memcmp(got, want, 20) == 0);
    ref_sha1((const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, got);
    unhex("84983e441c3bd26ebaae4aa1f95129e5e54670f1", want, 20);
    check("sha1/reference-fips-2block", memcmp(got, want, 20) == 0);

    int bad = 0;
    for (int c = 0; c < 200; c++) {
        uint8_t msg[55];
        const size_t n = rnd() % 56;
        for (size_t i = 0; i < n; i++) msg[i] = (uint8_t)rnd();
        char s[56];
        memcpy(s, msg, n);
        s[n] = 0;
        if (memchr(msg, 0, n) != NULL) continue;           /* one_block_sha1 takes a string */
        one_block_sha1(s, got);
        ref_sha1(msg, n, want);
        bad += memcmp(got, want, 20) != 0;
    }
    check("sha1/compress-vs-reference-random", bad == 0);

    /* compress20 = the second block of SHA-1(64-B block ‖ 20 B). */
    bad = 0;
    for (int c = 0; c < 200; c++) {
        uint8_t blk[64], m[20], msg[84];
        for (int i = 0; i < 64; i++) blk[i] = (uint8_t)rnd();
        for (int i = 0; i < 20; i++) m[i] = (uint8_t)rnd();
        memcpy(msg, blk, 64);
        memcpy(msg + 64, m, 20);
        uint32_t w[16] = {0}, from[5], mw[5] = {0}, st[5], scratch[16];
        tl_psk_load(w, blk, 64);
        tl_sha1_iv(from);
        tl_sha1_compress(from, w);
        tl_psk_load(mw, m, 20);
        tl_sha1_compress20(st, from, mw, scratch);
        digest_bytes(st, got);
        ref_sha1(msg, 84, want);
        bad += memcmp(got, want, 20) != 0;
    }
    check("sha1/compress20-vs-reference-random", bad == 0);
}

/* ---- The PSK ----------------------------------------------------------- */

typedef struct {
    const char *name;
    const char *pass;
    size_t      pass_len;
    const char *ssid;
    size_t      ssid_len;
    const char *psk;
} psk_vec_t;

static const psk_vec_t k_vecs[] = {
    /* IEEE 802.11-2020 J.4.1 */
    { "psk/ieee-j41-1", "password", 8, "IEEE", 4,
      "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e" },
    { "psk/ieee-j41-2", "ThisIsAPassword", 15, "ThisIsASSID", 11,
      "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af" },
    { "psk/ieee-j41-3", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 32,
      "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", 32,
      "becb93866bb8c3832cb777c2f559807c8c59afcb6eae734885001300a981cc62" },
    /* RFC 6070 (c = 4096, its first 20 bytes; 32 from OpenSSL) */
    { "psk/rfc6070-4096", "password", 8, "salt", 4,
      "4b007901b765489abead49d926f721d065a429c12e463f6c4cd79401085b03db" },
    /* Edges, OpenSSL (hashlib.pbkdf2_hmac('sha1', p, s, 4096, 32)) */
    { "psk/edge-63-byte-pass-32-nul-ssid",
      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 63,
      "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 32,
      "57c43ddbbfbf2dcf402ed02f88e734fcebd814b45142e95267c6f109e707ee99" },
    { "psk/edge-0xff-pass-1-byte-ssid",
      "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
      "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
      "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 63,
      "\xff", 1,
      "3f02a5e9a2f19a9e21cc46dd623a50012c18b75fa657b637965b6c0d486525ed" },
    { "psk/edge-8-byte-pass", "12345678", 8, "e", 1,
      "f200e0217cd1e192d623188c69e66965ba1c4066ee840813076406f02f8254ad" },
    { "psk/example", "correct horse battery staple", 28, "example-ssid", 12,
      "5175bd3c25a1d2afc49fdc4298d5a4b0e64fd9dd8e4fefe0de3bcd098f8bb9cb" },
};

static void test_vectors(void)
{
    for (size_t v = 0; v < sizeof(k_vecs) / sizeof(k_vecs[0]); v++) {
        const psk_vec_t *t = &k_vecs[v];
        uint8_t got[TL_PSK_LEN], want[TL_PSK_LEN], ref[TL_PSK_LEN];
        unhex(t->psk, want, sizeof(want));
        const bool ok = tl_psk_derive((const uint8_t *)t->pass, t->pass_len,
                                      (const uint8_t *)t->ssid, t->ssid_len, got);
        ref_pbkdf2((const uint8_t *)t->pass, t->pass_len, (const uint8_t *)t->ssid,
                   t->ssid_len, TL_PSK_ITER, ref, sizeof(ref));
        check(t->name, ok && memcmp(got, want, sizeof(want)) == 0 &&
                       memcmp(ref, want, sizeof(want)) == 0);
    }
}

static void test_random(void)
{
    int bad = 0, cases = 0;
    for (size_t pl = TL_PSK_PASS_MIN; pl <= TL_PSK_PASS_MAX; pl += 11) {
        for (size_t sl = 1; sl <= TL_PSK_SSID_MAX; sl += 7) {
            uint8_t pass[TL_PSK_PASS_MAX], ssid[TL_PSK_SSID_MAX];
            for (size_t i = 0; i < pl; i++) pass[i] = (uint8_t)(1 + rnd() % 255);
            for (size_t i = 0; i < sl; i++) ssid[i] = (uint8_t)rnd();
            uint8_t got[TL_PSK_LEN], want[TL_PSK_LEN];
            bad += !tl_psk_derive(pass, pl, ssid, sl, got);
            ref_pbkdf2(pass, pl, ssid, sl, TL_PSK_ITER, want, sizeof(want));
            bad += memcmp(got, want, sizeof(want)) != 0;
            cases++;
        }
    }
    printf("random: %d (pass, SSID) length pairs\n", cases);
    check("psk/random-lengths-vs-reference", bad == 0 && cases == 30);
}

static void test_bounds(void)
{
    uint8_t pass[64], ssid[33], pmk[TL_PSK_LEN];
    memset(pass, 'p', sizeof(pass));
    memset(ssid, 's', sizeof(ssid));
    check("bounds/pass-8-63-ssid-1-32",
          tl_psk_inputs_ok(8, 1) && tl_psk_inputs_ok(63, 32) && tl_psk_inputs_ok(20, 12));
    check("bounds/pass-7-short", !tl_psk_inputs_ok(7, 12));
    check("bounds/pass-64-already-hex", !tl_psk_inputs_ok(64, 12));
    check("bounds/ssid-0-and-33", !tl_psk_inputs_ok(20, 0) && !tl_psk_inputs_ok(20, 33));

    memset(pmk, 0xA5, sizeof(pmk));
    int untouched = 1;
    const struct { size_t pl, sl; } bad[] = { { 7, 12 }, { 64, 12 }, { 20, 0 }, { 20, 33 } };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        untouched &= !tl_psk_derive(pass, bad[i].pl, ssid, bad[i].sl, pmk);
    }
    untouched &= !tl_psk_derive(NULL, 20, ssid, 12, pmk);
    untouched &= !tl_psk_derive(pass, 20, NULL, 12, pmk);
    for (size_t i = 0; i < sizeof(pmk); i++) untouched &= pmk[i] == 0xA5;
    check("bounds/refused-pmk-untouched", untouched);
}

static void test_hex(void)
{
    uint8_t pmk[TL_PSK_LEN];
    for (unsigned i = 0; i < TL_PSK_LEN; i++) pmk[i] = (uint8_t)(i * 0x11 + 0x0f);
    char hex[TL_PSK_HEX_LEN + 1];
    memset(hex, '#', sizeof(hex));
    tl_psk_hex(pmk, hex);
    check("hex/64-digits-no-terminator", hex[TL_PSK_HEX_LEN] == '#');
    hex[TL_PSK_HEX_LEN] = 0;
    check("hex/lowercase", strcmp(hex, "0f20314253647586" "97a8b9cadbecfd0e"
                                       "1f30415263748596" "a7b8c9daebfc0d1e") == 0);
    check("hex/strlen-64", strlen(hex) == 64);   /* wpa.c: os_strlen(password) == 64 */

    /* What the driver does with it: hexstr2bin back to the derived PMK. */
    const psk_vec_t *t = &k_vecs[0];
    uint8_t derived[TL_PSK_LEN], back[TL_PSK_LEN];
    tl_psk_derive((const uint8_t *)t->pass, t->pass_len, (const uint8_t *)t->ssid,
                  t->ssid_len, derived);
    tl_psk_hex(derived, hex);
    check("hex/hexstr2bin-round-trip",
          hexstr2bin(hex, back, sizeof(back)) == 0 && memcmp(back, derived, sizeof(back)) == 0);
}

static void test_scrub(void)
{
    uint8_t buf[100];
    memset(buf, 0x5A, sizeof(buf));
    tl_psk_scrub(buf + 10, 64);
    int ok = 1;
    for (size_t i = 0; i < sizeof(buf); i++) ok &= buf[i] == ((i >= 10 && i < 74) ? 0 : 0x5A);
    check("scrub/zeroes-exactly-the-range", ok);
}

static void test_handoff(void)
{
    uint32_t s = TL_PSK_RUNNING;
    check("handoff/published-then-claimed",
          tl_psk_publish(&s) && s == TL_PSK_READY && tl_psk_claim(&s) && s == TL_PSK_DONE);
    check("handoff/claimed-once", !tl_psk_claim(&s));

    s = TL_PSK_RUNNING;
    check("handoff/consumer-gave-up-first",
          !tl_psk_claim(&s) && s == TL_PSK_DONE && !tl_psk_publish(&s) && s == TL_PSK_DONE);

    s = TL_PSK_IDLE;
    check("handoff/nothing-started", !tl_psk_claim(&s) && !tl_psk_publish(&s));
}

int main(void)
{
    test_sha1();
    test_vectors();
    test_random();
    test_bounds();
    test_hex();
    test_scrub();
    test_handoff();
    if (s_fails) {
        printf("%d FAILED\n", s_fails);
        return 1;
    }
    printf("ALL OK\n");
    return 0;
}
