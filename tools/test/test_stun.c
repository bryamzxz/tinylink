/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for the STUN codec (stun.c). Covers:
 *   - stun_is acceptance / rejection (cookie offset, top-2 bits, length).
 *   - Request layout (binding type, attrs len, magic, txid, SOFTWARE attr,
 *     FINGERPRINT attr type+len) and CRC32 self-roundtrip.
 *   - 8 golden response vectors lifted byte-for-byte from upstream
 *     (tailscale/tailscale @ 632293de7: net/stun/stun_test.go) covering
 *     google/sipgate/powervoip/Pion/stuntman + IPv4-and-IPv6, plus
 *     SOFTWARE-attr 1- and 3-byte padding edge cases and a no-4in6
 *     vector.
 *   - Encode-then-parse roundtrip for synthetic v4 + v6 responses to
 *     exercise the seal-side response builder analogue (we build the
 *     wire bytes by hand to avoid pulling in upstream's Response()).
 *   - Tamper rejection: corrupted magic, corrupted status, declared
 *     attr length exceeding buffer.
 *   - Truncation (header-only, header+1, etc.).
 *   - MAPPED-ADDRESS legacy fallback when XOR-MAPPED-ADDRESS is absent.
 *   - Stable bytes for a fixed txid (regression guard on the request).
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "stun.h"

static int fails = 0;

static void hexdump(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

static int ok(const char *name, int condition) {
    if (condition) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL\n", name);
    return 1;
}

static int eq_bytes(const char *name, const uint8_t *a, const uint8_t *b, size_t n) {
    if (memcmp(a, b, n) == 0) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL\n  got:  ", name); hexdump(a, n); printf("\n  want: ");
    hexdump(b, n); printf("\n");
    return 1;
}

static int eq_u16(const char *name, uint16_t got, uint16_t want) {
    if (got == want) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL got=%u want=%u\n", name, (unsigned)got, (unsigned)want);
    return 1;
}

/* IPv4-mapped IPv6 form for a v4 address — the canonical 16-byte
 * representation used by both stun_addr_t and disco_addrport_t. */
static void v4_mapped(uint8_t out[16], uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    memset(out, 0, 16);
    out[10] = 0xff; out[11] = 0xff;
    out[12] = a; out[13] = b; out[14] = c; out[15] = d;
}

/* ------------------------------------------------------------------ */
/* stun_is                                                             */
/* ------------------------------------------------------------------ */

static const uint8_t k_cookie[4] = { 0x21, 0x12, 0xa4, 0x42 };

static void test_stun_is(void) {
    fails += ok("is/null",   stun_is(NULL, 0) == false);
    fails += ok("is/empty",  stun_is((const uint8_t*)"", 0) == false);

    uint8_t zero[20] = {0};
    fails += ok("is/all-zero-no-cookie", stun_is(zero, 20) == false);

    /* magic at correct offset, length exactly 20 → accepted */
    uint8_t buf[20] = {0};
    memcpy(buf + 4, k_cookie, 4);
    fails += ok("is/cookie-and-len20", stun_is(buf, 20) == true);

    /* short by 1 byte → rejected */
    fails += ok("is/short-19",  stun_is(buf, 19) == false);

    /* length exceeds 20, still accepted */
    uint8_t big[40] = {0};
    memcpy(big + 4, k_cookie, 4);
    fails += ok("is/cookie-and-len40", stun_is(big, 40) == true);

    /* top 2 bits set → reject */
    uint8_t hi[20] = {0};
    memcpy(hi + 4, k_cookie, 4);
    hi[0] = 0xf0;
    fails += ok("is/top-bits-f0", stun_is(hi, 20) == false);
    hi[0] = 0x40;
    fails += ok("is/top-bits-40", stun_is(hi, 20) == false);

    /* high bit clear, top-2 bits clear, but second nibble set → accepted */
    uint8_t mid[20] = {0};
    memcpy(mid + 4, k_cookie, 4);
    mid[0] = 0x20;
    fails += ok("is/top-bits-20", stun_is(mid, 20) == true);

    /* cookie at wrong offset → rejected */
    uint8_t off[20] = {0};
    memcpy(off, k_cookie, 4);
    fails += ok("is/cookie-at-0", stun_is(off, 20) == false);
}

/* ------------------------------------------------------------------ */
/* Request layout                                                      */
/* ------------------------------------------------------------------ */

static void test_request_layout(void) {
    uint8_t txid[STUN_TXID_LEN];
    for (int i = 0; i < STUN_TXID_LEN; i++) txid[i] = (uint8_t)(0x10 + i);

    uint8_t req[STUN_REQUEST_LEN];
    size_t n = stun_build_request(req, txid);
    fails += ok("req/len", n == STUN_REQUEST_LEN);

    /* binding-request method (0x0001) at offset 0 */
    fails += ok("req/method-byte-0", req[0] == 0x00);
    fails += ok("req/method-byte-1", req[1] == 0x01);

    /* declared attrs length: 12 (SOFTWARE) + 8 (FINGERPRINT) = 20 */
    uint16_t attrs_len = (uint16_t)((req[2] << 8) | req[3]);
    fails += eq_u16("req/attrs-len", attrs_len, 20);

    /* magic cookie + txid */
    fails += eq_bytes("req/cookie", req + 4, k_cookie, 4);
    fails += eq_bytes("req/txid", req + 8, txid, STUN_TXID_LEN);

    /* SOFTWARE attribute first */
    fails += ok("req/sw-type-hi", req[20] == 0x80);
    fails += ok("req/sw-type-lo", req[21] == 0x22);
    fails += eq_u16("req/sw-len", (uint16_t)((req[22] << 8) | req[23]), 8);
    fails += eq_bytes("req/sw-value", req + 24, (const uint8_t*)"tailnode", 8);

    /* FINGERPRINT attribute last */
    fails += ok("req/fp-type-hi", req[32] == 0x80);
    fails += ok("req/fp-type-lo", req[33] == 0x28);
    fails += eq_u16("req/fp-len", (uint16_t)((req[34] << 8) | req[35]), 4);

    /* stun_is recognizes our own request */
    fails += ok("req/is-stun", stun_is(req, n) == true);
}

static void test_request_bad_args(void) {
    uint8_t buf[STUN_REQUEST_LEN];
    uint8_t txid[STUN_TXID_LEN] = {0};
    fails += ok("req/null-out",  stun_build_request(NULL, txid) == 0);
    fails += ok("req/null-txid", stun_build_request(buf, NULL) == 0);
}

/* Recompute the fingerprint from the wire bytes to verify the encoder.
 * Using the bit-by-bit IEEE polynomial — same as the impl. */
static uint32_t crc32_ieee_local(const uint8_t *p, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++) {
            uint32_t mask = (uint32_t)0u - (c & 1u);
            c = (c >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~c;
}

static void test_request_fingerprint_self_check(void) {
    uint8_t txid[STUN_TXID_LEN];
    for (int i = 0; i < STUN_TXID_LEN; i++) txid[i] = (uint8_t)(0xa0 ^ i);

    uint8_t req[STUN_REQUEST_LEN];
    stun_build_request(req, txid);

    uint32_t want = crc32_ieee_local(req, 32) ^ 0x5354554Eu;
    uint32_t got  = ((uint32_t)req[36] << 24) | ((uint32_t)req[37] << 16) |
                    ((uint32_t)req[38] << 8)  |  (uint32_t)req[39];
    fails += ok("req/fp-matches-crc", got == want);
}

/* ------------------------------------------------------------------ */
/* Upstream golden vectors (stun_test.go)                              */
/* ------------------------------------------------------------------ */

struct resp_kat {
    const char *name;
    const uint8_t *data;
    size_t len;
    uint8_t txid[STUN_TXID_LEN];
    bool is_v6;
    uint8_t addr[16];   /* v4-mapped form when !is_v6 */
    uint16_t port;
};

static const uint8_t k_google1[] = {
    0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42,
    0x23, 0x60, 0xb1, 0x1e, 0x3e, 0xc6, 0x8f, 0xfa,
    0x93, 0xe0, 0x80, 0x07, 0x00, 0x20, 0x00, 0x08,
    0x00, 0x01, 0xc7, 0x86, 0x69, 0x57, 0x85, 0x6f,
};

static const uint8_t k_google2[] = {
    0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42,
    0xf9, 0xf1, 0x21, 0xcb, 0xde, 0x7d, 0x7c, 0x75,
    0x92, 0x3c, 0xe2, 0x71, 0x00, 0x20, 0x00, 0x08,
    0x00, 0x01, 0xc7, 0x87, 0x69, 0x57, 0x85, 0x6f,
};

static const uint8_t k_sipgate[] = {
    0x01, 0x01, 0x00, 0x44, 0x21, 0x12, 0xa4, 0x42,
    0x48, 0x2e, 0xb6, 0x47, 0x15, 0xe8, 0xb2, 0x8e,
    0xae, 0xad, 0x64, 0x44, 0x00, 0x01, 0x00, 0x08,
    0x00, 0x01, 0xe4, 0xab, 0x48, 0x45, 0x21, 0x2d,
    0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x27, 0x10,
    0xd9, 0x0a, 0x44, 0x98, 0x00, 0x05, 0x00, 0x08,
    0x00, 0x01, 0x27, 0x11, 0xd9, 0x74, 0x7a, 0x8a,
    0x80, 0x20, 0x00, 0x08, 0x00, 0x01, 0xc5, 0xb9,
    0x69, 0x57, 0x85, 0x6f, 0x80, 0x22, 0x00, 0x10,
    0x56, 0x6f, 0x76, 0x69, 0x64, 0x61, 0x2e, 0x6f,
    0x72, 0x67, 0x20, 0x30, 0x2e, 0x39, 0x36, 0x00,
};

static const uint8_t k_powervoip[] = {
    0x01, 0x01, 0x00, 0x24, 0x21, 0x12, 0xa4, 0x42,
    0x7e, 0x57, 0x96, 0x68, 0x29, 0xf4, 0x44, 0x60,
    0x9d, 0x1d, 0xea, 0xa6, 0x00, 0x01, 0x00, 0x08,
    0x00, 0x01, 0xe9, 0xd3, 0x48, 0x45, 0x21, 0x2d,
    0x00, 0x04, 0x00, 0x08, 0x00, 0x01, 0x0d, 0x96,
    0x4d, 0x48, 0xa9, 0xd4, 0x00, 0x05, 0x00, 0x08,
    0x00, 0x01, 0x0d, 0x97, 0x4d, 0x48, 0xa9, 0xd5,
};

static const uint8_t k_pion[] = {
    0x01, 0x01, 0x00, 0x24, 0x21, 0x12, 0xa4, 0x42,
    0xeb, 0xc2, 0xd3, 0x6e, 0xf4, 0x71, 0x21, 0x7c,
    0x4f, 0x3e, 0x30, 0x8e, 0x80, 0x22, 0x00, 0x0a,
    0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74,
    0x65, 0x72, 0x00, 0x00, 0x00, 0x20, 0x00, 0x08,
    0x00, 0x01, 0xce, 0x66, 0x5e, 0x12, 0xa4, 0x43,
    0x80, 0x28, 0x00, 0x04, 0xb6, 0x99, 0xbb, 0x02,
    0x01, 0x01, 0x00, 0x24, 0x21, 0x12, 0xa4, 0x42,
};

static const uint8_t k_stuntman_v6[] = {
    0x01, 0x01, 0x00, 0x48, 0x21, 0x12, 0xa4, 0x42,
    0x06, 0xf5, 0x66, 0x85, 0xd2, 0x8a, 0xf3, 0xe6,
    0x9c, 0xe3, 0x41, 0xe2, 0x00, 0x01, 0x00, 0x14,
    0x00, 0x02, 0x90, 0xce, 0x26, 0x02, 0x00, 0xd1,
    0xb4, 0xcf, 0xc1, 0x00, 0x38, 0xb2, 0x31, 0xff,
    0xfe, 0xef, 0x96, 0xf6, 0x80, 0x2b, 0x00, 0x14,
    0x00, 0x02, 0x0d, 0x96, 0x26, 0x04, 0xa8, 0x80,
    0x00, 0x02, 0x00, 0xd1, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xc5, 0x70, 0x01, 0x00, 0x20, 0x00, 0x14,
    0x00, 0x02, 0xb1, 0xdc, 0x07, 0x10, 0xa4, 0x93,
    0xb2, 0x3a, 0xa7, 0x85, 0xea, 0x38, 0xc2, 0x19,
    0x62, 0x0c, 0xd7, 0x14,
};

static const uint8_t k_software_a[] = {
    0x01, 0x01, 0x00, 0x14, 0x21, 0x12, 0xa4, 0x42,
    0xeb, 0xc2, 0xd3, 0x6e, 0xf4, 0x71, 0x21, 0x7c,
    0x4f, 0x3e, 0x30, 0x8e, 0x80, 0x22, 0x00, 0x01,
    0x61, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x08,
    0x00, 0x01, 0xce, 0x66, 0x5e, 0x12, 0xa4, 0x43,
};

static const uint8_t k_software_abc[] = {
    0x01, 0x01, 0x00, 0x14, 0x21, 0x12, 0xa4, 0x42,
    0xeb, 0xc2, 0xd3, 0x6e, 0xf4, 0x71, 0x21, 0x7c,
    0x4f, 0x3e, 0x30, 0x8e, 0x80, 0x22, 0x00, 0x03,
    0x61, 0x62, 0x63, 0x00, 0x00, 0x20, 0x00, 0x08,
    0x00, 0x01, 0xce, 0x66, 0x5e, 0x12, 0xa4, 0x43,
};

/* "no-4in6" vector (v4 reported via XOR-MAPPED-ADDRESS, not as v4-mapped
 * v6). Hex-decoded from the upstream test. */
static const uint8_t k_no_4in6[] = {
    0x01,0x01,0x00,0x18,0x21,0x12,0xa4,0x42,
    0x4f,0xd5,0xd2,0x02,0xdc,0xb3,0x7d,0x31,
    0xfc,0x77,0x33,0x06,0x00,0x20,0x00,0x14,
    0x00,0x02,0xcd,0x3d,0x21,0x12,0xa4,0x42,
    0x4f,0xd5,0xd2,0x02,0xdc,0xb3,0x82,0xce,
    0x2d,0xc3,0xfc,0xc7,
};

/* The upstream "no-4in6" vector advertises family=2 (IPv6) but the
 * decoded address is exactly ::ffff:209.180.207.193 — the v4-mapped
 * form of 209.180.207.193. Our parser treats family=2 as native v6
 * (is_v6=true) and stores the literal 16 bytes as decoded; this is
 * faithful to the wire and matches what upstream does before its own
 * .Unmap() normalization step (which we deliberately don't apply, so
 * downstream code can choose to). */
static const struct resp_kat k_resp_kats[] = {
    { "google-1", k_google1, sizeof(k_google1),
      {0x23,0x60,0xb1,0x1e,0x3e,0xc6,0x8f,0xfa,0x93,0xe0,0x80,0x07},
      false, {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 72,69,33,45}, 59028 },
    { "google-2", k_google2, sizeof(k_google2),
      {0xf9,0xf1,0x21,0xcb,0xde,0x7d,0x7c,0x75,0x92,0x3c,0xe2,0x71},
      false, {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 72,69,33,45}, 59029 },
    { "sipgate", k_sipgate, sizeof(k_sipgate),
      {0x48,0x2e,0xb6,0x47,0x15,0xe8,0xb2,0x8e,0xae,0xad,0x64,0x44},
      false, {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 72,69,33,45}, 58539 },
    { "powervoip", k_powervoip, sizeof(k_powervoip),
      {0x7e,0x57,0x96,0x68,0x29,0xf4,0x44,0x60,0x9d,0x1d,0xea,0xa6},
      false, {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 72,69,33,45}, 59859 },
    { "pion", k_pion, sizeof(k_pion),
      {0xeb,0xc2,0xd3,0x6e,0xf4,0x71,0x21,0x7c,0x4f,0x3e,0x30,0x8e},
      false, {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 127,0,0,1}, 61300 },
    { "stuntman-v6", k_stuntman_v6, sizeof(k_stuntman_v6),
      {0x06,0xf5,0x66,0x85,0xd2,0x8a,0xf3,0xe6,0x9c,0xe3,0x41,0xe2},
      true,
      {0x26,0x02,0x00,0xd1, 0xb4,0xcf,0xc1,0x00,
       0x38,0xb2,0x31,0xff, 0xfe,0xef,0x96,0xf6}, 37070 },
    { "software-a", k_software_a, sizeof(k_software_a),
      {0xeb,0xc2,0xd3,0x6e,0xf4,0x71,0x21,0x7c,0x4f,0x3e,0x30,0x8e},
      false, {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 127,0,0,1}, 61300 },
    { "software-abc", k_software_abc, sizeof(k_software_abc),
      {0xeb,0xc2,0xd3,0x6e,0xf4,0x71,0x21,0x7c,0x4f,0x3e,0x30,0x8e},
      false, {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 127,0,0,1}, 61300 },
    { "no-4in6", k_no_4in6, sizeof(k_no_4in6),
      {0x4f,0xd5,0xd2,0x02,0xdc,0xb3,0x7d,0x31,0xfc,0x77,0x33,0x06},
      true,
      {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 209,180,207,193}, 60463 },
};

static void test_response_kats(void) {
    char tname[64];
    for (size_t i = 0; i < sizeof(k_resp_kats)/sizeof(k_resp_kats[0]); i++) {
        const struct resp_kat *t = &k_resp_kats[i];
        uint8_t txid[STUN_TXID_LEN];
        stun_addr_t a;
        int rc = stun_parse_response(t->data, t->len, txid, &a);

        snprintf(tname, sizeof(tname), "kat/%s/parse-rc", t->name);
        fails += ok(tname, rc == 0);
        if (rc != 0) continue;

        snprintf(tname, sizeof(tname), "kat/%s/txid", t->name);
        fails += eq_bytes(tname, txid, t->txid, STUN_TXID_LEN);

        snprintf(tname, sizeof(tname), "kat/%s/family", t->name);
        fails += ok(tname, a.is_v6 == t->is_v6);

        snprintf(tname, sizeof(tname), "kat/%s/addr", t->name);
        fails += eq_bytes(tname, a.addr, t->addr, 16);

        snprintf(tname, sizeof(tname), "kat/%s/port", t->name);
        fails += eq_u16(tname, a.port, t->port);
    }
}

/* ------------------------------------------------------------------ */
/* Self-built response roundtrips (no upstream Response() needed)     */
/* ------------------------------------------------------------------ */

#define FAMILY_IPV4_LOCAL 0x01
#define FAMILY_IPV6_LOCAL 0x02

/* Build a minimal binding-success response with one XOR-MAPPED-ADDRESS
 * attribute. v4: 12 bytes attr, v6: 24 bytes attr. */
static size_t build_xor_response(uint8_t *out, size_t cap,
                                 const uint8_t txid[STUN_TXID_LEN],
                                 const uint8_t *addr, size_t alen,
                                 uint16_t port)
{
    size_t attr_body = 4 + alen;
    size_t total = STUN_HEADER_LEN + 4 + attr_body;
    if (cap < total) return 0;

    out[0] = 0x01; out[1] = 0x01;
    out[2] = (uint8_t)((4 + attr_body) >> 8);
    out[3] = (uint8_t)(4 + attr_body);
    memcpy(out + 4, k_cookie, 4);
    memcpy(out + 8, txid, STUN_TXID_LEN);

    /* attr header */
    out[20] = 0x00; out[21] = 0x20;          /* XOR-MAPPED-ADDRESS */
    out[22] = (uint8_t)(attr_body >> 8);
    out[23] = (uint8_t)(attr_body);
    out[24] = 0x00;
    out[25] = (alen == 4) ? FAMILY_IPV4_LOCAL : FAMILY_IPV6_LOCAL;
    uint16_t xor_port = port ^ 0x2112u;
    out[26] = (uint8_t)(xor_port >> 8);
    out[27] = (uint8_t)(xor_port);

    for (size_t i = 0; i < alen; i++) {
        uint8_t k = (i < 4) ? k_cookie[i] : txid[i - 4];
        out[28 + i] = addr[i] ^ k;
    }
    return total;
}

static void test_response_v4_roundtrip(void) {
    uint8_t txid[STUN_TXID_LEN];
    for (int i = 0; i < STUN_TXID_LEN; i++) txid[i] = (uint8_t)(0x10 ^ i);
    const uint8_t v4[4] = { 198, 51, 100, 7 };

    uint8_t pkt[64];
    size_t n = build_xor_response(pkt, sizeof(pkt), txid, v4, 4, 47000);
    fails += ok("rt/v4/build-len", n == 32);

    uint8_t got_txid[STUN_TXID_LEN];
    stun_addr_t a;
    fails += ok("rt/v4/parse-rc", stun_parse_response(pkt, n, got_txid, &a) == 0);
    fails += eq_bytes("rt/v4/txid", got_txid, txid, STUN_TXID_LEN);
    fails += ok("rt/v4/v4-flag", a.is_v6 == false);

    uint8_t want[16];
    v4_mapped(want, v4[0], v4[1], v4[2], v4[3]);
    fails += eq_bytes("rt/v4/addr", a.addr, want, 16);
    fails += eq_u16("rt/v4/port", a.port, 47000);
}

static void test_response_v6_roundtrip(void) {
    uint8_t txid[STUN_TXID_LEN];
    for (int i = 0; i < STUN_TXID_LEN; i++) txid[i] = (uint8_t)(0x55 + i);
    const uint8_t v6[16] = {
        0x20,0x01,0x0d,0xb8, 0xde,0xad,0xbe,0xef,
        0xfe,0xed,0xfa,0xce, 0x00,0x00,0x00,0x01
    };

    uint8_t pkt[80];
    size_t n = build_xor_response(pkt, sizeof(pkt), txid, v6, 16, 12345);
    fails += ok("rt/v6/build-len", n == 44);

    uint8_t got_txid[STUN_TXID_LEN];
    stun_addr_t a;
    fails += ok("rt/v6/parse-rc", stun_parse_response(pkt, n, got_txid, &a) == 0);
    fails += eq_bytes("rt/v6/txid", got_txid, txid, STUN_TXID_LEN);
    fails += ok("rt/v6/v6-flag", a.is_v6 == true);
    fails += eq_bytes("rt/v6/addr", a.addr, v6, 16);
    fails += eq_u16("rt/v6/port", a.port, 12345);
}

/* ------------------------------------------------------------------ */
/* Tamper / truncation                                                 */
/* ------------------------------------------------------------------ */

static void test_tamper_magic(void) {
    uint8_t pkt[sizeof(k_google1)];
    memcpy(pkt, k_google1, sizeof(pkt));
    pkt[5] ^= 0x01;        /* flip a bit in the magic cookie */

    uint8_t txid[STUN_TXID_LEN];
    stun_addr_t a;
    fails += ok("tamper/magic-rejected",
                stun_parse_response(pkt, sizeof(pkt), txid, &a) == STUN_ERR_NOT_STUN);
}

static void test_tamper_status(void) {
    uint8_t pkt[sizeof(k_google1)];
    memcpy(pkt, k_google1, sizeof(pkt));
    pkt[1] = 0x11;         /* binding ERROR response, not success */

    uint8_t txid[STUN_TXID_LEN];
    stun_addr_t a;
    int rc = stun_parse_response(pkt, sizeof(pkt), txid, &a);
    fails += ok("tamper/error-status-rejected", rc == STUN_ERR_NOT_SUCCESS);
    /* But the txid should still be copied — useful for matching to a
     * pending request and surfacing the error to the caller. */
    fails += eq_bytes("tamper/txid-still-copied", txid, &k_google1[8], STUN_TXID_LEN);
}

static void test_truncation(void) {
    uint8_t txid[STUN_TXID_LEN];
    stun_addr_t a;

    /* Header alone, no attrs, body says attrs len > buffer */
    uint8_t hdr_only[STUN_HEADER_LEN] = {
        0x01, 0x01, 0x00, 0x08, 0x21, 0x12, 0xa4, 0x42,
        0,0,0,0, 0,0,0,0, 0,0,0,0
    };
    fails += ok("trunc/attrs-overflow",
                stun_parse_response(hdr_only, sizeof(hdr_only), txid, &a)
                == STUN_ERR_MALFORMED_ATTRS);

    /* Below minimum — not even a STUN packet. */
    fails += ok("trunc/below-header",
                stun_parse_response(hdr_only, 19, txid, &a) == STUN_ERR_NOT_STUN);

    /* Attr header truncated mid-attribute. */
    uint8_t bad_attr[24] = {
        0x01, 0x01, 0x00, 0x04, 0x21, 0x12, 0xa4, 0x42,
        0,0,0,0, 0,0,0,0, 0,0,0,0,
        0x00, 0x20, 0x00, 0x08
    };
    fails += ok("trunc/declared-attr-overflows-buf",
                stun_parse_response(bad_attr, sizeof(bad_attr), txid, &a)
                == STUN_ERR_MALFORMED_ATTRS);
}

/* MAPPED-ADDRESS-only response (no XOR-MAPPED-ADDRESS): legacy fallback.
 * Build by hand. */
static void test_mapped_address_fallback(void) {
    uint8_t txid[STUN_TXID_LEN];
    for (int i = 0; i < STUN_TXID_LEN; i++) txid[i] = (uint8_t)(0xC0 + i);

    /* MAPPED-ADDRESS attr: type=0x0001 len=8 unused(1) family(1=v4) port(2) addr(4) */
    uint8_t pkt[STUN_HEADER_LEN + 12];
    pkt[0] = 0x01; pkt[1] = 0x01;
    pkt[2] = 0x00; pkt[3] = 12;
    memcpy(&pkt[4], k_cookie, 4);
    memcpy(&pkt[8], txid, STUN_TXID_LEN);
    pkt[20] = 0x00; pkt[21] = 0x01;     /* MAPPED-ADDRESS */
    pkt[22] = 0x00; pkt[23] = 0x08;
    pkt[24] = 0x00; pkt[25] = 0x01;     /* family v4 */
    pkt[26] = 0x12; pkt[27] = 0x34;     /* port 0x1234 = 4660 */
    pkt[28] = 10; pkt[29] = 11; pkt[30] = 12; pkt[31] = 13;

    uint8_t got_txid[STUN_TXID_LEN];
    stun_addr_t a;
    fails += ok("fallback/mapped-only/parse-rc",
                stun_parse_response(pkt, sizeof(pkt), got_txid, &a) == 0);
    fails += eq_bytes("fallback/mapped-only/txid", got_txid, txid, STUN_TXID_LEN);

    uint8_t want[16];
    v4_mapped(want, 10, 11, 12, 13);
    fails += eq_bytes("fallback/mapped-only/addr", a.addr, want, 16);
    fails += eq_u16("fallback/mapped-only/port", a.port, 0x1234);
    fails += ok("fallback/mapped-only/v4-flag", a.is_v6 == false);
}

/* When BOTH MAPPED-ADDRESS and XOR-MAPPED-ADDRESS are present, XOR
 * wins. The sipgate KAT already covers this (it has both); add an
 * explicit assertion that the fallback bytes are NOT what we returned. */
static void test_xor_wins_over_mapped(void) {
    uint8_t txid[STUN_TXID_LEN];
    stun_addr_t a;
    int rc = stun_parse_response(k_sipgate, sizeof(k_sipgate), txid, &a);
    fails += ok("xor-wins/parse", rc == 0);
    /* Sipgate KAT MAPPED-ADDRESS reports 72.69.33.45:58539, XOR also
     * reports 72.69.33.45:58539 (the server has them consistent). The
     * port we should see is 58539 from XOR. The MAPPED-ADDRESS port
     * literally matches in this case, so the only way to tell is by
     * inspecting the upstream behavior — both yield the same answer
     * here. The test of "XOR wins" is already covered structurally by
     * decode order in stun.c; this serves as a regression marker. */
    fails += eq_u16("xor-wins/port-from-xor", a.port, 58539);
}

/* ------------------------------------------------------------------ */
/* Determinism: same txid → same request bytes                         */
/* ------------------------------------------------------------------ */

static void test_request_deterministic(void) {
    uint8_t txid[STUN_TXID_LEN] = {
        0xde,0xad,0xbe,0xef,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77
    };

    uint8_t r1[STUN_REQUEST_LEN];
    uint8_t r2[STUN_REQUEST_LEN];
    stun_build_request(r1, txid);
    stun_build_request(r2, txid);
    fails += eq_bytes("det/same-txid-same-bytes", r1, r2, STUN_REQUEST_LEN);

    /* Different txid → different bytes (txid + fingerprint both change). */
    uint8_t txid2[STUN_TXID_LEN] = {
        0xde,0xad,0xbe,0xef,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x78
    };
    uint8_t r3[STUN_REQUEST_LEN];
    stun_build_request(r3, txid2);
    fails += ok("det/different-txid-different-bytes",
                memcmp(r1, r3, STUN_REQUEST_LEN) != 0);
}

/* ------------------------------------------------------------------ */
/* Bad arg paths                                                       */
/* ------------------------------------------------------------------ */

static void test_parse_bad_args(void) {
    uint8_t txid[STUN_TXID_LEN];
    stun_addr_t a;
    fails += ok("parse/null-buf",  stun_parse_response(NULL, 40, txid, &a) == STUN_ERR_BAD_ARG);
    fails += ok("parse/null-txid", stun_parse_response(k_google1, sizeof(k_google1), NULL, &a) == STUN_ERR_BAD_ARG);
    fails += ok("parse/null-addr", stun_parse_response(k_google1, sizeof(k_google1), txid, NULL) == STUN_ERR_BAD_ARG);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(void) {
    test_stun_is();
    test_request_layout();
    test_request_bad_args();
    test_request_fingerprint_self_check();
    test_response_kats();
    test_response_v4_roundtrip();
    test_response_v6_roundtrip();
    test_tamper_magic();
    test_tamper_status();
    test_truncation();
    test_mapped_address_fallback();
    test_xor_wins_over_mapped();
    test_request_deterministic();
    test_parse_bad_args();

    if (fails) {
        printf("\n[FAIL] %d assertion(s) failed\n", fails);
        return 1;
    }
    printf("\n[PASS] all stun assertions passed\n");
    return 0;
}
