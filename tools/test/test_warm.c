// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// The warm-start record (tl_warm.h, round 1.3.9): the strict text forms
// of the netmap's addresses and endpoints, the record built from a
// netmap and handed back to wg_dataplane_start (byte for byte what a cold
// start passes), its NVS encoding and the decode's refusals (every
// truncation, every count, mutations and random blobs: what it accepts
// re-encodes to the same bytes), what differs between two records and
// which of that restarts the warm session, the write-on-change policy
// over a fake NVS that counts flash writes across simulated reboots
// (hard changes at once, endpoints / DiscoKey at most hourly, a daily
// refresh), the cold start's target pick and the in-place rules, the RTC
// crash guard and restart mark over every reset reason, the go / no-go
// of a boot, the warm session's state machine (seed, first-frame reset,
// wait / confirm / restart, bound and age, failed start) and boots in a
// row over a fake NVS and RTC, the age in the log line. Addresses are
// RFC 5737, keys made up.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tl_warm.h"

static int s_fails;

static void check(const char *name, int ok)
{
    printf("[%s] %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) s_fails++;
}

static uint32_t s_rng = 0x2545F491u;
static uint32_t rnd(void)
{
    s_rng ^= s_rng << 13;
    s_rng ^= s_rng >> 17;
    s_rng ^= s_rng << 5;
    return s_rng;
}

static const uint8_t k_self_pub[32] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };
static const uint8_t k_ctl_pub[32]  = { 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9 };

static void key_fill(uint8_t k[32], uint8_t seed)
{
    for (int i = 0; i < 32; i++) k[i] = (uint8_t)(seed + 7 * i);
}

static void set_str(char *dst, size_t cap, const char *s)
{
    memset(dst, 0, cap);
    snprintf(dst, cap, "%s", s);
}

/* A netmap peer as mapreq.c leaves it. */
static tl_peer_t mk_peer(uint64_t id, uint8_t key_seed, int disco_seed,
                         const char *const *addrs, size_t n_addrs,
                         const char *const *eps, size_t n_eps)
{
    tl_peer_t p;
    memset(&p, 0, sizeof(p));
    p.id = id;
    key_fill(p.node_pub, key_seed);
    if (disco_seed >= 0) {
        key_fill(p.disco_pub, (uint8_t)disco_seed);
        p.has_disco_pub = true;
    }
    p.home_derp = 16;
    for (size_t i = 0; i < n_addrs; i++) {
        set_str(p.addresses[i].str, sizeof(p.addresses[i].str), addrs[i]);
    }
    p.n_addresses = n_addrs;
    for (size_t i = 0; i < n_eps; i++) {
        set_str(p.endpoints[i].str, sizeof(p.endpoints[i].str), eps[i]);
    }
    p.n_endpoints = n_eps;
    return p;
}

static const char *const k_peer_addrs[] = { "192.0.2.20/32", "198.51.100.0/24" };
static const char *const k_peer_eps[]   = { "203.0.113.7:41641", "198.51.100.9:41641",
                                            "192.0.2.77:12345", "203.0.113.200:1" };
static const char *const k_self_addrs[] = { "192.0.2.10/32", "192.0.2.11/32" };

static void mk_self(tl_cidr_t self[2], size_t n)
{
    memset(self, 0, 2 * sizeof(tl_cidr_t));
    for (size_t i = 0; i < n; i++) set_str(self[i].str, sizeof(self[i].str), k_self_addrs[i]);
}

static tl_warm_rec_t mk_rec(void)
{
    tl_cidr_t self[2];
    mk_self(self, 2);
    const tl_peer_t p = mk_peer(0x1122334455667788ull, 0x40, 0x90, k_peer_addrs, 2, k_peer_eps, 4);
    tl_warm_rec_t r;
    tl_warm_rec_build(self, 2, &p, k_self_pub, k_ctl_pub, &r);
    return r;
}

static int cidr_is(const tl_warm_cidr_t *c, int a, int b, int x, int d, int p)
{
    return c->ip[0] == a && c->ip[1] == b && c->ip[2] == x && c->ip[3] == d && c->prefix == p;
}

/* Field by field (the structs have padding). */
static int rec_eq(const tl_warm_rec_t *a, const tl_warm_rec_t *b)
{
    if (a->written != b->written || memcmp(a->self_tag, b->self_tag, 8) ||
        memcmp(a->ctl_tag, b->ctl_tag, 8) || a->n_self != b->n_self) {
        return 0;
    }
    for (unsigned i = 0; i < a->n_self; i++) {
        if (!tl_warm_cidr_eq(&a->self[i], &b->self[i])) return 0;
    }
    const tl_warm_peer_t *p = &a->peer, *q = &b->peer;
    if (p->id != q->id || memcmp(p->node_pub, q->node_pub, 32) || p->has_disco != q->has_disco ||
        memcmp(p->disco_pub, q->disco_pub, 32) || p->n_addr != q->n_addr || p->n_ep != q->n_ep) {
        return 0;
    }
    for (unsigned i = 0; i < p->n_addr; i++) {
        if (!tl_warm_cidr_eq(&p->addr[i], &q->addr[i])) return 0;
    }
    for (unsigned i = 0; i < p->n_ep; i++) {
        if (memcmp(p->ep[i].ip, q->ep[i].ip, 4) || p->ep[i].port != q->ep[i].port) return 0;
    }
    return 1;
}

/* ---- Text forms --------------------------------------------------------- */

static void test_text(void)
{
    unsigned v = 99;
    check("dec/valid", tl_warm_dec("0", 1, 32, &v) && v == 0 && tl_warm_dec("32", 2, 32, &v) &&
                       v == 32 && tl_warm_dec("65535", 5, 65535, &v) && v == 65535);
    v = 7;
    check("dec/refuses", !tl_warm_dec("", 0, 32, &v) && !tl_warm_dec("01", 2, 32, &v) &&
                         !tl_warm_dec("33", 2, 32, &v) && !tl_warm_dec("65536", 5, 65535, &v) &&
                         !tl_warm_dec("123456", 6, 999999, &v) && !tl_warm_dec("-1", 2, 32, &v) &&
                         !tl_warm_dec("+1", 2, 32, &v) && !tl_warm_dec("1a", 2, 32, &v) && v == 7);

    tl_warm_cidr_t c;
    check("cidr/valid", tl_warm_cidr_parse("192.0.2.10/32", &c) && cidr_is(&c, 192, 0, 2, 10, 32) &&
                        tl_warm_cidr_parse("198.51.100.0/24", &c) && cidr_is(&c, 198, 51, 100, 0, 24) &&
                        tl_warm_cidr_parse("203.0.113.7/0", &c) && cidr_is(&c, 203, 0, 113, 7, 0));
    static const char *const bad_cidr[] = {
        "", "192.0.2.10", "192.0.2.10/", "/32", "192.0.2.10/33", "192.0.2.10/032",
        "192.0.2.010/32", "192.0.2.10/32 ", " 192.0.2.10/32", "192.0.2.10/3/2", "192.0.2.10/-1",
        "2001:db8::1/128", "0.0.0.0/0", "127.0.0.1/8", "224.0.0.1/32", "255.255.255.255/32",
        "192.0.2/24", "192.0.2.10:41641",
    };
    int all = 1;
    for (size_t i = 0; i < sizeof(bad_cidr) / sizeof(bad_cidr[0]); i++) {
        memset(&c, 0x5a, sizeof(c));
        if (tl_warm_cidr_parse(bad_cidr[i], &c) || c.ip[0] != 0x5a) {
            printf("  cidr accepted: '%s'\n", bad_cidr[i]);
            all = 0;
        }
    }
    check("cidr/refuses-18", all);
    char full[TL_CIDR_STRLEN];
    memset(full, '1', sizeof(full));   /* no NUL within the field */
    check("cidr/unterminated", !tl_warm_cidr_parse(full, &c));

    tl_warm_ep_t e;
    check("ep/valid", tl_warm_ep_parse("198.51.100.7:41641", &e) && e.port == 41641 &&
                      e.ip[0] == 198 && e.ip[3] == 7 && tl_warm_ep_parse("203.0.113.9:1", &e) &&
                      e.port == 1 && tl_warm_ep_parse("192.0.2.1:65535", &e) && e.port == 65535);
    static const char *const bad_ep[] = {
        "", "198.51.100.7", "198.51.100.7:", ":41641", "198.51.100.7:0", "198.51.100.7:65536",
        "198.51.100.7:041641", "198.51.100.7:41641:1", "[2001:db8::1]:41641", "2001:db8::1:41641",
        "0.1.2.3:41641", "127.0.0.1:41641", "239.1.2.3:41641", "198.51.100.07:41641",
        "198.51.100.7: 41641", "198.51.100.7:41641 ",
    };
    all = 1;
    for (size_t i = 0; i < sizeof(bad_ep) / sizeof(bad_ep[0]); i++) {
        memset(&e, 0x5a, sizeof(e));
        if (tl_warm_ep_parse(bad_ep[i], &e) || e.ip[0] != 0x5a) {
            printf("  endpoint accepted: '%s'\n", bad_ep[i]);
            all = 0;
        }
    }
    check("ep/refuses-16", all);
    char efull[TL_ENDPOINT_STRLEN];
    memset(efull, '2', sizeof(efull));
    check("ep/unterminated", !tl_warm_ep_parse(efull, &e));

    /* Go's canonical forms survive the round trip unchanged. */
    static const char *const cidrs[] = { "192.0.2.10/32", "198.51.100.0/24", "203.0.113.255/31",
                                         "1.0.0.0/8", "223.255.255.254/32" };
    all = 1;
    for (size_t i = 0; i < sizeof(cidrs) / sizeof(cidrs[0]); i++) {
        tl_cidr_t out;
        all &= tl_warm_cidr_parse(cidrs[i], &c);
        tl_warm_cidr_str(&c, &out);
        all &= strcmp(out.str, cidrs[i]) == 0;
    }
    check("cidr/canonical-round-trip", all);
    static const char *const eps[] = { "203.0.113.7:41641", "198.51.100.9:1", "192.0.2.255:65535",
                                       "10.0.0.1:41641", "223.255.255.254:53" };
    all = 1;
    for (size_t i = 0; i < sizeof(eps) / sizeof(eps[0]); i++) {
        tl_endpoint_t out;
        all &= tl_warm_ep_parse(eps[i], &e);
        tl_warm_ep_str(&e, &out);
        all &= strcmp(out.str, eps[i]) == 0;
    }
    check("ep/canonical-round-trip", all);
}

/* ---- From / to the netmap ----------------------------------------------- */

static int peers_match(const tl_peer_t *a, const tl_peer_t *b)
{
    if (a->id != b->id || memcmp(a->node_pub, b->node_pub, 32) ||
        a->has_disco_pub != b->has_disco_pub ||
        (a->has_disco_pub && memcmp(a->disco_pub, b->disco_pub, 32)) ||
        a->n_addresses != b->n_addresses || a->n_endpoints != b->n_endpoints) {
        return 0;
    }
    for (size_t i = 0; i < a->n_addresses; i++) {
        if (strcmp(a->addresses[i].str, b->addresses[i].str) != 0) return 0;
    }
    for (size_t i = 0; i < a->n_endpoints; i++) {
        if (strcmp(a->endpoints[i].str, b->endpoints[i].str) != 0) return 0;
    }
    return 1;
}

static void test_netmap(void)
{
    const tl_peer_t p = mk_peer(0x0102030405060708ull, 0x40, 0x90, k_peer_addrs, 2, k_peer_eps, 4);
    tl_warm_peer_t w;
    tl_warm_peer_from(&p, &w);
    check("peer/from", w.id == p.id && w.has_disco == 1 && w.n_addr == 2 && w.n_ep == 4 &&
                       memcmp(w.node_pub, p.node_pub, 32) == 0 &&
                       memcmp(w.disco_pub, p.disco_pub, 32) == 0 &&
                       cidr_is(&w.addr[1], 198, 51, 100, 0, 24) && w.ep[3].port == 1);
    tl_peer_t back;
    memset(&back, 0x77, sizeof(back));
    tl_warm_peer_to(&w, &back);
    check("peer/to-equals-netmap", peers_match(&back, &p) && back.home_derp == 0);

    const tl_peer_t nd = mk_peer(9, 0x41, -1, k_peer_addrs, 1, k_peer_eps, 1);
    tl_warm_peer_from(&nd, &w);
    static const uint8_t zero[32] = { 0 };
    tl_warm_peer_to(&w, &back);
    check("peer/no-disco", w.has_disco == 0 && memcmp(w.disco_pub, zero, 32) == 0 &&
                           !back.has_disco_pub && peers_match(&back, &nd));

    /* Unparseable entries are left out, the rest keep their order. */
    static const char *const mixed_eps[] = { "garbage", "203.0.113.7:41641", "0.0.0.0:41641",
                                             "198.51.100.9:41641" };
    static const char *const mixed_addr[] = { "not-an-address", "192.0.2.20/32" };
    const tl_peer_t m = mk_peer(10, 0x42, 0x91, mixed_addr, 2, mixed_eps, 4);
    tl_warm_peer_from(&m, &w);
    check("peer/skips-unparseable-keeps-order",
          w.n_ep == 2 && w.ep[0].ip[0] == 203 && w.ep[1].ip[0] == 198 && w.n_addr == 1 &&
          cidr_is(&w.addr[0], 192, 0, 2, 20, 32));

    /* A record of the netmap's self + target: storable as built. */
    tl_cidr_t self[2];
    mk_self(self, 2);
    tl_warm_rec_t r;
    tl_warm_rec_build(self, 2, &p, k_self_pub, k_ctl_pub, &r);
    check("rec/build", r.n_self == 2 && cidr_is(&r.self[0], 192, 0, 2, 10, 32) &&
                       cidr_is(&r.self[1], 192, 0, 2, 11, 32) && r.written == 0 &&
                       memcmp(r.self_tag, k_self_pub, 8) == 0 &&
                       memcmp(r.ctl_tag, k_ctl_pub, 8) == 0 && tl_warm_rec_storable(&r));
    check("rec/for-these-keys", tl_warm_rec_for(&r, k_self_pub, k_ctl_pub));
    uint8_t other[32];
    memcpy(other, k_self_pub, 32);
    other[7] ^= 1;
    check("rec/not-for-other-node-key", !tl_warm_rec_for(&r, other, k_ctl_pub));
    memcpy(other, k_ctl_pub, 32);
    other[0] ^= 0x80;
    check("rec/not-for-other-control", !tl_warm_rec_for(&r, k_self_pub, other));
    other[0] ^= 0x80;
    other[8] ^= 1;   /* past the tag */
    check("rec/tag-is-8-bytes", tl_warm_rec_for(&r, k_self_pub, other));

    /* self[0] keeps its place: unparseable → nothing to attach. */
    set_str(self[0].str, sizeof(self[0].str), "192.0.2.300/32");
    tl_warm_rec_build(self, 2, &p, k_self_pub, k_ctl_pub, &r);
    check("rec/self0-unparseable-not-storable", r.n_self == 0 && !tl_warm_rec_storable(&r));
    mk_self(self, 2);
    set_str(self[1].str, sizeof(self[1].str), "2001:db8::1/128");
    tl_warm_rec_build(self, 2, &p, k_self_pub, k_ctl_pub, &r);
    check("rec/self1-unparseable-dropped", r.n_self == 1 && tl_warm_rec_storable(&r));
    mk_self(self, 1);
    const tl_peer_t noep = mk_peer(11, 0x43, 0x92, k_peer_addrs, 2, k_peer_eps, 0);
    tl_warm_rec_build(self, 1, &noep, k_self_pub, k_ctl_pub, &r);
    check("rec/peer-without-endpoint-not-storable", !tl_warm_rec_storable(&r));
    uint8_t b[TL_WARM_BLOB_MAX];
    check("rec/unstorable-not-encoded", tl_warm_encode(&r, b, sizeof(b)) == 0);
    tl_warm_rec_build(self, 0, &p, k_self_pub, k_ctl_pub, &r);
    check("rec/no-self-not-storable", !tl_warm_rec_storable(&r));
}

/* ---- Encode / decode ---------------------------------------------------- */

static void test_codec(void)
{
    /* Every count combination round-trips, at the documented size. */
    int all = 1;
    size_t smallest = 1000, largest = 0;
    for (size_t ns = 1; ns <= 2; ns++) {
        for (size_t na = 0; na <= 2; na++) {
            for (size_t ne = 1; ne <= 4; ne++) {
                for (int disco = 0; disco <= 1; disco++) {
                    tl_cidr_t self[2];
                    mk_self(self, ns);
                    const tl_peer_t p = mk_peer(0xfedcba9876543210ull, 0x50,
                                                disco ? 0xa0 : -1, k_peer_addrs, na, k_peer_eps, ne);
                    tl_warm_rec_t r, d;
                    tl_warm_rec_build(self, ns, &p, k_self_pub, k_ctl_pub, &r);
                    r.written = 0xA1B2C3D4u;
                    uint8_t b[TL_WARM_BLOB_MAX];
                    const size_t n = tl_warm_encode(&r, b, sizeof(b));
                    const size_t want = TL_WARM_HDR + 5 * (ns + na) + 6 * ne;
                    all &= n == want && tl_warm_decode(b, n, &d) && rec_eq(&r, &d);
                    if (n < smallest) smallest = n;
                    if (n > largest) largest = n;
                }
            }
        }
    }
    check("codec/round-trip-all-48-shapes", all);
    check("codec/size-108..141", smallest == TL_WARM_BLOB_MIN && smallest == 108 &&
                                 largest == TL_WARM_BLOB_MAX && largest == 141);

    tl_warm_rec_t r = mk_rec(), d;
    r.written = 0x01020304u;
    uint8_t b[TL_WARM_BLOB_MAX + 8];
    const size_t n = tl_warm_encode(&r, b, sizeof(b));
    check("codec/layout", n == 141 && b[0] == TL_WARM_REC_V1 && b[1] == 0x04 && b[4] == 0x01 &&
                          b[5] == 0x11 && b[13] == 0xc1 && b[21] == 2 && b[22] == 2 && b[23] == 4 &&
                          b[24] == 1 && b[25] == 0x88 && b[32] == 0x11 &&
                          b[TL_WARM_HDR] == 192 && b[TL_WARM_HDR + 4] == 32);
    check("codec/cap-too-small", tl_warm_encode(&r, b, n - 1) == 0 && tl_warm_encode(&r, b, n) == n);

    all = 1;
    for (size_t k = 0; k < n; k++) all &= !tl_warm_decode(b, k, &d);
    check("decode/every-truncation", all);
    b[n] = 0;
    check("decode/extra-byte", !tl_warm_decode(b, n + 1, &d) && !tl_warm_decode(NULL, n, &d));

    struct { const char *name; size_t at; uint8_t v; } bad[] = {
        { "decode/version-0",       0,  0 },
        { "decode/version-2",       0,  2 },
        { "decode/n-self-0",        21, 0 },
        { "decode/n-self-3",        21, 3 },
        { "decode/n-addr-3",        22, 3 },
        { "decode/n-ep-0",          23, 0 },
        { "decode/n-ep-5",          23, 5 },
        { "decode/unknown-flag",    24, 3 },
        { "decode/self-prefix-33",  TL_WARM_HDR + 4, 33 },
        { "decode/self-ip-0-8",     TL_WARM_HDR, 0 },
        { "decode/self-ip-127-8",   TL_WARM_HDR, 127 },
        { "decode/self-ip-224-3",   TL_WARM_HDR + 5, 224 },
        { "decode/addr-prefix-255", TL_WARM_HDR + 14, 255 },
        { "decode/ep-ip-0",         TL_WARM_HDR + 20, 0 },
        { "decode/ep-ip-240",       TL_WARM_HDR + 26, 240 },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        uint8_t m[TL_WARM_BLOB_MAX];
        memcpy(m, b, n);
        m[bad[i].at] = bad[i].v;
        memset(&d, 0x5a, sizeof(d));
        check(bad[i].name, !tl_warm_decode(m, n, &d) && d.n_self == 0x5a);
    }
    {
        uint8_t m[TL_WARM_BLOB_MAX];
        memcpy(m, b, n);
        m[TL_WARM_HDR + 20 + 4] = 0;   /* first endpoint's port: 0 */
        m[TL_WARM_HDR + 20 + 5] = 0;
        check("decode/port-0", !tl_warm_decode(m, n, &d));
        memcpy(m, b, n);
        m[24] = 0;                     /* no DiscoKey flag, key bytes left */
        check("decode/disco-bytes-without-flag", !tl_warm_decode(m, n, &d));
        memset(m + 65, 0, 32);
        check("decode/no-disco-zero-key-ok", tl_warm_decode(m, n, &d) && !d.peer.has_disco);
    }

    /* Mutations: no read past the blob (ASan), and what is accepted is
     * canonical — it re-encodes to exactly its bytes. */
    int accepted = 0, canonical = 1;
    for (int it = 0; it < 20000; it++) {
        uint8_t m[TL_WARM_BLOB_MAX + 1];
        memcpy(m, b, n);
        const int flips = 1 + (int)(rnd() % 3);
        for (int f = 0; f < flips; f++) m[rnd() % n] ^= (uint8_t)(1u << (rnd() % 8));
        size_t mn = n;
        if (rnd() % 8 == 0) mn = rnd() % (n + 1);
        if (tl_warm_decode(m, mn, &d)) {
            accepted++;
            uint8_t again[TL_WARM_BLOB_MAX];
            const size_t an = tl_warm_encode(&d, again, sizeof(again));
            canonical &= an == mn && memcmp(again, m, mn) == 0;
        }
    }
    check("decode/mutations-canonical", canonical && accepted > 1000);
    int rand_canon = 1;
    for (int it = 0; it < 20000; it++) {
        uint8_t m[160];
        const size_t mn = rnd() % sizeof(m);
        for (size_t k = 0; k < mn; k++) m[k] = (uint8_t)rnd();
        if (mn > 24) {   /* plausible header, so some get past the counts */
            m[0] = TL_WARM_REC_V1;
            m[21] = (uint8_t)(1 + rnd() % 2);
            m[22] = (uint8_t)(rnd() % 3);
            m[23] = (uint8_t)(1 + rnd() % 4);
            m[24] = (uint8_t)(rnd() % 2);
        }
        if (tl_warm_decode(m, mn, &d)) {
            uint8_t again[TL_WARM_BLOB_MAX];
            const size_t an = tl_warm_encode(&d, again, sizeof(again));
            rand_canon &= an == mn && memcmp(again, m, mn) == 0;
        }
    }
    check("decode/random-blobs-canonical", rand_canon);
}

/* ---- The next boot is fed what the cold start was --------------------- */

static void test_cold_equivalence(void)
{
    /* Boot N: a netmap with three peers; the target is #1. */
    tl_cidr_t self[2];
    mk_self(self, 2);
    static const char *const a0[] = { "192.0.2.30/32" };
    static const char *const e0[] = { "192.0.2.31:41641" };
    static const char *const a2[] = { "192.0.2.40/32" };
    static const char *const e2[] = { "198.51.100.40:41641", "192.0.2.41:41641" };
    const tl_peer_t table[3] = {
        mk_peer(101, 0x10, 0x60, a0, 1, e0, 1),
        mk_peer(202, 0x20, 0x70, k_peer_addrs, 2, k_peer_eps, 4),
        mk_peer(303, 0x30, -1, a2, 1, e2, 2),
    };
    int all = 1;
    for (size_t t = 0; t < 3; t++) {
        tl_warm_rec_t r;
        tl_warm_rec_build(self, 2, &table[t], k_self_pub, k_ctl_pub, &r);
        r.written = 1700000000u;
        uint8_t b[TL_WARM_BLOB_MAX];
        const size_t n = tl_warm_encode(&r, b, sizeof(b));
        /* Boot N+1: decode, seed the tables with the warm start's own
         * call (tl_warm_sm_begin, what tinylink.c runs). */
        tl_warm_rec_t d;
        all &= n > 0 && tl_warm_decode(b, n, &d);
        tl_cidr_t s2[TL_MAX_PEER_ADDRESSES];
        tl_peer_t p2[TL_MAX_PEERS];
        size_t ns2 = 99, np2 = 99;
        memset(s2, 0x6b, sizeof(s2));
        memset(p2, 0x6b, sizeof(p2));
        tl_warm_tables_t tt = { s2, &ns2, p2, &np2 };
        tl_warm_sm_t sm;
        tl_warm_rtc_t rtc;
        memset(&rtc, 0, sizeof(rtc));
        tl_warm_sm_begin(&sm, &rtc, &d, &tt);
        all &= ns2 == 2 && np2 == 1 && sm.seeded && rtc.attempt == 1 &&
               strcmp(s2[0].str, self[0].str) == 0 && strcmp(s2[1].str, self[1].str) == 0 &&
               peers_match(&p2[0], &table[t]);
        /* …and the same netmap again confirms it. */
        tl_warm_rec_t again;
        tl_warm_rec_build(self, 2, &table[t], k_self_pub, k_ctl_pub, &again);
        all &= tl_warm_diff(&d, &again) == 0;
    }
    check("cold-equivalence/wg_dataplane_start-inputs-byte-equal", all);
}

/* ---- What differs ------------------------------------------------------- */

static void test_diff(void)
{
    const tl_warm_rec_t a = mk_rec();
    tl_warm_rec_t b = a;
    check("diff/identical", tl_warm_diff(&a, &b) == 0);
    b.written = 12345;
    check("diff/timestamp-ignored", tl_warm_diff(&a, &b) == 0);

    b = a; b.peer.node_pub[31] ^= 1;
    check("diff/node-key", tl_warm_diff(&a, &b) == TL_WARM_D_KEY);
    b = a; b.peer.disco_pub[0] ^= 1;
    check("diff/disco-key", tl_warm_diff(&a, &b) == TL_WARM_D_DISCO);
    b = a; b.peer.has_disco = 0; memset(b.peer.disco_pub, 0, 32);
    check("diff/disco-lost", tl_warm_diff(&a, &b) == TL_WARM_D_DISCO);
    b = a; b.peer.ep[2].port++;
    check("diff/endpoint-port", tl_warm_diff(&a, &b) == TL_WARM_D_EP);
    b = a; b.peer.ep[0] = a.peer.ep[1]; b.peer.ep[1] = a.peer.ep[0];
    check("diff/endpoint-order", tl_warm_diff(&a, &b) == TL_WARM_D_EP);
    b = a; b.peer.n_ep = 3;
    check("diff/endpoint-count", tl_warm_diff(&a, &b) == TL_WARM_D_EP);
    b = a; b.peer.addr[0].ip[3] = 21;
    check("diff/peer-address", tl_warm_diff(&a, &b) == TL_WARM_D_ADDR);
    b = a; b.peer.n_addr = 1;
    check("diff/peer-address-count", tl_warm_diff(&a, &b) == TL_WARM_D_ADDR);
    b = a; b.self[0].ip[3] = 99;
    check("diff/self0", tl_warm_diff(&a, &b) == (TL_WARM_D_SELF0 | TL_WARM_D_SELF));
    b = a; b.self[1].ip[3] = 99;
    check("diff/self1-only-list", tl_warm_diff(&a, &b) == TL_WARM_D_SELF);
    b = a; b.n_self = 1;
    check("diff/self-count", tl_warm_diff(&a, &b) == TL_WARM_D_SELF);
    b = a; b.n_self = 0;
    check("diff/self-unusable", tl_warm_diff(&a, &b) == (TL_WARM_D_SELF0 | TL_WARM_D_SELF));
    b = a; b.self_tag[3] ^= 1;
    check("diff/ident-node", tl_warm_diff(&a, &b) == TL_WARM_D_IDENT);
    b = a; b.ctl_tag[7] ^= 1;
    check("diff/ident-control", tl_warm_diff(&a, &b) == TL_WARM_D_IDENT);
    b = a; b.peer.id++;
    check("diff/other-peer-same-key", tl_warm_diff(&a, &b) == TL_WARM_D_PEER);
    b = a; b.peer.id++; b.peer.node_pub[0] ^= 1;
    check("diff/other-peer", tl_warm_diff(&a, &b) == (TL_WARM_D_PEER | TL_WARM_D_KEY));
    /* NodeID 0 (never sent by real control): matched by NodeKey, as
     * wg_dataplane_update_peers does. */
    tl_warm_rec_t z = a;
    z.peer.id = 0;
    b = z;
    b.peer.ep[0].port++;
    check("diff/id0-same-by-key", tl_warm_diff(&z, &b) == TL_WARM_D_EP);
    b = z;
    b.peer.node_pub[5] ^= 1;
    check("diff/id0-other-key-other-peer",
          tl_warm_diff(&z, &b) == (TL_WARM_D_PEER | TL_WARM_D_KEY));

    /* Which of it restarts the warm session. */
    check("verdict/restart-peer-self0-ident",
          (TL_WARM_D_PEER & TL_WARM_RESTART) && (TL_WARM_D_SELF0 & TL_WARM_RESTART) &&
          (TL_WARM_D_IDENT & TL_WARM_RESTART));
    check("verdict/in-place-key-disco-ep-addr-self-list",
          !(TL_WARM_RESTART & (TL_WARM_D_KEY | TL_WARM_D_DISCO | TL_WARM_D_EP |
                               TL_WARM_D_ADDR | TL_WARM_D_SELF)));
    check("verdict/soft-only-ep-disco",
          (TL_WARM_HARD & (TL_WARM_D_EP | TL_WARM_D_DISCO)) == 0 &&
          (TL_WARM_HARD | TL_WARM_D_EP | TL_WARM_D_DISCO) == 0xffu);

    char s[112];
    check("diffstr/none", strcmp(tl_warm_diff_str(0, s, sizeof(s)), "") == 0);
    check("diffstr/key-ep", strcmp(tl_warm_diff_str(TL_WARM_D_KEY | TL_WARM_D_EP, s, sizeof(s)),
                                   "peer NodeKey, peer endpoints") == 0);
    check("diffstr/self0-once",
          strcmp(tl_warm_diff_str(TL_WARM_D_SELF0 | TL_WARM_D_SELF, s, sizeof(s)),
                 "self address") == 0 &&
          strcmp(tl_warm_diff_str(TL_WARM_D_SELF, s, sizeof(s)), "self addresses") == 0);
    tl_warm_diff_str(0xffu, s, sizeof(s));
    check("diffstr/all-fit", strcmp(s, "our keys, target peer, self address, peer NodeKey, "
                                       "peer DiscoKey, peer endpoints, peer addresses") == 0);
    char tiny[12];
    memset(tiny, 0x7f, sizeof(tiny));
    tl_warm_diff_str(0xffu, tiny, sizeof(tiny));
    check("diffstr/small-buffer-terminated", memchr(tiny, '\0', sizeof(tiny)) != NULL);
}

/* ---- Written only on change -------------------------------------------- */

typedef struct {
    uint8_t b[TL_WARM_BLOB_MAX];
    size_t  n;
    int     writes;
    int     fail;
} fake_nvs_t;

static int fake_write(const uint8_t *b, size_t n, const void *ctx)
{
    fake_nvs_t *f = (fake_nvs_t *)(uintptr_t)ctx;
    f->writes++;
    if (f->fail) return -1;
    memcpy(f->b, b, n);
    f->n = n;
    return 0;
}

/* tinylink_init's load. */
static void boot(tl_warm_nvs_t *m, const fake_nvs_t *f)
{
    memset(m, 0, sizeof(*m));
    m->valid = f->n > 0 && tl_warm_decode(f->b, f->n, &m->rec);
}

#define MIN_US (60LL * 1000000LL)

static void test_store(void)
{
    check("due/nothing-stored", tl_warm_store_due(0, false, false, 0, 0));
    check("due/unchanged", !tl_warm_store_due(0, true, true, 0, 0));
    check("due/hard-at-once", tl_warm_store_due(TL_WARM_D_KEY, true, true, MIN_US, 0) &&
                              tl_warm_store_due(TL_WARM_D_PEER, true, true, 1, 0) &&
                              tl_warm_store_due(TL_WARM_D_ADDR, true, true, 1, 0) &&
                              tl_warm_store_due(TL_WARM_D_SELF, true, true, 1, 0));
    check("due/soft-first-of-boot", tl_warm_store_due(TL_WARM_D_EP, true, false, 1, 0));
    check("due/soft-hourly", !tl_warm_store_due(TL_WARM_D_EP | TL_WARM_D_DISCO, true, true,
                                                TL_WARM_SOFT_MIN_US - 1, 0) &&
                             tl_warm_store_due(TL_WARM_D_DISCO, true, true, TL_WARM_SOFT_MIN_US, 0));

    fake_nvs_t f;
    memset(&f, 0, sizeof(f));
    tl_warm_nvs_t m;
    boot(&m, &f);
    tl_warm_rec_t r = mk_rec();
    check("store/first-boot-writes", tl_warm_store(&m, &r, 1700000000u, MIN_US, false, fake_write, &f) == 1 &&
                                     f.writes == 1 && m.valid && m.rec.written == 1700000000u);
    check("store/same-no-write", tl_warm_store(&m, &r, 1700000060u, 2 * MIN_US, false, fake_write, &f) == 0 &&
                                 f.writes == 1);
    tl_warm_rec_t soft = r;
    soft.peer.ep[0].port = 41642;
    check("store/soft-held-back", tl_warm_store(&m, &soft, 1700000120u, 3 * MIN_US, false, fake_write, &f) == 0 &&
                                  f.writes == 1);
    check("store/soft-after-an-hour",
          tl_warm_store(&m, &soft, 1700003700u, MIN_US + TL_WARM_SOFT_MIN_US, false, fake_write, &f) == 1 &&
          f.writes == 2);
    tl_warm_rec_t hard = soft;
    hard.peer.node_pub[0] ^= 0xff;
    check("store/hard-at-once",
          tl_warm_store(&m, &hard, 1700003760u, 2 * MIN_US + TL_WARM_SOFT_MIN_US, false, fake_write, &f) == 1 &&
          f.writes == 3);
    tl_warm_rec_t back;
    check("store/nvs-holds-last", tl_warm_decode(f.b, f.n, &back) && back.written == 1700003760u &&
                                  tl_warm_diff(&back, &hard) == 0);

    /* Reboot: same netmap → no write; a soft change is the boot's first
     * write → at once; the next one an hour later. */
    boot(&m, &f);
    check("store/reboot-same-no-write", m.valid &&
          tl_warm_store(&m, &hard, 1700010000u, MIN_US, false, fake_write, &f) == 0 && f.writes == 3);
    tl_warm_rec_t soft2 = hard;
    soft2.peer.disco_pub[1] ^= 1;
    check("store/reboot-soft-first-at-once",
          tl_warm_store(&m, &soft2, 1700010060u, 2 * MIN_US, false, fake_write, &f) == 1 && f.writes == 4);
    tl_warm_rec_t soft3 = soft2;
    soft3.peer.ep[3].port = 2;
    check("store/reboot-soft-second-held",
          tl_warm_store(&m, &soft3, 1700010120u, 3 * MIN_US, false, fake_write, &f) == 0 && f.writes == 4);

    /* A layout this firmware cannot read counts as nothing stored. */
    f.b[0] = 2;
    boot(&m, &f);
    check("store/unknown-layout-replaced", !m.valid &&
          tl_warm_store(&m, &soft3, 1700010180u, MIN_US, false, fake_write, &f) == 1 && f.writes == 5 &&
          f.b[0] == TL_WARM_REC_V1);

    /* A failing NVS: one attempt per change, not one per housekeeping. */
    f.fail = 1;
    tl_warm_rec_t h2 = soft3;
    h2.peer.addr[0].ip[3] = 21;
    const int w0 = f.writes;
    const int rc1 = tl_warm_store(&m, &h2, 0, 2 * MIN_US, false, fake_write, &f);
    const int rc2 = tl_warm_store(&m, &h2, 0, 3 * MIN_US, false, fake_write, &f);
    check("store/write-failure-no-retry-storm", rc1 == -1 && rc2 == 0 && f.writes == w0 + 1);
    f.fail = 0;

    tl_warm_rec_t bad = h2;
    bad.peer.n_ep = 0;
    const int w1 = f.writes;
    check("store/unstorable-refused", tl_warm_store(&m, &bad, 0, 4 * MIN_US, false, fake_write, &f) == -1 &&
                                      f.writes == w1);

    /* A day of endpoints churning every minute: the boot's first write,
     * then one an hour. */
    memset(&f, 0, sizeof(f));
    boot(&m, &f);
    tl_warm_rec_t c = mk_rec();
    int writes_day = 0;
    for (int min = 1; min <= 24 * 60; min++) {
        c.peer.ep[min % 4].port = (uint16_t)(1000 + min);
        if (tl_warm_store(&m, &c, 1700000000u + 60u * (uint32_t)min, (int64_t)min * MIN_US,
                          false, fake_write, &f) == 1) {
            writes_day++;
        }
    }
    check("store/churn-day-24-writes", writes_day == 24 && f.writes == 24);
}

/* ---- Refresh and age ---------------------------------------------------- */

#define DAY 86400u

static void test_refresh_age(void)
{
    check("refresh/needs-fresh", !tl_warm_refresh_due(1700000000u, 1700000000u + 2 * DAY, false));
    check("refresh/needs-clock", !tl_warm_refresh_due(1700000000u, 0, true));
    check("refresh/unknown-written", tl_warm_refresh_due(0, 1700000000u, true));
    check("refresh/daily", !tl_warm_refresh_due(1700000000u, 1700000000u + DAY - 1, true) &&
                           tl_warm_refresh_due(1700000000u, 1700000000u + DAY, true));
    check("refresh/clock-behind", !tl_warm_refresh_due(1700000000u, 1600000000u, true));

    fake_nvs_t f;
    memset(&f, 0, sizeof(f));
    tl_warm_nvs_t m;
    boot(&m, &f);
    const tl_warm_rec_t r = mk_rec();
    tl_warm_store(&m, &r, 1700000000u, MIN_US, false, fake_write, &f);
    const int w = f.writes;
    check("refresh/not-within-a-day",
          tl_warm_store(&m, &r, 1700000000u + DAY - 60, 2 * MIN_US, true, fake_write, &f) == 0 &&
          f.writes == w);
    check("refresh/not-when-stale-netmap",
          tl_warm_store(&m, &r, 1700000000u + 2 * DAY, 3 * MIN_US, false, fake_write, &f) == 0 &&
          f.writes == w);
    tl_warm_rec_t back;
    check("refresh/a-day-later-fresh",
          tl_warm_store(&m, &r, 1700000000u + 2 * DAY, 4 * MIN_US, true, fake_write, &f) == 1 &&
          f.writes == w + 1 && tl_warm_decode(f.b, f.n, &back) &&
          back.written == 1700000000u + 2 * DAY && tl_warm_diff(&back, &r) == 0);
    /* Up for 60 days, control heard: one write a day keeps it young. */
    int writes = 0;
    for (uint32_t h = 1; h <= 60 * 24; h++) {
        if (tl_warm_store(&m, &r, 1700000000u + 2 * DAY + 3600u * h, (int64_t)(5 + h) * MIN_US,
                          true, fake_write, &f) == 1) {
            writes++;
        }
    }
    check("refresh/60-days-60-writes", writes == 60 &&
          !tl_warm_too_old(1700000000 + 62 * (int64_t)DAY + 3600, m.rec.written));

    check("age/too-old-unknown", !tl_warm_too_old(1700000000, 0));
    check("age/too-old-clock-behind", !tl_warm_too_old(1600000000, 1700000000u));
    check("age/too-old-30d", !tl_warm_too_old(1700000000 + 30 * (int64_t)DAY, 1700000000u) &&
                             tl_warm_too_old(1700000000 + 30 * (int64_t)DAY + 1, 1700000000u));
}

/* ---- The target pick, the address and register rules --------------------- */

static void test_pick(void)
{
    static const uint8_t pub1[4] = { 203, 0, 113, 7 }, pub2[4] = { 198, 51, 100, 9 },
                         p10[4] = { 10, 1, 2, 3 }, p172[4] = { 172, 20, 0, 1 },
                         p172o[4] = { 172, 32, 0, 1 }, p192[4] = { 192, 168, 1, 2 },
                         ll[4] = { 169, 254, 1, 1 }, lo[4] = { 127, 0, 0, 1 },
                         z[4] = { 0, 1, 2, 3 }, mc[4] = { 224, 0, 0, 1 };
    check("pick/public", tl_warm_ipv4_public(pub1) && tl_warm_ipv4_public(pub2) &&
                         tl_warm_ipv4_public(p172o));
    check("pick/not-public", !tl_warm_ipv4_public(p10) && !tl_warm_ipv4_public(p172) &&
                             !tl_warm_ipv4_public(p192) && !tl_warm_ipv4_public(ll) &&
                             !tl_warm_ipv4_public(lo) && !tl_warm_ipv4_public(z) &&
                             !tl_warm_ipv4_public(mc));

    static const char *const a[] = { "192.0.2.50/32" };
    static const char *const lan[] = { "10.0.0.5:41641", "192.168.1.5:41641" };
    static const char *const ours[] = { "203.0.113.7:41641", "10.0.0.6:41641" };
    static const char *const other[] = { "garbage", "198.51.100.9:41641" };
    static const char *const both[] = { "203.0.113.7:41641", "198.51.100.10:41641" };
    const tl_peer_t t[4] = {
        mk_peer(1, 0x01, 0x81, a, 1, lan, 2),     /* LAN only */
        mk_peer(2, 0x02, 0x82, a, 1, ours, 2),    /* public = our STUN address */
        mk_peer(3, 0x03, 0x83, a, 1, other, 2),   /* another public (after junk) */
        mk_peer(4, 0x04, 0x84, a, 1, both, 2),
    };
    bool q = false;
    check("pick/first-cross-nat", tl_warm_target_index(t, 4, true, pub1, &q) == 2 && q);
    q = false;
    check("pick/no-stun-optimistic", tl_warm_target_index(t, 4, false, pub1, &q) == 1 && q);
    q = true;
    check("pick/fallback-peers0", tl_warm_target_index(t, 2, true, pub1, &q) == 0 && !q);
    q = true;
    check("pick/fallback-single", tl_warm_target_index(t, 1, true, pub1, &q) == 0 && !q);
    q = true;
    check("pick/empty", tl_warm_target_index(t, 0, true, pub1, &q) == 0 && !q);
    check("pick/ours-then-other", tl_warm_peer_reachable(&t[3], true, pub1) &&
                                  !tl_warm_peer_reachable(&t[1], true, pub1) &&
                                  !tl_warm_peer_reachable(&t[0], false, pub1));
    q = false;
    check("pick/second-of-three", tl_warm_target_index(&t[1], 3, true, pub1, &q) == 1 && q);
    q = false;
    check("pick/only-the-last-qualifies", tl_warm_target_index(t, 3, true, pub1, &q) == 2 && q);
    const tl_peer_t first[2] = { t[2], t[0] };
    q = false;
    check("pick/peers0-qualifies", tl_warm_target_index(first, 2, true, pub1, &q) == 0 && q);

    check("addr/moved", tl_warm_addr_moved(0x0102000au, 0x0202000au));
    check("addr/same", !tl_warm_addr_moved(0x0102000au, 0x0102000au));
    check("addr/none-keeps", !tl_warm_addr_moved(0x0102000au, 0));
    check("addr/first-one", tl_warm_addr_moved(0, 0x0102000au));

    check("reg/known-no-retry", tl_warm_reg_reused(true, false));
    check("reg/retried-with-key", !tl_warm_reg_reused(true, true));
    check("reg/unknown", !tl_warm_reg_reused(false, false) && !tl_warm_reg_reused(false, true));
}

/* ---- The RTC marks ------------------------------------------------------ */

#define RST_POWERON 1
#define RST_SW      3
#define RST_PANIC   4
#define RST_TWDT    6
#define RST_BROWN   9

static void test_rtc(void)
{
    tl_warm_rtc_t r;
    bool erase = true;
    memset(&r, 0xa7, sizeof(r));
    check("rtc/garbage-clean", tl_warm_rtc_boot(&r, RST_SW, &erase) == TL_WARM_RTC_CLEAN &&
                               !erase && r.magic == TL_WARM_RTC_MAGIC && r.attempt == 0 &&
                               r.skip == 0 && r.crashes == 0);
    r.attempt = 1;
    tl_warm_rtc_seal(&r);
    check("rtc/attempt-sw-not-a-crash",
          tl_warm_rtc_boot(&r, RST_SW, &erase) == TL_WARM_RTC_CLEAN && !erase &&
          r.attempt == 0 && r.crashes == 0);
    r.attempt = 1;
    tl_warm_rtc_seal(&r);
    check("rtc/attempt-panic-crash", tl_warm_rtc_boot(&r, RST_PANIC, &erase) == TL_WARM_RTC_CRASHED &&
                                     erase && r.crashes == 1 && r.attempt == 0);
    check("rtc/after-crash-clean", tl_warm_rtc_boot(&r, RST_SW, &erase) == TL_WARM_RTC_CLEAN &&
                                   !erase && r.crashes == 1);
    r.attempt = 1;
    tl_warm_rtc_seal(&r);
    check("rtc/second-crash-off", tl_warm_rtc_boot(&r, RST_TWDT, &erase) == TL_WARM_RTC_OFF &&
                                  erase && r.crashes == TL_WARM_RTC_MAX_CRASHES);
    check("rtc/off-stays", tl_warm_rtc_boot(&r, RST_SW, &erase) == TL_WARM_RTC_OFF && !erase &&
                           tl_warm_rtc_boot(&r, RST_PANIC, &erase) == TL_WARM_RTC_OFF && !erase);
    check("rtc/power-on-re-enables", tl_warm_rtc_boot(&r, RST_POWERON, &erase) == TL_WARM_RTC_CLEAN &&
                                     !erase && r.crashes == 0);
    r.attempt = 1;
    tl_warm_rtc_seal(&r);
    check("rtc/power-on-clears-attempt",
          tl_warm_rtc_boot(&r, RST_POWERON, &erase) == TL_WARM_RTC_CLEAN && !erase && r.attempt == 0);
    r.attempt = 1;
    tl_warm_rtc_seal(&r);
    check("rtc/brownout-counts", tl_warm_rtc_boot(&r, RST_BROWN, &erase) == TL_WARM_RTC_CRASHED && erase);
    memset(&r, 0, sizeof(r));
    tl_warm_rtc_seal(&r);
    r.attempt = 1;
    tl_warm_rtc_restart(&r);
    check("rtc/restart-mark", r.skip == 1 && r.attempt == 0 &&
                              tl_warm_rtc_boot(&r, RST_SW, &erase) == TL_WARM_RTC_RESTARTED && !erase);
    check("rtc/restart-consumed-once", tl_warm_rtc_boot(&r, RST_SW, &erase) == TL_WARM_RTC_CLEAN &&
                                       r.skip == 0);
    r.skip = 1;
    r.attempt = 1;
    tl_warm_rtc_seal(&r);
    check("rtc/crash-beats-skip", tl_warm_rtc_boot(&r, RST_PANIC, &erase) == TL_WARM_RTC_CRASHED &&
                                  erase && r.skip == 0);
    r.attempt = 1;   /* not resealed: the check fails */
    check("rtc/torn-reset", tl_warm_rtc_boot(&r, RST_PANIC, &erase) == TL_WARM_RTC_CLEAN && !erase &&
                            r.crashes == 0);
    r.crashes = 7;
    tl_warm_rtc_seal(&r);
    check("rtc/out-of-range-reset", tl_warm_rtc_boot(&r, RST_SW, &erase) == TL_WARM_RTC_CLEAN &&
                                    r.crashes == 0);
}

/* ---- Does a boot warm-start? -------------------------------------------- */

static tl_warm_go_in_t go_ok(void)
{
    return (tl_warm_go_in_t){ .rtc = TL_WARM_RTC_CLEAN, .have_rec = true, .keys_ok = true,
                              .reg_reused = true, .heap_ok = true,
                              .now_unix = 1700000000 + 3600, .written = 1700000000u };
}

static void test_go(void)
{
    tl_warm_go_in_t in = go_ok();
    check("go/all-good", tl_warm_go(&in) == TL_WARM_GO);
    in = go_ok(); in.have_rec = false;
    check("go/no-record", tl_warm_go(&in) == TL_WARM_NO_RECORD);
    in = go_ok(); in.rtc = TL_WARM_RTC_CRASHED; in.have_rec = false;
    check("go/crash-first", tl_warm_go(&in) == TL_WARM_SKIP_CRASH);
    in = go_ok(); in.rtc = TL_WARM_RTC_OFF;
    check("go/off", tl_warm_go(&in) == TL_WARM_SKIP_OFF);
    in = go_ok(); in.rtc = TL_WARM_RTC_RESTARTED;
    check("go/after-restart", tl_warm_go(&in) == TL_WARM_SKIP_RESTART);
    in = go_ok(); in.keys_ok = false;
    check("go/other-keys", tl_warm_go(&in) == TL_WARM_OTHER_KEYS);
    in = go_ok(); in.now_unix = 1700000000 + 31 * (int64_t)DAY;
    check("go/stale", tl_warm_go(&in) == TL_WARM_STALE);
    in = go_ok(); in.now_unix = 1600000000;   /* floor behind the write: can't tell */
    check("go/age-unknown-goes", tl_warm_go(&in) == TL_WARM_GO);
    in = go_ok(); in.reg_reused = false;
    check("go/needed-auth", tl_warm_go(&in) == TL_WARM_NEEDED_AUTH);
    in = go_ok(); in.heap_ok = false;
    check("go/low-heap", tl_warm_go(&in) == TL_WARM_LOW_HEAP);
    /* Only GO starts it: every single failing input stops it. */
    int only = 1;
    for (int k = 0; k < 6; k++) {
        in = go_ok();
        if (k == 0) in.have_rec = false;
        if (k == 1) in.keys_ok = false;
        if (k == 2) in.reg_reused = false;
        if (k == 3) in.heap_ok = false;
        if (k == 4) in.rtc = TL_WARM_RTC_RESTARTED;
        if (k == 5) in.written = 1, in.now_unix = 1 + 31 * (int64_t)DAY;
        only &= tl_warm_go(&in) != TL_WARM_GO;
    }
    check("go/each-input-gates", only);
}

/* ---- The state machine -------------------------------------------------- */

typedef struct {
    tl_cidr_t        self[TL_MAX_PEER_ADDRESSES];
    tl_peer_t        peers[TL_MAX_PEERS];
    size_t           n_self, n_peers;
    tl_warm_tables_t t;
    tl_warm_sm_t     sm;
    tl_warm_rtc_t    rtc;
    tl_warm_rec_t    rec;
} rig_t;

static void rig_start(rig_t *g, bool ok, uint32_t now_s)
{
    memset(g, 0, sizeof(*g));
    g->t = (tl_warm_tables_t){ g->self, &g->n_self, g->peers, &g->n_peers };
    tl_warm_rtc_seal(&g->rtc);
    g->rec = mk_rec();
    g->rec.written = 1700000000u;
    tl_warm_sm_begin(&g->sm, &g->rtc, &g->rec, &g->t);
    tl_warm_sm_started(&g->sm, &g->rtc, &g->t, ok, now_s, g->rec.written);
}

static tl_warm_act_t rig_netmap(rig_t *g, const tl_warm_rec_t *now, bool have_self,
                                bool expired, bool moved, unsigned *why)
{
    const tl_warm_nm_t in = { .expired = expired, .have_self = have_self,
                              .self0_moved = moved, .now = now };
    return tl_warm_sm_netmap(&g->sm, &g->rtc, &g->rec, &in, why);
}

static void test_sm(void)
{
    rig_t g;
    unsigned why = 0;
    rig_start(&g, true, 100);
    check("sm/started", g.sm.state == TL_WARM_ST_PENDING && g.sm.pending_s == 101 &&
                        g.sm.seeded && g.n_self == 2 && g.n_peers == 1 && g.rtc.attempt == 1);
    /* The first frame empties the seeded tables, once. */
    check("sm/first-frame-resets", tl_warm_sm_frame(&g.sm, &g.t) && g.n_self == 0 &&
                                   g.n_peers == 0 && !g.sm.seeded);
    g.n_self = 2;
    g.n_peers = 3;
    check("sm/second-frame-keeps", tl_warm_sm_frame(&g.sm, &g.t) && g.n_self == 2 && g.n_peers == 3);
    check("sm/wait-before-full-map", rig_netmap(&g, NULL, false, false, false, &why) ==
                                     TL_WARM_ACT_WAIT && g.sm.state == TL_WARM_ST_PENDING &&
                                     !g.sm.restart && g.sm.pending_s == 101);
    const tl_warm_rec_t same = g.rec;
    check("sm/confirm", rig_netmap(&g, &same, true, false, false, &why) == TL_WARM_ACT_CONFIRM &&
                        why == 0 && g.sm.state == TL_WARM_ST_CONFIRMED && g.sm.pending_s == 0 &&
                        g.rtc.attempt == 0 && !g.sm.restart);
    /* Confirmed: the bound never fires, later frames take the cold path. */
    check("sm/confirmed-no-bound", tl_warm_sm_bound(&g.sm, 101 + 100000, 600, true,
                                                    1700000000 + 400 * (int64_t)DAY) == 0);
    check("sm/confirmed-cold-path", !tl_warm_sm_frame(&g.sm, &g.t) &&
                                    rig_netmap(&g, &same, true, false, false, &why) ==
                                    TL_WARM_ACT_COLD);

    rig_start(&g, true, 100);
    tl_warm_sm_frame(&g.sm, &g.t);
    tl_warm_rec_t d = g.rec;
    d.peer.disco_pub[3] ^= 1;
    d.peer.ep[0].port = 2;
    d.peer.addr[0].ip[3] = 99;
    d.peer.node_pub[0] ^= 1;
    check("sm/in-place", rig_netmap(&g, &d, true, false, false, &why) == TL_WARM_ACT_CONFIRM &&
                         why == (TL_WARM_D_DISCO | TL_WARM_D_EP | TL_WARM_D_ADDR | TL_WARM_D_KEY));

    struct { const char *name; int kind; unsigned want; } rs[] = {
        { "sm/restart-other-peer", 0, TL_WARM_D_PEER },
        { "sm/restart-self0",      1, TL_WARM_D_SELF0 },
        { "sm/restart-expired",    2, TL_WARM_WHY_EXPIRED },
        { "sm/restart-moved",      3, TL_WARM_D_SELF0 },
        { "sm/restart-empty",      4, TL_WARM_WHY_EMPTY },
    };
    for (size_t i = 0; i < sizeof(rs) / sizeof(rs[0]); i++) {
        rig_start(&g, true, 100);
        tl_warm_sm_frame(&g.sm, &g.t);
        tl_warm_rec_t n = g.rec;
        tl_warm_act_t act;
        if (rs[i].kind == 0) { n.peer.id++; act = rig_netmap(&g, &n, true, false, false, &why); }
        else if (rs[i].kind == 1) { n.self[0].ip[3]++; act = rig_netmap(&g, &n, true, false, false, &why); }
        else if (rs[i].kind == 2) act = rig_netmap(&g, NULL, true, true, false, &why);
        else if (rs[i].kind == 3) act = rig_netmap(&g, NULL, true, false, true, &why);
        else act = rig_netmap(&g, NULL, true, false, false, &why);
        check(rs[i].name, act == TL_WARM_ACT_RESTART && (why & rs[i].want) && g.sm.restart &&
                          g.sm.pending_s == 0 && g.sm.state == TL_WARM_ST_PENDING &&
                          g.rtc.attempt == 1);
    }

    /* The bound: 600 s after the start, once; then the netmap is late. */
    rig_start(&g, true, 100);
    tl_warm_sm_frame(&g.sm, &g.t);
    check("sm/bound-not-yet", tl_warm_sm_bound(&g.sm, 699, 600, false, 0) == 0);
    check("sm/bound-due", tl_warm_sm_bound(&g.sm, 700, 600, false, 0) == TL_WARM_BOUND_TIME &&
                          g.sm.bound_fired && g.sm.pending_s == 0);
    check("sm/bound-once", tl_warm_sm_bound(&g.sm, 800, 600, false, 0) == 0);
    check("sm/netmap-after-bound-late",
          rig_netmap(&g, &same, true, false, false, &why) == TL_WARM_ACT_LATE &&
          g.sm.state == TL_WARM_ST_PENDING);
    /* The age, once the clock can tell. */
    rig_start(&g, true, 100);
    check("sm/age-unsynced-waits", tl_warm_sm_bound(&g.sm, 200, 600, false,
                                                    1700000000 + 31 * (int64_t)DAY) == 0);
    check("sm/age-synced-ends", tl_warm_sm_bound(&g.sm, 200, 600, true,
                                                 1700000000 + 31 * (int64_t)DAY) == TL_WARM_BOUND_AGE);
    rig_start(&g, true, 100);
    check("sm/age-young-stays", tl_warm_sm_bound(&g.sm, 200, 600, true,
                                                 1700000000 + 29 * (int64_t)DAY) == 0);

    /* A failed bring-up: tables as before a cold boot's netmap, no mark,
     * the frames take the cold path. */
    rig_start(&g, false, 100);
    check("sm/failed-start", g.sm.state == TL_WARM_ST_OFF && !g.sm.seeded && g.n_self == 0 &&
                             g.n_peers == 0 && g.rtc.attempt == 0);
    g.n_peers = 2;
    check("sm/failed-start-cold-path", !tl_warm_sm_frame(&g.sm, &g.t) && g.n_peers == 2 &&
                                       tl_warm_sm_bound(&g.sm, 100000, 600, false, 0) == 0 &&
                                       rig_netmap(&g, &same, true, false, false, &why) ==
                                       TL_WARM_ACT_COLD);
    tl_warm_sm_cold(&g.sm);
    check("sm/cold-start-confirmed", g.sm.state == TL_WARM_ST_CONFIRMED);

    /* While pending, no input takes the cold path or keeps the bound. */
    int never_cold = 1;
    for (int k = 0; k < 2000; k++) {
        rig_start(&g, true, 100);
        tl_warm_sm_frame(&g.sm, &g.t);
        tl_warm_rec_t n = g.rec;
        const uint32_t m = rnd();
        if (m & 1) n.peer.id ^= rnd();
        if (m & 2) n.peer.ep[0].port ^= (uint16_t)rnd();
        if (m & 4) n.self[0].ip[3] ^= (uint8_t)rnd();
        if (m & 8) n.peer.disco_pub[0] ^= 1;
        const tl_warm_act_t act = rig_netmap(&g, (m & 16) ? NULL : &n, (m & 32) != 0,
                                             (m & 64) != 0, (m & 128) != 0, &why);
        never_cold &= act != TL_WARM_ACT_COLD;
        if (act == TL_WARM_ACT_CONFIRM || act == TL_WARM_ACT_RESTART) {
            never_cold &= g.sm.pending_s == 0 &&
                          tl_warm_sm_bound(&g.sm, 1000000, 600, true, 0) == 0;
        }
        never_cold &= (act == TL_WARM_ACT_RESTART) == g.sm.restart;
    }
    check("sm/pending-never-cold-path", never_cold);
}

/* ---- Boots in a row: fake NVS + RTC ----------------------------------- */

static void test_boots(void)
{
    fake_nvs_t f;
    memset(&f, 0, sizeof(f));
    tl_warm_rtc_t rtc;
    memset(&rtc, 0x3c, sizeof(rtc));   /* power-on garbage */
    tl_warm_nvs_t m;
    bool erase = false;
    unsigned why = 0;
    int ok = 1;

    /* Boot 1 (power-on): nothing stored → cold, the record written. */
    tl_warm_rtc_verdict_t v = tl_warm_rtc_boot(&rtc, RST_POWERON, &erase);
    boot(&m, &f);
    tl_warm_go_in_t in = go_ok();
    in.rtc = v;
    in.have_rec = m.valid;
    ok &= tl_warm_go(&in) == TL_WARM_NO_RECORD;
    tl_warm_sm_t sm;
    memset(&sm, 0, sizeof(sm));
    tl_warm_sm_cold(&sm);
    const tl_warm_rec_t r = mk_rec();
    ok &= tl_warm_store(&m, &r, 1700000000u, MIN_US, true, fake_write, &f) == 1;
    check("boots/1-cold-then-stored", ok);

    /* Boot 2 (software reset): warm, the netmap confirms. */
    v = tl_warm_rtc_boot(&rtc, RST_SW, &erase);
    boot(&m, &f);
    in = go_ok();
    in.rtc = v;
    in.have_rec = m.valid;
    in.written = m.rec.written;
    ok = tl_warm_go(&in) == TL_WARM_GO;
    tl_cidr_t self[2];
    tl_peer_t peers[TL_MAX_PEERS];
    size_t ns = 0, np = 0;
    tl_warm_tables_t t = { self, &ns, peers, &np };
    tl_warm_sm_begin(&sm, &rtc, &m.rec, &t);
    tl_warm_sm_started(&sm, &rtc, &t, true, 3, m.rec.written);
    tl_warm_sm_frame(&sm, &t);
    tl_warm_nm_t nm = { .have_self = true, .now = &r };
    ok &= tl_warm_sm_netmap(&sm, &rtc, &m.rec, &nm, &why) == TL_WARM_ACT_CONFIRM && rtc.attempt == 0;
    check("boots/2-warm-confirmed", ok);

    /* Boot 3: the netmap picks another peer → restart (mark, erase). */
    v = tl_warm_rtc_boot(&rtc, RST_SW, &erase);
    boot(&m, &f);
    tl_warm_sm_begin(&sm, &rtc, &m.rec, &t);
    tl_warm_sm_started(&sm, &rtc, &t, true, 3, m.rec.written);
    tl_warm_sm_frame(&sm, &t);
    tl_warm_rec_t other = r;
    other.peer.id = 777;
    nm.now = &other;
    ok = v == TL_WARM_RTC_CLEAN &&
         tl_warm_sm_netmap(&sm, &rtc, &m.rec, &nm, &why) == TL_WARM_ACT_RESTART && sm.restart;
    tl_warm_rtc_restart(&rtc);   /* warm_restart_now */
    f.n = 0;                     /* …and its erase */
    check("boots/3-diverged-restart", ok);

    /* Boot 4: cold (marked and erased), and its record replaces it. */
    v = tl_warm_rtc_boot(&rtc, RST_SW, &erase);
    boot(&m, &f);
    in = go_ok();
    in.rtc = v;
    in.have_rec = m.valid;
    ok = v == TL_WARM_RTC_RESTARTED && tl_warm_go(&in) == TL_WARM_NO_RECORD &&
         tl_warm_store(&m, &other, 1700000100u, MIN_US, true, fake_write, &f) == 1;
    check("boots/4-cold-after-restart", ok);

    /* Boot 5: warm, panics before its netmap. Boot 6: erased, cold. */
    v = tl_warm_rtc_boot(&rtc, RST_SW, &erase);
    boot(&m, &f);
    tl_warm_sm_begin(&sm, &rtc, &m.rec, &t);
    tl_warm_sm_started(&sm, &rtc, &t, true, 3, m.rec.written);
    v = tl_warm_rtc_boot(&rtc, RST_PANIC, &erase);
    if (erase) f.n = 0;
    boot(&m, &f);
    in = go_ok();
    in.rtc = v;
    in.have_rec = m.valid;
    ok = v == TL_WARM_RTC_CRASHED && erase && !m.valid && tl_warm_go(&in) == TL_WARM_SKIP_CRASH;
    check("boots/5-6-crash-guard", ok);
}

/* ---- Log helpers, bound ------------------------------------------------- */

static void test_misc(void)
{
    char s[64];
    tl_warm_age_str(s, sizeof(s), 1700000042, true, 1700000000u);
    check("age/seconds", strcmp(s, "cached 42 s ago") == 0);
    tl_warm_age_str(s, sizeof(s), 1700000000 + 5 * 60 + 7, true, 1700000000u);
    check("age/minutes", strcmp(s, "cached 5 min ago") == 0);
    tl_warm_age_str(s, sizeof(s), 1700000000 + 3 * 3600 + 59, true, 1700000000u);
    check("age/hours", strcmp(s, "cached 3 h ago") == 0);
    tl_warm_age_str(s, sizeof(s), 1700000000 + 9 * 86400, true, 1700000000u);
    check("age/days", strcmp(s, "cached 9 d ago") == 0);
    tl_warm_age_str(s, sizeof(s), 1700000000 + 3 * 3600, false, 1700000000u);
    check("age/unsynced-lower-bound", strcmp(s, "cached ≥ 3 h ago, clock not synced") == 0);
    tl_warm_age_str(s, sizeof(s), 1600000000, false, 1700000000u);
    check("age/floor-behind-write", strcmp(s, "cached, age unknown, clock not synced") == 0);
    tl_warm_age_str(s, sizeof(s), 1700000000, true, 0);
    check("age/never-synced-write", strcmp(s, "cached, age unknown") == 0);

    check("bound/not-yet", !tl_warm_bound_due(699, 100, 600));
    check("bound/due", tl_warm_bound_due(700, 100, 600) && tl_warm_bound_due(5000, 100, 600));
    check("bound/clock-before-start", !tl_warm_bound_due(50, 100, 600));
}

int main(void)
{
    test_text();
    test_netmap();
    test_codec();
    test_cold_equivalence();
    test_diff();
    test_store();
    test_refresh_age();
    test_pick();
    test_rtc();
    test_go();
    test_sm();
    test_boots();
    test_misc();
    if (s_fails) {
        printf("test_warm: %d FAIL\n", s_fails);
        return 1;
    }
    printf("test_warm: all OK\n");
    return 0;
}
