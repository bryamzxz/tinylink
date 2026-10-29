// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// X25519 on fiat-crypto's 32-bit field with the carry-free field
// multiplication of round 1.3.3 (crypto/curve25519_fiat32.c, C6):
//  - RFC 7748 §5.2 iterated vector: 1 and 1 000 iterations (1 000 000
//    with X25519_MILLION=1 in the environment: ~1 min, not in `make test`);
//  - differential against curve25519-donna, the pre-1.3.3 X25519
//    (ref/curve25519_donna.c): 4 000 random (scalar, point) pairs, half
//    with the point's top bit set or a non-canonical u >= p, plus edge
//    points and scalars;
//  - the rewritten field operations directly (this file includes the .c,
//    so the static functions are visible): fe_mul_impl, fe_sqr_impl,
//    fe_mul121666_impl, fe_add_impl, fe_sub_impl and fe_tobytes against
//    an independent 64-bit-word reference mod p, 200 000 random inputs
//    each up to the "loose" bound (3.375·2^w, half of them pinned at
//    it), outputs checked against the "tight" bound (1.125·2^w);
//  - low-order points: curve25519_scalarmult reports -1 for the 7
//    canonical small-order u-coordinates.
// The host build runs P28's C version; the Xtensa asm is checked on the
// compiled firmware objects (round 1.3.3 notes) and on the device by
// CONFIG_TINYLINK_BENCH_AEAD's X25519 KAT.

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../components/tinylink/src/crypto/curve25519_fiat32.c"

/* esp_fill_random for curve25519.c's keypair path (not exercised). */
void esp_fill_random(void *buf, size_t len) { memset(buf, 0, len); }

int curve25519_donna(uint8_t *mypublic, const uint8_t *secret, const uint8_t *basepoint);

static int hex32(uint8_t out[32], const char *hex)
{
    for (size_t i = 0; i < 32; i++) {
        unsigned b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return 0;
}

static void print_hex(const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

static uint64_t rng_s = 0x123456789abcdefULL;
static uint64_t rnd64(void)
{
    rng_s ^= rng_s << 13; rng_s ^= rng_s >> 7; rng_s ^= rng_s << 17;
    return rng_s;
}

/* ---- independent reference: integers as little-endian u64 words ---- */

#define NW 9
static const unsigned limb_pos[10] = { 0, 26, 51, 77, 102, 128, 153, 179, 204, 230 };
static const unsigned limb_w[10]   = { 26, 25, 26, 25, 26, 25, 26, 25, 26, 25 };

static void w_add_shifted(uint64_t t[NW], uint64_t v, unsigned pos)
{
    unsigned i = pos / 64, sh = pos % 64;
    unsigned __int128 c = (unsigned __int128)v << sh;
    for (; i < NW && c; i++) {
        c += t[i];
        t[i] = (uint64_t)c;
        c >>= 64;
    }
}

/* t := t mod 2^255 + 19·(t >> 255) until t < 2^255. */
static void w_fold255(uint64_t t[NW])
{
    for (;;) {
        uint64_t hi[NW] = { 0 };
        int nz = 0;
        for (int i = 0; i + 3 < NW; i++) {
            hi[i] = (t[3 + i] >> 63) | (i + 4 < NW ? t[4 + i] << 1 : 0);
            nz |= hi[i] != 0;
        }
        if (!nz) return;
        t[3] &= 0x7fffffffffffffffULL;
        for (int i = 4; i < NW; i++) t[i] = 0;
        unsigned __int128 c = 0;
        for (int i = 0; i < NW; i++) {
            c += (unsigned __int128)t[i] + (unsigned __int128)hi[i] * 19;
            t[i] = (uint64_t)c;
            c >>= 64;
        }
    }
}

/* Canonical 32-byte encoding of t mod p. */
static void w_canon(const uint64_t in[NW], uint8_t out[32])
{
    uint64_t t[NW];
    memcpy(t, in, sizeof(t));
    w_fold255(t);
    /* t < 2^255 < 2p: t >= p iff t + 19 >= 2^255 */
    uint64_t u[4];
    unsigned __int128 c = 19;
    for (int i = 0; i < 4; i++) { c += t[i]; u[i] = (uint64_t)c; c >>= 64; }
    if (u[3] >> 63) {
        u[3] &= 0x7fffffffffffffffULL;
        memcpy(t, u, sizeof(u));
    }
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)(t[i / 8] >> (8 * (i % 8)));
}

static void w_from_limbs(uint64_t t[NW], const u32 v[10])
{
    memset(t, 0, NW * sizeof(t[0]));
    for (int i = 0; i < 10; i++) w_add_shifted(t, v[i], limb_pos[i]);
}

static void w_from_bytes(uint64_t t[NW], const uint8_t b[32])
{
    memset(t, 0, NW * sizeof(t[0]));
    for (int i = 0; i < 32; i++) t[i / 8] |= (uint64_t)b[i] << (8 * (i % 8));
}

/* (a · b) mod p, canonical. */
static void ref_mul(uint8_t out[32], const uint8_t a[32], const uint8_t b[32])
{
    uint64_t x[NW], y[NW], t[NW + 8] = { 0 };
    w_from_bytes(x, a);
    w_from_bytes(y, b);
    for (int i = 0; i < 4; i++) {
        unsigned __int128 c = 0;
        for (int j = 0; j < 4; j++) {
            c += (unsigned __int128)x[i] * y[j] + t[i + j];
            t[i + j] = (uint64_t)c;
            c >>= 64;
        }
        t[i + 4] = (uint64_t)c;
    }
    w_canon(t, out);
}

static void limbs_canon(uint8_t out[32], const u32 v[10])
{
    uint64_t t[NW];
    w_from_limbs(t, v);
    w_canon(t, out);
}

/* Random limbs below 3.375·2^w (loose) or 1.125·2^w (tight); mode 1 pins
 * them near the bound, mode 2 mixes. */
static void rand_limbs(u32 v[10], int loose, int mode)
{
    for (int i = 0; i < 10; i++) {
        const uint64_t lim = ((uint64_t)(loose ? 27 : 9) << limb_w[i]) / 8;
        const uint64_t r = rnd64();
        const int top = mode == 1 || (mode == 2 && (r & 1));
        v[i] = (u32)(top ? lim - 1 - (r >> 8) % 16 : (r >> 8) % lim);
    }
}

static int tight_ok(const u32 v[10])
{
    for (int i = 0; i < 10; i++)
        if ((uint64_t)v[i] >= ((uint64_t)9 << limb_w[i]) / 8) return 0;
    return 1;
}

static int loose_ok(const u32 v[10])
{
    for (int i = 0; i < 10; i++)
        if ((uint64_t)v[i] >= ((uint64_t)27 << limb_w[i]) / 8) return 0;
    return 1;
}

static int field_tests(void)
{
    static const uint8_t c121666[32] = { 0x42, 0xdb, 0x01 };   /* 121666 LE */
    int fails = 0, bad_mul = 0, bad_sq = 0, bad_121 = 0, bad_as = 0, bad_tb = 0, bad_bound = 0;
    for (int it = 0; it < 200000; it++) {
        u32 a[10], b[10], o[10];
        uint8_t ca[32], cb[32], got[32], want[32];
        rand_limbs(a, 1, it % 3);
        rand_limbs(b, 1, (it / 3) % 3);
        limbs_canon(ca, a);
        limbs_canon(cb, b);

        fe_mul_impl(o, a, b);
        limbs_canon(got, o); ref_mul(want, ca, cb);
        bad_mul += memcmp(got, want, 32) != 0;
        bad_bound += !tight_ok(o);

        fe_sqr_impl(o, a);
        limbs_canon(got, o); ref_mul(want, ca, ca);
        bad_sq += memcmp(got, want, 32) != 0;
        bad_bound += !tight_ok(o);

        fe_mul121666_impl(o, a);
        limbs_canon(got, o); ref_mul(want, ca, c121666);
        bad_121 += memcmp(got, want, 32) != 0;
        bad_bound += !tight_ok(o);

        /* in place, as the ladder and the inversion call them */
        memcpy(o, a, sizeof(o));
        fe_mul_impl(o, o, b);
        limbs_canon(got, o); ref_mul(want, ca, cb);
        bad_mul += memcmp(got, want, 32) != 0;
        memcpy(o, a, sizeof(o));
        fe_sqr_impl(o, o);
        limbs_canon(got, o); ref_mul(want, ca, ca);
        bad_sq += memcmp(got, want, 32) != 0;

        /* tight in → loose out for add / sub; tobytes = canonical */
        rand_limbs(a, 0, it % 3);
        rand_limbs(b, 0, (it / 3) % 3);
        limbs_canon(ca, a);
        limbs_canon(cb, b);
        uint64_t ta[NW], tb[NW], ts[NW];
        w_from_bytes(ta, ca);
        w_from_bytes(tb, cb);
        fe_add_impl(o, a, b);
        bad_bound += !loose_ok(o);
        memset(ts, 0, sizeof(ts));
        for (int i = 0; i < 5; i++) { w_add_shifted(ts, ta[i], 64 * i); w_add_shifted(ts, tb[i], 64 * i); }
        limbs_canon(got, o); w_canon(ts, want);
        bad_as += memcmp(got, want, 32) != 0;
        fe_sub_impl(o, a, b);
        bad_bound += !loose_ok(o);
        /* a − b ≡ a + (2p − b): 2p − b over words */
        {
            uint64_t tp[NW] = { 0 };
            const uint64_t twop[4] = { 0xffffffffffffffdaULL, 0xffffffffffffffffULL,
                                       0xffffffffffffffffULL, 0xffffffffffffffffULL };
            unsigned __int128 c = 0;
            for (int i = 0; i < 4; i++) {        /* 2p − b, b canonical < p */
                unsigned __int128 d = (unsigned __int128)twop[i] - tb[i] - (uint64_t)c;
                tp[i] = (uint64_t)d;
                c = (d >> 64) ? 1 : 0;
            }
            for (int i = 0; i < 5; i++) w_add_shifted(tp, ta[i], 64 * i);
            limbs_canon(got, o); w_canon(tp, want);
            bad_as += memcmp(got, want, 32) != 0;
        }
        fe tf;
        memcpy(tf.v, a, sizeof(tf.v));
        fe_tobytes(got, &tf);
        bad_tb += memcmp(got, ca, 32) != 0;
    }
    printf("[field fe_mul vs reference mod p, 400000 (half in place), loose inputs] %s\n", bad_mul ? "FAIL" : "OK");
    printf("[field fe_sqr vs reference mod p, 400000 (half in place), loose inputs] %s\n", bad_sq ? "FAIL" : "OK");
    printf("[field fe_mul121666 vs reference mod p, 200000] %s\n", bad_121 ? "FAIL" : "OK");
    printf("[field fe_add / fe_sub vs reference mod p, 200000 each] %s\n", bad_as ? "FAIL" : "OK");
    printf("[field fe_tobytes canonical, 200000 tight inputs] %s\n", bad_tb ? "FAIL" : "OK");
    printf("[field outputs within fiat32 bounds (mul/sqr/121666 tight, add/sub loose)] %s\n",
           bad_bound ? "FAIL" : "OK");
    fails += bad_mul + bad_sq + bad_121 + bad_as + bad_tb + bad_bound != 0;

    /* every limb at the loose maximum: the accumulator worst case */
    u32 a[10], o[10];
    uint8_t ca[32], got[32], want[32];
    for (int i = 0; i < 10; i++) a[i] = (u32)((((uint64_t)27 << limb_w[i]) / 8) - 1);
    limbs_canon(ca, a);
    fe_mul_impl(o, a, a);
    limbs_canon(got, o); ref_mul(want, ca, ca);
    int bad = memcmp(got, want, 32) != 0 || !tight_ok(o);
    fe_sqr_impl(o, a);
    limbs_canon(got, o);
    bad |= memcmp(got, want, 32) != 0 || !tight_ok(o);
    printf("[field mul/sqr with every limb at the loose bound] %s\n", bad ? "FAIL" : "OK");
    fails += bad;
    return fails;
}

int main(void)
{
    int fails = 0;
    uint8_t k[32], u[32], t[32], want[32];

    /* RFC 7748 §5.2: k = u = 9; k' = X25519(k, u); u = k; k = k'. */
    memset(k, 0, 32); k[0] = 9;
    memcpy(u, k, 32);
    const int million = getenv("X25519_MILLION") != NULL;
    for (int i = 1; i <= (million ? 1000000 : 1000); i++) {
        curve25519_fiat32(t, k, u);
        memcpy(u, k, 32);
        memcpy(k, t, 32);
        const char *w = i == 1       ? "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
                      : i == 1000    ? "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
                      : i == 1000000 ? "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"
                      : NULL;
        if (!w) continue;
        hex32(want, w);
        const int bad = memcmp(k, want, 32) != 0;
        printf("[rfc7748-5.2-iterated-%d] %s\n", i, bad ? "FAIL" : "OK");
        if (bad) { printf("  got: "); print_hex(k, 32); printf("\n"); }
        fails += bad;
    }

    /* Differential against donna. */
    {
        int bad = 0;
        static const char *edge_u[] = {
            "0900000000000000000000000000000000000000000000000000000000000000",
            "0200000000000000000000000000000000000000000000000000000000000000",
            "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  /* p − 2 */
            "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  /* p + 2 */
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  /* 2^255 − 1 */
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  /* top bit set */
            "0900000000000000000000000000000000000000000000000000000000000080",
        };
        static const char *edge_k[] = {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "0800000000000000000000000000000000000000000000000000000000000040",
        };
        uint8_t q1[32], q2[32];
        for (size_t i = 0; i < sizeof(edge_u) / sizeof(edge_u[0]); i++) {
            for (size_t j = 0; j < sizeof(edge_k) / sizeof(edge_k[0]); j++) {
                hex32(u, edge_u[i]);
                hex32(k, edge_k[j]);
                curve25519_fiat32(q1, k, u);
                curve25519_donna(q2, k, u);
                bad += memcmp(q1, q2, 32) != 0;
            }
        }
        printf("[diff-vs-donna: 21 edge (scalar, point) pairs] %s\n", bad ? "FAIL" : "OK");
        fails += bad != 0;
        bad = 0;
        for (int it = 0; it < 4000; it++) {
            for (int i = 0; i < 32; i += 8) {
                const uint64_t a = rnd64(), b = rnd64();
                memcpy(k + i, &a, 8);
                memcpy(u + i, &b, 8);
            }
            if (it % 4 == 1) u[31] &= 0x7f;                       /* canonical range */
            if (it % 4 == 2) { memset(u + 1, 0xff, 30); u[31] = 0x7f; u[0] |= 0xec; }  /* near / above p */
            curve25519_fiat32(q1, k, u);
            curve25519_donna(q2, k, u);
            if (memcmp(q1, q2, 32) != 0) {
                if (!bad) {
                    printf("  mismatch at %d: k=", it); print_hex(k, 32);
                    printf(" u="); print_hex(u, 32); printf("\n");
                }
                bad++;
            }
        }
        printf("[diff-vs-donna: 4000 random (scalar, point), incl. top bit / u >= p] %s\n",
               bad ? "FAIL" : "OK");
        fails += bad != 0;

        /* DH agreement through the shim: a·(b·9) == b·(a·9) */
        bad = 0;
        for (int it = 0; it < 200; it++) {
            uint8_t a[32], b[32], pa[32], pb[32], s1[32], s2[32];
            for (int i = 0; i < 32; i++) { a[i] = (uint8_t)rnd64(); b[i] = (uint8_t)rnd64(); }
            curve25519_derive_pub(pa, a);
            curve25519_derive_pub(pb, b);
            bad += curve25519_dh(s1, a, pb) != 0 || curve25519_dh(s2, b, pa) != 0 ||
                   memcmp(s1, s2, 32) != 0;
        }
        printf("[x25519 DH agreement through curve25519_dh, 200 pairs] %s\n", bad ? "FAIL" : "OK");
        fails += bad != 0;
    }

    /* Low-order points: the shared secret is all zero → -1. */
    {
        static const char *lo[] = {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        };
        int bad = 0;
        for (size_t i = 0; i < sizeof(lo) / sizeof(lo[0]); i++) {
            for (int r = 0; r < 4; r++) {
                for (int j = 0; j < 32; j++) k[j] = (uint8_t)rnd64();
                hex32(u, lo[i]);
                bad += curve25519_scalarmult(t, k, u) != -1;
            }
        }
        printf("[x25519 low-order points rejected (7 points x 4 scalars)] %s\n", bad ? "FAIL" : "OK");
        fails += bad != 0;
    }

    fails += field_tests();

    if (fails == 0) {
        printf("\nALL OK\n");
        return 0;
    }
    printf("\n%d FAILURES\n", fails);
    return 1;
}
