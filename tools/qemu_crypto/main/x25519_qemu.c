// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// X25519 on the emulated ESP32: asm field ops vs the C fallback, bit for
// bit, at the loose limb bounds; asm X25519 vs C-fallback X25519 vs donna;
// RFC 7748 §5.2 iterated vector (1 and 1 000).
#include <stdio.h>
#include <stdint.h>
#include <string.h>
typedef uint32_t u32;
void A_mul(u32 o[10], const u32 a[10], const u32 b[10]);
void A_sqr(u32 o[10], const u32 a[10]);
void A_121(u32 o[10], const u32 a[10]);
void C_mul(u32 o[10], const u32 a[10], const u32 b[10]);
void C_sqr(u32 o[10], const u32 a[10]);
void C_121(u32 o[10], const u32 a[10]);
void curve25519_fiat32(uint8_t o[32], const uint8_t n[32], const uint8_t p[32]);
void curve25519_fiat32_c(uint8_t o[32], const uint8_t n[32], const uint8_t p[32]);
int curve25519_donna(uint8_t *o, const uint8_t *n, const uint8_t *p);

static uint64_t s = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void) { s ^= s << 13; s ^= s >> 7; s ^= s << 17; return (uint32_t)(s >> 32); }
static const unsigned W[10] = { 26, 25, 26, 25, 26, 25, 26, 25, 26, 25 };
static u32 lmax(int i) { return (u32)((((uint64_t)27 << W[i]) / 8) - 1); }   /* loose */
static int tight(const u32 v[10]) {
    for (int i = 0; i < 10; i++) if ((uint64_t)v[i] >= (((uint64_t)9 << W[i]) / 8)) return 0;
    return 1;
}
static void limbs(u32 v[10], int mode) {
    for (int i = 0; i < 10; i++) {
        const u32 m = lmax(i);
        int k = mode == 0 ? (int)(rnd() % 8) : mode;
        switch (k) {
        case 1: v[i] = m; break;
        case 2: v[i] = 0; break;
        case 3: v[i] = m - (rnd() & 0xff); break;
        case 4: v[i] = (1u << W[i]) - 1; break;
        case 5: v[i] = 1u << W[i]; break;
        case 6: v[i] = rnd() & 1; break;
        default: v[i] = rnd() % (m + 1); break;
        }
    }
}
static int hex(uint8_t o[32], const char *h) {
    for (int i = 0; i < 32; i++) { unsigned b; if (sscanf(h + 2 * i, "%2x", &b) != 1) return -1; o[i] = (uint8_t)b; }
    return 0;
}

int m_xq(void)
{
    int fails = 0;
    /* 1. field ops, asm vs C, exact limbs + output bound */
    const int N = 200000;
    int bad_mul = 0, bad_sq = 0, bad_121 = 0, bad_bound = 0;
    for (int it = 0; it < N; it++) {
        u32 a[10], b[10], oa[10], oc[10];
        const int mode = it < 6 * 1000 ? 1 + it / 1000 : 0;   /* fixed patterns first */
        limbs(a, mode); limbs(b, it & 1 ? 0 : mode);
        A_mul(oa, a, b); C_mul(oc, a, b);
        if (memcmp(oa, oc, sizeof oa)) bad_mul++;
        if (!tight(oa)) bad_bound++;
        A_sqr(oa, a); C_sqr(oc, a);
        if (memcmp(oa, oc, sizeof oa)) bad_sq++;
        if (!tight(oa)) bad_bound++;
        A_121(oa, a); C_121(oc, a);
        if (memcmp(oa, oc, sizeof oa)) bad_121++;
        /* aliasing: out == in1 (all of an input is read before out is written) */
        memcpy(oa, a, sizeof a); A_mul(oa, oa, b); C_mul(oc, a, b);
        if (memcmp(oa, oc, sizeof oa)) bad_mul++;
    }
    printf("[qemu/field asm==C x%d: mul=%d sqr=%d m121666=%d out-of-bound=%d] %s\n", N,
           bad_mul, bad_sq, bad_121, bad_bound, (bad_mul | bad_sq | bad_121 | bad_bound) ? "FAIL" : "OK");
    fails += (bad_mul | bad_sq | bad_121 | bad_bound) != 0;

    /* 2. X25519: asm vs C fallback vs donna, random + edge */
    const int P = 3000;
    int bad_x = 0;
    for (int it = 0; it < P; it++) {
        uint8_t n[32], p[32], qa[32], qc[32], qd[32];
        for (int i = 0; i < 32; i++) { n[i] = (uint8_t)rnd(); p[i] = (uint8_t)rnd(); }
        if (it % 10 == 1) memset(p, 0xff, 32);                         /* u >= p, top bit */
        if (it % 10 == 2) { memset(p, 0, 32); p[0] = (uint8_t)(it % 40); }   /* small u */
        if (it % 10 == 3) { memset(n, 0xff, 32); }
        if (it % 10 == 4) { memset(p, 0xff, 32); p[0] = 0xed; p[31] = 0x7f; }   /* u = p */
        curve25519_fiat32(qa, n, p); curve25519_fiat32_c(qc, n, p); curve25519_donna(qd, n, p);
        if (memcmp(qa, qc, 32) || memcmp(qa, qd, 32)) {
            if (bad_x++ < 3) printf("  mismatch at pair %d\n", it);
        }
    }
    printf("[qemu/x25519 asm==C==donna x%d] %s (%d bad)\n", P, bad_x ? "FAIL" : "OK", bad_x);
    fails += bad_x != 0;

    /* 3. RFC 7748 §5.2 iterated */
    uint8_t k[32] = { 9 }, u[32] = { 9 }, r[32], w[32];
    for (int i = 1; i <= 1000; i++) {
        curve25519_fiat32(r, k, u);
        memcpy(u, k, 32); memcpy(k, r, 32);
        if (i == 1 || i == 1000) {
            hex(w, i == 1 ? "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
                          : "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
            const int ok = memcmp(k, w, 32) == 0;
            printf("[qemu/rfc7748-iter-%d] %s\n", i, ok ? "OK" : "FAIL");
            fails += !ok;
        }
    }
    return fails;
}
