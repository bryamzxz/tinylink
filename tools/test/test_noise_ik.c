/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for noise_ik.c — the ts2021 Noise_IK_25519_ChaChaPoly_BLAKE2s
 * initiator (handshake + transport records). Three implementations have
 * to agree byte for byte:
 *
 *   1. noise_ik.c under test (in-tree ChaCha20-Poly1305 since 1.3.2);
 *   2. the vectors below, from gen_noise_vectors.py — Noise written from
 *      the spec on OpenSSL (`cryptography`) + hashlib, Tailscale's BE64
 *      counter nonce;
 *   3. a responder written in this file (own MixHash / MixKey / nonce
 *      code over the in-tree primitives) that must decrypt what the
 *      initiator sends and produce what it accepts.
 *
 * `make test_noise_ik_mbedtls` rebuilds this file against the pre-1.3.2
 * noise_ik.c (mbedTLS chachapoly, taken from git) and IDF's mbedTLS
 * sources: the same OK lines prove the move to the in-tree AEAD changed
 * no byte on the wire. Under NOISE_OLD_PATH the only relaxed check is
 * "output untouched on auth failure" (mbedTLS zeroes it instead).
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "blake2s.h"
#include "chacha20poly1305.h"
#include "curve25519.h"
#include "hkdf_blake2s.h"
#include "noise_ik.h"

/* --- vectors (tools/test/gen_noise_vectors.py) ---------------------- */

static const uint8_t kMachinePriv[32] = { 0x5d, 0x9f, 0x83, 0xf9, 0x23, 0xfa, 0x7c, 0x7f, 0xeb, 0xae, 0x1e, 0x98, 0x37, 0x78, 0x69, 0xfb, 0x9f, 0xf9, 0x56, 0xfb, 0x46, 0xd8, 0x4e, 0xc7, 0xfc, 0x5c, 0x6a, 0x87, 0x83, 0x3f, 0x09, 0xff };
static const uint8_t kControlPriv[32] = { 0x5d, 0x21, 0x40, 0xa8, 0xee, 0x2b, 0x94, 0x43, 0x29, 0xb5, 0xb9, 0x21, 0x43, 0xbd, 0x25, 0x2f, 0x68, 0xf6, 0xef, 0x72, 0xf1, 0x62, 0x22, 0x0d, 0x50, 0x11, 0xbf, 0x53, 0xde, 0x75, 0xe3, 0xc0 };
static const uint8_t kEphemeralSeed[32] = { 0x4d, 0xca, 0x58, 0xd4, 0x44, 0xb2, 0xf7, 0x80, 0xe3, 0x73, 0x69, 0x0b, 0x80, 0xd5, 0x0e, 0x77, 0x87, 0x18, 0x4d, 0xbf, 0x05, 0x3c, 0x2d, 0xdb, 0x93, 0x33, 0xf9, 0x46, 0x30, 0x13, 0x16, 0x92 };
static const uint8_t kControlEphPriv[32] = { 0xfc, 0x39, 0x93, 0x09, 0x47, 0xe4, 0x60, 0xd0, 0xa1, 0xb0, 0x35, 0x5d, 0x6d, 0x20, 0x58, 0x29, 0xbd, 0x58, 0x62, 0x31, 0xfe, 0x54, 0x1b, 0x1f, 0xcd, 0x08, 0x3a, 0xee, 0x90, 0xbf, 0x2d, 0x8b };
static const uint8_t kMsg1[96] = { 0x50, 0x88, 0xbe, 0x91, 0x7f, 0x6a, 0xff, 0x6b, 0xa1, 0x9b, 0x05, 0x6e, 0x8c, 0x42, 0xf0, 0x52, 0xdb, 0x65, 0xf5, 0x14, 0x74, 0xee, 0xc0, 0x53, 0x11, 0x23, 0x14, 0xd4, 0x12, 0x69, 0xba, 0x17, 0x71, 0xaf, 0xca, 0x81, 0x82, 0x67, 0x34, 0xaf, 0x21, 0xeb, 0x76, 0x0b, 0xa4, 0xec, 0xc2, 0x63, 0xf8, 0x59, 0xd9, 0x76, 0x65, 0x99, 0x6a, 0xa8, 0x42, 0xb2, 0x28, 0xe1, 0x8a, 0x2b, 0x34, 0x98, 0x69, 0x78, 0xe9, 0xf3, 0x7e, 0xc8, 0x93, 0xd2, 0x5e, 0x14, 0x3d, 0xad, 0xc0, 0xbc, 0xe9, 0xdc, 0x15, 0x3e, 0xd3, 0x0f, 0xc6, 0x11, 0x96, 0x03, 0xf1, 0xfa, 0x6a, 0xd5, 0x74, 0xdd, 0x5b, 0xa2 };
static const uint8_t kMsg2[48] = { 0x96, 0x2a, 0xd1, 0x57, 0x07, 0x12, 0xb7, 0x37, 0xe4, 0x3e, 0x9b, 0xd3, 0x5d, 0x93, 0x4e, 0x53, 0xa1, 0xf6, 0x64, 0x8d, 0xd9, 0x67, 0x31, 0xd4, 0xee, 0x62, 0x26, 0x1c, 0x6a, 0xe3, 0xdc, 0x06, 0xc4, 0xef, 0xc0, 0x2a, 0x64, 0x97, 0xab, 0x34, 0x19, 0x89, 0xd4, 0x08, 0x36, 0x6f, 0x53, 0xa1 };
static const uint8_t kSplitSend[32] = { 0x5f, 0x5b, 0x15, 0xf2, 0x89, 0x31, 0x36, 0x49, 0xcd, 0x00, 0x23, 0x0b, 0xca, 0x92, 0x1c, 0x8a, 0x92, 0x51, 0x40, 0x99, 0x56, 0xae, 0xfd, 0x5e, 0x0b, 0x87, 0x30, 0xd9, 0xf2, 0x16, 0xc6, 0x44 };
static const uint8_t kSplitRecv[32] = { 0xe2, 0x0d, 0x5d, 0xc0, 0xac, 0x39, 0xba, 0x9f, 0x9c, 0x87, 0x39, 0xb9, 0x4c, 0x69, 0xd2, 0x9f, 0x88, 0xdb, 0x8d, 0xb7, 0x1e, 0x9a, 0x12, 0x95, 0x85, 0x29, 0xe8, 0x49, 0x5b, 0x7e, 0xd4, 0x98 };
static const uint8_t kC2SCt0[16] = { 0xe6, 0x05, 0x19, 0x7a, 0xf1, 0x8e, 0xa3, 0x8a, 0x84, 0x7d, 0xc8, 0xbc, 0xd9, 0x26, 0x29, 0xe5 };
static const uint8_t kC2SCt1[17] = { 0x23, 0x4b, 0xa5, 0x1d, 0x7c, 0xa6, 0xa2, 0x1c, 0xee, 0x77, 0xd7, 0x82, 0x6d, 0x64, 0x8e, 0x9c, 0x86 };
static const uint8_t kC2SCt2[31] = { 0x34, 0x90, 0x24, 0x69, 0x9a, 0xf9, 0x53, 0x57, 0xa3, 0x68, 0xa9, 0xa2, 0x37, 0xe8, 0x10, 0x34, 0xba, 0xc8, 0xd8, 0xf2, 0x7b, 0x2a, 0xf0, 0xfd, 0xb9, 0x4c, 0x5a, 0xe6, 0x8e, 0x5b, 0x4b };
static const uint8_t kC2SCt3[32] = { 0x4f, 0x66, 0x07, 0xb8, 0xcb, 0xff, 0x22, 0x32, 0x0e, 0x97, 0xa3, 0x4d, 0x98, 0xa2, 0xb3, 0xf6, 0x09, 0xbe, 0xdb, 0x74, 0xa5, 0x85, 0xd3, 0xc9, 0x5a, 0x42, 0x25, 0x33, 0xe8, 0x8d, 0xa1, 0xc3 };
static const uint8_t kC2SCt4[33] = { 0x41, 0xf1, 0x39, 0xa3, 0xed, 0x24, 0x43, 0x90, 0x09, 0x61, 0x27, 0x86, 0x22, 0x15, 0x18, 0xc6, 0xb4, 0xb1, 0xd1, 0xb1, 0x3c, 0xbe, 0xa8, 0xdc, 0xa9, 0xb3, 0xc2, 0xeb, 0x56, 0xd9, 0x91, 0x42, 0xe0 };
static const uint8_t kC2SCt5B2s[32] = { 0xde, 0x4b, 0x6e, 0x42, 0x15, 0xba, 0x78, 0x02, 0x02, 0x10, 0x5e, 0x4d, 0xbc, 0xbc, 0xae, 0x60, 0x73, 0x08, 0xaf, 0x6d, 0xbb, 0x99, 0xdf, 0x75, 0x79, 0xcb, 0x39, 0xf3, 0xf7, 0x98, 0x4d, 0x2f };
static const uint8_t kC2SCt6B2s[32] = { 0x12, 0xa4, 0xca, 0xe7, 0xd2, 0x00, 0xcb, 0x27, 0x21, 0xfd, 0x1d, 0x64, 0x38, 0x66, 0x25, 0x47, 0x9d, 0x32, 0x70, 0x31, 0xa8, 0x6c, 0xbb, 0x56, 0x8e, 0x17, 0xaa, 0x3b, 0xa6, 0x24, 0x4c, 0x8b };
static const uint8_t kC2SCt7B2s[32] = { 0x92, 0x99, 0x82, 0x5f, 0xce, 0x1f, 0xa8, 0xad, 0x64, 0x65, 0xf7, 0xdb, 0x5f, 0xce, 0xa1, 0x40, 0x65, 0x81, 0xdd, 0x15, 0x9d, 0x3d, 0x3e, 0x76, 0x1f, 0xa3, 0xe4, 0x7d, 0xb0, 0xce, 0x1c, 0x43 };
static const uint8_t kC2SCt8B2s[32] = { 0x95, 0x34, 0xe1, 0x22, 0xac, 0x6a, 0xd5, 0x96, 0x75, 0xa1, 0x23, 0x1a, 0x82, 0xdd, 0x53, 0x3b, 0xc3, 0xc7, 0x3f, 0x95, 0x6c, 0x2e, 0x58, 0xbb, 0x4e, 0x9e, 0x5c, 0x53, 0x35, 0x03, 0xf3, 0xba };
static const uint8_t kS2CCt0[16] = { 0xe9, 0x43, 0xa9, 0xc3, 0xfb, 0x27, 0x2d, 0xc5, 0xf6, 0x65, 0x82, 0xed, 0x03, 0x7d, 0x48, 0x60 };
static const uint8_t kS2CCt1[21] = { 0x1b, 0x1d, 0xbb, 0x12, 0x8d, 0x5f, 0xcc, 0x3e, 0x15, 0xee, 0x55, 0xfa, 0x3f, 0x09, 0x9e, 0x21, 0x15, 0x23, 0xf4, 0x19, 0x34 };
static const uint8_t kS2CCt2B2s[32] = { 0x7e, 0x1a, 0x1f, 0x32, 0xfa, 0x20, 0x5f, 0x37, 0x4e, 0x3f, 0xe2, 0xd4, 0xd2, 0xf3, 0xc5, 0xde, 0xda, 0x8d, 0xd6, 0xfb, 0xab, 0x8e, 0xf8, 0xba, 0x09, 0xf5, 0x62, 0xdd, 0xb9, 0xf4, 0x50, 0x37 };
static const uint8_t kS2CCt3B2s[32] = { 0x88, 0xc7, 0xa0, 0x1c, 0xf1, 0x1b, 0xf7, 0x92, 0xea, 0xe1, 0x34, 0x30, 0x34, 0x34, 0x24, 0xbf, 0x98, 0x07, 0xe6, 0x72, 0xdb, 0x40, 0x7e, 0xb5, 0x1c, 0xbf, 0x74, 0x08, 0xa9, 0x54, 0xbc, 0xcc };
static const uint8_t kS2CCt4B2s[32] = { 0x96, 0xce, 0xb6, 0xe4, 0x6a, 0x6a, 0x27, 0xad, 0xa5, 0xc7, 0x88, 0x0a, 0xfe, 0x89, 0xc0, 0x8e, 0x6f, 0x4a, 0xc2, 0x53, 0xc4, 0x49, 0x3d, 0xe1, 0xf8, 0x72, 0x65, 0xb1, 0xcd, 0x7c, 0x97, 0x3b };
static const uint8_t kFarCt[33] = { 0xbf, 0x03, 0x5a, 0x12, 0xec, 0xf4, 0x6c, 0xb0, 0xbe, 0x0c, 0xdb, 0xde, 0xe2, 0xab, 0x88, 0xb1, 0x30, 0x83, 0x34, 0xa4, 0xf7, 0xd9, 0xe0, 0xec, 0xc8, 0x1b, 0x4f, 0x8d, 0x4e, 0xca, 0xc5, 0x31, 0xe1 };

#define PROTOCOL_NAME "Noise_IK_25519_ChaChaPoly_BLAKE2s"
#define PROLOGUE      "Tailscale Control Protocol v1"
static const size_t kC2SLens[] = { 0, 1, 15, 16, 17, 64, 65, 300, 4080 };
static const size_t kS2CLens[] = { 0, 5, 64, 1000, 4080 };
#define FAR_N   0x0102030405060708ULL
#define FULL_MAX 65
#define REC_MAX (4080 + NOISE_TAGLEN)

/* The initiator's only randomness is its ephemeral key
 * (curve25519_keypair → esp_fill_random). Hand out the generator's seed
 * on the first call, then a counter pattern. */
static unsigned s_rng_calls;
void esp_fill_random(void *buf, size_t len)
{
    uint8_t *p = buf;
    for (size_t i = 0; i < len; i++) {
        p[i] = (s_rng_calls == 0 && i < sizeof(kEphemeralSeed))
                   ? kEphemeralSeed[i] : (uint8_t)(0xC3 ^ i ^ s_rng_calls);
    }
    s_rng_calls++;
}

static int s_fails;

static void hexdump(const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}

static void check(const char *name, int ok)
{
    printf("[%s] %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) s_fails++;
}

static void check_bytes(const char *name, const uint8_t *got,
                        const uint8_t *want, size_t n)
{
    int ok = memcmp(got, want, n) == 0;
    check(name, ok);
    if (!ok) {
        printf("  got:  "); hexdump(got, n);
        printf("\n  want: "); hexdump(want, n); printf("\n");
    }
}

static void b2s(uint8_t out[32], const uint8_t *in, size_t n)
{
    blake2s(out, 32, in, n, NULL, 0);
}

static void pt_bytes(uint8_t *out, size_t len, uint8_t dirtag)
{
    for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(i * 31 + len + dirtag);
}

/* --- independent responder ------------------------------------------ */

typedef struct {
    uint8_t h[32], ck[32], k[32];
} resp_sym_t;

static void r_mix_hash(resp_sym_t *r, const uint8_t *d, size_t n)
{
    blake2s_state S;
    blake2s_init(&S, 32);
    blake2s_update(&S, r->h, 32);
    if (n) blake2s_update(&S, d, n);
    blake2s_final(&S, r->h, 32);
}

static void r_mix_key(resp_sym_t *r, const uint8_t ikm[32])
{
    uint8_t ck[32];
    noise_hkdf2(r->ck, ikm, 32, ck, r->k);
    memcpy(r->ck, ck, 32);
}

/* controlbase: 4 zero bytes, then the counter big-endian. */
static void r_nonce(uint8_t out[12], uint64_t n)
{
    memset(out, 0, 12);
    for (int i = 0; i < 8; i++) out[11 - i] = (uint8_t)(n >> (8 * i));
}

/* The same nonce with the Noise spec's LE64 counter — the negative
 * control for the byte order. */
static void r_nonce_le(uint8_t out[12], uint64_t n)
{
    memset(out, 0, 12);
    for (int i = 0; i < 8; i++) out[4 + i] = (uint8_t)(n >> (8 * i));
}

static int r_open(const uint8_t k[32], uint64_t n, const uint8_t *ad,
                  size_t ad_len, const uint8_t *ct, size_t ct_len, uint8_t *pt)
{
    uint8_t nonce[12];
    r_nonce(nonce, n);
    return chacha20poly1305_decrypt(pt, ct, ct_len, ad, ad_len, k, nonce);
}

static void r_seal(const uint8_t k[32], uint64_t n, const uint8_t *pt,
                   size_t len, uint8_t *ct)
{
    uint8_t nonce[12];
    r_nonce(nonce, n);
    chacha20poly1305_encrypt(ct, pt, len, NULL, 0, k, nonce);
}

/* Round 1.3.7, B2: msg1 from precomputed DH (noise_ik_pre_t) is the same
 * message, with the same transport keys. */
static void test_precomputed_msg1(const uint8_t s_pub[32], const uint8_t c_pub[32])
{
    static noise_ik_state_t st;
    noise_ik_pre_t pre;
    uint8_t msg1[NOISE_IK_MSG1_LEN];

    /* e + es + ss ahead: e is the generator's seed, as in the vector */
    memset(&pre, 0, sizeof(pre));
    s_rng_calls = 0;
    check("pre/compute-all",
          noise_ik_precompute(&pre, kMachinePriv, c_pub, true) == ESP_OK &&
          pre.have_ss && pre.have_e);
    noise_ik_init(&st, kMachinePriv, s_pub, c_pub, PROTOCOL_NAME,
                  (const uint8_t *)PROLOGUE, strlen(PROLOGUE));
    const unsigned calls = s_rng_calls;
    check("pre/msg1-all-ahead",
          noise_ik_write_msg1_pre(&st, msg1, &pre) == ESP_OK && s_rng_calls == calls);
    check_bytes("pre/msg1-vector", msg1, kMsg1, sizeof(kMsg1));
    check("pre/split-vector",
          noise_ik_read_msg2(&st, kMsg2) == ESP_OK &&
          memcmp(st.k_send, kSplitSend, 32) == 0 && memcmp(st.k_recv, kSplitRecv, 32) == 0);

    /* ss only: e drawn in msg1 */
    noise_ik_pre_t ss_only;
    memset(&ss_only, 0, sizeof(ss_only));
    check("pre/compute-ss-only",
          noise_ik_precompute(&ss_only, kMachinePriv, c_pub, false) == ESP_OK &&
          ss_only.have_ss && !ss_only.have_e && memcmp(ss_only.ss, pre.ss, 32) == 0);
    s_rng_calls = 0;
    noise_ik_init(&st, kMachinePriv, s_pub, c_pub, PROTOCOL_NAME,
                  (const uint8_t *)PROLOGUE, strlen(PROLOGUE));
    check("pre/msg1-ss-ahead", noise_ik_write_msg1_pre(&st, msg1, &ss_only) == ESP_OK);
    check_bytes("pre/msg1-ss-vector", msg1, kMsg1, sizeof(kMsg1));

    /* the cached ss is used: a wrong one changes only the payload tag */
    ss_only.ss[7] ^= 0x80;
    s_rng_calls = 0;
    noise_ik_init(&st, kMachinePriv, s_pub, c_pub, PROTOCOL_NAME,
                  (const uint8_t *)PROLOGUE, strlen(PROLOGUE));
    noise_ik_write_msg1_pre(&st, msg1, &ss_only);
    check("pre/wrong-ss-tag-only",
          memcmp(msg1, kMsg1, 80) == 0 && memcmp(msg1 + 80, kMsg1 + 80, 16) != 0);

    /* a low-order server key: nothing computed */
    static const uint8_t zero[32] = { 0 };
    noise_ik_pre_t bad;
    memset(&bad, 0, sizeof(bad));
    check("pre/low-order-refused",
          noise_ik_precompute(&bad, kMachinePriv, zero, true) == ESP_FAIL &&
          !bad.have_ss && !bad.have_e);
    check("pre/null-args", noise_ik_precompute(NULL, kMachinePriv, c_pub, true) ==
                           ESP_ERR_INVALID_ARG);
}

/* --- test ----------------------------------------------------------- */

int main(void)
{
    uint8_t s_pub[32], c_pub[32], re_pub[32];
    curve25519_derive_pub(s_pub, kMachinePriv);
    curve25519_derive_pub(c_pub, kControlPriv);
    curve25519_derive_pub(re_pub, kControlEphPriv);

    /* ---- msg1 ---- */
    static noise_ik_state_t st;
    check("init", noise_ik_init(&st, kMachinePriv, s_pub, c_pub, PROTOCOL_NAME,
                                (const uint8_t *)PROLOGUE,
                                strlen(PROLOGUE)) == ESP_OK);
    check("transport-before-split",
          noise_ik_encrypt(&st, (uint8_t[16]){0}, 16, NULL, 0,
                           &(size_t){0}) == ESP_ERR_INVALID_STATE);
    uint8_t msg1[NOISE_IK_MSG1_LEN];
    check("write-msg1", noise_ik_write_msg1(&st, msg1) == ESP_OK);
    check_bytes("msg1-vector", msg1, kMsg1, sizeof(kMsg1));

    /* Responder reads msg1: the spec's IK pattern, independently. */
    resp_sym_t r;
    blake2s(r.h, 32, PROTOCOL_NAME, strlen(PROTOCOL_NAME), NULL, 0);
    memcpy(r.ck, r.h, 32);
    r_mix_hash(&r, (const uint8_t *)PROLOGUE, strlen(PROLOGUE));
    r_mix_hash(&r, c_pub, 32);
    const uint8_t *ie = msg1;
    r_mix_hash(&r, ie, 32);
    uint8_t dh[32];
    curve25519_dh(dh, kControlPriv, ie);
    r_mix_key(&r, dh);
    uint8_t got_s[32];
    check("resp-open-static",
          r_open(r.k, 0, r.h, 32, msg1 + 32, 48, got_s) == 0);
    check_bytes("resp-initiator-static", got_s, s_pub, 32);
    r_mix_hash(&r, msg1 + 32, 48);
    curve25519_dh(dh, kControlPriv, got_s);
    r_mix_key(&r, dh);
    check("resp-open-payload",
          r_open(r.k, 0, r.h, 32, msg1 + 80, 16, NULL) == 0);
    r_mix_hash(&r, msg1 + 80, 16);

    /* Responder writes msg2: <- e, ee, se, empty payload. */
    uint8_t msg2[NOISE_IK_MSG2_LEN];
    memcpy(msg2, re_pub, 32);
    r_mix_hash(&r, re_pub, 32);
    curve25519_dh(dh, kControlEphPriv, ie);
    r_mix_key(&r, dh);
    curve25519_dh(dh, kControlEphPriv, got_s);
    r_mix_key(&r, dh);
    {
        uint8_t nonce[12];
        r_nonce(nonce, 0);
        chacha20poly1305_encrypt(msg2 + 32, NULL, 0, r.h, 32, r.k, nonce);
    }
    check_bytes("msg2-vector", msg2, kMsg2, sizeof(kMsg2));
    uint8_t r_recv[32], r_send[32];      /* responder's view of Split() */
    noise_hkdf2(r.ck, NULL, 0, r_recv, r_send);

    /* A forged msg2 (tag bit flip) must not complete the handshake. */
    {
        static noise_ik_state_t bad;
        memcpy(&bad, &st, sizeof(bad));
        uint8_t forged[NOISE_IK_MSG2_LEN];
        memcpy(forged, msg2, sizeof(forged));
        forged[40] ^= 0x01;
        check("msg2-forged-tag",
              noise_ik_read_msg2(&bad, forged) == ESP_FAIL && !bad.transport_ready);
    }

    check("read-msg2", noise_ik_read_msg2(&st, msg2) == ESP_OK && st.transport_ready);
    check_bytes("split-send", st.k_send, kSplitSend, 32);
    check_bytes("split-recv", st.k_recv, kSplitRecv, 32);
    check("split-agrees",
          memcmp(st.k_send, r_recv, 32) == 0 && memcmp(st.k_recv, r_send, 32) == 0);

    /* ---- initiator → control records ---- */
    static uint8_t pt[REC_MAX], ct[REC_MAX], back[REC_MAX];
    static const uint8_t *const c2s_full[] = { kC2SCt0, kC2SCt1, kC2SCt2, kC2SCt3, kC2SCt4 };
    static const uint8_t *const c2s_b2s[]  = { kC2SCt5B2s, kC2SCt6B2s, kC2SCt7B2s, kC2SCt8B2s };
    for (size_t n = 0; n < sizeof(kC2SLens) / sizeof(kC2SLens[0]); n++) {
        char name[48];
        size_t len = kC2SLens[n], ct_len = 0;
        pt_bytes(pt, len, 0x00);
        int ok = noise_ik_encrypt(&st, ct, sizeof(ct), len ? pt : NULL, len,
                                  &ct_len) == ESP_OK &&
                 ct_len == len + NOISE_TAGLEN;
        if (ct_len <= FULL_MAX) {
            ok = ok && memcmp(ct, c2s_full[n], ct_len) == 0;
        } else {
            uint8_t d[32];
            b2s(d, ct, ct_len);
            ok = ok && memcmp(d, c2s_b2s[n - 5], 32) == 0;
        }
        snprintf(name, sizeof(name), "c2s-n%zu-len%zu-vector", n, len);
        check(name, ok);
        ok = r_open(r_recv, n, NULL, 0, ct, ct_len, back) == 0 &&
             memcmp(back, pt, len) == 0;
        snprintf(name, sizeof(name), "c2s-n%zu-len%zu-resp-open", n, len);
        check(name, ok);
    }
    check("c2s-counter", st.n_send == sizeof(kC2SLens) / sizeof(kC2SLens[0]));

    /* ---- control → initiator records ---- */
    static const uint8_t *const s2c_full[] = { kS2CCt0, kS2CCt1 };
    static const uint8_t *const s2c_b2s[]  = { kS2CCt2B2s, kS2CCt3B2s, kS2CCt4B2s };
    for (size_t n = 0; n < sizeof(kS2CLens) / sizeof(kS2CLens[0]); n++) {
        char name[48];
        size_t len = kS2CLens[n], out_len = 0;
        pt_bytes(pt, len, 0x80);
        r_seal(r_send, n, pt, len, ct);
        int ok;
        if (len + NOISE_TAGLEN <= FULL_MAX) {
            ok = memcmp(ct, s2c_full[n], len + NOISE_TAGLEN) == 0;
        } else {
            uint8_t d[32];
            b2s(d, ct, len + NOISE_TAGLEN);
            ok = memcmp(d, s2c_b2s[n - 2], 32) == 0;
        }
        snprintf(name, sizeof(name), "s2c-n%zu-len%zu-vector", n, len);
        check(name, ok);

        if (n == 2) {
            /* Tampered copy first: must fail, leave out alone, keep n. */
            static uint8_t bad[REC_MAX];
            memcpy(bad, ct, len + NOISE_TAGLEN);
            bad[len / 2] ^= 0x80;
            memset(back, 0xA5, sizeof(back));
            uint64_t n_before = st.n_recv;
            int rc = noise_ik_decrypt(&st, back, sizeof(back), bad,
                                      len + NOISE_TAGLEN, &out_len);
            int untouched = 1;
            for (size_t i = 0; i < len; i++) {
#ifdef NOISE_OLD_PATH
                /* mbedTLS writes, then zeroes; only "no plaintext". */
                if (back[i] == pt[i] && pt[i] != 0) untouched = 0;
#else
                if (back[i] != 0xA5) untouched = 0;
#endif
            }
            check("s2c-tampered-rejected",
                  rc == ESP_FAIL && untouched && st.n_recv == n_before);
        }

        memset(back, 0, sizeof(back));
        int rc = noise_ik_decrypt(&st, back, sizeof(back), ct,
                                  len + NOISE_TAGLEN, &out_len);
        ok = rc == ESP_OK && out_len == len && memcmp(back, pt, len) == 0;
        snprintf(name, sizeof(name), "s2c-n%zu-len%zu-decrypt", n, len);
        check(name, ok);
        if (n == 3) {
            /* The same record again is a replay: n moved on, tag fails. */
            rc = noise_ik_decrypt(&st, back, sizeof(back), ct,
                                  len + NOISE_TAGLEN, &out_len);
            check("s2c-replay-rejected", rc == ESP_FAIL);
        }
    }

    /* In place (out == ciphertext), as noted in noise_ik.h. */
    {
        size_t out_len = 0;
        uint64_t n = st.n_recv;
        pt_bytes(pt, 333, 0x80);
        r_seal(r_send, n, pt, 333, ct);
        int rc = noise_ik_decrypt(&st, ct, sizeof(ct), ct, 333 + NOISE_TAGLEN,
                                  &out_len);
        check("s2c-in-place", rc == ESP_OK && out_len == 333 &&
                              memcmp(ct, pt, 333) == 0);
    }

    /* ---- nonce byte order across all 8 counter bytes ---- */
    {
        size_t ct_len = 0;
        st.n_send = FAR_N;
        pt_bytes(pt, 17, 0x00);
        int rc = noise_ik_encrypt(&st, ct, sizeof(ct), pt, 17, &ct_len);
        check_bytes("far-counter-vector", ct, kFarCt, sizeof(kFarCt));
        check("far-counter-len", rc == ESP_OK && ct_len == sizeof(kFarCt));
        check("far-counter-resp-open",
              r_open(r_recv, FAR_N, NULL, 0, ct, ct_len, back) == 0 &&
              memcmp(back, pt, 17) == 0);
        uint8_t le[12];
        r_nonce_le(le, FAR_N);
        check("far-counter-not-le",
              chacha20poly1305_decrypt(back, ct, ct_len, NULL, 0, r_recv, le) != 0);
        check("far-counter-advances", st.n_send == FAR_N + 1);
    }

    /* ---- argument / size errors ---- */
    {
        size_t out_len = 0;
        uint8_t small[8];
        check("decrypt-short-ct", noise_ik_decrypt(&st, back, sizeof(back), ct,
                                                   NOISE_TAGLEN - 1, &out_len)
                                      == ESP_ERR_INVALID_SIZE);
        check("decrypt-small-out", noise_ik_decrypt(&st, small, sizeof(small), ct,
                                                    sizeof(small) + 1 + NOISE_TAGLEN,
                                                    &out_len)
                                       == ESP_ERR_INVALID_SIZE);
        check("encrypt-small-out", noise_ik_encrypt(&st, small, sizeof(small), pt,
                                                    1, &out_len)
                                       == ESP_ERR_INVALID_SIZE);
        check("encrypt-null-pt", noise_ik_encrypt(&st, ct, sizeof(ct), NULL, 1,
                                                  &out_len)
                                     == ESP_ERR_INVALID_ARG);
    }

    test_precomputed_msg1(s_pub, c_pub);

    if (s_fails == 0) printf("\nALL OK\n");
    return s_fails ? 1 : 0;
}
