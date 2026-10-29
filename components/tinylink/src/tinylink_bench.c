// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "tinylink_bench.h"

#if CONFIG_TINYLINK_BENCH_AEAD

#include <stdint.h>
#include <string.h>

#include "esp_cpu.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "crypto/chacha20.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/curve25519.h"

static const char *TAG = "bench-aead";

/* 4-byte aligned so a future aligned-load optimization isn't penalized
 * by stack/BSS chance alignment when reading these. The current
 * implementation does byte-by-byte loads regardless, so this is
 * forward-looking only. */
static uint8_t __attribute__((aligned(4))) s_key[CHACHA20POLY1305_KEY_LEN];
static uint8_t __attribute__((aligned(4))) s_nonce[CHACHA20POLY1305_NONCE_LEN];
static uint8_t __attribute__((aligned(4))) s_aad[16];

/* Largest payload + tag. 1500 = WG-typical MTU minus headers; we
 * intentionally bench at the carrier MTU rather than 1280 because that
 * matches the worst case the data path has to sustain. */
#define BENCH_MAX_PT 1500
static uint8_t __attribute__((aligned(4))) s_pt [BENCH_MAX_PT];
static uint8_t __attribute__((aligned(4))) s_ct [BENCH_MAX_PT + CHACHA20POLY1305_TAG_LEN];
static uint8_t __attribute__((aligned(4))) s_dec[BENCH_MAX_PT];

static void bench_one(const char *label, size_t mlen, uint32_t iters)
{
    /* Encrypt loop. Keep nonce constant across iterations: we're
     * measuring AEAD throughput, not key-schedule churn. */
    int64_t t0 = esp_timer_get_time();
    for (uint32_t i = 0; i < iters; ++i) {
        chacha20poly1305_encrypt(s_ct, s_pt, mlen,
                                 s_aad, sizeof(s_aad),
                                 s_key, s_nonce);
    }
    int64_t t1 = esp_timer_get_time();

    /* Decrypt loop on the ciphertext we just produced. Same iterations
     * so the two numbers are directly comparable. */
    int rc = 0;
    int64_t t2 = esp_timer_get_time();
    for (uint32_t i = 0; i < iters; ++i) {
        rc |= chacha20poly1305_decrypt(s_dec, s_ct, mlen + CHACHA20POLY1305_TAG_LEN,
                                       s_aad, sizeof(s_aad),
                                       s_key, s_nonce);
    }
    int64_t t3 = esp_timer_get_time();

    int64_t enc_us = t1 - t0;
    int64_t dec_us = t3 - t2;

    /* µs per call with one decimal — printed as integer.fraction so we
     * don't drag in printf %f. */
    uint32_t enc_ns_per_call = (uint32_t)((enc_us * 1000) / iters);
    uint32_t dec_ns_per_call = (uint32_t)((dec_us * 1000) / iters);
    uint32_t enc_ns_per_byte = (uint32_t)((enc_us * 1000) / iters / mlen);
    uint32_t dec_ns_per_byte = (uint32_t)((dec_us * 1000) / iters / mlen);
    /* MB/s = bytes / µs. (mlen * iters) / total_us = bytes/µs = MB/s. */
    uint32_t enc_mbps = (uint32_t)((uint64_t)mlen * iters / (uint64_t)enc_us);
    uint32_t dec_mbps = (uint32_t)((uint64_t)mlen * iters / (uint64_t)dec_us);

    /* enc_us / dec_us are int64_t per esp_timer_get_time(); for benches
     * with iters ≤ 10_000 and per-call cost ≲ 1 ms the totals stay well
     * under 2^31 µs (~36 min), so a long cast is safe and avoids %lld. */
    ESP_LOGI(TAG,
             "%-7s mlen=%4u iters=%4u | enc %ld us total, %u ns/call, %u ns/B, %u MB/s | dec %ld us total, %u ns/call, %u ns/B, %u MB/s | dec_rc=%d",
             label, (unsigned)mlen, (unsigned)iters,
             (long)enc_us, (unsigned)enc_ns_per_call, (unsigned)enc_ns_per_byte, (unsigned)enc_mbps,
             (long)dec_us, (unsigned)dec_ns_per_call, (unsigned)dec_ns_per_byte, (unsigned)dec_mbps,
             rc);
}

/* Cold-cache variant (2026-09): between timed calls, read 64 KiB of the
 * app's flash-mapped text through the cache (the ESP32 has a 32 KiB
 * flash cache per core, so this evicts everything), then time ONE
 * encrypt / decrypt. This is what a WG packet costs after TLS / WiFi
 * code has run in between — the case CONFIG_TINYLINK_CRYPTO_IN_IRAM
 * targets; the hot loop above cannot show it. */
#define BENCH_EVICT_BYTES (64 * 1024)
static uint32_t evict_flash_cache(void)
{
    /* 0x400D0000 is the IROM (flash text) mapping base on the ESP32;
     * the app text is ≥ 600 KiB, so 64 KiB from the base is always
     * mapped. Volatile so the reads are not folded away. */
    const volatile uint32_t *p = (const volatile uint32_t *)0x400D0000;
    uint32_t sink = 0;
    for (size_t i = 0; i < BENCH_EVICT_BYTES / 4; i += 8) {   /* one word per 32-B line */
        sink += p[i];
    }
    return sink;
}

static void bench_cold(const char *label, size_t mlen, uint32_t iters)
{
    int64_t enc_us = 0, dec_us = 0;
    uint32_t sink = 0;
    int rc = 0;
    for (uint32_t i = 0; i < iters; ++i) {
        sink += evict_flash_cache();
        int64_t t0 = esp_timer_get_time();
        chacha20poly1305_encrypt(s_ct, s_pt, mlen, s_aad, sizeof(s_aad), s_key, s_nonce);
        enc_us += esp_timer_get_time() - t0;
        sink += evict_flash_cache();
        t0 = esp_timer_get_time();
        rc |= chacha20poly1305_decrypt(s_dec, s_ct, mlen + CHACHA20POLY1305_TAG_LEN,
                                       s_aad, sizeof(s_aad), s_key, s_nonce);
        dec_us += esp_timer_get_time() - t0;
    }
    ESP_LOGI(TAG, "%-7s mlen=%4u iters=%4u COLD | enc %u us/call | dec %u us/call | dec_rc=%d sink=%u",
             label, (unsigned)mlen, (unsigned)iters,
             (unsigned)(enc_us / iters), (unsigned)(dec_us / iters), rc, (unsigned)sink);
}

/* The keystream half of the MTU number alone (round 1.3.3, C4), so the
 * ChaCha20 and Poly1305 shares can be told apart across builds. */
static void bench_chacha20(size_t mlen, uint32_t iters)
{
    struct chacha20_ctx ctx;
    int64_t t0 = esp_timer_get_time();
    for (uint32_t i = 0; i < iters; ++i) {
        chacha20_init(&ctx, s_key, i);
        chacha20(&ctx, s_ct, s_pt, (uint32_t)mlen);
    }
    int64_t us = esp_timer_get_time() - t0;
    ESP_LOGI(TAG, "chacha20 mlen=%4u iters=%4u | %u ns/call, %u ns/B",
             (unsigned)mlen, (unsigned)iters,
             (unsigned)((us * 1000) / iters), (unsigned)((us * 1000) / iters / mlen));
}

esp_err_t tinylink_bench_aead(void)
{
    /* Fixed inputs: we want bit-identical work across builds so two
     * runs differ only by code, not by entropy. */
    for (int i = 0; i < (int)sizeof(s_key);   ++i) s_key[i]   = (uint8_t)i;
    for (int i = 0; i < (int)sizeof(s_nonce); ++i) s_nonce[i] = (uint8_t)(0xa0 + i);
    for (int i = 0; i < (int)sizeof(s_aad);   ++i) s_aad[i]   = (uint8_t)(0xc0 + i);
    for (int i = 0; i < BENCH_MAX_PT;         ++i) s_pt[i]    = (uint8_t)(i & 0xff);

    /* Round-trip sanity on the largest size before timing — a regression
     * that breaks correctness must not be reported as "faster". */
    chacha20poly1305_encrypt(s_ct, s_pt, BENCH_MAX_PT,
                             s_aad, sizeof(s_aad),
                             s_key, s_nonce);
    int rc = chacha20poly1305_decrypt(s_dec, s_ct, BENCH_MAX_PT + CHACHA20POLY1305_TAG_LEN,
                                      s_aad, sizeof(s_aad),
                                      s_key, s_nonce);
    if (rc != 0 || memcmp(s_dec, s_pt, BENCH_MAX_PT) != 0) {
        ESP_LOGE(TAG, "round-trip mismatch — bench aborted");
        return ESP_FAIL;
    }

    /* RFC 8439 §2.8.2 known answer (2026-09): the Xtensa build uses inline
     * SAR/SRC asm in ChaCha20 and Poly1305 that the host KATs cannot
     * exercise; this is the on-device oracle for it. */
    {
        static const uint8_t k[32] = {
            0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
            0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f };
        static const uint8_t n12[12] = { 0x07,0,0,0,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47 };
        static const uint8_t ad[12]  = { 0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7 };
        static const char    pt[]    = "Ladies and Gentlemen of the class of '99: If I could offer you "
                                       "only one tip for the future, sunscreen would be it.";
        static const uint8_t ct_head[16] = { 0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,0x7b,0x86,0xaf,0xbc,0x53,0xef,0x7e,0xc2 };
        static const uint8_t tag[16] = { 0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91 };
        uint8_t out[114 + 16];
        chacha20poly1305_encrypt(out, (const uint8_t *)pt, 114, ad, sizeof(ad), k, n12);
        bool ok = memcmp(out, ct_head, 16) == 0 && memcmp(out + 114, tag, 16) == 0;
        /* Both ChaCha20 paths (round 1.3.3, C4): word-aligned buffers take
         * the fused block → XOR loop for every full block, others the
         * keystream + byte-assembly one; the tag covers every ciphertext
         * byte. The 1500-B round trip above cannot tell: it decrypts with
         * the same keystream it encrypted with. */
        memcpy(s_pt, pt, 114);
        chacha20poly1305_encrypt(s_ct, s_pt, 114, ad, sizeof(ad), k, n12);
        const bool ok_al = memcmp(s_ct, ct_head, 16) == 0 && memcmp(s_ct + 114, tag, 16) == 0;
        memmove(s_pt + 1, s_pt, 114);
        chacha20poly1305_encrypt(s_ct + 3, s_pt + 1, 114, ad, sizeof(ad), k, n12);
        const bool ok_un = memcmp(s_ct + 3, ct_head, 16) == 0 && memcmp(s_ct + 3 + 114, tag, 16) == 0;
        ESP_LOGI(TAG, "RFC 8439 2.8.2 KAT: %s (aligned %s, unaligned %s)", ok ? "OK" : "MISMATCH",
                 ok_al ? "OK" : "MISMATCH", ok_un ? "OK" : "MISMATCH");
        ok = ok && ok_al && ok_un;
        for (int i = 0; i < BENCH_MAX_PT; ++i) s_pt[i] = (uint8_t)(i & 0xff);
        if (!ok) return ESP_FAIL;
    }

    ESP_LOGI(TAG, "round-trip OK; starting timed loops");

    /* Iteration counts chosen so each phase runs ~250-500 ms on the
     * existing baseline (~1.5 MB/s order of magnitude on ESP32 LX6
     * for software ChaCha20-Poly1305). Tune if the numbers come back
     * outside that band. */
    bench_one("small",   64,  4000);
    bench_one("mtu",   1500,   500);
    bench_cold("cold", 64, 50);
    bench_cold("cold", 1500, 50);
    bench_chacha20(1500, 500);

    return ESP_OK;
}

/* X25519 (round 1.3.3, C6). RFC 7748 §5.2 vector 1 through the shim
 * first: on the device it is the only oracle for the Xtensa asm in the
 * field multiplication (mull / muluh / src with SAR = 28), which the host
 * KATs never compile. Then the time per scalarmult, and a timing probe:
 * CCOUNT cycles for a spread of scalars and points, the minimum of 3 runs
 * each (filters interrupts; the code runs from flash, so the first call
 * also pays the cache fill). The field code has no secret-dependent
 * branch or address (round 1.3.3 notes); what this measures is the rest
 * — the multiplier's latency is not documented as constant (REFERENCE.md,
 * "Multiplier timing is unspecified"). Expect a spread of a few cycles. */
esp_err_t tinylink_bench_x25519(void)
{
    static const char *TAG_X = "bench-x25519";
    static const uint8_t k[32] = {
        0xa5,0x46,0xe3,0x6b,0xf0,0x52,0x7c,0x9d,0x3b,0x16,0x15,0x4b,0x82,0x46,0x5e,0xdd,
        0x62,0x14,0x4c,0x0a,0xc1,0xfc,0x5a,0x18,0x50,0x6a,0x22,0x44,0xba,0x44,0x9a,0xc4 };
    static const uint8_t u[32] = {
        0xe6,0xdb,0x68,0x67,0x58,0x30,0x30,0xdb,0x35,0x94,0xc1,0xa4,0x24,0xb1,0x5f,0x7c,
        0x72,0x66,0x24,0xec,0x26,0xb3,0x35,0x3b,0x10,0xa9,0x03,0xa6,0xd0,0xab,0x1c,0x4c };
    static const uint8_t want[32] = {
        0xc3,0xda,0x55,0x37,0x9d,0xe9,0xc6,0x90,0x8e,0x94,0xea,0x4d,0xf2,0x8d,0x08,0x4f,
        0x32,0xec,0xcf,0x03,0x49,0x1c,0x71,0xf7,0x54,0xb4,0x07,0x55,0x77,0xa2,0x85,0x52 };
    uint8_t q[32], sk[32], pt[32];

    int rc = curve25519_scalarmult(q, k, u);
    const bool ok = rc == 0 && memcmp(q, want, 32) == 0;
    ESP_LOGI(TAG_X, "RFC 7748 5.2 KAT: %s", ok ? "OK" : "MISMATCH");
    if (!ok) return ESP_FAIL;

    const uint32_t iters = 10;
    int64_t t0 = esp_timer_get_time();
    for (uint32_t i = 0; i < iters; ++i) {
        rc |= curve25519_scalarmult(q, k, u);
    }
    const int64_t us = esp_timer_get_time() - t0;
    ESP_LOGI(TAG_X, "scalarmult iters=%u | %u us/call rc=%d",
             (unsigned)iters, (unsigned)(us / iters), rc);

    /* Inputs: zero / all-ones / alternating scalars (clamped inside),
     * the base point, the RFC point, an all-ones (non-canonical) u. */
    uint32_t cmin = UINT32_MAX, cmax = 0;
    for (int v = 0; v < 8; ++v) {
        for (int i = 0; i < 32; ++i) {
            sk[i] = v == 0 ? 0x00 : v == 1 ? 0xff : v == 2 ? 0x55 : (uint8_t)(k[i] * (v + 1) + i);
            pt[i] = v == 3 ? (i == 0 ? 9 : 0) : v == 4 ? 0xff : (uint8_t)(u[i] ^ (uint8_t)(v * 37));
        }
        pt[31] &= v == 4 ? 0xff : 0x7f;
        uint32_t best = UINT32_MAX;
        for (int r = 0; r < 3; ++r) {
            const uint32_t c0 = esp_cpu_get_cycle_count();
            (void)curve25519_scalarmult(q, sk, pt);
            const uint32_t c = esp_cpu_get_cycle_count() - c0;
            if (c < best) best = c;
        }
        if (best < cmin) cmin = best;
        if (best > cmax) cmax = best;
        ESP_LOGI(TAG_X, "input %d: %u cycles", v, (unsigned)best);
    }
    ESP_LOGI(TAG_X, "timing probe: min %u max %u spread %u cycles over 8 inputs",
             (unsigned)cmin, (unsigned)cmax, (unsigned)(cmax - cmin));
    return ESP_OK;
}

#endif /* CONFIG_TINYLINK_BENCH_AEAD */
