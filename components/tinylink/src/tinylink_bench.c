// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "tinylink_bench.h"

#if CONFIG_TINYLINK_BENCH_AEAD

#include <stdint.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"

#include "crypto/chacha20poly1305.h"

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
        const bool ok = memcmp(out, ct_head, 16) == 0 && memcmp(out + 114, tag, 16) == 0;
        ESP_LOGI(TAG, "RFC 8439 2.8.2 KAT: %s", ok ? "OK" : "MISMATCH");
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

    return ESP_OK;
}

#endif /* CONFIG_TINYLINK_BENCH_AEAD */
