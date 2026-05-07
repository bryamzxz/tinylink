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

    ESP_LOGI(TAG,
             "%-7s mlen=%4u iters=%4u | enc %lld us total, %u ns/call, %u ns/B, %u MB/s | dec %lld us total, %u ns/call, %u ns/B, %u MB/s | dec_rc=%d",
             label, (unsigned)mlen, (unsigned)iters,
             (long long)enc_us, (unsigned)enc_ns_per_call, (unsigned)enc_ns_per_byte, (unsigned)enc_mbps,
             (long long)dec_us, (unsigned)dec_ns_per_call, (unsigned)dec_ns_per_byte, (unsigned)dec_mbps,
             rc);
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

    ESP_LOGI(TAG, "round-trip OK; starting timed loops");

    /* Iteration counts chosen so each phase runs ~250-500 ms on the
     * existing baseline (~1.5 MB/s order of magnitude on ESP32 LX6
     * for software ChaCha20-Poly1305). Tune if the numbers come back
     * outside that band. */
    bench_one("small",   64,  4000);
    bench_one("mtu",   1500,   500);

    return ESP_OK;
}

#endif /* CONFIG_TINYLINK_BENCH_AEAD */
