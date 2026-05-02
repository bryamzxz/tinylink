// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "wg_proto.h"

#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "crypto/blake2s.h"
#include "crypto/hkdf_blake2s.h"

#ifdef ESP_PLATFORM
#include "esp_timer.h"
#endif

/* --- Protocol constants ---------------------------------------------- */

const uint8_t WG_CONSTRUCTION[37]  = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const uint8_t WG_IDENTIFIER[34]    = "WireGuard v1 zx2c4 Jason@zx2c4.com";
const uint8_t WG_LABEL_MAC1[8]     = "mac1----";
const uint8_t WG_LABEL_COOKIE[8]   = "cookie--";

/* --- Lazy initialization of derived initial constants ---------------- */

static uint8_t s_initial_chain_key[WG_HASH_LEN];
static uint8_t s_initial_hash[WG_HASH_LEN];
static bool    s_initial_constants_ready;

static void compute_initial_constants(void)
{
    /* INITIAL_CHAIN_KEY = BLAKE2s(WG_CONSTRUCTION). */
    blake2s_state st;
    blake2s_init(&st, WG_HASH_LEN);
    blake2s_update(&st, WG_CONSTRUCTION, sizeof(WG_CONSTRUCTION));
    blake2s_final(&st, s_initial_chain_key, WG_HASH_LEN);

    /* INITIAL_HASH = BLAKE2s(INITIAL_CHAIN_KEY || WG_IDENTIFIER). */
    blake2s_init(&st, WG_HASH_LEN);
    blake2s_update(&st, s_initial_chain_key, WG_HASH_LEN);
    blake2s_update(&st, WG_IDENTIFIER, sizeof(WG_IDENTIFIER));
    blake2s_final(&st, s_initial_hash, WG_HASH_LEN);

    s_initial_constants_ready = true;
}

const uint8_t *wg_initial_chain_key(void)
{
    if (!s_initial_constants_ready) compute_initial_constants();
    return s_initial_chain_key;
}

const uint8_t *wg_initial_hash(void)
{
    if (!s_initial_constants_ready) compute_initial_constants();
    return s_initial_hash;
}

/* --- Protocol helpers ------------------------------------------------- */

void wg_mix_hash(uint8_t h[WG_HASH_LEN],
                 const uint8_t *data, size_t data_len)
{
    blake2s_state st;
    blake2s_init(&st, WG_HASH_LEN);
    blake2s_update(&st, h, WG_HASH_LEN);
    if (data_len) blake2s_update(&st, data, data_len);
    blake2s_final(&st, h, WG_HASH_LEN);
}

void wg_mix_key(uint8_t ck[WG_HASH_LEN],
                const uint8_t *x, size_t x_len,
                uint8_t out_key[WG_KEY_LEN])
{
    /* (C, k) = KDF2(C, x). noise_hkdf2 writes both outputs in one shot. */
    uint8_t new_ck[WG_HASH_LEN];
    noise_hkdf2(ck, x, x_len, new_ck, out_key);
    memcpy(ck, new_ck, WG_HASH_LEN);
    /* Best-effort scrub the temporary. */
    memset(new_ck, 0, sizeof(new_ck));
}

void wg_mix_chain_only(uint8_t ck[WG_HASH_LEN],
                       const uint8_t *x, size_t x_len)
{
    /* C = KDF1(C, x). */
    uint8_t new_ck[WG_HASH_LEN];
    noise_hkdf1(ck, x, x_len, new_ck);
    memcpy(ck, new_ck, WG_HASH_LEN);
    memset(new_ck, 0, sizeof(new_ck));
}

void wg_mac1_key(uint8_t out_key[WG_HASH_LEN],
                 const uint8_t responder_static_pub[WG_KEY_LEN])
{
    /* mac1 key = BLAKE2s(LABEL_MAC1 || S_pub_responder). */
    blake2s_state st;
    blake2s_init(&st, WG_HASH_LEN);
    blake2s_update(&st, WG_LABEL_MAC1, sizeof(WG_LABEL_MAC1));
    blake2s_update(&st, responder_static_pub, WG_KEY_LEN);
    blake2s_final(&st, out_key, WG_HASH_LEN);
}

void wg_keyed_mac16(uint8_t out_mac[WG_MAC_LEN],
                    const uint8_t key[WG_HASH_LEN],
                    const uint8_t *data, size_t data_len)
{
    /* WG uses keyed BLAKE2s with output length 16 bytes. The key is the
     * 32-byte key derived above. */
    blake2s_state st;
    blake2s_init_key(&st, WG_MAC_LEN, key, WG_HASH_LEN);
    if (data_len) blake2s_update(&st, data, data_len);
    blake2s_final(&st, out_mac, WG_MAC_LEN);
}

/* --- TAI64N --------------------------------------------------------- */

static uint64_t monotonic_seconds(void)
{
#ifdef ESP_PLATFORM
    /* esp_timer_get_time() returns microseconds since boot. */
    return (uint64_t)(esp_timer_get_time() / 1000000);
#else
    /* Host build: use clock_gettime(CLOCK_MONOTONIC). */
    struct timespec ts = {0, 0};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)ts.tv_sec;
    }
    return 0;
#endif
}

static uint32_t monotonic_nanos_partial(void)
{
#ifdef ESP_PLATFORM
    /* Microseconds × 1000 for the nanos field, modulo 1 s. */
    int64_t us = esp_timer_get_time();
    return (uint32_t)((us % 1000000) * 1000);
#else
    struct timespec ts = {0, 0};
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint32_t)ts.tv_nsec;
    }
    return 0;
#endif
}

void wg_tai64n_now(uint8_t out[WG_TAI64N_LEN])
{
    /* Try wall-clock first; if it returns 0 (no SNTP), fall back to
     * a monotonic counter. The handshake just needs strict monotonic
     * progression from the same peer. */
    uint64_t secs = (uint64_t)time(NULL);
    uint32_t nanos = 0;
    if (secs == 0) {
        secs = monotonic_seconds();
        nanos = monotonic_nanos_partial();
    } else {
        /* When wall-clock is set, prefer real nanos for jitter. */
        nanos = monotonic_nanos_partial();
    }
    /* TAI64 epoch shifts seconds by 2^62. WG doesn't strictly require
     * the shift (it treats the bytes as opaque ordering), but real
     * peers serialize TAI64 this way. We follow the convention. */
    uint64_t tai = secs + 0x4000000000000000ULL;

    /* Big-endian seconds (8 B) then big-endian nanos (4 B). */
    for (int i = 0; i < 8; i++) out[i]     = (uint8_t)(tai   >> (8 * (7 - i)));
    for (int i = 0; i < 4; i++) out[8 + i] = (uint8_t)(nanos >> (8 * (3 - i)));
}
