// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// The early PSK (main/wifi_psk.h, round 1.3.8) against the derivation
// the Wi-Fi driver itself runs, on the target: the IDF's pbkdf2_sha1
// (wpa_supplicant crypto_mbedtls.c → fastpbkdf2, software SHA-1 on the
// ESP32), which wpa.c wpa_set_passphrase calls for a passphrase. Byte-
// identical over every passphrase length the early path takes and SSIDs
// of 1..32 bytes, random contents.

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wifi_psk.h"

/* wpa_supplicant src/crypto/sha1.h (not on this component's include path). */
int pbkdf2_sha1(const char *passphrase, const uint8_t *ssid, size_t ssid_len,
                int iterations, uint8_t *buf, size_t buflen);

static uint32_t s_seed = 0x13801380u;

static uint32_t rnd(void)
{
    s_seed ^= s_seed << 13; s_seed ^= s_seed >> 17; s_seed ^= s_seed << 5;
    return s_seed;
}

int m_psk_idf(void)
{
    int fails = 0, cases = 0;
    for (size_t pl = TL_PSK_PASS_MIN; pl <= TL_PSK_PASS_MAX; pl += 5) {
        for (size_t sl = 1; sl <= TL_PSK_SSID_MAX; sl += 13) {
            char pass[TL_PSK_PASS_MAX + 1];
            uint8_t ssid[TL_PSK_SSID_MAX], idf[TL_PSK_LEN], tl[TL_PSK_LEN];
            for (size_t i = 0; i < pl; i++) pass[i] = (char)(1 + rnd() % 255);   /* a C string */
            pass[pl] = 0;
            for (size_t i = 0; i < sl; i++) ssid[i] = (uint8_t)rnd();
            const bool ok_idf = pbkdf2_sha1(pass, ssid, sl, TL_PSK_ITER, idf, sizeof(idf)) == 0;
            const bool ok_tl = tl_psk_derive((const uint8_t *)pass, pl, ssid, sl, tl);
            fails += !(ok_idf && ok_tl && memcmp(idf, tl, sizeof(tl)) == 0);
            cases++;
        }
    }
    const int ok = fails == 0 && cases == 36;
    printf("[psk/idf-pbkdf2_sha1-%d-cases] %s\n", cases, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
