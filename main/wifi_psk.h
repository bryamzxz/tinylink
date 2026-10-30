// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// The WPA2 PSK, derived off the boot critical path (round 1.3.8). With
// WIFI_STORAGE_RAM (app_wifi.c: no second copy of the credentials in
// nvs.net80211) the driver derives the PMK from the passphrase at every
// boot: wpa.c wpa_set_passphrase → pbkdf2_sha1(passphrase, SSID, 4096,
// 32) — 4096 × 2 HMAC-SHA1 in software (crypto_mbedtls.c takes
// fastpbkdf2 on the ESP32, SHA-1 forced to software), on the Wi-Fi task
// between the scan match and the auth frame: a constant 170 ms of the
// ~180-ms STA start → auth on the 1.3.7 sensor (32.98 M instructions
// under QEMU -icount, ≈ 165 ms at 240 MHz).
//
// Here the same PBKDF2-HMAC-SHA1 runs on CPU 1 from the moment the
// credentials are read, while CPU 0 does esp_wifi_init / PHY calibration
// / STA start, and the driver gets the 64-hex-digit PSK instead of the
// passphrase: for a 64-character password wpa_set_passphrase takes
// hexstr2bin, no PBKDF2 (wpa.c; the blob's profile keeps the 64 bytes
// plus a terminator, libnet80211 wifi_nvs_validate_sta_password). Both
// paths store the result through the same call (esp_wifi_sta_update_ap_
// info_internal), so with WIFI_STORAGE_RAM nothing more reaches flash.
//
// Specialized for the PSK — passphrase 8..63 B (the HMAC key is never
// hashed first), SSID 1..32 B (U1's message fits one block), two output
// blocks — with the HMAC pad states computed once and every later block,
// a 20-B digest after a pad block, compressed by an unrolled SHA-1 whose
// constant message words the compiler folds away: 23.8 M instructions
// against the driver's 32.98 M (QEMU -icount, -Os as in the firmware;
// ≈ 115–120 ms at 240 MHz).
// tools/test/test_wifi_psk.c checks it against published vectors and a
// plain reference; tools/qemu_crypto runs that suite on the target and
// compares with the IDF's own pbkdf2_sha1 there. Every intermediate is
// scrubbed before return.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TL_PSK_PASS_MIN   8
#define TL_PSK_PASS_MAX   63     /* 64 = already a hex PSK, used as is */
#define TL_PSK_SSID_MAX   32
#define TL_PSK_LEN        32
#define TL_PSK_HEX_LEN    64
#define TL_PSK_ITER       4096

/* Zeroing the compiler may not drop (the buffers are dead afterwards). */
static void *(*const volatile tl_psk_memset)(void *, int, size_t) = memset;

static inline void tl_psk_scrub(void *p, size_t n)
{
    tl_psk_memset(p, 0, n);
}

/* ---- SHA-1 compression (FIPS 180-4 §6.1.2) ---------------------------- */

#define TL_SHA1_ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* One 64-B block given as 16 big-endian words; w is clobbered (the
 * message schedule runs in place). Rolled: it only takes the four blocks
 * per PSK that are not a digest (the two HMAC pads, U1's inner message). */
static __attribute__((noinline, unused)) void tl_sha1_compress(uint32_t st[5], uint32_t w[16])
{
    uint32_t a = st[0], b = st[1], c = st[2], d = st[3], e = st[4];
    for (unsigned i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i >= 16) {
            w[i & 15] = TL_SHA1_ROL(w[(i + 13) & 15] ^ w[(i + 8) & 15] ^
                                    w[(i + 2) & 15] ^ w[i & 15], 1);
        }
        if (i < 20)      { f = (b & (c ^ d)) ^ d;       k = 0x5A827999u; }
        else if (i < 40) { f = b ^ c ^ d;               k = 0x6ED9EBA1u; }
        else if (i < 60) { f = (b & c) | (d & (b | c)); k = 0x8F1BBCDCu; }
        else             { f = b ^ c ^ d;               k = 0xCA62C1D6u; }
        const uint32_t t = TL_SHA1_ROL(a, 5) + f + e + k + w[i & 15];
        e = d; d = c; c = TL_SHA1_ROL(b, 30); b = a; a = t;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d; st[4] += e;
}

/* st = the compression of `from` over m (5 words) ‖ 0x80 ‖ zeros ‖ the
 * bit length 672 — the second block of SHA-1(64-B pad block ‖ 20-B
 * digest), i.e. every HMAC block of the PBKDF2 loop. Unrolled, with the
 * eleven constant words spelled out so the compiler folds them into the
 * first rounds and schedule words (≈ 3.6 KB of code, one copy: not
 * inlined). w is the caller's scratch, scrubbed by the caller once its
 * loop is done. */
static __attribute__((noinline, unused)) void tl_sha1_compress20(uint32_t st[5],
                                                                 const uint32_t from[5],
                                                                 const uint32_t m[5],
                                                                 uint32_t w[16])
{
    w[0] = m[0]; w[1] = m[1]; w[2] = m[2]; w[3] = m[3]; w[4] = m[4];
    w[5] = 0x80000000u;
    w[6] = 0; w[7] = 0; w[8] = 0; w[9] = 0; w[10] = 0; w[11] = 0; w[12] = 0; w[13] = 0;
    w[14] = 0;
    w[15] = (64 + 20) * 8;
    uint32_t a = from[0], b = from[1], c = from[2], d = from[3], e = from[4];

#define TL_SHA1_W(i) (w[(i) & 15] = TL_SHA1_ROL(w[((i) + 13) & 15] ^ w[((i) + 8) & 15] ^ \
                                                w[((i) + 2) & 15] ^ w[(i) & 15], 1))
#define TL_SHA1_R(v, x, y, z, u, f, k, wi) \
    u += (f) + (wi) + (k) + TL_SHA1_ROL(v, 5); x = TL_SHA1_ROL(x, 30);
#define TL_SHA1_F1(x, y, z) ((x & (y ^ z)) ^ z)
#define TL_SHA1_F2(x, y, z) (x ^ y ^ z)
#define TL_SHA1_F3(x, y, z) ((x & y) | (z & (x | y)))
#define TL_SHA1_R0(v, x, y, z, u, i) TL_SHA1_R(v, x, y, z, u, TL_SHA1_F1(x, y, z), 0x5A827999u, w[i])
#define TL_SHA1_R1(v, x, y, z, u, i) TL_SHA1_R(v, x, y, z, u, TL_SHA1_F1(x, y, z), 0x5A827999u, TL_SHA1_W(i))
#define TL_SHA1_R2(v, x, y, z, u, i) TL_SHA1_R(v, x, y, z, u, TL_SHA1_F2(x, y, z), 0x6ED9EBA1u, TL_SHA1_W(i))
#define TL_SHA1_R3(v, x, y, z, u, i) TL_SHA1_R(v, x, y, z, u, TL_SHA1_F3(x, y, z), 0x8F1BBCDCu, TL_SHA1_W(i))
#define TL_SHA1_R4(v, x, y, z, u, i) TL_SHA1_R(v, x, y, z, u, TL_SHA1_F2(x, y, z), 0xCA62C1D6u, TL_SHA1_W(i))
/* Five rounds rotate the five variables back into place. */
#define TL_SHA1_5(R, i) \
    R(a, b, c, d, e, (i)) R(e, a, b, c, d, (i) + 1) R(d, e, a, b, c, (i) + 2) \
    R(c, d, e, a, b, (i) + 3) R(b, c, d, e, a, (i) + 4)

    TL_SHA1_5(TL_SHA1_R0, 0)  TL_SHA1_5(TL_SHA1_R0, 5)  TL_SHA1_5(TL_SHA1_R0, 10)
    TL_SHA1_R0(a, b, c, d, e, 15)
    TL_SHA1_R1(e, a, b, c, d, 16) TL_SHA1_R1(d, e, a, b, c, 17) TL_SHA1_R1(c, d, e, a, b, 18)
    TL_SHA1_R1(b, c, d, e, a, 19)
    TL_SHA1_5(TL_SHA1_R2, 20) TL_SHA1_5(TL_SHA1_R2, 25) TL_SHA1_5(TL_SHA1_R2, 30)
    TL_SHA1_5(TL_SHA1_R2, 35)
    TL_SHA1_5(TL_SHA1_R3, 40) TL_SHA1_5(TL_SHA1_R3, 45) TL_SHA1_5(TL_SHA1_R3, 50)
    TL_SHA1_5(TL_SHA1_R3, 55)
    TL_SHA1_5(TL_SHA1_R4, 60) TL_SHA1_5(TL_SHA1_R4, 65) TL_SHA1_5(TL_SHA1_R4, 70)
    TL_SHA1_5(TL_SHA1_R4, 75)

#undef TL_SHA1_5
#undef TL_SHA1_R4
#undef TL_SHA1_R3
#undef TL_SHA1_R2
#undef TL_SHA1_R1
#undef TL_SHA1_R0
#undef TL_SHA1_F3
#undef TL_SHA1_F2
#undef TL_SHA1_F1
#undef TL_SHA1_R
#undef TL_SHA1_W

    st[0] = from[0] + a; st[1] = from[1] + b; st[2] = from[2] + c;
    st[3] = from[3] + d; st[4] = from[4] + e;
}

static inline void tl_sha1_iv(uint32_t st[5])
{
    st[0] = 0x67452301u; st[1] = 0xEFCDAB89u; st[2] = 0x98BADCFEu;
    st[3] = 0x10325476u; st[4] = 0xC3D2E1F0u;
}

/* ---- PBKDF2-HMAC-SHA1 for the 802.11 PSK ------------------------------ */

static inline bool tl_psk_inputs_ok(size_t pass_len, size_t ssid_len)
{
    return pass_len >= TL_PSK_PASS_MIN && pass_len <= TL_PSK_PASS_MAX &&
           ssid_len >= 1 && ssid_len <= TL_PSK_SSID_MAX;
}

/* Big-endian words of `n` bytes (zero-padded to the word) into w. */
static inline void tl_psk_load(uint32_t *w, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        w[i >> 2] |= (uint32_t)b[i] << (24 - 8 * (i & 3));
    }
}

/* T_i of PBKDF2 (RFC 8018 §5.2) with the HMAC key states precomputed:
 * U1 = HMAC(P, S ‖ INT(i)), U_j = HMAC(P, U_{j-1}), T = U1 ^ … ^ U4096. */
static inline void tl_psk_block(const uint32_t ist[5], const uint32_t ost[5],
                                const uint8_t *ssid, size_t ssid_len, uint32_t idx,
                                uint32_t t[5])
{
    uint32_t w[16], st[5], u[5];

    /* U1, inner: S ‖ INT(i) after the ipad block — one block for S ≤ 51 B. */
    memset(w, 0, sizeof(w));
    tl_psk_load(w, ssid, ssid_len);
    const uint8_t tail[5] = { (uint8_t)(idx >> 24), (uint8_t)(idx >> 16),
                              (uint8_t)(idx >> 8), (uint8_t)idx, 0x80 };
    for (size_t i = 0; i < sizeof(tail); i++) {
        const size_t p = ssid_len + i;
        w[p >> 2] |= (uint32_t)tail[i] << (24 - 8 * (p & 3));
    }
    w[15] = (uint32_t)(64 + ssid_len + 4) * 8;
    memcpy(st, ist, sizeof(st));
    tl_sha1_compress(st, w);

    /* Every later message is a 20-B digest after a pad block. */
    tl_sha1_compress20(u, ost, st, w);                     /* U1, outer */
    memcpy(t, u, sizeof(u));
    for (unsigned j = 1; j < TL_PSK_ITER; j++) {
        tl_sha1_compress20(st, ist, u, w);                 /* inner */
        tl_sha1_compress20(u, ost, st, w);                 /* outer */
        t[0] ^= u[0]; t[1] ^= u[1]; t[2] ^= u[2]; t[3] ^= u[3]; t[4] ^= u[4];
    }

    tl_psk_scrub(w, sizeof(w));
    tl_psk_scrub(st, sizeof(st));
    tl_psk_scrub(u, sizeof(u));
}

/* PMK = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 32) (IEEE 802.11-2020
 * J.4.1). False (pmk untouched) when the inputs are not a passphrase /
 * SSID the driver would run PBKDF2 on. */
static inline bool tl_psk_derive(const uint8_t *pass, size_t pass_len, const uint8_t *ssid,
                                 size_t ssid_len, uint8_t pmk[TL_PSK_LEN])
{
    if (pass == NULL || ssid == NULL || !tl_psk_inputs_ok(pass_len, ssid_len)) return false;
    uint32_t w[16], ist[5], ost[5], t[10];

    /* The HMAC key states: K ⊕ ipad, K ⊕ opad, one compression each. */
    memset(w, 0, sizeof(w));
    tl_psk_load(w, pass, pass_len);
    for (unsigned i = 0; i < 16; i++) w[i] ^= 0x36363636u;
    tl_sha1_iv(ist);
    tl_sha1_compress(ist, w);
    memset(w, 0, sizeof(w));
    tl_psk_load(w, pass, pass_len);
    for (unsigned i = 0; i < 16; i++) w[i] ^= 0x5C5C5C5Cu;
    tl_sha1_iv(ost);
    tl_sha1_compress(ost, w);

    tl_psk_block(ist, ost, ssid, ssid_len, 1, t);
    tl_psk_block(ist, ost, ssid, ssid_len, 2, t + 5);
    for (unsigned i = 0; i < TL_PSK_LEN; i++) {
        pmk[i] = (uint8_t)(t[i >> 2] >> (24 - 8 * (i & 3)));
    }

    tl_psk_scrub(w, sizeof(w));
    tl_psk_scrub(ist, sizeof(ist));
    tl_psk_scrub(ost, sizeof(ost));
    tl_psk_scrub(t, sizeof(t));
    return true;
}

/* The 64 lowercase hex digits wifi_sta_config_t.password takes as a PSK
 * (exactly 64 bytes, no terminator — the field is 64 bytes long). */
static inline void tl_psk_hex(const uint8_t pmk[TL_PSK_LEN], char hex[TL_PSK_HEX_LEN])
{
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < TL_PSK_LEN; i++) {
        hex[2 * i]     = digits[pmk[i] >> 4];
        hex[2 * i + 1] = digits[pmk[i] & 15];
    }
}

/* ---- Hand-off between the deriving task and the connect --------------- */

/* Exactly one side ends up owning the result, whichever finishes first:
 * the deriving task publishes it (RUNNING → READY) only while the
 * consumer still waits, the consumer takes it (anything → DONE) and owns
 * it only if it was READY. The side that does not own it scrubs it. */
enum { TL_PSK_IDLE, TL_PSK_RUNNING, TL_PSK_READY, TL_PSK_DONE };

/* Deriving task, result written: true = handed over; false = the
 * consumer gave up first — scrub the result. */
static inline bool tl_psk_publish(uint32_t *state)
{
    uint32_t expect = TL_PSK_RUNNING;
    return __atomic_compare_exchange_n(state, &expect, TL_PSK_READY, false,
                                       __ATOMIC_RELEASE, __ATOMIC_RELAXED);
}

/* Consumer, once: true = the result is ready and now its own; false =
 * none (nothing started, still running — the task scrubs it —, or
 * already taken). */
static inline bool tl_psk_claim(uint32_t *state)
{
    return __atomic_exchange_n(state, TL_PSK_DONE, __ATOMIC_ACQ_REL) == TL_PSK_READY;
}

#ifdef __cplusplus
}
#endif
