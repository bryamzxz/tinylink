// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// mbedTLS user configuration (MBEDTLS_USER_CONFIG_FILE) — round 1.3.2.
//
// Removes mbedTLS features that ESP-IDF's port/include/mbedtls/esp_config.h
// turns on unconditionally (no Kconfig exists for them) and that nothing in
// this firmware uses. Each #undef was checked against every caller in
// ESP-IDF v5.5.6 + managed_components + this repo.
//
// How it is applied: the top-level CMakeLists.txt adds
// MBEDTLS_USER_CONFIG_FILE="<project>/mbedtls_user_config.h" to the build's
// global COMPILE_DEFINITIONS, so every translation unit of every component
// (and mbedTLS's own mbedtls / mbedx509 / mbedcrypto targets) sees the
// same value. That matters: a TU that included mbedTLS headers without it
// would compile a different configuration, and any struct whose layout
// depends on a removed option would differ between TUs. (None of the
// options below changes a public struct in this build — the
// mbedtls_block_cipher_context_t union that embeds the ARIA context only
// exists with MBEDTLS_BLOCK_CIPHER_C, which is off here, and PKCS7 padding
// keeps MBEDTLS_CIPHER_MODE_WITH_PADDING, which sizes
// mbedtls_cipher_context_t — but the rule holds by construction anyway.)
// esp_config.h includes this file at its end and build_info.h includes it
// again after that; #undef is idempotent, so the double inclusion is
// harmless.
//
// Stays, deliberately (both verified by compiling / linking without it):
//   MBEDTLS_CIPHER_MODE_XTS  — nvs_flash builds src/nvs_encrypted_partition.cpp
//                              for every non-Linux target whether or not
//                              CONFIG_NVS_ENCRYPTION is set (it is off
//                              here); the class holds mbedtls_aes_xts_context
//                              members, so the build breaks without XTS, and
//                              esp_aes_xts_init/setkey are linked today.
//   MBEDTLS_PKCS5_C          — WPA2-PSK passphrase -> PMK: the supplicant's
//                              pbkdf2_sha1() (crypto_mbedtls.c) calls
//                              mbedtls_pkcs5_pbkdf2_hmac_ext(), linked today.
//   MBEDTLS_CIPHER_PADDING_PKCS7 — the cipher layer's default padding;
//                              keeps MBEDTLS_CIPHER_MODE_WITH_PADDING.

#pragma once

// ARIA block cipher: no TLS peer of this firmware negotiates ARIA suites
// (Go crypto/tls has none); cipher_wrap.c still linked mbedtls_aria_* and
// the four 256-byte S-boxes. CAMELLIA is already #undef'd by esp_config.h.
#undef MBEDTLS_ARIA_C

// CFB / OFB block modes: TLS uses GCM only (and CBC is not negotiated);
// the only callers in IDF are the ESP32-C5/C6/H2 TEE secure services.
#undef MBEDTLS_CIPHER_MODE_CFB
#undef MBEDTLS_CIPHER_MODE_OFB

// Cipher-layer paddings other than PKCS#7: the only callers of
// mbedtls_cipher_set_padding_mode() in IDF (wpa_supplicant, lwIP SNMPv3)
// select MBEDTLS_PADDING_NONE.
#undef MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS
#undef MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN
#undef MBEDTLS_CIPHER_PADDING_ZEROS

// PKCS#12 (password-based encryption of PKCS#8 keys / PFX files): the
// firmware parses no private keys at all (TLS is server-auth only, the
// bundle is DER certificates).
#undef MBEDTLS_PKCS12_C
