/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host-only stand-in for mbedtls/x509.h: the verify-result bit tls_offer.c
 * tests (round 1.3.8; value as in mbedTLS 3.6). */
#pragma once

#define MBEDTLS_X509_BADCERT_NOT_TRUSTED   0x08
#define MBEDTLS_X509_BADCERT_CN_MISMATCH   0x04
#define MBEDTLS_X509_BADCERT_EXPIRED       0x01
