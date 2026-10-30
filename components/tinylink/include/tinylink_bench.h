// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Opt-in micro-benchmarks for ChaCha20-Poly1305 AEAD and X25519
// (CONFIG_TINYLINK_BENCH_AEAD) and the TLS handshake crypto
// (CONFIG_TINYLINK_BENCH_TLS). Used as the baseline against which crypto
// changes are measured; the symbols are absent unless enabled.

#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#if CONFIG_TINYLINK_BENCH_AEAD

/* Run encrypt + decrypt loops over fixed payloads, log timings, and
 * verify round-trip correctness. Returns ESP_OK on success, ESP_FAIL
 * if the round-trip mismatched (which would invalidate any timing). */
esp_err_t tinylink_bench_aead(void);

/* X25519: RFC 7748 KAT, µs per scalarmult, CCOUNT spread over inputs.
 * ESP_FAIL if the KAT mismatched. */
esp_err_t tinylink_bench_x25519(void);

#endif /* CONFIG_TINYLINK_BENCH_AEAD */

#if CONFIG_TINYLINK_BENCH_TLS

/* TLS handshake crypto (round 1.3.8): ECDSA / RSA verifies of the
 * served chains, each chain through the bundle, ECDHE per group, with
 * this image's mbedTLS configuration (tinylink_bench_tls.c lists the
 * lines). ESP_FAIL if the vectors did not parse. */
esp_err_t tinylink_bench_tls(void);

#endif /* CONFIG_TINYLINK_BENCH_TLS */

#ifdef __cplusplus
}
#endif
