// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Opt-in micro-benchmarks for ChaCha20-Poly1305 AEAD and X25519. Used as
// the baseline against which crypto changes are measured. Built only
// when CONFIG_TINYLINK_BENCH_AEAD=y; the symbols are otherwise absent.

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

#ifdef __cplusplus
}
#endif
