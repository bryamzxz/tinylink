// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Guaranteed secret scrubbing that survives dead-store elimination (CWE-14).
//
// Plain memset() of a stack buffer that is never read again before the
// function returns is a candidate for dead-store elimination. Empirically
// the production toolchain (xtensa-esp32-elf-gcc 14.2, -O2 + per-component
// perf-trim) does NOT eliminate the AEAD scrubs today — the secret buffers'
// addresses escape to out-of-TU crypto helpers, which defeats GCC's escape
// analysis — but that guarantee is *incidental*, not enforced. Project-wide
// LTO, a single-TU refactor that inlines the helpers, or a future toolchain
// could silently drop the scrub. tl_secure_zero() makes the guarantee hold
// *by construction* on both targets.
//
//   - ESP-IDF: mbedtls_platform_zeroize(), the same barrier-backed primitive
//     tinylink.c already uses for the auth key.
//   - Host KAT build (no ESP_PLATFORM): a volatile indirect call to memset
//     that the optimizer must treat as opaque — no mbedtls dependency, so the
//     vendored-crypto host tests link with stock gcc unchanged.

#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ESP_PLATFORM

#include "mbedtls/platform_util.h"

static inline void tl_secure_zero(void *buf, size_t len)
{
    mbedtls_platform_zeroize(buf, len);
}

#else  /* host build */

#include <string.h>

static inline void tl_secure_zero(void *buf, size_t len)
{
    /* The volatile function pointer forces the compiler to emit the call:
     * it cannot prove the indirect target is a no-op, so the store survives
     * regardless of whether the buffer is read afterwards. */
    static void *(*const volatile vmemset)(void *, int, size_t) = memset;
    vmemset(buf, 0, len);
}

#endif

#ifdef __cplusplus
}
#endif
