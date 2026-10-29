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
// *by construction*.
//
// One implementation for the firmware and the host KATs (round 1.3.2; it
// used to be mbedtls_platform_zeroize() on ESP-IDF): memset followed by an
// empty asm statement that takes the buffer address as an input and
// clobbers "memory" — the barrier_data() idiom of Linux's
// memzero_explicit(). The compiler must assume the asm reads every byte
// of *buf, so the stores before it are live and stay, across inlining and
// LTO alike; the asm itself emits no instruction.
//
// Why not mbedtls_platform_zeroize: it is an out-of-line call into flash
// (mbedcrypto's platform_util.c), made 2–3 times per WireGuard packet by
// the IRAM AEAD — a cache miss on every cold packet. Inlined, the scrub
// lives wherever its caller lives (IRAM for TL_HOT_ATTR code): GCC
// expands a small constant-size memset into word stores, larger or
// variable ones call newlib's memset, which the ESP32 runs from mask ROM
// (esp32.rom.libc-funcs.ld) — never from flash.

#pragma once

#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline __attribute__((always_inline))
void tl_secure_zero(void *buf, size_t len)
{
    memset(buf, 0, len);
    __asm__ __volatile__("" : : "r"(buf) : "memory");
}

#ifdef __cplusplus
}
#endif
