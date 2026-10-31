// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Placement attribute for the per-packet crypto hot path. With
// CONFIG_TINYLINK_CRYPTO_IN_IRAM the ChaCha20 / Poly1305 / AEAD glue live
// in IRAM (≈4.3 KiB of the ~56 KiB unused; 1.3.3's ChaCha20 is 0.8 KiB
// larger), so a packet that arrives after TLS / WiFi code evicted them
// from the 32 KiB flash cache does not pay ~225 CPU cycles per 32-byte
// line to refill. On by default since the cold numbers of
// CONFIG_TINYLINK_BENCH_AEAD (Kconfig help); the Noise (ts2021) records
// share the same AEAD since 1.3.2. Host builds: no-op.

#pragma once

#ifdef ESP_PLATFORM
#include "sdkconfig.h"   /* the CONFIG_ macro is not visible otherwise — the
                          * first M16 build silently left chacha20/poly1305 in
                          * flash and only the AEAD glue moved (linker map) */
#endif

/* TL_HOT_RODATA_ATTR is the data-side counterpart for the small
 * constant tables the hot path reads (the AEAD's zero pad): DRAM instead
 * of flash .rodata, which is reached through the same flash cache. */
#if defined(ESP_PLATFORM) && defined(CONFIG_TINYLINK_CRYPTO_IN_IRAM) && CONFIG_TINYLINK_CRYPTO_IN_IRAM
#include "esp_attr.h"
#define TL_HOT_ATTR        IRAM_ATTR
#define TL_HOT_RODATA_ATTR DRAM_ATTR
#else
#define TL_HOT_ATTR
#define TL_HOT_RODATA_ATTR
#endif
