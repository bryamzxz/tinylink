// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Placement attribute for the per-packet crypto hot path. With
// CONFIG_TINYLINK_CRYPTO_IN_IRAM the ChaCha20 / Poly1305 / AEAD glue live
// in IRAM (3.6 KiB of the ~56 KiB unused), so a packet that arrives after
// TLS / WiFi code evicted them from the 32 KiB flash cache does not pay
// ~225 CPU cycles per 32-byte line to refill. Off by default; decide
// with the cold numbers of CONFIG_TINYLINK_BENCH_AEAD. Host builds: no-op.

#pragma once

#ifdef ESP_PLATFORM
#include "sdkconfig.h"   /* the CONFIG_ macro is not visible otherwise — the
                          * first M16 build silently left chacha20/poly1305 in
                          * flash and only the AEAD glue moved (linker map) */
#endif

#if defined(ESP_PLATFORM) && defined(CONFIG_TINYLINK_CRYPTO_IN_IRAM) && CONFIG_TINYLINK_CRYPTO_IN_IRAM
#include "esp_attr.h"
#define TL_HOT_ATTR IRAM_ATTR
#else
#define TL_HOT_ATTR
#endif
