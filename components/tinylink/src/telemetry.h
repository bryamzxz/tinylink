// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Telemetry task: every CONFIG_TINYLINK_TELEMETRY_PERIOD_MS, read the
// TMP117 and push a JSON sample over UDP to the configured destination.
// Sized for the M3 demo: a single sensor → home-node datagram path
// over the WG netif. There is no retransmit, no sequence number, no
// ack — UDP is fire-and-forget on purpose; the home-side collector is
// expected to handle dedup if needed.

#pragma once

#ifdef ESP_PLATFORM

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t telemetry_start(void);

#ifdef __cplusplus
}
#endif

#endif /* ESP_PLATFORM */
