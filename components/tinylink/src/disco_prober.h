// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// DISCO outbound prober + tx-id binding (M3 step 3).
//
// Outbound DISCO Pings (prepunch on netmap arrival, CMM-driven punches)
// are fire-and-forget at the network layer, but the *application* layer
// needs to correlate the resulting Pongs with their probes so that:
//
//   1. Only Pongs we actually solicited can roam the WG transport
//      endpoint (defeats a replay-of-captured-Pong-from-spoofed-AddrPort
//      attack without needing a separate replay window).
//
//   2. Late Pongs that arrive after the probe's logical timeout get
//      dropped silently rather than confusingly causing a roam.
//
// Models upstream tailscale `wgengine/magicsock/endpoint.go`:
//   - `endpoint.sentPing map[stun.TxID]sentPing` (endpoint.go:94)
//   - populated in `startDiscoPingLocked` with a 5-second timer
//     (endpoint.go:1338, pingTimeoutDuration at magicsock.go:3933)
//   - looked up in `handlePongConnLocked`; absent txid → return false →
//     no state change (endpoint.go:1712-1716).
//
// Table size: 16 slots. Each prepunch burst sends one ping per (peer,
// endpoint) pair — typical netmap has 1-3 peers × 2-4 endpoints = up to
// 12; CMM batches up to 8 endpoints; with 5 s timeout an in-flight pair
// peaks around ~12-16. 16 covers it comfortably; oldest entry is
// overwritten on overflow (consistent with upstream which also bounds
// the map indirectly via timer cleanup).
//
// Threading: single-writer / single-reader is the common case
// (supervisor task → wg_rx task). On ESP-IDF the table is protected by
// a portMUX_TYPE / taskENTER_CRITICAL pair so the supervisor's
// `record()` cannot tear a slot mid-update against the wg_rx's
// `match_and_remove()`. Host builds compile to no-op locks.
//
// Pure C codec — no I/O, no FreeRTOS dependencies at API level.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "disco.h"   /* DISCO_TXID_LEN */

#ifdef __cplusplus
extern "C" {
#endif

/* 16 entries × 32 B (padded) = 512 B BSS. */
#ifndef DISCO_PROBER_TABLE_SIZE
#define DISCO_PROBER_TABLE_SIZE 16
#endif

/* Entries older than this are considered expired and may be evicted
 * to make room for fresh records. Matches upstream tailscale
 * `pingTimeoutDuration = 5 * time.Second` (magicsock.go:3933). */
#ifndef DISCO_PROBER_TIMEOUT_MS
#define DISCO_PROBER_TIMEOUT_MS 5000
#endif

/* Initialise (zero the table, set up the lock). Idempotent. */
void disco_prober_init(void);

/* Record an outbound Ping that was just successfully sendto'd. Caller
 * should NOT call this if sendto failed — recording a never-actually-
 * sent probe wastes a slot and would lock out legitimate matches.
 *
 * dst_v4_be is the destination IPv4 address in network byte order.
 * dst_port is host order.
 * now_us is the monotonic time stamp (esp_timer_get_time() on ESP-IDF,
 * a deterministic counter on host tests). */
void disco_prober_record(const uint8_t txid[DISCO_TXID_LEN],
                         uint32_t dst_v4_be, uint16_t dst_port,
                         int64_t now_us);

/* Look up a Pong's txid in the table. If a matching outstanding probe
 * is found AND it has not yet expired, remove it and return true.
 * Otherwise return false (caller must drop the roam decision).
 *
 * now_us is used to enforce the timeout — a stale matching entry
 * returns false AND is cleared so a subsequent legitimate probe can
 * reuse the slot. */
bool disco_prober_match_and_remove(const uint8_t txid[DISCO_TXID_LEN],
                                   int64_t now_us);

/* Test helper: wipe the table. Production code never needs this
 * because boot-time disco_prober_init zeros the state. */
void disco_prober_reset(void);

#ifdef __cplusplus
}
#endif
