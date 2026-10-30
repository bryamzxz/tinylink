// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Telemetry task ("tinylink_tlm"): every CONFIG_TINYLINK_TELEMETRY_PERIOD_MS,
// read the TMP117 and push a JSON sample over UDP to the configured
// destination, and answer /stats queries in between. Sized for the M3
// demo: a single sensor → home-node datagram path over the WG netif.
// There is no retransmit, no ack — UDP is fire-and-forget on purpose;
// the home-side collector is expected to handle dedup if needed.
//
// Since 1.3.2 the same task also runs the periodic STUN re-probe
// (tinylink_stun_reprobe_poll, formerly its own 3 KiB task) and the 60-s
// housekeeping (stack diag, NVS time floor, since 1.3.5 the address
// cache, since 1.3.7 the application's tinylink_set_persist_hook — the
// Wi-Fi association hint), so it exists in every build: with
// CONFIG_TINYLINK_TELEMETRY_ENABLE=n it does only those.

#pragma once

#ifdef ESP_PLATFORM

#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Spawn the task if it isn't running. Idempotent and safe from several
 * tasks at once; on NO_MEM it retries every 30 s from an esp_timer and
 * still returns ESP_OK (the loop *will* run). Called from
 * tinylink_stun_reprobe_start at the end of bringup. */
esp_err_t telemetry_task_start(void);

/* The WG netif is up: start sampling (spawns the task if needed). Called
 * from the long-poll handler on the first netmap, so nothing is sent to
 * a 100.64.x.y destination before the tunnel's route exists. */
esp_err_t telemetry_start(void);

/* Wake the task's wait early (STUN re-probe requested). Any context
 * except ISRs; a no-op before the task exists. */
void telemetry_kick(void);

/* Provided by tinylink.c: run the STUN re-probe if it is due within
 * early_us (it then shares a sample's wake, tlm_sched.h) or was
 * requested, and return when the next one is due (esp_timer µs;
 * INT64_MAX while tinylink_stun_reprobe_start hasn't armed it). Called
 * only from the telemetry task; may block for one probe. */
int64_t tinylink_stun_reprobe_poll(int64_t now_us, int64_t early_us);

/* Provided by tinylink.c: write the address-cache records (tl_addr.h)
 * whose bytes changed to NVS. Called only from the 60-s housekeeping,
 * so an NVS write never lands on the boot path. */
void tinylink_addr_persist_poll(void);

/* Provided by tinylink.c (round 1.3.9, tl_warm.h): write the warm-start
 * record when it changed enough (at most hourly for endpoints / DiscoKey
 * alone), and end a warm start no netmap confirmed within
 * CONFIG_TINYLINK_WARM_START_MAX_S (erase, restart). 60-s housekeeping
 * only; a no-op without CONFIG_TINYLINK_WARM_START. */
void tinylink_warm_persist_poll(void);

#ifdef __cplusplus
}
#endif

#endif /* ESP_PLATFORM */
