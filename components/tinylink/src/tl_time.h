// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Wall clock for TLS certificate validation (M16, 2026-09).
//
// Until now CONFIG_MBEDTLS_HAVE_TIME_DATE was off: none of the TLS
// clients (control plane, DERP, /key bootstrap) ever checked a
// certificate's notBefore / notAfter, because the ESP32 boots at
// 1970 and has no NTP. Enabling the check naively would fail every
// handshake until the clock is set — and an offline boot must not
// brick.
//
// Design:
//   1. tl_time_init() floors the system clock at boot to
//      max(build epoch, last persisted NTP time). Both are <= real time
//      by construction, so certs valid "now" cannot look expired; a cert
//      issued after the floor may look "not yet valid".
//   2. tl_time_start_sntp() runs SNTP (lwIP) once WiFi has an address;
//      the sync callback flips s_synced and the telemetry task persists
//      the time to NVS (tl_state:time_floor) via tl_time_poll_persist(),
//      at most hourly, so the floor advances across reboots.
//   3. tl_crt_bundle_attach() wraps esp_crt_bundle_attach(): while the
//      clock is NOT NTP-synced, BADCERT_FUTURE / BADCERT_EXPIRED are
//      cleared before the bundle's own callback runs (which only acts on
//      a bare NOT_TRUSTED flag), i.e. exactly today's "no date check"
//      behaviour — for the first handshakes of a boot only. Once synced,
//      dates are enforced on every handshake.
// Host builds compile nothing from here (all ESP_PLATFORM).

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Floor the clock (build epoch / persisted). Call before the first TLS
 * handshake; idempotent. Never fails hard (NVS trouble = build floor). */
esp_err_t tl_time_init(void);

/* Start SNTP against CONFIG_TINYLINK_SNTP_SERVER. Call once WiFi has an
 * IP; idempotent. */
esp_err_t tl_time_start_sntp(void);

/* True once at least one SNTP sync landed this boot. */
bool tl_time_synced(void);

/* Persist the synced time as the next boot's floor when due (hourly).
 * Cheap when nothing is pending; call from a task with stack to spare
 * (the telemetry task), never from the SNTP callback (lwIP context). */
void tl_time_poll_persist(void);

/* Drop-in for esp_tls_cfg_t / esp_http_client_config_t .crt_bundle_attach:
 * the IDF bundle plus the date-tolerance-until-synced verify callback. */
esp_err_t tl_crt_bundle_attach(void *conf);

#ifdef __cplusplus
}
#endif
