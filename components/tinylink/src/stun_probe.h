// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// One-shot STUN binding probe over UDP. Resolves the configured STUN
// server, sends a binding request built by stun_build_request(), and
// parses the XOR-MAPPED-ADDRESS response into a stun_probe_result_t.
//
// Used during boot (after WiFi up) to learn the device's public-side
// AddrPort. The result is uploaded to the Tailscale control plane via
// the Hostinfo.Endpoints field of every MapRequest, so peers learn the
// reflexive endpoint they can try to dial directly. Without this, the
// control plane only sees the LAN-internal endpoints magicsock would
// have probed via STUN — which is what we just did, only on-device.
//
// This module needs lwIP sockets and esp_random and is therefore NOT
// host-testable; the wire codec it depends on (stun.{c,h}) IS, with
// 102 host KATs (test_stun.c).

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool     valid;
    uint8_t  addr_v4[4];   /* public IPv4 (network byte order: a.b.c.d) */
    uint16_t port;         /* host byte order */
} stun_probe_result_t;

/* Run a single STUN binding probe. Resolves server_host, sends one
 * binding request, waits up to timeout_ms for a matching response,
 * parses it into out. Caller-owned out is set to {valid=false} on
 * any failure path (DNS, socket, send, recv timeout, txid mismatch,
 * malformed response).
 *
 * Returns ESP_OK only when out->valid is true. */
esp_err_t stun_probe_run(const char *server_host, uint16_t server_port,
                         uint32_t timeout_ms, stun_probe_result_t *out);

#ifdef __cplusplus
}
#endif
