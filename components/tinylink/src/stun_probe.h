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


/* Run a single RFC 5389 binding probe over an externally-managed UDP
 * socket. The socket MUST be AF_INET
 * SOCK_DGRAM, already bound. The caller retains ownership — this
 * function does not close it. The recv timeout is set on the socket
 * for the duration of the call (and left set; callers that need a
 * different timeout afterwards must restore it). Used at boot to
 * probe through the WireGuard socket so the public AddrPort the
 * server returns matches the NAT mapping the WG keepalives keep
 * alive — peers dialing that AddrPort actually reach the WG socket. */
esp_err_t stun_probe_run_on_socket(int sock,
                                   const char *server_host,
                                   uint16_t server_port,
                                   uint32_t timeout_ms,
                                   stun_probe_result_t *out);

#ifdef __cplusplus
}
#endif
