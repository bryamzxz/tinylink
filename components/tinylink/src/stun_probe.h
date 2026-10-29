// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// STUN probe support around the codec (stun.{c,h}): resolving the
// configured STUN server, and the result type the probes publish.
//
// The device's public-side AddrPort is learnt at boot (tinylink.c, the
// boot probe, on its own task since round 1.3.5) and re-learnt by the
// periodic re-probe through wg_rx; both probe through the WireGuard
// socket and their result is uploaded to the Tailscale control plane via
// the Hostinfo.Endpoints field of the lite MapRequest, so peers learn the
// reflexive endpoint they can try to dial directly. Without this, the
// control plane only sees the LAN-internal endpoints magicsock would
// have probed via STUN — which is what we just did, only on-device.
//
// This module needs lwIP and is therefore NOT host-testable; the wire
// codec it depends on (stun.{c,h}), including the answer matching both
// probes share (stun_match_v4), IS — test_stun.c.

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

struct sockaddr_in;

/* Resolve the STUN server to an IPv4 sockaddr (getaddrinfo, AF_INET).
 * Blocks for the lwIP DNS lookup — up to ~24 s against dead resolvers
 * (1+1+2+3 s x 3 servers) — and touches no socket of the caller's, so
 * the boot probe runs it before it claims the WG socket (round 1.3.5,
 * stun_boot.h). Logs a failure. */
esp_err_t stun_probe_resolve(const char *server_host, uint16_t server_port,
                             struct sockaddr_in *out);

#ifdef __cplusplus
}
#endif
