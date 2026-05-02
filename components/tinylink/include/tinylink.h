// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TINYLINK_VERSION_MAJOR 0
#define TINYLINK_VERSION_MINOR 0
#define TINYLINK_VERSION_PATCH 1

const char *tinylink_version_string(void);

/* ----------------------------------------------------------------------- */
/* Milestone 2 — ts2021 Noise IK over HTTP/2 inside TLS to control plane.  */
/* ----------------------------------------------------------------------- */

typedef struct tinylink_ts2021_ctx tinylink_ts2021_ctx_t;

esp_err_t tinylink_ts2021_handshake(tinylink_ts2021_ctx_t *ctx);

/* ----------------------------------------------------------------------- */
/* Milestone 3 — MapResponse parsing.                                       */
/* ----------------------------------------------------------------------- */

typedef struct tinylink_map_response tinylink_map_response_t;

esp_err_t tinylink_map_response_parse(const uint8_t *buf, size_t len,
                                      tinylink_map_response_t *out);

/* ----------------------------------------------------------------------- */
/* Milestone 4 — DISCO P2P discovery (NaCl-box on the WG UDP socket).       */
/* ----------------------------------------------------------------------- */

typedef struct tinylink_disco_ctx tinylink_disco_ctx_t;

esp_err_t tinylink_disco_send_ping(tinylink_disco_ctx_t *ctx);

/* ----------------------------------------------------------------------- */
/* Milestone 5 — DERP relay fallback.                                       */
/* ----------------------------------------------------------------------- */

typedef struct tinylink_derp_ctx tinylink_derp_ctx_t;

esp_err_t tinylink_derp_connect(tinylink_derp_ctx_t *ctx, const char *region);

/* ----------------------------------------------------------------------- */
/* Milestone 6 — Production hardening (rate-limit, replay, key rotation).   */
/* ----------------------------------------------------------------------- */

esp_err_t tinylink_harden_apply_defaults(void);

#ifdef __cplusplus
}
#endif
