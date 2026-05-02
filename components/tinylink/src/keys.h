// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include "esp_err.h"

#include "tinylink.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Load the three Curve25519 identities from NVS namespace "tl_keys".
 * On first boot (no entry found) generate fresh keypairs, persist them,
 * and log "generated new node identity". */
esp_err_t keys_load_or_generate(tinylink_keys_t *out);

#ifdef __cplusplus
}
#endif
