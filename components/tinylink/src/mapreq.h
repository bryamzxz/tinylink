// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// MapRequest / MapResponse over the Noise+HTTP/2 control channel. M2
// scaffolding only: one-shot non-streaming round-trip suitable for
// bootstrapping `tl_netmap_t`. The long-lived `Stream: true` form lands
// alongside the WireGuard data plane in the next M2 commit, since
// keep-alive scheduling only matters once a peer is actually being
// pinged.
//
// Wire format and field semantics: see
// `tailscale/tailcfg/tailcfg.go` (`MapRequest`, `MapResponse`, `Node`,
// `DERPMap`). Compress is intentionally left empty so the server does
// not zstd the body — see docs/ROADMAP.md §M2 for the flash budget
// rationale.

#pragma once

#include "netmap.h"

#ifdef ESP_PLATFORM
#include "esp_err.h"
#include "ts2021_client.h"
#include "tinylink.h"
#else
/* Host-side compile (parser KAT) — no ESP-IDF available. Provide the
 * subset of esp_err symbols mapreq.c references. Values match the
 * ESP-IDF originals so error returns are still recognizable in tests. */
typedef int esp_err_t;
#define ESP_OK                   0
#define ESP_FAIL                 -1
#define ESP_ERR_INVALID_ARG      0x102
#define ESP_ERR_INVALID_SIZE     0x104
#define ESP_ERR_INVALID_RESPONSE 0x108
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ESP_PLATFORM
/* POST /machine/map with `Stream:false`, parse the single MapResponse the
 * server returns, and fill `out`. The HTTP/2 stream is closed by the
 * server after the single message in non-stream mode. */
esp_err_t mapreq_fetch_once(ts2021_conn_t *conn,
                            const tinylink_keys_t *keys,
                            tl_netmap_t *out);
#endif

/* Internal — exposed for host-side KAT. Parses the JSON body of one
 * MapResponse into `out`. */
esp_err_t mapresp_parse(const char *json, size_t json_len, tl_netmap_t *out);

#ifdef __cplusplus
}
#endif
