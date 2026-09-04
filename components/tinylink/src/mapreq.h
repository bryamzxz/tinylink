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
#define ESP_ERR_NO_MEM           0x101
#define ESP_ERR_INVALID_ARG      0x102
#define ESP_ERR_INVALID_SIZE     0x104
#define ESP_ERR_INVALID_RESPONSE 0x108
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ESP_PLATFORM
/* Lite endpoint update: POST /machine/map with `Stream:false` AND
 * `OmitPeers:true`. Per upstream
 * tailscale/control/controlclient/auto.go:249-251, this is the only
 * MapRequest shape the modern (CapVer >= 68) control plane treats as
 * a writable Hostinfo / NetInfo / Endpoints push. The server is
 * documented to be allowed to omit the response body entirely; we
 * only inspect the HTTP status code. After this returns ESP_OK,
 * peers receiving fresh MapResponses will see our top-level
 * Endpoints (and their `Addrs` field is no longer null). */
esp_err_t mapreq_push_endpoints(ts2021_conn_t *conn,
                                const tinylink_keys_t *keys);

/* Long-poll variant. POSTs `/machine/map` with `Stream:true`; the server
 * replies with a sequence of length-prefixed (LE32) MapResponse JSON
 * objects on the same HTTP/2 stream and keeps the connection open. The
 * function blocks for the lifetime of the stream and invokes `on_netmap`
 * once per non-KeepAlive MapResponse, with a parsed `tl_netmap_t`.
 * Server-initiated `KeepAlive:true` messages are silently absorbed.
 *
 * Returns when the stream closes (server EOF or transport error). The
 * caller is expected to retry on a slow cadence.
 */
typedef esp_err_t (*mapreq_handler_t)(const tl_netmap_t *nm, void *ctx);

esp_err_t mapreq_run_stream(ts2021_conn_t *conn,
                            const tinylink_keys_t *keys,
                            mapreq_handler_t on_netmap, void *ctx);
#endif

/* Internal — exposed for host-side KAT. Parses the JSON body of one
 * MapResponse into `out`. */
esp_err_t mapresp_parse(const char *json, size_t json_len, tl_netmap_t *out);

#ifdef __cplusplus
}
#endif
