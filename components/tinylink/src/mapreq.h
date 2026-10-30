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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "jsmn_split.h"
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
 * `OmitPeers:true`. Since round 1.3.7 the long-poll sends it with the
 * stream request (mapreq_run_stream's push_status); this one-shot form
 * is the fallback for a server window it does not fit or a server that
 * allows one stream at a time. Per upstream
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
/* `on_netmap` returning MAPREQ_STREAM_RECYCLE ends the stream at once
 * (mapreq_run_stream returns an error and the caller reconnects or
 * re-registers); any other return value is ignored and the stream goes
 * on. Used for a self node that control marks expired/deleted. Outside
 * the ESP-IDF error ranges on purpose. */
#define MAPREQ_STREAM_RECYCLE ((esp_err_t)0x7e01)
typedef esp_err_t (*mapreq_handler_t)(const tl_netmap_t *nm, void *ctx);

/* push_status non-NULL: the endpoint push (mapreq_push_endpoints' lite
 * MapRequest) rides with the stream request as a second HTTP/2 stream,
 * in the same burst (round 1.3.7, B1) instead of a round trip of its
 * own before it. *push_status: 0 while unanswered, the push's HTTP
 * status once answered (logged then, mid-stream), -1 for a reset; only
 * 200 means pushed. The conn is under the one-shot request deadline
 * until the push is answered. */
esp_err_t mapreq_run_stream(ts2021_conn_t *conn,
                            const tinylink_keys_t *keys,
                            mapreq_handler_t on_netmap, void *ctx,
                            int *push_status);
#endif

/* ---- Streaming MapResponse parser (round 1.3.4, D2) -------------------
 *
 * The long-poll's frames are parsed as their bytes arrive instead of
 * being assembled whole (up to 32 KiB) first. The top-level object is
 * split on the fly; the values the data plane consumes — the self
 * `Node`, each `Peers` / `PeersChanged` / `PeersRemoved` /
 * `PeersChangedPatch` element, each `DERPMap.Regions` value — are copied
 * one at a time into a small element buffer and handed to the same
 * per-element jsmn parsers as before; everything else is scanned past
 * without being stored. The buffer therefore only has to hold the
 * largest single element. An element larger than it is skipped with a
 * logged error (a PeersChangedPatch entry raises patches_overflow
 * instead, as an unparseable one always did); the frame goes on and the
 * length prefix keeps the stream in sync either way.
 *
 * Results are those of the pre-1.3.4 parser (jsmn_split.h's iterators
 * over the whole body) for every input whose elements fit the buffer,
 * malformed ones included — the per-container extent scans reproduce how
 * that parser bounded each container (test_mapresp.c compares the two). */

#define MAPRESP_LEVELS  3     /* the top object, Peers*|DERPMap, DERPMap.Regions */
#define MAPRESP_KEY_MAX 20    /* longest key matched: "PeersChangedPatch" (17) */

typedef struct {
    uint8_t          role;    /* which container (mapreq.c MS_*) */
    uint8_t          g;       /* member-grammar state (mapreq.c G_*) */
    tl_jsplit_scan_t ext;     /* its extent as a whole-body split saw it */
} mapresp_level_t;

/* One MapResponse body being parsed. */
typedef struct {
    tl_netmap_t     *out;
    char            *elem;          /* element buffer */
    size_t           elem_cap;
    tl_jsplit_scan_t val;           /* the value being scanned */
    uint8_t          vact;          /* what it is for (mapreq.c MV_*) */
    size_t           vlen;          /* its bytes so far (stored up to vlim) */
    size_t           vlim;
    uint8_t          n;             /* open containers */
    mapresp_level_t  lvl[MAPRESP_LEVELS];
    uint8_t          key_len;       /* saturates at 255: no match */
    char             key[MAPRESP_KEY_MAX];
    unsigned         regions_seen;
    bool             done;          /* top-level object closed */
    esp_err_t        err;
    size_t           pos;           /* body bytes consumed */
    size_t           err_pos;
    /* Observability ("stream peak" / "mapresp peak"). */
    size_t           elem_peak;     /* largest element stored (or over the cap) */
    int              tok_peak;      /* largest jsmn sub-parse */
    unsigned         n_oversized;   /* elements skipped for size */
} mapresp_json_t;

void      mapresp_json_begin(mapresp_json_t *m, char *elem, size_t elem_cap,
                             tl_netmap_t *out);
void      mapresp_json_feed(mapresp_json_t *m, const char *data, size_t len);
/* After the body's last byte. ESP_OK = `out` holds the parsed frame;
 * ESP_ERR_INVALID_RESPONSE = malformed or truncated (err_pos), discard. */
esp_err_t mapresp_json_end(mapresp_json_t *m);

/* The long-poll framing, `LE32 size || body`, repeated. The size may be
 * split across DATA chunks at any byte, like the body. */
#define MAPRESP_FRAME_MAX (4u << 20)   /* see mapreq.c */

struct mapresp_stream;
/* Called once per frame after its last byte, with `json.out` filled in
 * when parse_err == ESP_OK. Non-zero stops the stream. */
typedef int (*mapresp_frame_fn)(const struct mapresp_stream *ms,
                                esp_err_t parse_err, void *ctx);

typedef struct mapresp_stream {
    uint8_t          hdr[4];
    uint8_t          hdr_have;
    bool             in_body;
    uint32_t         body_size;
    uint32_t         body_have;
    mapresp_json_t   json;
    char            *elem;
    size_t           elem_cap;
    tl_netmap_t     *nm;
    mapresp_frame_fn on_frame;
    void            *ctx;
} mapresp_stream_t;

void mapresp_stream_init(mapresp_stream_t *ms, char *elem, size_t elem_cap,
                         tl_netmap_t *nm, mapresp_frame_fn on_frame, void *ctx);
/* 0 = go on; -1 = stop (a frame over MAPRESP_FRAME_MAX, or on_frame). */
int  mapresp_stream_feed(mapresp_stream_t *ms, const uint8_t *data, size_t len);

#ifndef ESP_PLATFORM
/* Host KAT entry point: one whole MapResponse body through the streaming
 * parser, with an element buffer of the firmware's size
 * (TL_CTRL_MAPRESP_CAP). The firmware only uses the stream above. */
esp_err_t mapresp_parse(const char *json, size_t json_len, tl_netmap_t *out);
#endif

#ifdef __cplusplus
}
#endif
