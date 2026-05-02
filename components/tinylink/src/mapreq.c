// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "mapreq.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_system.h"
#include "sdkconfig.h"
#include "h2_client.h"
#endif

#define JSMN_STATIC
#include "jsmn.h"

#ifdef ESP_PLATFORM
static const char *TAG = "mapreq";
#endif

#define REQUEST_BUF_SZ   2048
/* Real Tailscale MapResponse for a small tailnet (sensor + home peer)
 * comfortably exceeds 16 KiB once DERP map + DNSConfig + the peer's
 * Hostinfo are folded in. Observed 16383-byte truncation on first HW
 * boot 2026-05-02. 48 KiB gives us headroom for a handful of peers
 * before we'd need streaming. */
#define RESPONSE_BUF_SZ  32768
/* MapResponse JSON is structurally dense: a 19 KiB body parses to
 * ~3500 tokens (~1 token / 5 bytes). 3500 + 12% headroom = 3920;
 * round to 3920 → 62.7 KiB BSS table at sizeof(jsmntok_t)=16. The
 * companion Tailscale-on-ESP32 protocol artifact recommends a 20 KiB
 * parse budget assuming SAX-style streaming, but we use jsmn (DOM-
 * style) which needs the full token table. 62 KiB is the smallest we
 * can go without truncating real netmaps observed on-device. */
#define MAX_TOKENS       3920

/* ------------------------------ helpers ----------------------------------- */

void tl_netmap_clear(tl_netmap_t *nm)
{
    if (nm == NULL) return;
    memset(nm, 0, sizeof(*nm));
}

static bool tok_is_str(const jsmntok_t *t)
{
    return t->type == JSMN_STRING;
}

static bool tok_is_obj(const jsmntok_t *t)
{
    return t->type == JSMN_OBJECT;
}

static bool tok_is_arr(const jsmntok_t *t)
{
    return t->type == JSMN_ARRAY;
}

static bool tok_eq(const char *js, const jsmntok_t *t, const char *s)
{
    size_t slen = strlen(s);
    int    tlen = t->end - t->start;
    return (tlen >= 0 && (size_t)tlen == slen &&
            strncmp(js + t->start, s, slen) == 0);
}

static int tok_copy(const char *js, const jsmntok_t *t,
                    char *out, size_t out_size)
{
    int n = t->end - t->start;
    if (n < 0 || (size_t)n + 1 > out_size) return -1;
    memcpy(out, js + t->start, (size_t)n);
    out[n] = '\0';
    return n;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

/* Parse "<prefix>:<64hex>" into a 32-byte raw key. */
static esp_err_t parse_keyed_hex(const char *s, size_t len,
                                 const char *prefix,
                                 uint8_t out[TINYLINK_KEY_LEN])
{
    size_t plen = strlen(prefix);
    if (len != plen + 64) return ESP_ERR_INVALID_ARG;
    if (memcmp(s, prefix, plen) != 0) return ESP_ERR_INVALID_ARG;
    for (size_t i = 0; i < 32; i++) {
        int hi = hex_nibble(s[plen + 2 * i]);
        int lo = hex_nibble(s[plen + 2 * i + 1]);
        if (hi < 0 || lo < 0) return ESP_ERR_INVALID_ARG;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return ESP_OK;
}

/* Walk forward from token index `i` past the entire subtree it describes,
 * returning the next sibling index. jsmn produces tokens in document order
 * with `size` = number of immediate children, so this is just a recursive
 * skip without re-parsing. */
static int skip_value(const jsmntok_t *toks, int i)
{
    int children = toks[i].size;
    int next = i + 1;
    if (toks[i].type == JSMN_OBJECT) {
        for (int k = 0; k < children; k++) {
            next = skip_value(toks, next);  /* key (string) */
            next = skip_value(toks, next);  /* value         */
        }
        return next;
    }
    if (toks[i].type == JSMN_ARRAY) {
        for (int k = 0; k < children; k++) {
            next = skip_value(toks, next);
        }
        return next;
    }
    return i + 1;
}

/* ------------------------------ parsers ----------------------------------- */

static esp_err_t parse_addresses(const char *js, const jsmntok_t *toks,
                                 int arr_idx,
                                 tl_cidr_t *out, size_t out_max,
                                 size_t *n_out)
{
    if (!tok_is_arr(&toks[arr_idx])) return ESP_ERR_INVALID_ARG;
    int n = toks[arr_idx].size;
    int next = arr_idx + 1;
    size_t kept = 0;
    for (int k = 0; k < n; k++) {
        if (tok_is_str(&toks[next]) && kept < out_max) {
            int slen = toks[next].end - toks[next].start;
            /* drop v6 — anything containing ':' is v6 in CIDR form */
            const char *s = js + toks[next].start;
            bool is_v6 = false;
            for (int i = 0; i < slen; i++) {
                if (s[i] == ':') { is_v6 = true; break; }
            }
            if (!is_v6) {
                if (tok_copy(js, &toks[next], out[kept].str,
                             sizeof(out[kept].str)) < 0) {
                    /* CIDR too long — skip silently */
                } else {
                    kept++;
                }
            }
        }
        next = skip_value(toks, next);
    }
    *n_out = kept;
    return ESP_OK;
}

static esp_err_t parse_endpoints(const char *js, const jsmntok_t *toks,
                                 int arr_idx,
                                 tl_endpoint_t *out, size_t out_max,
                                 size_t *n_out)
{
    if (!tok_is_arr(&toks[arr_idx])) return ESP_ERR_INVALID_ARG;
    int n = toks[arr_idx].size;
    int next = arr_idx + 1;
    size_t kept = 0;
    for (int k = 0; k < n; k++) {
        if (tok_is_str(&toks[next]) && kept < out_max) {
            int slen = toks[next].end - toks[next].start;
            const char *s = js + toks[next].start;
            /* "[v6]:port" or "v6%zone:port" → drop. v4 endpoints have
             * exactly one ':' separating addr and port. */
            int colons = 0;
            for (int i = 0; i < slen; i++) {
                if (s[i] == ':') colons++;
                if (s[i] == '[' || s[i] == ']') { colons = 99; break; }
            }
            if (colons == 1) {
                if (tok_copy(js, &toks[next], out[kept].str,
                             sizeof(out[kept].str)) >= 0) {
                    kept++;
                }
            }
        }
        next = skip_value(toks, next);
    }
    *n_out = kept;
    return ESP_OK;
}

static esp_err_t parse_node_obj(const char *js, const jsmntok_t *toks,
                                int obj_idx, tl_netmap_t *out)
{
    if (!tok_is_obj(&toks[obj_idx])) return ESP_ERR_INVALID_ARG;
    int n = toks[obj_idx].size;
    int next = obj_idx + 1;
    for (int k = 0; k < n; k++) {
        const jsmntok_t *key = &toks[next];
        int val_idx = next + 1;
        if (tok_eq(js, key, "ID") && toks[val_idx].type == JSMN_PRIMITIVE) {
            char buf[24];
            if (tok_copy(js, &toks[val_idx], buf, sizeof(buf)) > 0) {
                out->self_id = strtoull(buf, NULL, 10);
            }
        } else if (tok_eq(js, key, "Addresses") &&
                   tok_is_arr(&toks[val_idx])) {
            parse_addresses(js, toks, val_idx,
                            out->self_addresses, TL_MAX_PEER_ADDRESSES,
                            &out->n_self_addresses);
        }
        next = skip_value(toks, val_idx);
    }
    out->have_self = true;
    return ESP_OK;
}

static esp_err_t parse_one_peer(const char *js, const jsmntok_t *toks,
                                int obj_idx, tl_peer_t *peer)
{
    if (!tok_is_obj(&toks[obj_idx])) return ESP_ERR_INVALID_ARG;
    int n = toks[obj_idx].size;
    int next = obj_idx + 1;
    memset(peer, 0, sizeof(*peer));
    for (int k = 0; k < n; k++) {
        const jsmntok_t *key = &toks[next];
        int val_idx = next + 1;
        if (tok_eq(js, key, "ID") && toks[val_idx].type == JSMN_PRIMITIVE) {
            char buf[24];
            if (tok_copy(js, &toks[val_idx], buf, sizeof(buf)) > 0) {
                peer->id = strtoull(buf, NULL, 10);
            }
        } else if (tok_eq(js, key, "Key") && tok_is_str(&toks[val_idx])) {
            int slen = toks[val_idx].end - toks[val_idx].start;
            parse_keyed_hex(js + toks[val_idx].start, (size_t)slen,
                            "nodekey:", peer->node_pub);
        } else if (tok_eq(js, key, "DiscoKey") && tok_is_str(&toks[val_idx])) {
            int slen = toks[val_idx].end - toks[val_idx].start;
            if (parse_keyed_hex(js + toks[val_idx].start, (size_t)slen,
                                "discokey:", peer->disco_pub) == ESP_OK) {
                peer->has_disco_pub = true;
            }
        } else if (tok_eq(js, key, "HomeDERP") &&
                   toks[val_idx].type == JSMN_PRIMITIVE) {
            char buf[12];
            if (tok_copy(js, &toks[val_idx], buf, sizeof(buf)) > 0) {
                peer->home_derp = atoi(buf);
            }
        } else if (tok_eq(js, key, "Addresses") &&
                   tok_is_arr(&toks[val_idx])) {
            parse_addresses(js, toks, val_idx,
                            peer->addresses, TL_MAX_PEER_ADDRESSES,
                            &peer->n_addresses);
        } else if (tok_eq(js, key, "Endpoints") &&
                   tok_is_arr(&toks[val_idx])) {
            parse_endpoints(js, toks, val_idx,
                            peer->endpoints, TL_MAX_PEER_ENDPOINTS,
                            &peer->n_endpoints);
        }
        next = skip_value(toks, val_idx);
    }
    return ESP_OK;
}

static esp_err_t parse_peers_arr(const char *js, const jsmntok_t *toks,
                                 int arr_idx, tl_netmap_t *out)
{
    if (!tok_is_arr(&toks[arr_idx])) return ESP_ERR_INVALID_ARG;
    int n = toks[arr_idx].size;
    int next = arr_idx + 1;
    out->n_peers = 0;
    for (int k = 0; k < n; k++) {
        if (tok_is_obj(&toks[next]) && out->n_peers < TL_MAX_PEERS) {
            parse_one_peer(js, toks, next, &out->peers[out->n_peers]);
            out->n_peers++;
        }
        next = skip_value(toks, next);
    }
    return ESP_OK;
}

static esp_err_t parse_one_derp_region(const char *js, const jsmntok_t *toks,
                                       int obj_idx, tl_derp_region_t *region)
{
    if (!tok_is_obj(&toks[obj_idx])) return ESP_ERR_INVALID_ARG;
    int n = toks[obj_idx].size;
    int next = obj_idx + 1;
    memset(region, 0, sizeof(*region));
    for (int k = 0; k < n; k++) {
        const jsmntok_t *key = &toks[next];
        int val_idx = next + 1;
        if (tok_eq(js, key, "RegionID") &&
            toks[val_idx].type == JSMN_PRIMITIVE) {
            char buf[12];
            if (tok_copy(js, &toks[val_idx], buf, sizeof(buf)) > 0) {
                region->region_id = atoi(buf);
            }
        } else if (tok_eq(js, key, "Nodes") && tok_is_arr(&toks[val_idx])) {
            int nn = toks[val_idx].size;
            int nx = val_idx + 1;
            region->n_nodes = 0;
            for (int j = 0; j < nn; j++) {
                if (tok_is_obj(&toks[nx]) &&
                    region->n_nodes < TL_MAX_DERP_NODES) {
                    tl_derp_node_t *dn = &region->nodes[region->n_nodes];
                    int nfields = toks[nx].size;
                    int nf = nx + 1;
                    for (int q = 0; q < nfields; q++) {
                        const jsmntok_t *nk = &toks[nf];
                        int nv = nf + 1;
                        if (tok_eq(js, nk, "RegionID") &&
                            toks[nv].type == JSMN_PRIMITIVE) {
                            char buf[12];
                            if (tok_copy(js, &toks[nv], buf, sizeof(buf)) > 0) {
                                dn->region_id = atoi(buf);
                            }
                        } else if (tok_eq(js, nk, "HostName") &&
                                   tok_is_str(&toks[nv])) {
                            tok_copy(js, &toks[nv], dn->hostname,
                                     sizeof(dn->hostname));
                        } else if (tok_eq(js, nk, "DERPPort") &&
                                   toks[nv].type == JSMN_PRIMITIVE) {
                            char buf[8];
                            if (tok_copy(js, &toks[nv], buf, sizeof(buf)) > 0) {
                                dn->port = (uint16_t)atoi(buf);
                            }
                        }
                        nf = skip_value(toks, nv);
                    }
                    region->n_nodes++;
                }
                nx = skip_value(toks, nx);
            }
        }
        next = skip_value(toks, val_idx);
    }
    return ESP_OK;
}

static esp_err_t parse_derp_map(const char *js, const jsmntok_t *toks,
                                int obj_idx, tl_netmap_t *out)
{
    if (!tok_is_obj(&toks[obj_idx])) return ESP_ERR_INVALID_ARG;
    int n = toks[obj_idx].size;
    int next = obj_idx + 1;
    out->n_derp_regions = 0;
    for (int k = 0; k < n; k++) {
        const jsmntok_t *key = &toks[next];
        int val_idx = next + 1;
        if (tok_eq(js, key, "Regions") && tok_is_obj(&toks[val_idx])) {
            int rn = toks[val_idx].size;
            int rx = val_idx + 1;
            for (int r = 0; r < rn; r++) {
                /* key is region-id-as-string; we ignore it (RegionID is
                 * also inside the value object). */
                int region_obj = rx + 1;
                if (tok_is_obj(&toks[region_obj]) &&
                    out->n_derp_regions < TL_MAX_DERP_REGIONS) {
                    parse_one_derp_region(js, toks, region_obj,
                                          &out->derp_regions[out->n_derp_regions]);
                    out->n_derp_regions++;
                }
                rx = skip_value(toks, region_obj);
            }
            out->have_derp_map = true;
        }
        next = skip_value(toks, val_idx);
    }
    return ESP_OK;
}

esp_err_t mapresp_parse(const char *json, size_t json_len, tl_netmap_t *out)
{
    if (json == NULL || out == NULL) return ESP_ERR_INVALID_ARG;
    tl_netmap_clear(out);

    /* Token budget in BSS. MAX_TOKENS * sizeof(jsmntok_t) = 4500 * 16
     * = 72 KiB. Putting this in BSS instead of malloc'ing per parse:
     * (a) avoids heap fragmentation — after two TLS handshakes (register
     * + long-poll) the heap's largest_free_block dropped to ~68 KiB,
     * smaller than the alloc, and mapresp_parse started failing with
     * ESP_ERR_NO_MEM; (b) makes the cost a constant we can budget for
     * at link time instead of a runtime mystery. We have ~110 KiB of
     * free DRAM at boot before WiFi/TLS bring-up, so 72 KiB resident
     * fits cleanly. */
    static jsmntok_t toks[MAX_TOKENS];
    jsmn_parser p;
    jsmn_init(&p);
    int n = jsmn_parse(&p, json, json_len, toks, MAX_TOKENS);
    if (n < 1 || !tok_is_obj(&toks[0])) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    int fields = toks[0].size;
    int next = 1;
    for (int k = 0; k < fields; k++) {
        const jsmntok_t *key = &toks[next];
        int val_idx = next + 1;
        if (tok_eq(json, key, "Node") && tok_is_obj(&toks[val_idx])) {
            parse_node_obj(json, toks, val_idx, out);
        } else if (tok_eq(json, key, "Peers") && tok_is_arr(&toks[val_idx])) {
            parse_peers_arr(json, toks, val_idx, out);
        } else if (tok_eq(json, key, "PeersChanged") && tok_is_arr(&toks[val_idx])) {
            /* Stream-mode delta-add. The control plane sends the full peer
             * list in PeersChanged on the first MapResponse instead of
             * Peers (verified on-device 2026-05-02 via field-substring
             * scan: first frame has PeersChanged=1, Peers=0). Subsequent
             * updates carry only the changed peers. For our M2 first cut
             * we treat PeersChanged identically to Peers — replace the
             * full peer list. PeersRemoved is not yet honored. */
            parse_peers_arr(json, toks, val_idx, out);
        } else if (tok_eq(json, key, "DERPMap") &&
                   tok_is_obj(&toks[val_idx])) {
            parse_derp_map(json, toks, val_idx, out);
        }
        next = skip_value(toks, val_idx);
    }
    return ESP_OK;
}

/* ------------------------------ MapRequest -------------------------------- */

#ifdef ESP_PLATFORM

static void hex_encode(const uint8_t *in, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hex[in[i] >> 4];
        out[2 * i + 1] = hex[in[i] & 0x0F];
    }
    out[2 * len] = '\0';
}

/* MapRequest body builder. `stream=false` → the server returns one
 * MapResponse and closes; `stream=true` → long-poll, see
 * `mapreq_run_stream` for the framing format. `Compress:""` disables
 * zstd (we don't link it). Hostinfo is intentionally minimal; the
 * server treats it as informational once we're already registered. */
static int build_request_body(const tinylink_keys_t *keys,
                              bool stream,
                              char *out, size_t out_size)
{
    char node_key_hex[8 + 64 + 1];
    char disco_key_hex[9 + 64 + 1];

    memcpy(node_key_hex, "nodekey:", 8);
    hex_encode(keys->node_pub, 32, node_key_hex + 8);
    memcpy(disco_key_hex, "discokey:", 9);
    hex_encode(keys->disco_pub, 32, disco_key_hex + 9);

    /* Version is the Tailscale CapabilityVersion. Same as RegisterRequest:
     * production clients use tailcfg.CurrentCapabilityVersion (138 as of
     * 2026-05-02). M1 hardcoded 1 here too — server rejects a v1
     * MapRequest with HTTP 422 because the response shape it would have
     * to emit is no longer wire-compatible with anything that old. */
    /* Compress="" tells the server we cannot decode zstd (we don't link
     * a zstd library). Field is omitzero in upstream Go so omitting it
     * is equivalent in the wire JSON, BUT — first hardware run on
     * 2026-05-02 saw the server reply with non-JSON bytes when the
     * field was missing, suggesting the control plane treats "absent"
     * as "client supports our default compression". Send the explicit
     * empty string. */
    int n = snprintf(out, out_size,
        "{"
        "\"Version\":138,"
        "\"Compress\":\"\","
        "\"NodeKey\":\"%s\","
        "\"DiscoKey\":\"%s\","
        "\"Stream\":%s,"
        "\"Hostinfo\":{\"OS\":\"esp32\",\"Hostname\":\"%s\",\"IPNVersion\":\"0.1.0-tinylink\"}"
        "}",
        node_key_hex, disco_key_hex,
        stream ? "true" : "false",
        CONFIG_TINYLINK_DEVICE_HOSTNAME);
    if (n < 0 || (size_t)n >= out_size) return -1;
    return n;
}

esp_err_t mapreq_fetch_once(ts2021_conn_t *conn,
                            const tinylink_keys_t *keys,
                            tl_netmap_t *out)
{
    if (conn == NULL || keys == NULL || out == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Buffers heap-allocated: response can be ~32 KiB + tokens table
     * is sizeof(jsmntok_t) * MAX_TOKENS = 64 KiB. Keeping these in BSS
     * overflows the 168 KiB DRAM segment once esp_main_task and the
     * WiFi/lwIP/mbedtls stacks have taken their share. */
    char    *body = malloc(REQUEST_BUF_SZ);
    uint8_t *resp = malloc(RESPONSE_BUF_SZ);
    if (body == NULL || resp == NULL) {
        free(body); free(resp);
        return ESP_ERR_NO_MEM;
    }

    int body_len = build_request_body(keys, false, body, REQUEST_BUF_SZ);
    if (body_len < 0) {
        free(body); free(resp);
        return ESP_ERR_INVALID_SIZE;
    }

    size_t  resp_len = 0;
    int     status = 0;
    esp_err_t err = h2_post_json(conn, "/machine/map",
                                 CONFIG_TINYLINK_CONTROL_HOST,
                                 (const uint8_t *)body, (size_t)body_len,
                                 &status, resp, RESPONSE_BUF_SZ - 1, &resp_len);
    free(body);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "h2_post_json failed: 0x%x", err);
        free(resp);
        return err;
    }
    resp[resp_len] = '\0';
    ESP_LOGI(TAG, "/machine/map status=%d body=%u bytes",
             status, (unsigned)resp_len);
    if (status != 200) {
        ESP_LOGE(TAG, "control plane returned HTTP %d: %.*s",
                 status, (int)(resp_len > 200 ? 200 : resp_len),
                 (const char *)resp);
        free(resp);
        return ESP_FAIL;
    }

    /* Even for non-streaming MapResponse, the control plane frames the
     * body as `LE32 length || JSON`. Verified on real HW 2026-05-02:
     * first 4 bytes were `51 4b 00 00` = 19281, matching the JSON
     * length right after. Strip the prefix before parsing. (Upstream
     * Go reads it in controlclient/direct.go as part of its standard
     * stream framing whether Stream is true or not.) */
    if (resp_len < 4) {
        ESP_LOGE(TAG, "MapResponse too short: %u bytes", (unsigned)resp_len);
        free(resp);
        return ESP_ERR_INVALID_RESPONSE;
    }
    uint32_t framed_len = (uint32_t)resp[0]
                        | ((uint32_t)resp[1] <<  8)
                        | ((uint32_t)resp[2] << 16)
                        | ((uint32_t)resp[3] << 24);
    if (framed_len + 4 > resp_len) {
        ESP_LOGE(TAG, "MapResponse framing: declared %u + 4 > received %u",
                 (unsigned)framed_len, (unsigned)resp_len);
        free(resp);
        return ESP_ERR_INVALID_RESPONSE;
    }
    /* Shrink down to actual JSON size before parsing — mapresp_parse
     * allocates a ~72 KiB token table; keeping the full 32 KiB
     * response alongside risks DRAM exhaustion. */
    memmove(resp, resp + 4, framed_len);
    resp[framed_len] = '\0';
    uint8_t *trimmed = realloc(resp, framed_len + 1);
    if (trimmed != NULL) resp = trimmed;
    err = mapresp_parse((const char *)resp, framed_len, out);
    free(resp);
    return err;
}

/* ---- streaming reader ----------------------------------------------------
 *
 * The control plane frames each MapResponse as `LE32 size || body`
 * (verified against `tailscale/control/controlclient/direct.go:~1248`).
 * We accumulate header bytes, then `size` body bytes, dispatch, repeat.
 * The body buffer is in BSS (large enough for one MapResponse plus
 * slack); it is reused across messages.
 *
 * The chunk callback feeds bytes into this state machine; nghttp2 may
 * deliver partial / multiple messages per DATA frame.
 */

typedef enum {
    STREAM_WANT_HDR,
    STREAM_WANT_BODY,
} stream_phase_t;

typedef struct {
    stream_phase_t phase;
    uint8_t        hdr[4];
    size_t         hdr_have;
    uint32_t       body_size;
    size_t         body_have;
    /* `body_buf` and `body_cap` come from the caller's BSS. */
    uint8_t       *body_buf;
    size_t         body_cap;
    /* Higher-level callback fired once per assembled MapResponse. */
    mapreq_handler_t on_netmap;
    void            *handler_ctx;
} stream_state_t;

static void stream_dispatch(stream_state_t *s)
{
    /* Parse the assembled body. KeepAlive messages set `KeepAlive:true`
     * with no peer data — `mapresp_parse` will leave `have_self=false`
     * and `n_peers=0`, which is safe to recognize.
     *
     * For the M2 long-poll first cut, only full netmaps trigger the
     * handler. Partial/incremental updates beyond KeepAlive are logged
     * and skipped — the upstream server only sends incrementals to
     * clients that opt in via capability flags we don't advertise. */
    /* DIAGNÓSTICO 2026-05-02 (per upstream investigation): inspect the
     * first 16 bytes + key field substrings to distinguish:
     *   - 0x7B '{'             → JSON plain
     *   - 0x28 0xB5 0x2F 0xFD  → zstd magic (server compressed despite our
     *                            Compress="" — cliente Go siempre manda
     *                            "zstd", server puede ignorar Compress="")
     *   - other                → unknown framing */
    {
        const uint8_t *b = s->body_buf;
        size_t n = s->body_have;
        size_t hn = n < 16 ? n : 16;
        char hex[16*3 + 1] = {0};
        for (size_t i = 0; i < hn; i++) {
            snprintf(hex + i*3, 4, "%02x ", b[i]);
        }
        bool has_peers       = false, has_peers_changed = false;
        bool has_keepalive   = false, has_node          = false;
        bool has_peers_patch = false, has_peers_removed = false;
        if (n >= 9) {
            for (size_t i = 0; i + 7 < n; i++) {
                if (!has_peers       && memcmp(b+i, "\"Peers\"", 7) == 0)             has_peers = true;
                if (!has_keepalive   && i + 11 < n && memcmp(b+i, "\"KeepAlive\"", 11) == 0) has_keepalive = true;
                if (!has_node        && memcmp(b+i, "\"Node\"", 6) == 0)              has_node = true;
                if (!has_peers_changed && i + 14 < n && memcmp(b+i, "\"PeersChanged\"", 14) == 0) has_peers_changed = true;
                if (!has_peers_patch   && i + 19 < n && memcmp(b+i, "\"PeersChangedPatch\"", 19) == 0) has_peers_patch = true;
                if (!has_peers_removed && i + 14 < n && memcmp(b+i, "\"PeersRemoved\"", 14) == 0) has_peers_removed = true;
            }
        }
        ESP_LOGI(TAG, "frame[%u] hex: %s", (unsigned)n, hex);
        ESP_LOGI(TAG, "frame fields: Node=%d Peers=%d PeersChanged=%d PeersChangedPatch=%d PeersRemoved=%d KeepAlive=%d",
                 has_node, has_peers, has_peers_changed,
                 has_peers_patch, has_peers_removed, has_keepalive);
    }

    static tl_netmap_t nm;  /* ~1 KiB; reused across messages */
    esp_err_t pe = mapresp_parse((const char *)s->body_buf, s->body_have, &nm);
    if (pe != ESP_OK) {
        ESP_LOGW(TAG, "MapResponse parse failed (size=%u err=0x%x free_heap=%u largest_block=%u)",
                 (unsigned)s->body_have, (unsigned)pe,
                 (unsigned)esp_get_free_heap_size(),
                 (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));
        return;
    }
    if (!nm.have_self && nm.n_peers == 0) {
        /* KeepAlive (or empty incremental). Nothing actionable. */
        ESP_LOGD(TAG, "KeepAlive (%u bytes)", (unsigned)s->body_have);
        return;
    }
    if (s->on_netmap != NULL) {
        s->on_netmap(&nm, s->handler_ctx);
    }
}

static int stream_chunk_cb(const uint8_t *data, size_t len, void *ctx)
{
    stream_state_t *s = (stream_state_t *)ctx;
    size_t off = 0;
    while (off < len) {
        if (s->phase == STREAM_WANT_HDR) {
            size_t need = 4 - s->hdr_have;
            size_t take = (len - off < need) ? (len - off) : need;
            memcpy(s->hdr + s->hdr_have, data + off, take);
            s->hdr_have += take;
            off += take;
            if (s->hdr_have == 4) {
                /* LE32 size — see `direct.go` watchdog loop. */
                s->body_size = ((uint32_t)s->hdr[0])       |
                               ((uint32_t)s->hdr[1] <<  8) |
                               ((uint32_t)s->hdr[2] << 16) |
                               ((uint32_t)s->hdr[3] << 24);
                if (s->body_size > s->body_cap) {
                    ESP_LOGE(TAG, "MapResponse too large: %u > %u",
                             (unsigned)s->body_size, (unsigned)s->body_cap);
                    return -1;
                }
                s->body_have = 0;
                s->phase = STREAM_WANT_BODY;
            }
        } else { /* STREAM_WANT_BODY */
            size_t need = s->body_size - s->body_have;
            size_t take = (len - off < need) ? (len - off) : need;
            memcpy(s->body_buf + s->body_have, data + off, take);
            s->body_have += take;
            off += take;
            if (s->body_have == s->body_size) {
                stream_dispatch(s);
                s->phase = STREAM_WANT_HDR;
                s->hdr_have = 0;
                s->body_size = 0;
                s->body_have = 0;
            }
        }
    }
    return 0;
}

esp_err_t mapreq_run_stream(ts2021_conn_t *conn,
                            const tinylink_keys_t *keys,
                            mapreq_handler_t on_netmap, void *ctx)
{
    if (conn == NULL || keys == NULL || on_netmap == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    static char body[REQUEST_BUF_SZ];
    int body_len = build_request_body(keys, true, body, sizeof(body));
    if (body_len < 0) return ESP_ERR_INVALID_SIZE;

    /* Body buffer for one assembled MapResponse. 16 KiB matches the
     * non-stream RESPONSE_BUF_SZ — enough headroom for a 4-peer netmap
     * with a few DERP regions. Sized statically so the stream task
     * stack stays small. */
    static uint8_t body_buf[RESPONSE_BUF_SZ];
    stream_state_t s = {
        .phase       = STREAM_WANT_HDR,
        .body_buf    = body_buf,
        .body_cap    = sizeof(body_buf),
        .on_netmap   = on_netmap,
        .handler_ctx = ctx,
    };

    int status = 0;
    esp_err_t err = h2_post_json_stream(conn, "/machine/map",
                                        CONFIG_TINYLINK_CONTROL_HOST,
                                        (const uint8_t *)body,
                                        (size_t)body_len,
                                        &status, stream_chunk_cb, &s);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "h2_post_json_stream failed: 0x%x", err);
        return err;
    }
    if (status != 200) {
        ESP_LOGE(TAG, "/machine/map (stream) returned HTTP %d", status);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "/machine/map stream closed cleanly");
    return ESP_OK;
}

#endif /* ESP_PLATFORM */
