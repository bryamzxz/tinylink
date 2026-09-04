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
#include "tinylink.h"   /* tinylink_get_public_endpoint */
#endif

#define JSMN_STATIC
#include "jsmn.h"
#include "jsmn_skip.h"
#include "jsmn_split.h"

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
/* jsmn token budget for ONE sub-document. Since 2026-09 the MapResponse
 * is not tokenized as a whole: jsmn_split.h cuts it into its top-level
 * values and this table only ever holds the self Node object, one peer
 * object, one DERP region object or one patch entry at a time. The
 * largest of those in the wild is a peer with a full Hostinfo (a few
 * hundred tokens); 640 leaves ~2× headroom, and an oversized element is
 * skipped with a log instead of failing the whole map. Was 2 500 tokens
 * (40 KiB BSS) for the whole document — which also capped the tailnet
 * size the parser could handle at all. 640 × 16 = 10 KiB BSS. */
#define SUB_MAX_TOKENS   640

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
    /* Decode into a scratch buffer first so a malformed nibble at any
     * position bails without ever publishing partial bytes to *out. The
     * old shape wrote bytes 0..k-1 before returning ESP_ERR_INVALID_ARG
     * on bad nibble at index k, and one call site (parse_one_peer "Key")
     * ignores the return value — leaving peer->node_pub with attacker-hex
     * bytes mixed with the previous memset(0)'d remainder. */
    uint8_t tmp[TINYLINK_KEY_LEN];
    for (size_t i = 0; i < 32; i++) {
        int hi = hex_nibble(s[plen + 2 * i]);
        int lo = hex_nibble(s[plen + 2 * i + 1]);
        if (hi < 0 || lo < 0) return ESP_ERR_INVALID_ARG;
        tmp[i] = (uint8_t)((hi << 4) | lo);
    }
    memcpy(out, tmp, TINYLINK_KEY_LEN);
    return ESP_OK;
}

/* Walk forward from token index `i` past the entire subtree it describes,
 * returning the next sibling index. jsmn produces tokens in document order
 * with `size` = number of immediate children, so this is just a recursive
 * skip without re-parsing. */
/* Skip the JSON value at toks[i], returning the index just past its
 * subtree. Depth-bounded (see jsmn_skip.h) so an adversarially deep
 * MapResponse can't overflow the long-poll task stack. */
static int skip_value(const jsmntok_t *toks, int i)
{
    return jsmn_skip(toks, i);
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
            /* parse_keyed_hex's own header documents this used to be the
             * call site that "ignored the return value, leaving node_pub
             * with attacker-hex bytes". PR #58 made the function itself
             * safe (scratch buffer, memcpy only on success), so a parse
             * failure now leaves node_pub at its memset(0) value above.
             * Still gate explicitly so the failure is observable and the
             * call shape matches DiscoKey below. */
            if (parse_keyed_hex(js + toks[val_idx].start, (size_t)slen,
                                "nodekey:", peer->node_pub) != ESP_OK) {
#ifdef ESP_PLATFORM
                ESP_LOGW(TAG, "parse_one_peer: malformed Key — node_pub zeroed");
#endif
            }
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

/* One jsmn token table for every sub-parse (BSS, see SUB_MAX_TOKENS). */
static jsmntok_t s_toks[SUB_MAX_TOKENS];

/* Tokenize one extracted value. Returns the jsmn token count (≥ 1) or a
 * negative jsmn error; updates *peak for the soak log. */
static int sub_parse(const char *js, size_t len, int *peak)
{
    jsmn_parser p;
    jsmn_init(&p);
    int n = jsmn_parse(&p, js, len, s_toks, SUB_MAX_TOKENS);
    if (n > *peak) *peak = n;
#ifdef ESP_PLATFORM
    if (n == JSMN_ERROR_NOMEM) {
        ESP_LOGW(TAG, "sub-document exceeds %d tokens (%u bytes) — skipped",
                 SUB_MAX_TOKENS, (unsigned)len);
    }
#endif
    return n;
}

/* Peers / PeersChanged: array of Node objects, one sub-parse each. */
static esp_err_t parse_peers_split(const char *js, size_t len,
                                   tl_netmap_t *out, int *peak)
{
    size_t pos = 0;
    const char *v; size_t vlen; int rc;
    out->n_peers = 0;
    while ((rc = tl_jsplit_arr_next(js, len, &pos, &v, &vlen)) == 1) {
        if (out->n_peers >= TL_MAX_PEERS) continue;   /* keep draining; cap like before */
        int n = sub_parse(v, vlen, peak);
        if (n < 1 || !tok_is_obj(&s_toks[0])) continue;
        parse_one_peer(v, s_toks, 0, &out->peers[out->n_peers]);
        out->n_peers++;
    }
    return (rc < 0) ? ESP_ERR_INVALID_RESPONSE : ESP_OK;
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

/* DERPMap: {"Regions": {"<id>": {...region...}, ...}} — one sub-parse per
 * region object. The key (region id as string) is ignored: RegionID is
 * inside the value too. */
static esp_err_t parse_derp_map_split(const char *js, size_t len,
                                      tl_netmap_t *out, int *peak)
{
    size_t pos = 0;
    tl_jsplit_kv_t kv; int rc;
    out->n_derp_regions = 0;
    while ((rc = tl_jsplit_obj_next(js, len, &pos, &kv)) == 1) {
        if (!tl_jsplit_key_is(&kv, "Regions") || kv.val[0] != '{') continue;
        size_t rp = 0;
        tl_jsplit_kv_t rkv; int rrc;
        while ((rrc = tl_jsplit_obj_next(kv.val, kv.val_len, &rp, &rkv)) == 1) {
            if (out->n_derp_regions >= TL_MAX_DERP_REGIONS) continue;
            int n = sub_parse(rkv.val, rkv.val_len, peak);
            if (n < 1 || !tok_is_obj(&s_toks[0])) continue;
            parse_one_derp_region(rkv.val, s_toks, 0,
                                  &out->derp_regions[out->n_derp_regions]);
            out->n_derp_regions++;
        }
        if (rrc < 0) return ESP_ERR_INVALID_RESPONSE;
        out->have_derp_map = true;
    }
    return (rc < 0) ? ESP_ERR_INVALID_RESPONSE : ESP_OK;
}

/* PeersRemoved: array of NodeIDs (JSON numbers). */
static esp_err_t parse_removed_split(const char *js, size_t len, tl_netmap_t *out)
{
    size_t pos = 0;
    const char *v; size_t vlen; int rc;
    while ((rc = tl_jsplit_arr_next(js, len, &pos, &v, &vlen)) == 1) {
        if (out->n_removed >= TL_MAX_PEERS_REMOVED) continue;
        char buf[24];
        if (vlen == 0 || vlen >= sizeof(buf) || v[0] < '0' || v[0] > '9') continue;
        memcpy(buf, v, vlen);
        buf[vlen] = '\0';
        out->removed_ids[out->n_removed++] = strtoull(buf, NULL, 10);
    }
    return (rc < 0) ? ESP_ERR_INVALID_RESPONSE : ESP_OK;
}

/* PeersChangedPatch: array of tailcfg.PeerChange objects. Only the
 * presence of "Key" / "DiscoKey" matters (see netmap.h) — read straight
 * off the split, no tokens needed. */
static esp_err_t parse_patch_split(const char *js, size_t len, tl_netmap_t *out)
{
    size_t pos = 0;
    const char *v; size_t vlen; int rc;
    while ((rc = tl_jsplit_arr_next(js, len, &pos, &v, &vlen)) == 1) {
        if (v[0] != '{') continue;
        size_t ep = 0;
        tl_jsplit_kv_t ekv; int erc;
        while ((erc = tl_jsplit_obj_next(v, vlen, &ep, &ekv)) == 1) {
            if (tl_jsplit_key_is(&ekv, "Key") || tl_jsplit_key_is(&ekv, "DiscoKey")) {
                out->patch_identity_changed = true;
            }
        }
        if (erc < 0) return ESP_ERR_INVALID_RESPONSE;
    }
    return (rc < 0) ? ESP_ERR_INVALID_RESPONSE : ESP_OK;
}

esp_err_t mapresp_parse(const char *json, size_t json_len, tl_netmap_t *out)
{
    if (json == NULL || out == NULL) return ESP_ERR_INVALID_ARG;
    tl_netmap_clear(out);

    /* Shallow split of the top-level object (jsmn_split.h), then one
     * bounded jsmn parse per value we care about. Every other key
     * (DNSConfig, PacketFilter, UserProfiles, ...) is skipped by byte
     * range without being tokenized at all. */
    int peak = 0;
    size_t pos = 0;
    tl_jsplit_kv_t kv;
    int rc;
    esp_err_t err = ESP_OK;
    while ((rc = tl_jsplit_obj_next(json, json_len, &pos, &kv)) == 1) {
        if (tl_jsplit_key_is(&kv, "Node") && kv.val[0] == '{') {
            int n = sub_parse(kv.val, kv.val_len, &peak);
            if (n >= 1 && tok_is_obj(&s_toks[0])) {
                parse_node_obj(kv.val, s_toks, 0, out);
            }
        } else if (tl_jsplit_key_is(&kv, "Peers") && kv.val[0] == '[') {
            /* Full peer list: the caller replaces its table. */
            err = parse_peers_split(kv.val, kv.val_len, out, &peak);
            out->peers_is_delta = false;
        } else if (tl_jsplit_key_is(&kv, "PeersChanged") && kv.val[0] == '[') {
            /* Stream-mode delta: upsert into the caller's table. The
             * control plane sends the whole list this way on the first
             * MapResponse (observed 2026-05-02), which merges into an
             * empty table identically to a full list. */
            err = parse_peers_split(kv.val, kv.val_len, out, &peak);
            out->peers_is_delta = true;
        } else if (tl_jsplit_key_is(&kv, "PeersRemoved") && kv.val[0] == '[') {
            err = parse_removed_split(kv.val, kv.val_len, out);
        } else if (tl_jsplit_key_is(&kv, "PeersChangedPatch") && kv.val[0] == '[') {
            /* Minimal patch handling (upstream-audit 2026-07-16): a patch
             * touching a peer's "Key" (NodeKey rotation) or "DiscoKey"
             * flags the netmap so the streaming caller recycles the
             * stream and refetches a full map. Nothing is merged. */
            err = parse_patch_split(kv.val, kv.val_len, out);
        } else if (tl_jsplit_key_is(&kv, "DERPMap") && kv.val[0] == '{') {
            err = parse_derp_map_split(kv.val, kv.val_len, out, &peak);
        }
        if (err != ESP_OK) break;
    }
    if (rc < 0 || err != ESP_OK) {
#ifdef ESP_PLATFORM
        ESP_LOGE(TAG, "MapResponse malformed at byte %u of %u",
                 (unsigned)pos, (unsigned)json_len);
#endif
        return ESP_ERR_INVALID_RESPONSE;
    }

    /* Soak observability: largest single sub-parse this message. */
#ifdef ESP_PLATFORM
    ESP_LOGI(TAG, "mapresp peak: tokens=%d/%d body=%u",
             peak, SUB_MAX_TOKENS, (unsigned)json_len);
#endif
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
 * `mapreq_run_stream` for the framing format. `omit_peers=true` plus
 * `stream=false` is the upstream "lite" endpoint-update request
 * documented in tailscale/control/controlclient/auto.go:249-251 —
 * the ONLY combination at Version >= 68 where the control plane
 * actually persists Hostinfo + top-level Endpoints. `Stream=true` is
 * read-only (tailcfg.go:1408+1436); `Stream=false && OmitPeers=false`
 * is treated as a normal map fetch and the embedded Endpoints are
 * silently ignored, which left every peer with `Addrs: null` for
 * sensor-cali after PR #37 — same symptom as before #37 had been
 * applied. `Compress:""` disables zstd (we don't link it). Hostinfo
 * is intentionally minimal; the server treats it as informational
 * once we're already registered. */
static int build_request_body(const tinylink_keys_t *keys,
                              bool stream,
                              bool omit_peers,
                              char *out, size_t out_size)
{
    char node_key_hex[8 + 64 + 1];
    char disco_key_hex[9 + 64 + 1];

    memcpy(node_key_hex, "nodekey:", 8);
    hex_encode(keys->node_pub, 32, node_key_hex + 8);
    memcpy(disco_key_hex, "discokey:", 9);
    hex_encode(keys->disco_pub, 32, disco_key_hex + 9);

    /* Version is the Tailscale CapabilityVersion (TINYLINK_CAPVER, single
     * source of truth). Same as RegisterRequest: production clients use
     * tailcfg.CurrentCapabilityVersion. M1 hardcoded 1 here too — server
     * rejects a v1 MapRequest with HTTP 422 because the response shape it
     * would have to emit is no longer wire-compatible with anything that
     * old. Emitted into the JSON below via TINYLINK_STR(TINYLINK_CAPVER). */
    /* Compress="" tells the server we cannot decode zstd (we don't link
     * a zstd library). Field is omitzero in upstream Go so omitting it
     * is equivalent in the wire JSON, BUT — first hardware run on
     * 2026-05-02 saw the server reply with non-JSON bytes when the
     * field was missing, suggesting the control plane treats "absent"
     * as "client supports our default compression". Send the explicit
     * empty string. */
    /* Endpoints go at the TOP LEVEL of MapRequest, not inside
     * Hostinfo (per upstream tailcfg.go:1436). The control plane
     * persists these in the node's database record and propagates
     * them to peers as their dial candidates. Hostinfo had a legacy
     * Endpoints field too but the modern (Version >= 68) shape reads
     * the top-level slice. Putting them in the wrong place is what
     * left every peer with `Addrs: null` for sensor-cali — verified
     * 2026-05-07 via `tailscale debug peer-status` from a peer that
     * shared our tailnet but couldn't dial us. */
    /* `EndpointTypes` mirrors the upstream client (direct.go:1082);
     * `2` = EndpointSTUN per tailcfg.go:1334, which is what our STUN
     * probe is. The slice MUST be the same length as Endpoints — we
     * only ever push one. */
    char endpoints_field[96] = "";
    uint8_t  ep_addr[4] = {0};
    uint16_t ep_port = 0;
    bool stun_ok = tinylink_get_public_endpoint(ep_addr, &ep_port);
    if (stun_ok) {
        snprintf(endpoints_field, sizeof(endpoints_field),
                 ",\"Endpoints\":[\"%u.%u.%u.%u:%u\"]"
                 ",\"EndpointTypes\":[2]",
                 ep_addr[0], ep_addr[1], ep_addr[2], ep_addr[3],
                 (unsigned)ep_port);
    }

    /* Hostinfo.NetInfo.PreferredDERP — tells the control plane (and
     * via the netmap, our peers) which DERP region to relay through
     * when they can't reach us directly. Without it, every peer's
     * StableRelay falls back to whatever they last knew, and packets
     * to us get black-holed at peers that picked a region we don't
     * actually maintain a connection to. Hardcoded bootstrap value;
     * 0 = omit (matches Go's omitzero on the field).
     *
     * WorkingUDP is conditioned on a successful STUN probe — we just
     * received a binding response, so UDP is empirically working. Without
     * this signal, controlplane.tailscale.com appears NOT to propagate
     * the Endpoints field to peers (peer's `tailscale status` shows
     * `Addrs: null` even after a `Stream=false, OmitPeers=true` lite
     * update returns 200). With it, peers get the dial candidate. */
    char netinfo_field[96] = "";
    if (CONFIG_TINYLINK_PREFERRED_DERP > 0 || stun_ok) {
        char preferred_part[40] = "";
        if (CONFIG_TINYLINK_PREFERRED_DERP > 0) {
            snprintf(preferred_part, sizeof(preferred_part),
                     "\"PreferredDERP\":%d",
                     CONFIG_TINYLINK_PREFERRED_DERP);
        }
        const char *sep = (preferred_part[0] != '\0' && stun_ok) ? "," : "";
        snprintf(netinfo_field, sizeof(netinfo_field),
                 ",\"NetInfo\":{%s%s%s}",
                 preferred_part, sep,
                 stun_ok ? "\"WorkingUDP\":true" : "");
    }

    /* `KeepAlive:true` requests the server to emit periodic
     * KeepAlive=true frames on the long-poll stream so we have a
     * liveness signal beyond TCP keepalives. Upstream tailscale sets
     * this unconditionally on every MapRequest (direct.go:1078); we
     * match for the streaming path (no effect for the lite Stream=false
     * paths). Matches the in-source comment at L746 documenting the
     * server's KeepAlive=true behaviour we already parse on receipt. */
    int n = snprintf(out, out_size,
        "{"
        "\"Version\":" TINYLINK_STR(TINYLINK_CAPVER) ","
        "\"Compress\":\"\","
        "\"NodeKey\":\"%s\","
        "\"DiscoKey\":\"%s\","
        "\"Stream\":%s,"
        "\"KeepAlive\":true,"
        "%s"
        "\"Hostinfo\":{\"OS\":\"esp32\",\"Hostname\":\"%s\","
        "\"IPNVersion\":\"" TINYLINK_IPN_VERSION "\"%s}"
        "%s"
        "}",
        node_key_hex, disco_key_hex,
        stream ? "true" : "false",
        omit_peers ? "\"OmitPeers\":true," : "",
        CONFIG_TINYLINK_DEVICE_HOSTNAME,
        netinfo_field,    /* %s inside Hostinfo */
        endpoints_field); /* %s at top level */
    if (n < 0 || (size_t)n >= out_size) return -1;
    return n;
}

esp_err_t mapreq_push_endpoints(ts2021_conn_t *conn,
                                const tinylink_keys_t *keys)
{
    if (conn == NULL || keys == NULL) return ESP_ERR_INVALID_ARG;

    /* Body fits comfortably in the ~600-byte upper bound of a
     * minimal Hostinfo + Endpoints request — no need for the
     * heap-allocated REQUEST_BUF_SZ used by the netmap-fetching
     * path. Use a stack buffer to avoid heap pressure. */
    char body[1024];
    int body_len = build_request_body(keys, /*stream=*/false,
                                      /*omit_peers=*/true,
                                      body, sizeof(body));
    if (body_len < 0) return ESP_ERR_INVALID_SIZE;

    /* The server is documented to be allowed to omit the response
     * body entirely (tailcfg.go MapRequest.OmitPeers comment). 256 B
     * is plenty whether the body is empty, "{}", or a tiny error
     * message — we only check the HTTP status. */
    uint8_t resp[256];
    size_t resp_len = 0;
    int status = 0;
    esp_err_t err = h2_post_json(conn, "/machine/map",
                                 CONFIG_TINYLINK_CONTROL_HOST,
                                 (const uint8_t *)body, (size_t)body_len,
                                 &status, resp, sizeof(resp), &resp_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "endpoint push h2_post_json failed: 0x%x", err);
        return err;
    }
    ESP_LOGI(TAG, "endpoint push: HTTP %d (resp %u B)",
             status, (unsigned)resp_len);
    if (status != 200) {
        if (status == 429 || status == 503) {
            ESP_LOGW(TAG, "endpoint push throttled: HTTP %d "
                          "(Retry-After=%d s)",
                     status, conn->h2_retry_after_s);
        } else {
            ESP_LOGE(TAG, "endpoint push HTTP %d (server rejected lite update)",
                     status);
        }
        return ESP_FAIL;
    }
    return ESP_OK;
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

/* Returns 0 to keep the stream running, -1 to stop it (the caller's
 * chunk callback propagates the stop through nghttp2 so the long-poll
 * task tears the conn down and reconnects — used when a frame demands
 * a full-netmap refetch we can't satisfy in-stream). */
static int stream_dispatch(stream_state_t *s)
{
    /* Parse the assembled body. KeepAlive messages set `KeepAlive:true`
     * with no peer data — `mapresp_parse` will leave `have_self=false`
     * and `n_peers=0`, which is safe to recognize.
     *
     * For the M2 long-poll first cut, only full netmaps trigger the
     * handler. Partial/incremental updates beyond KeepAlive are logged
     * and skipped — the upstream server only sends incrementals to
     * clients that opt in via capability flags we don't advertise. */
    /* The 2026-05-02 framing diagnostic (hex dump of the first 16 bytes
     * + six memcmp-per-byte substring scans over the whole body, three
     * INFO lines per frame) was removed 2026-09: the framing question it
     * answered (plain JSON vs zstd) has been settled since M2, and it
     * cost up to 6 × 32 KiB comparisons plus ~250 B of UART output on
     * every frame of the long-poll hot path. mapresp_parse below reports
     * the same field presence (n_peers, keepalive, patch flags) from the
     * real parse. */

    /* Soak observability: per-dispatch assembled body size. Grep
     * `stream peak: body` over a multi-hour log and take the max to
     * size RESPONSE_BUF_SZ (currently 32 KiB BSS for body_buf) down
     * to (peak + 20 % margin). The frame[] hex line above also carries
     * this number but as a hex-prefixed string; this is the explicit
     * grep target. */
    ESP_LOGI(TAG, "stream peak: body=%u (cap=%u)",
             (unsigned)s->body_have, (unsigned)s->body_cap);

    static tl_netmap_t nm;  /* ~1 KiB; reused across messages */
    esp_err_t pe = mapresp_parse((const char *)s->body_buf, s->body_have, &nm);
    if (pe != ESP_OK) {
        ESP_LOGW(TAG, "MapResponse parse failed (size=%u err=0x%x free_heap=%u largest_block=%u)",
                 (unsigned)s->body_have, (unsigned)pe,
                 (unsigned)esp_get_free_heap_size(),
                 (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));
        return 0;
    }
    if (nm.patch_identity_changed && nm.n_peers == 0) {
        /* A peer rotated its NodeKey/DiscoKey and the server told us
         * via PeersChangedPatch, which we don't merge. Recycle the
         * stream: the reconnect's first frame is always a full netmap
         * (headscale f4eeb94b guarantees it; tailscale.com always did),
         * so the data plane gets the fresh keys within seconds instead
         * of handshaking against dead ones until the next full push. */
        ESP_LOGW(TAG, "PeersChangedPatch carries peer Key/DiscoKey change — "
                      "recycling stream for a full netmap");
        return -1;
    }
    if (!nm.have_self && nm.n_peers == 0) {
        /* KeepAlive (or empty incremental). Nothing actionable. */
        ESP_LOGD(TAG, "KeepAlive (%u bytes)", (unsigned)s->body_have);
        return 0;
    }
    if (s->on_netmap != NULL) {
        s->on_netmap(&nm, s->handler_ctx);
    }
    return 0;
}

static int stream_chunk_cb(const uint8_t *data, size_t len, void *ctx)
{
    /* Any byte from the control plane — netmap, delta, KeepAlive, even
     * an error body — proves the control path works end-to-end. Feeds
     * the wedge-restart last resort in tinylink.c. */
    tinylink_control_mark_alive();

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
                int stop = stream_dispatch(s);
                s->phase = STREAM_WANT_HDR;
                s->hdr_have = 0;
                s->body_size = 0;
                s->body_have = 0;
                if (stop != 0) {
                    /* Propagates through data_chunk_cb → h2_cb_stop →
                     * h2_drive_request unwinds; long-poll reconnects. */
                    return -1;
                }
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
    int body_len = build_request_body(keys, true, false, body, sizeof(body));
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
        if (status == 429 || status == 503) {
            ESP_LOGW(TAG, "/machine/map (stream) throttled: HTTP %d "
                          "(Retry-After=%d s)",
                     status, conn->h2_retry_after_s);
        } else {
            ESP_LOGE(TAG, "/machine/map (stream) returned HTTP %d", status);
        }
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "/machine/map stream closed cleanly");
    return ESP_OK;
}

#endif /* ESP_PLATFORM */
