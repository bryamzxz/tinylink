// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// tinylink test oracle: the whole-body MapResponse parser of
// components/tinylink/src/mapreq.c as of 50a962b (1.3.3 plus the
// jsmn_tree_ok fix; lines 1–643 — the parser, without the ESP-only
// MapRequest / stream code), before the round-1.3.4 streaming splitter
// (D2). Host tests only — never built into the firmware; test_mapresp.c
// compiles it under ref_* names through mapresp_ref.c and requires the
// streaming parser to produce the same tl_netmap_t (or the same failure)
// for every input whose elements fit its buffer. Verbatim below this
// header, except the DERP node's IPv4 / STUNPort (round 1.3.5), marked
// where they are parsed.
//

#include "mapreq.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "sdkconfig.h"
#include "ctrl_buf.h"
#include "h2_client.h"
#include "tinylink.h"   /* tinylink_get_public_endpoint */
#endif

#define JSMN_STATIC
#include "jsmn.h"
#include "jsmn_skip.h"
#include "jsmn_split.h"
#include "tl_addr.h"   /* 1.3.5 */
#include "tl_date.h"

#ifdef ESP_PLATFORM
static const char *TAG = "mapreq";
#endif

/* Real Tailscale MapResponse for a small tailnet (sensor + home peer)
 * comfortably exceeds 16 KiB once DERP map + DNSConfig + the peer's
 * Hostinfo are folded in. Observed 16383-byte truncation on first HW
 * boot 2026-05-02. The stream assembles one MapResponse at a time in the
 * shared control buffer (ctrl_buf.h): TL_CTRL_MAPRESP_CAP = 32 KiB
 * (soak peak 25 838 B); its MapRequest goes out of the buffer's tail
 * (TL_CTRL_REQ_CAP). */
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
        } else if (tok_eq(js, key, "Expired") &&
                   toks[val_idx].type == JSMN_PRIMITIVE) {
            out->self_expired = tok_eq(js, &toks[val_idx], "true");
        } else if (tok_eq(js, key, "KeyExpiry") && tok_is_str(&toks[val_idx])) {
            /* Go's zero time ("0001-01-01T00:00:00Z", = never expires)
             * lands at a negative Unix time; keep 0 for "no expiry". */
            int64_t t = 0;
            if (tl_parse_rfc3339(js + toks[val_idx].start,
                                 (size_t)(toks[val_idx].end - toks[val_idx].start),
                                 &t) && t > 0) {
                out->self_key_expiry = t;
            }
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
 * negative jsmn error; updates *peak for the soak log. A token tree the
 * parsers below cannot walk inside the table (jsmn_tree_ok: a member
 * without its colon) is refused like a jsmn error — round 1.3.4; until
 * then they walked into stale tokens and past the table. */
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
    if (n >= 1 && !jsmn_tree_ok(s_toks, n)) {
#ifdef ESP_PLATFORM
        ESP_LOGW(TAG, "sub-document of %u bytes is not key/value pairs — skipped",
                 (unsigned)len);
#endif
        return JSMN_ERROR_INVAL;
    }
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
                    dn->stun_port = TL_STUN_DEFAULT_PORT;   /* 1.3.5, as mapreq.c */
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
                        } else if (tok_eq(js, nk, "IPv4") && tok_is_str(&toks[nv])) {
                            /* Round 1.3.5: the node fields tl_derp_node_t
                             * gained, parsed as mapreq.c does — the tests
                             * compare whole netmaps against this parser. */
                            if (!tl_ipv4_parse(js + toks[nv].start,
                                               (size_t)(toks[nv].end - toks[nv].start),
                                               dn->ipv4)) {
                                memset(dn->ipv4, 0, sizeof(dn->ipv4));
                            }
                        } else if (tok_eq(js, nk, "STUNPort") &&
                                   toks[nv].type == JSMN_PRIMITIVE) {
                            dn->stun_port = tl_stun_port_parse(
                                js + toks[nv].start,
                                (size_t)(toks[nv].end - toks[nv].start));
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

/* Which DERPMap regions are stored (1.3.2). The parsed map has exactly
 * one consumer, tinylink.c::update_derp_host_from_netmap: the DERP
 * supervisor dials the region we advertise as PreferredDERP, because
 * that is where peers relay to us. Peers' HomeDERP needs no region
 * entry — this node keeps a single DERP connection: a peer that wants
 * to reach us dials our home region (DERP servers do not forward
 * across regions; the mesh is per region), and our relayed replies go
 * back through that same server while the peer holds its connection
 * there — and nothing else reads the map. So every other region is dropped here instead of stored
 * (Tailscale ships 28: −6 KiB BSS). Matched on the RegionID inside the
 * region object, never on its position: Go marshals the Regions map in
 * string-key order ("1", "10", …, "16", …, "2", …), and keeping "the
 * first N" is how the 2026-05 cap=4 build lost region 16. A DERPMap
 * without the region still sets have_derp_map with n_derp_regions = 0,
 * and the current DERP host stays as it is — the hook for a future
 * home-DERP fallback, which would add its pick to this predicate and
 * raise TL_MAX_DERP_REGIONS. */
#ifdef ESP_PLATFORM
#define DERP_KEEP_REGION CONFIG_TINYLINK_PREFERRED_DERP
#else
#define DERP_KEEP_REGION 16   /* host KAT: the Kconfig default */
#endif

static bool derp_region_wanted(int region_id)
{
    return region_id > 0 && region_id == DERP_KEEP_REGION;
}

/* DERPMap: {"Regions": {"<id>": {...region...}, ...}} — one sub-parse per
 * region object until the wanted region is stored; the rest are drained
 * by byte range. The key (region id as string) is ignored: RegionID is
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
        unsigned seen = 0;
        tl_jsplit_kv_t rkv; int rrc;
        while ((rrc = tl_jsplit_obj_next(kv.val, kv.val_len, &rp, &rkv)) == 1) {
            seen++;
            if (out->n_derp_regions >= TL_MAX_DERP_REGIONS) continue;
            int n = sub_parse(rkv.val, rkv.val_len, peak);
            if (n < 1 || !tok_is_obj(&s_toks[0])) continue;
            tl_derp_region_t *r = &out->derp_regions[out->n_derp_regions];
            parse_one_derp_region(rkv.val, s_toks, 0, r);
            if (derp_region_wanted(r->region_id)) {
                out->n_derp_regions++;
            } else {
                memset(r, 0, sizeof(*r));   /* slot reused by the next one */
            }
        }
        if (rrc < 0) return ESP_ERR_INVALID_RESPONSE;
        out->have_derp_map = true;
#ifdef ESP_PLATFORM
        if (out->n_derp_regions == 0 && DERP_KEEP_REGION > 0) {
            ESP_LOGW(TAG, "DERPMap (%u regions) has no region %d — "
                          "keeping the current DERP host",
                     seen, DERP_KEEP_REGION);
        }
#else
        (void)seen;
#endif
    }
    return (rc < 0) ? ESP_ERR_INVALID_RESPONSE : ESP_OK;
}

/* PeersRemoved: array of NodeIDs (JSON numbers). */
static esp_err_t parse_removed_split(const char *js, size_t len, tl_netmap_t *out)
{
    size_t pos = 0;
    const char *v; size_t vlen; int rc;
    while ((rc = tl_jsplit_arr_next(js, len, &pos, &v, &vlen)) == 1) {
        if (out->n_removed >= TL_MAX_PEERS_REMOVED) {
            out->removed_overflow = true;
            continue;
        }
        char buf[24];
        if (vlen == 0 || vlen >= sizeof(buf) || v[0] < '0' || v[0] > '9') continue;
        memcpy(buf, v, vlen);
        buf[vlen] = '\0';
        out->removed_ids[out->n_removed++] = strtoull(buf, NULL, 10);
    }
    return (rc < 0) ? ESP_ERR_INVALID_RESPONSE : ESP_OK;
}

/* One tailcfg.PeerChange object → tl_peer_patch_t. Fields tinylink does
 * not consume (Cap, CapMap, KeySignature, Online, LastSeen, KeyExpiry)
 * are skipped. A malformed Key/DiscoKey leaves that field unset rather
 * than publishing a partial key. */
static void parse_one_patch(const char *js, const jsmntok_t *toks,
                            int obj_idx, tl_peer_patch_t *pc)
{
    int n = toks[obj_idx].size;
    int next = obj_idx + 1;
    memset(pc, 0, sizeof(*pc));
    for (int k = 0; k < n; k++) {
        const jsmntok_t *key = &toks[next];
        int val_idx = next + 1;
        const jsmntok_t *val = &toks[val_idx];
        if (tok_eq(js, key, "NodeID") && val->type == JSMN_PRIMITIVE) {
            char buf[24];
            if (tok_copy(js, val, buf, sizeof(buf)) > 0) {
                pc->id = strtoull(buf, NULL, 10);
            }
        } else if (tok_eq(js, key, "DERPRegion") && val->type == JSMN_PRIMITIVE) {
            char buf[12];
            if (tok_copy(js, val, buf, sizeof(buf)) > 0) pc->derp_region = atoi(buf);
        } else if (tok_eq(js, key, "Endpoints") && tok_is_arr(val)) {
            /* Present (omitempty) = replace; v6 entries are dropped by
             * parse_endpoints, so a v6-only list replaces with none. */
            parse_endpoints(js, toks, val_idx, pc->endpoints,
                            TL_MAX_PEER_ENDPOINTS, &pc->n_endpoints);
            pc->has_endpoints = true;
        } else if (tok_eq(js, key, "Key") && tok_is_str(val)) {
            pc->has_key = parse_keyed_hex(js + val->start,
                                          (size_t)(val->end - val->start),
                                          "nodekey:", pc->node_pub) == ESP_OK;
        } else if (tok_eq(js, key, "DiscoKey") && tok_is_str(val)) {
            pc->has_disco = parse_keyed_hex(js + val->start,
                                            (size_t)(val->end - val->start),
                                            "discokey:", pc->disco_pub) == ESP_OK;
        }
        next = skip_value(toks, val_idx);
    }
}

/* PeersChangedPatch: array of tailcfg.PeerChange objects, one sub-parse
 * each. Only entries touching Key / DiscoKey / Endpoints / DERPRegion
 * are kept (one per NodeID); they are applied in tinylink.c merge_peers.
 * More than TL_MAX_PEER_PATCHES distinct relevant NodeIDs raise
 * patches_overflow → the caller recycles the stream for a full map
 * instead of applying a partial delta. */
static esp_err_t parse_patch_split(const char *js, size_t len,
                                   tl_netmap_t *out, int *peak)
{
    size_t pos = 0;
    const char *v; size_t vlen; int rc;
    while ((rc = tl_jsplit_arr_next(js, len, &pos, &v, &vlen)) == 1) {
        if (v[0] != '{') continue;
        int n = sub_parse(v, vlen, peak);
        if (n < 1 || !tok_is_obj(&s_toks[0])) {
            out->patches_overflow = true;   /* unparseable: don't guess */
            continue;
        }
        tl_peer_patch_t pc;
        parse_one_patch(v, s_toks, 0, &pc);
        /* Online / LastSeen / KeyExpiry / Cap-only entries carry nothing
         * the data plane uses — headscale sends one per peer (dis)connect
         * and folds a tick's worth into one frame, so counting them would
         * overflow the cap and recycle the stream for nothing. */
        if (pc.id == 0 ||
            !(pc.has_key || pc.has_disco || pc.has_endpoints || pc.derp_region != 0)) {
            continue;
        }
        /* Same NodeID twice in one frame: fold into the first entry, later
         * fields winning, as applying both in order would. */
        size_t j = 0;
        while (j < out->n_patches && out->patches[j].id != pc.id) j++;
        if (j < out->n_patches) {
            tl_peer_patch_t *d = &out->patches[j];
            if (pc.has_key) { d->has_key = true; memcpy(d->node_pub, pc.node_pub, sizeof(d->node_pub)); }
            if (pc.has_disco) { d->has_disco = true; memcpy(d->disco_pub, pc.disco_pub, sizeof(d->disco_pub)); }
            if (pc.has_endpoints) {
                d->has_endpoints = true;
                d->n_endpoints = pc.n_endpoints;
                memcpy(d->endpoints, pc.endpoints, sizeof(d->endpoints));
            }
            if (pc.derp_region != 0) d->derp_region = pc.derp_region;
            continue;
        }
        if (out->n_patches >= TL_MAX_PEER_PATCHES) {
            out->patches_overflow = true;
            continue;
        }
        out->patches[out->n_patches++] = pc;
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
            err = parse_patch_split(kv.val, kv.val_len, out, &peak);
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
