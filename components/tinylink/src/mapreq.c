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
#include "freertos/FreeRTOS.h"
#include "sdkconfig.h"
#include "h2_client.h"
#include "tinylink.h"   /* tinylink_get_public_endpoint */
#endif

#include "ctrl_buf.h"

#define JSMN_STATIC
#include "jsmn.h"
#include "jsmn_skip.h"
#include "tl_addr.h"
#include "tl_date.h"

#ifdef ESP_PLATFORM
static const char *TAG = "mapreq";
#endif

/* Real Tailscale MapResponse for a small tailnet (sensor + home peer)
 * comfortably exceeds 16 KiB once DERP map + DNSConfig + the peer's
 * Hostinfo are folded in (soak peak 25 972 B). Observed 16383-byte
 * truncation on first HW boot 2026-05-02. Since 1.3.4 (D2) no frame is
 * assembled whole: the stream splits it as it arrives and collects one
 * element at a time in the MapResponse area of the shared control buffer
 * (ctrl_buf.h, TL_CTRL_MAPRESP_CAP = 8 KiB); its MapRequest goes out of
 * the buffer's tail (TL_CTRL_REQ_CAP). */
/* jsmn token budget for ONE sub-document. Since 2026-09 the MapResponse
 * is not tokenized as a whole: it is cut into its top-level values (since
 * 1.3.4 on the stream, below) and this table only ever holds the self
 * Node object, one peer object, one DERP region object or one patch
 * entry at a time. The largest of those the sensor logs has 179 tokens
 * (`mapresp peak`); 640 leaves 3.5× headroom and matches the 8 KiB
 * element buffer at ~12.5 B per token, and an oversized element is
 * skipped with a log instead of failing the whole map. Was 2 500 tokens
 * (40 KiB BSS) for the whole document — which also capped the tailnet
 * size the parser could handle at all. 640 × 16 = 10 KiB, in IRAM since
 * 1.3.4 (s_toks below). */
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

/* One jsmn token table for every sub-parse (see SUB_MAX_TOKENS).
 *
 * In IRAM on the target (round 1.3.4, D6): 10 KiB out of DRAM — the
 * byte-addressable memory every heap user competes for — into the IRAM
 * behind the code (56 KB of it unused before; it only competes with
 * future IRAM code, round C3). IRAM takes 32-bit loads and stores only;
 * a byte or half-word access is a LoadStoreError. jsmntok_t is four
 * ints and every use compiles to l32i / s32i: jsmn_parse (inlined into
 * sub_parse), jsmn_tree_ok, jsmn_skip_d, tok_eq / tok_copy (start /
 * end) and the parse_* walkers; no token pointer reaches memcpy /
 * memset / a string function — only `js + tok->start`, which is the
 * element buffer. That is proved on the object code after every build
 * (tools/iram_access_check.py, run from
 * components/tinylink/CMakeLists.txt), because an innocent edit — e.g.
 * `(tok->type & 0xff)`, which GCC compiles to an l8ui — would trap.
 * .iram.bss is IDF's NOLOAD IRAM section (IRAM_BSS_ATTR is only defined
 * with the 8-bit IRAM option, which also zeroes it at boot; nothing
 * here needs that: jsmn writes every token before it is read, and
 * jsmn_tree_ok keeps every walk below the tokens jsmn wrote). */
#ifdef ESP_PLATFORM
#define TL_TOKS_ATTR __attribute__((section(".iram.bss"), aligned(4)))
#else
#define TL_TOKS_ATTR
#endif
static jsmntok_t s_toks[SUB_MAX_TOKENS] TL_TOKS_ATTR;

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

/* Peers / PeersChanged element: one Node object, one sub-parse. The
 * caller stops storing at TL_MAX_PEERS (the rest are drained unparsed). */
static void elem_peer(const char *v, size_t vlen, tl_netmap_t *out, int *peak)
{
    int n = sub_parse(v, vlen, peak);
    if (n < 1 || !tok_is_obj(&s_toks[0])) return;
    parse_one_peer(v, s_toks, 0, &out->peers[out->n_peers]);
    out->n_peers++;
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
                    dn->stun_port = TL_STUN_DEFAULT_PORT;   /* STUNPort omitempty */
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
                            /* Round 1.3.5 (tl_addr.h): the boot dials it
                             * and probes its STUN without DNS. */
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
 * region value until the wanted region is stored; the caller drains the
 * rest unparsed. The key (region id as string) is ignored: RegionID is
 * inside the value too. */
static void elem_region(const char *v, size_t vlen, tl_netmap_t *out, int *peak)
{
    int n = sub_parse(v, vlen, peak);
    if (n < 1 || !tok_is_obj(&s_toks[0])) return;
    tl_derp_region_t *r = &out->derp_regions[out->n_derp_regions];
    parse_one_derp_region(v, s_toks, 0, r);
    if (derp_region_wanted(r->region_id)) {
        out->n_derp_regions++;
    } else {
        memset(r, 0, sizeof(*r));   /* slot reused by the next one */
    }
}

/* End of one DERPMap.Regions object. */
static void regions_done(tl_netmap_t *out, unsigned seen)
{
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

/* PeersRemoved element: a NodeID (JSON number). Anything of 24 bytes or
 * more is no NodeID — the caller does not even store it (REMOVED_LIM). */
#define REMOVED_LIM 23u
static void elem_removed(const char *v, size_t vlen, tl_netmap_t *out)
{
    char buf[REMOVED_LIM + 1];
    if (vlen == 0 || vlen >= sizeof(buf) || v[0] < '0' || v[0] > '9') return;
    memcpy(buf, v, vlen);
    buf[vlen] = '\0';
    out->removed_ids[out->n_removed++] = strtoull(buf, NULL, 10);
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

/* PeersChangedPatch element: one tailcfg.PeerChange object, one
 * sub-parse. Only entries touching Key / DiscoKey / Endpoints /
 * DERPRegion are kept (one per NodeID); they are applied in tinylink.c
 * merge_peers. More than TL_MAX_PEER_PATCHES distinct relevant NodeIDs
 * raise patches_overflow → the caller recycles the stream for a full map
 * instead of applying a partial delta. */
static void elem_patch(const char *v, size_t vlen, tl_netmap_t *out, int *peak)
{
    int n = sub_parse(v, vlen, peak);
    if (n < 1 || !tok_is_obj(&s_toks[0])) {
        out->patches_overflow = true;   /* unparseable: don't guess */
        return;
    }
    tl_peer_patch_t pc;
    parse_one_patch(v, s_toks, 0, &pc);
    /* Online / LastSeen / KeyExpiry / Cap-only entries carry nothing
     * the data plane uses — headscale sends one per peer (dis)connect
     * and folds a tick's worth into one frame, so counting them would
     * overflow the cap and recycle the stream for nothing. */
    if (pc.id == 0 ||
        !(pc.has_key || pc.has_disco || pc.has_endpoints || pc.derp_region != 0)) {
        return;
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
        return;
    }
    if (out->n_patches >= TL_MAX_PEER_PATCHES) {
        out->patches_overflow = true;
        return;
    }
    out->patches[out->n_patches++] = pc;
}

/* ------------------------- streaming splitter ----------------------------
 *
 * Round 1.3.4 (D2). Until 1.3.3 each long-poll frame was assembled whole
 * in the 32 KiB MapResponse area of the shared control buffer (initial
 * netmap 25.9 KB) and then split with jsmn_split.h's iterators: the top
 * object member by member, Peers* / PeersRemoved / PeersChangedPatch
 * element by element, DERPMap → Regions value by value, each element
 * tokenized on its own. This does the same split while the bytes arrive:
 * only the element being collected is stored (mapreq.h), so the buffer
 * shrinks to the largest element — 8 KiB (ctrl_buf.h has the sizing).
 *
 * The old results for any input whose elements fit the buffer, malformed
 * input included. The old split bounded each container by a
 * depth-counting scan of its text from its opening bracket
 * (tl_jsplit_value) BEFORE iterating it, so its members were read from
 * that extent only: an iteration that closed early left the rest of the
 * extent unread, one that ran past it failed. A one-pass grammar only
 * disagrees with that on invalid JSON (a scalar element holding a quote
 * or bracket), but the per-container scan (`ext`, levels ≥ 1) is a few
 * instructions per byte and lets the host test demand identical output
 * for arbitrary input (test_mapresp.c: chunking, every truncation, 40 000
 * random edits against the whole-body parser). */

/* Containers descended into (mapresp_level_t.role). Objects: TOP,
 * DERPMAP, REGIONS; the rest are arrays. */
enum { MS_TOP, MS_PEERS, MS_PEERS_CHANGED, MS_REMOVED, MS_PATCH, MS_DERPMAP, MS_REGIONS };
/* What a value is collected for (mapresp_json_t.vact). */
enum { MV_SKIP, MV_NODE, MV_PEER, MV_REMOVED, MV_PATCH, MV_REGION };
/* Member grammar of tl_jsplit_obj_next / _arr_next, one byte at a time:
 * after a value an object takes `,` or (leniently) the next key at once,
 * a `,` may precede the closing bracket, and nothing may precede the first
 * member. G_VALUE: a member value is being scanned (mapresp_json_t.val).
 * G_CLOSED: closed by the grammar, waiting for the end of its extent. */
enum { G_PRE, G_OBJ_FIRST, G_OBJ_AFTER_VAL, G_OBJ_AFTER_COMMA, G_KEY, G_KEY_ESC,
       G_COLON, G_OBJ_VAL, G_ARR_FIRST, G_ARR_AFTER_VAL, G_ARR_AFTER_COMMA,
       G_VALUE, G_CLOSED };

_Static_assert(TL_JSPLIT_MAX_DEPTH < 255, "tl_jsplit_scan_t counts depth in a byte");
_Static_assert(MS_REGIONS < 8 && MAPRESP_LEVELS <= 8, "fits mapresp_level_t / the ended mask");

static bool ms_is_obj(uint8_t role)
{
    return role == MS_TOP || role == MS_DERPMAP || role == MS_REGIONS;
}

static void ms_fail(mapresp_json_t *m)
{
    if (m->err == ESP_OK) {
        m->err = ESP_ERR_INVALID_RESPONSE;
        m->err_pos = m->pos;
    }
}

static bool ms_key_is(const mapresp_json_t *m, const char *name)
{
    const size_t n = strlen(name);
    return m->key_len == n && memcmp(m->key, name, n) == 0;
}

static void ms_key_add(mapresp_json_t *m, char c)
{
    if (m->key_len < sizeof(m->key)) m->key[m->key_len] = c;
    if (m->key_len < 255) m->key_len++;
}

#ifdef ESP_PLATFORM
static const char *ms_what(uint8_t act)
{
    switch (act) {
    case MV_NODE:  return "Node";
    case MV_PEER:  return "peer";
    case MV_PATCH: return "PeersChangedPatch";
    default:       return "DERP region";
    }
}
#endif

/* A collected value is complete: hand it to its parser. */
static void ms_element(mapresp_json_t *m)
{
    tl_netmap_t *out = m->out;
    if (m->vlen > m->vlim) {
        if (m->vact == MV_REMOVED) return;   /* > REMOVED_LIM: no NodeID, skipped as before */
        /* Larger than the element buffer (round 1.3.4, D2): only its
         * first bytes are stored, so it cannot be parsed. Skipped — the
         * scan has followed it to its end, so the frame goes on in sync;
         * a lost patch could hide a key change, so it recycles the stream
         * for a full map like an unparseable one does. */
        m->n_oversized++;
        if (m->vact == MV_PATCH) out->patches_overflow = true;
#ifdef ESP_PLATFORM
        ESP_LOGE(TAG, "MapResponse %s element of %u B exceeds the %u-B buffer — skipped",
                 ms_what(m->vact), (unsigned)m->vlen, (unsigned)m->elem_cap);
#endif
        return;
    }
    const char *v = m->elem;
    switch (m->vact) {
    case MV_NODE: {
        int n = sub_parse(v, m->vlen, &m->tok_peak);
        if (n >= 1 && tok_is_obj(&s_toks[0])) parse_node_obj(v, s_toks, 0, out);
        break;
    }
    case MV_PEER:    elem_peer(v, m->vlen, out, &m->tok_peak); break;
    case MV_REMOVED: elem_removed(v, m->vlen, out); break;
    case MV_PATCH:   elem_patch(v, m->vlen, out, &m->tok_peak); break;
    case MV_REGION:  elem_region(v, m->vlen, out, &m->tok_peak); break;
    default: break;
    }
}

static void ms_store(mapresp_json_t *m, char c)
{
    if (m->vlen < m->vlim) m->elem[m->vlen] = c;
    m->vlen++;
}

static void ms_value_end(mapresp_json_t *m)
{
    mapresp_level_t *L = &m->lvl[m->n - 1];
    L->g = ms_is_obj(L->role) ? G_OBJ_AFTER_VAL : G_ARR_AFTER_VAL;
    if (m->vact == MV_SKIP) return;
    if (m->vact != MV_REMOVED && m->vlen > m->elem_peak) m->elem_peak = m->vlen;
    ms_element(m);
}

/* First byte of a member value (`c`, not whitespace) in the innermost
 * container: descend into it, collect it or skip it — the old
 * mapresp_parse / *_split dispatch. */
static void ms_value_start(mapresp_json_t *m, char c)
{
    mapresp_level_t *L = &m->lvl[m->n - 1];
    tl_netmap_t *out = m->out;
    uint8_t act = MV_SKIP;
    int sub = -1;
    switch (L->role) {
    case MS_TOP:
        if (c == '{' && ms_key_is(m, "Node")) act = MV_NODE;
        /* Peers: the full list, the caller replaces its table.
         * PeersChanged: a stream-mode delta, upserted. The control plane
         * sends the whole list this way on the first MapResponse
         * (observed 2026-05-02), which merges into an empty table
         * identically to a full list. */
        else if (c == '[' && ms_key_is(m, "Peers"))             sub = MS_PEERS;
        else if (c == '[' && ms_key_is(m, "PeersChanged"))      sub = MS_PEERS_CHANGED;
        else if (c == '[' && ms_key_is(m, "PeersRemoved"))      sub = MS_REMOVED;
        else if (c == '[' && ms_key_is(m, "PeersChangedPatch")) sub = MS_PATCH;
        else if (c == '{' && ms_key_is(m, "DERPMap"))           sub = MS_DERPMAP;
        /* Everything else (DNSConfig, PacketFilter, UserProfiles, ...) is
         * scanned past without being stored or tokenized. */
        break;
    case MS_PEERS:
    case MS_PEERS_CHANGED:
        if (out->n_peers < TL_MAX_PEERS) act = MV_PEER;   /* keep draining; cap like before */
        break;
    case MS_REMOVED:
        if (out->n_removed >= TL_MAX_PEERS_REMOVED) out->removed_overflow = true;
        else act = MV_REMOVED;
        break;
    case MS_PATCH:
        if (c == '{') act = MV_PATCH;
        break;
    case MS_DERPMAP:
        if (c == '{' && ms_key_is(m, "Regions")) sub = MS_REGIONS;
        break;
    case MS_REGIONS:
        m->regions_seen++;
        if (out->n_derp_regions < TL_MAX_DERP_REGIONS) act = MV_REGION;
        break;
    default:
        break;
    }
    if (sub >= 0) {
        /* Only TOP and DERPMAP descend: at most MAPRESP_LEVELS deep. */
        if (m->n >= MAPRESP_LEVELS) { ms_fail(m); return; }
        mapresp_level_t *D = &m->lvl[m->n++];
        D->role = (uint8_t)sub;
        D->g = (c == '{') ? G_OBJ_FIRST : G_ARR_FIRST;
        (void)tl_jsplit_scan_begin(&D->ext, c);   /* a bracket: cannot fail */
        if (sub == MS_PEERS || sub == MS_PEERS_CHANGED) out->n_peers = 0;
        else if (sub == MS_DERPMAP) out->n_derp_regions = 0;
        else if (sub == MS_REGIONS) m->regions_seen = 0;
        return;
    }
    if (tl_jsplit_scan_begin(&m->val, c) != TL_JSCAN_MORE) { ms_fail(m); return; }
    L->g = G_VALUE;
    m->vact = act;
    m->vlen = 0;
    m->vlim = (act == MV_SKIP) ? 0 : (act == MV_REMOVED) ? REMOVED_LIM : m->elem_cap;
    ms_store(m, c);
}

/* The innermost container's closing bracket, as its grammar sees it. */
static void ms_close(mapresp_json_t *m)
{
    mapresp_level_t *L = &m->lvl[m->n - 1];
    if (m->n == 1) { m->done = true; return; }   /* trailing bytes are ignored, as before */
    if (L->role == MS_PEERS) m->out->peers_is_delta = false;
    else if (L->role == MS_PEERS_CHANGED) m->out->peers_is_delta = true;
    else if (L->role == MS_REGIONS) regions_done(m->out, m->regions_seen);
    L->g = G_CLOSED;   /* popped when its extent ends — normally at this byte */
}

/* One byte of member grammar in the innermost container. */
static void ms_grammar(mapresp_json_t *m, char c)
{
    mapresp_level_t *L = &m->lvl[m->n - 1];
again:
    switch (L->g) {
    case G_PRE:
        if (tl_jsplit_is_ws(c)) return;
        if (c == '{') { L->g = G_OBJ_FIRST; return; }
        break;
    case G_OBJ_AFTER_VAL:
        if (c == ',') { L->g = G_OBJ_AFTER_COMMA; return; }
        /* fall through */
    case G_OBJ_FIRST:
    case G_OBJ_AFTER_COMMA:
        if (tl_jsplit_is_ws(c)) return;
        if (c == '}') { ms_close(m); return; }
        if (c == '"') { L->g = G_KEY; m->key_len = 0; return; }
        break;
    case G_KEY:
        if (c == '"') { L->g = G_COLON; return; }
        if (c == '\\') L->g = G_KEY_ESC;
        ms_key_add(m, c);          /* raw bytes, escapes intact (tl_jsplit_key_is) */
        return;
    case G_KEY_ESC:
        L->g = G_KEY;
        ms_key_add(m, c);
        return;
    case G_COLON:
        if (tl_jsplit_is_ws(c)) return;
        if (c == ':') { L->g = G_OBJ_VAL; return; }
        break;
    case G_OBJ_VAL:
        if (tl_jsplit_is_ws(c)) return;
        ms_value_start(m, c);
        return;
    case G_ARR_AFTER_VAL:
        if (c == ',') { L->g = G_ARR_AFTER_COMMA; return; }
        /* fall through */
    case G_ARR_FIRST:
    case G_ARR_AFTER_COMMA:
        if (tl_jsplit_is_ws(c)) return;
        if (c == ']') { ms_close(m); return; }
        ms_value_start(m, c);      /* a misplaced `}` / `,` fails there */
        return;
    case G_VALUE: {
        int r = tl_jsplit_scan_byte(&m->val, c);
        if (r == TL_JSCAN_ERR) break;
        if (r == TL_JSCAN_END_BEFORE) {     /* a scalar's delimiter: the container's byte */
            ms_value_end(m);                /* L->g is an AFTER_VAL state now */
            goto again;
        }
        ms_store(m, c);
        if (r == TL_JSCAN_END) ms_value_end(m);
        return;
    }
    default:   /* G_CLOSED: the rest of its extent is not read */
        return;
    }
    ms_fail(m);
}

static void ms_byte(mapresp_json_t *m, char c)
{
    /* The extents of the open containers below the top object (each scan
     * started at its opening bracket), fed before the grammar so a
     * container pushed at this byte is not fed it twice. */
    unsigned ended = 0;
    const unsigned n_before = m->n;
    for (unsigned k = 1; k < n_before; k++) {
        int r = tl_jsplit_scan_byte(&m->lvl[k].ext, c);
        if (r == TL_JSCAN_ERR) { ms_fail(m); return; }   /* deeper than TL_JSPLIT_MAX_DEPTH */
        if (r == TL_JSCAN_END) ended |= 1u << k;
    }
    ms_grammar(m, c);
    if (m->err != ESP_OK) return;
    /* A closed container is popped where its extent ends; an extent that
     * ends inside a still-open container is the old iteration running off
     * the end of its text. */
    while (m->n > 1 && m->n <= n_before) {
        const unsigned k = m->n - 1u;
        if (m->lvl[k].g != G_CLOSED || !(ended & (1u << k))) break;
        ended &= ~(1u << k);
        m->n--;
        mapresp_level_t *P = &m->lvl[m->n - 1];
        P->g = ms_is_obj(P->role) ? G_OBJ_AFTER_VAL : G_ARR_AFTER_VAL;
    }
    if (ended != 0) ms_fail(m);
}

void mapresp_json_begin(mapresp_json_t *m, char *elem, size_t elem_cap,
                        tl_netmap_t *out)
{
    memset(m, 0, sizeof(*m));
    m->out = out;
    m->elem = elem;
    m->elem_cap = elem_cap;
    m->n = 1;
    m->lvl[0].role = MS_TOP;
    m->lvl[0].g = G_PRE;
    tl_netmap_clear(out);
}

/* Bytes some scanner reacts to inside a value: quotes, escapes, brackets,
 * the scalar delimiters `,` / whitespace (and control bytes, harmlessly).
 * A 256-bit set. */
static const uint8_t k_ms_special[32] = {
    0xff, 0xff, 0xff, 0xff,   /* 0x00-0x1f */
    0x05,                     /* 0x20 ' ', 0x22 '"' */
    0x10,                     /* 0x2c ',' */
    0, 0, 0, 0, 0,
    0x38,                     /* 0x5b '[', 0x5c '\\', 0x5d ']' */
    0, 0, 0,
    0x28,                     /* 0x7b '{', 0x7d '}' */
};

static bool ms_special(unsigned char c)
{
    return (k_ms_special[c >> 3] >> (c & 7)) & 1;
}

/* How many bytes from `p` change no scanner state: inside a member value,
 * the content of a string (when every extent scan is inside it too) or a
 * run of letters / digits. Most of a MapResponse — and of every skipped
 * member — is that, so the per-byte machinery only runs on structure. */
static size_t ms_inert_run(const mapresp_json_t *m, const char *p, size_t n)
{
    if (m->lvl[m->n - 1].g != G_VALUE || m->val.mode == TL_JSCAN_ESC) return 0;
    bool in_str = (m->val.mode == TL_JSCAN_STR);
    for (unsigned k = 1; k < m->n; k++) {
        const unsigned char mode = m->lvl[k].ext.mode;
        if (mode == TL_JSCAN_ESC) return 0;
        if (mode != TL_JSCAN_STR) in_str = false;
    }
    size_t r = 0;
    if (in_str) {
        while (r < n && p[r] != '"' && p[r] != '\\') r++;
    } else {
        while (r < n && !ms_special((unsigned char)p[r])) r++;
    }
    return r;
}

void mapresp_json_feed(mapresp_json_t *m, const char *data, size_t len)
{
    size_t i = 0;
    while (i < len && m->err == ESP_OK && !m->done) {
        const size_t run = ms_inert_run(m, data + i, len - i);
        if (run > 0) {
            if (m->vlen < m->vlim) {
                const size_t room = m->vlim - m->vlen;
                memcpy(m->elem + m->vlen, data + i, run < room ? run : room);
            }
            m->vlen += run;
            m->pos += run;
            i += run;
            continue;
        }
        ms_byte(m, data[i]);
        m->pos++;
        i++;
    }
}

esp_err_t mapresp_json_end(mapresp_json_t *m)
{
    if (!m->done) ms_fail(m);   /* the old split ran off the end of the body */
    return m->err;
}

/* ------------------------------ framing ---------------------------------- */

/* The control plane frames each MapResponse as `LE32 size || body`
 * (tailscale/control/controlclient/direct.go readMapResponseMessage).
 * With the body parsed on the fly a frame no longer has to fit a buffer;
 * the cap only keeps a desynchronised stream from waiting forever (four
 * JSON bytes read as a size are ≥ 512 MiB). Upstream allows 256 MiB of
 * zstd; 4 MiB is 160× today's initial netmap. Over the cap the stream
 * stops and long-poll reconnects, as an over-32-KiB frame did before. */
void mapresp_stream_init(mapresp_stream_t *ms, char *elem, size_t elem_cap,
                         tl_netmap_t *nm, mapresp_frame_fn on_frame, void *ctx)
{
    memset(ms, 0, sizeof(*ms));
    ms->elem = elem;
    ms->elem_cap = elem_cap;
    ms->nm = nm;
    ms->on_frame = on_frame;
    ms->ctx = ctx;
}

int mapresp_stream_feed(mapresp_stream_t *ms, const uint8_t *data, size_t len)
{
    size_t off = 0;
    while (off < len) {
        if (!ms->in_body) {
            ms->hdr[ms->hdr_have++] = data[off++];
            if (ms->hdr_have < 4) continue;
            ms->hdr_have = 0;
            ms->body_size = ((uint32_t)ms->hdr[0])       |
                            ((uint32_t)ms->hdr[1] <<  8) |
                            ((uint32_t)ms->hdr[2] << 16) |
                            ((uint32_t)ms->hdr[3] << 24);
            if (ms->body_size > MAPRESP_FRAME_MAX) {
#ifdef ESP_PLATFORM
                ESP_LOGE(TAG, "MapResponse too large: %u > %u",
                         (unsigned)ms->body_size, (unsigned)MAPRESP_FRAME_MAX);
#endif
                return -1;
            }
            ms->body_have = 0;
            ms->in_body = true;
            mapresp_json_begin(&ms->json, ms->elem, ms->elem_cap, ms->nm);
        } else {
            size_t take = len - off;
            if (take > ms->body_size - ms->body_have) take = ms->body_size - ms->body_have;
            mapresp_json_feed(&ms->json, (const char *)data + off, take);
            ms->body_have += (uint32_t)take;
            off += take;
        }
        if (ms->in_body && ms->body_have == ms->body_size) {
            ms->in_body = false;
            esp_err_t pe = mapresp_json_end(&ms->json);
            if (ms->on_frame != NULL && ms->on_frame(ms, pe, ms->ctx) != 0) return -1;
        }
    }
    return 0;
}

#ifndef ESP_PLATFORM
esp_err_t mapresp_parse(const char *json, size_t json_len, tl_netmap_t *out)
{
    static char elem[TL_CTRL_MAPRESP_CAP];
    if (json == NULL || out == NULL) return ESP_ERR_INVALID_ARG;
    mapresp_json_t m;
    mapresp_json_begin(&m, elem, sizeof(elem), out);
    mapresp_json_feed(&m, json, json_len);
    return mapresp_json_end(&m);
}
#endif

/* ------------------------------ MapRequest -------------------------------- */

#ifdef ESP_PLATFORM

/* The shared control buffer (ctrl_buf.h has the layout and the proof
 * that its users are never live at the same time). Defined here because
 * the MapResponse stream is its biggest user. */
static uint8_t     s_ctrl_buf[TL_CTRL_BUF_SZ] __attribute__((aligned(4)));
static const char *s_ctrl_owner;
static portMUX_TYPE s_ctrl_mux = portMUX_INITIALIZER_UNLOCKED;

uint8_t *tl_ctrl_buf_claim(const char *who)
{
    const char *prev;
    taskENTER_CRITICAL(&s_ctrl_mux);
    prev = s_ctrl_owner;
    if (prev == NULL) s_ctrl_owner = who;
    taskEXIT_CRITICAL(&s_ctrl_mux);
    if (prev != NULL) {
        ESP_LOGE(TAG, "control buffer busy (%s) — %s refused", prev, who);
        return NULL;
    }
    return s_ctrl_buf;
}

void tl_ctrl_buf_release(void)
{
    taskENTER_CRITICAL(&s_ctrl_mux);
    s_ctrl_owner = NULL;
    taskEXIT_CRITICAL(&s_ctrl_mux);
}

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

static esp_err_t push_endpoints_in(ts2021_conn_t *conn,
                                   const tinylink_keys_t *keys, uint8_t *buf)
{
    /* Request from the buffer's MapRequest tail (TL_CTRL_REQ_CAP, the
     * 1 KiB this always had — a minimal Hostinfo + Endpoints body is
     * ~600 B at most), response at offset 0. */
    char *body = (char *)buf + TL_CTRL_REQ_OFF;
    int body_len = build_request_body(keys, /*stream=*/false,
                                      /*omit_peers=*/true,
                                      body, TL_CTRL_REQ_CAP);
    if (body_len < 0) return ESP_ERR_INVALID_SIZE;

    /* The server is documented to be allowed to omit the response
     * body entirely (tailcfg.go MapRequest.OmitPeers comment). 256 B
     * is plenty whether the body is empty, "{}", or a tiny error
     * message — we only check the HTTP status. */
    uint8_t *resp = buf;
    size_t resp_len = 0;
    int status = 0;
    esp_err_t err = h2_post_json(conn, "/machine/map",
                                 CONFIG_TINYLINK_CONTROL_HOST,
                                 (const uint8_t *)body, (size_t)body_len,
                                 &status, resp, 256, &resp_len);
    if (err != ESP_OK) {
        /* A recycle or the request deadline is logged once in ts2021
         * (I / W), the consequence by the caller (round 1.3.5). */
        if (conn->aborted || conn->req_expired) {
            ESP_LOGD(TAG, "endpoint push left: %s", conn->aborted ? "recycle" : "deadline");
        } else {
            ESP_LOGE(TAG, "endpoint push h2_post_json failed: 0x%x", err);
        }
        return err;
    }
    ESP_LOGI(TAG, "endpoint push: HTTP %d (resp %u B)",
             status, (unsigned)resp_len);
    if (status != 200) {
        if (status == 429 || status == 503) {
            ESP_LOGW(TAG, "endpoint push throttled: HTTP %d "
                          "(Retry-After %s, %d s valid)",
                     status, conn->h2_retry_after_present ? "set" : "absent",
                     conn->h2_retry_after_s);
        } else {
            ESP_LOGE(TAG, "endpoint push HTTP %d (server rejected lite update)",
                     status);
        }
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t mapreq_push_endpoints(ts2021_conn_t *conn,
                                const tinylink_keys_t *keys)
{
    if (conn == NULL || keys == NULL) return ESP_ERR_INVALID_ARG;
    uint8_t *buf = tl_ctrl_buf_claim("endpoint push");
    if (buf == NULL) return ESP_ERR_INVALID_STATE;
    esp_err_t err = push_endpoints_in(conn, keys, buf);
    tl_ctrl_buf_release();
    return err;
}


/* ---- streaming reader ----------------------------------------------------
 *
 * The chunk callback feeds the DATA bytes, split anywhere (the HTTP/2
 * layer delivers partial / multiple frames per DATA frame), into the framing +
 * splitter above (round 1.3.4, D2); each complete frame lands in
 * stream_frame. Until 1.3.3 every frame was first assembled whole in
 * the shared control buffer's 32 KiB MapResponse area.
 */

typedef struct {
    mapresp_stream_t ms;
    /* Higher-level callback fired once per parsed MapResponse. */
    mapreq_handler_t on_netmap;
    void            *handler_ctx;
} stream_state_t;

/* Returns 0 to keep the stream running, -1 to stop it (the caller's
 * chunk callback propagates the stop through the HTTP/2 layer so the long-poll
 * task tears the conn down and reconnects — used when a frame demands
 * a full-netmap refetch we can't satisfy in-stream). */
static int stream_frame(const mapresp_stream_t *ms, esp_err_t pe, void *ctx)
{
    /* Hand every frame that carries something the data plane consumes —
     * self node, Peers / PeersChanged, PeersRemoved, PeersChangedPatch,
     * DERPMap — to the handler, which merges deltas (tinylink.c
     * merge_peers). KeepAlive frames parse to none of those and are
     * absorbed here. */
    /* The 2026-05-02 framing diagnostic (hex dump of the first 16 bytes
     * + six memcmp-per-byte substring scans over the whole body, three
     * INFO lines per frame) was removed 2026-09: the framing question it
     * answered (plain JSON vs zstd) has been settled since M2, and it
     * cost up to 6 × 32 KiB comparisons plus ~250 B of UART output on
     * every frame of the long-poll hot path. The parse reports the same
     * field presence (n_peers, keepalive, patch flags). */
    stream_state_t *s = (stream_state_t *)ctx;
    const mapresp_json_t *j = &ms->json;
    const tl_netmap_t *nm = j->out;

    /* Soak observability, per frame: its size, and the largest element
     * the splitter had to hold against the element buffer — grep
     * `stream peak:` over a multi-hour log and take the max of `elem` to
     * size TL_CTRL_MAPRESP_CAP (ctrl_buf.h) against. Since 1.3.4 the
     * body no longer has a buffer to fit. */
    ESP_LOGI(TAG, "stream peak: body=%u elem=%u (cap=%u)",
             (unsigned)ms->body_size, (unsigned)j->elem_peak,
             (unsigned)ms->elem_cap);
    if (pe != ESP_OK) {
        ESP_LOGE(TAG, "MapResponse malformed at byte %u of %u",
                 (unsigned)j->err_pos, (unsigned)ms->body_size);
        ESP_LOGW(TAG, "MapResponse parse failed (size=%u err=0x%x free_heap=%u largest_block=%u)",
                 (unsigned)ms->body_size, (unsigned)pe,
                 (unsigned)esp_get_free_heap_size(),
                 (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));
        return 0;
    }
    /* Largest single sub-parse this message. */
    ESP_LOGI(TAG, "mapresp peak: tokens=%d/%d body=%u",
             j->tok_peak, SUB_MAX_TOKENS, (unsigned)ms->body_size);
    if (nm->patches_overflow || nm->removed_overflow) {
        /* More deltas than the per-frame caps (netmap.h): applying a
         * partial delta could leave a peer with stale keys or endpoints.
         * Recycle — the reconnect's first frame is a full netmap
         * (headscale f4eeb94b; tailscale.com always did). */
        ESP_LOGW(TAG, "delta frame over caps (patches%s removed%s) — "
                      "recycling stream for a full netmap",
                 nm->patches_overflow ? "+" : "", nm->removed_overflow ? "+" : "");
        return -1;
    }
    if (!nm->have_self && nm->n_peers == 0 && nm->n_removed == 0 &&
        nm->n_patches == 0 && !nm->have_derp_map) {
        /* KeepAlive, or a frame carrying only fields tinylink does not
         * consume (DNSConfig, SSHPolicy, PacketFilter, Debug, ...).
         * headscale sends removals and DERPMap updates as frames of their
         * own (batcher withRemovals, change.go), so those must NOT be
         * folded in here. */
        ESP_LOGD(TAG, "KeepAlive (%u bytes)", (unsigned)ms->body_size);
        return 0;
    }
    if (s->on_netmap != NULL &&
        s->on_netmap(nm, s->handler_ctx) == MAPREQ_STREAM_RECYCLE) {
        return -1;
    }
    return 0;
}

static int stream_chunk_cb(const uint8_t *data, size_t len, void *ctx)
{
    /* Any byte from the control plane — netmap, delta, KeepAlive, even
     * an error body — proves the control path works end-to-end. Feeds
     * the wedge-restart last resort in tinylink.c. */
    tinylink_control_mark_alive();

    /* -1 (a frame over MAPRESP_FRAME_MAX, or stream_frame asking for a
     * recycle) propagates through data_chunk_cb → h2_cb_stop →
     * h2_drive_request unwinds; long-poll reconnects. */
    stream_state_t *s = (stream_state_t *)ctx;
    return mapresp_stream_feed(&s->ms, data, len);
}

/* The endpoint push riding with the stream answered (round 1.3.7, B1):
 * the push's own log line, at the time it lands — the stream goes on. */
static void push_side_done(int status, int stream_error, void *ctx)
{
    *(int *)ctx = status > 0 ? status : -1;
    if (status == 200) {
        ESP_LOGI(TAG, "endpoint push: HTTP 200 (with the map stream)");
    } else if (status == 429 || status == 503) {
        ESP_LOGW(TAG, "endpoint push throttled: HTTP %d", status);
    } else if (status > 0) {
        ESP_LOGE(TAG, "endpoint push HTTP %d (server rejected lite update)", status);
    } else {
        ESP_LOGW(TAG, "endpoint push: stream reset (HTTP/2 error 0x%x)",
                 (unsigned)stream_error);
    }
}

static esp_err_t run_stream_in(ts2021_conn_t *conn,
                               const tinylink_keys_t *keys,
                               mapreq_handler_t on_netmap, void *ctx,
                               uint8_t *buf, int *push_status)
{
    /* MapRequest from the buffer's tail, MapResponse elements collected at
     * offset 0 — disjoint: nghttp2 (until 1.3.4) could still be reading
     * the request body while response DATA arrived; the in-tree client
     * seals the body before it reads, so this is now only a margin. */
    char *body = (char *)buf + TL_CTRL_REQ_OFF;
    int body_len = build_request_body(keys, true, false, body, TL_CTRL_REQ_CAP);
    if (body_len < 0) return ESP_ERR_INVALID_SIZE;

    /* The parse state lives in BSS like the element buffer (the shared
     * control buffer) and the netmap, so the stream task stack stays
     * small; one stream at a time (the buffer claim). */
    static tl_netmap_t    nm;   /* ~2.5 KiB (peers + patches); reused */
    static stream_state_t s;
    mapresp_stream_init(&s.ms, (char *)buf, TL_CTRL_MAPRESP_CAP, &nm,
                        stream_frame, &s);
    s.on_netmap   = on_netmap;
    s.handler_ctx = ctx;

    int status = 0;
    esp_err_t err = ESP_ERR_INVALID_SIZE;
    if (push_status != NULL) {
        /* The endpoint push goes as a second HTTP/2 stream ahead of the
         * map stream, in the same burst (round 1.3.7, B1) — upstream's
         * updateRoutine runs its lite update alongside the poll the same
         * way. Its body sits in the element area: h2_post_json_stream_side
         * sends it whole before the first response byte can land there. */
        *push_status = 0;
        const int push_len = build_request_body(keys, /*stream=*/false,
                                                /*omit_peers=*/true,
                                                (char *)buf, TL_CTRL_REQ_CAP);
        if (push_len < 0) return ESP_ERR_INVALID_SIZE;
        err = h2_post_json_stream_side(conn, "/machine/map",
                                       CONFIG_TINYLINK_CONTROL_HOST,
                                       buf, (size_t)push_len,
                                       push_side_done, push_status,
                                       (const uint8_t *)body, (size_t)body_len,
                                       &status, stream_chunk_cb, &s);
        if (err == ESP_ERR_INVALID_SIZE) {
            /* A server window under the push's size (never seen): push,
             * then the stream, one after the other as before 1.3.7. The
             * push's body went where the stream's was. */
            err = push_endpoints_in(conn, keys, buf);
            *push_status = err == ESP_OK ? 200 : conn->h2_status;
            if (err != ESP_OK && conn->h2_status == 0) return err;   /* unanswered */
            body_len = build_request_body(keys, true, false, body, TL_CTRL_REQ_CAP);
            if (body_len < 0) return ESP_ERR_INVALID_SIZE;
            err = ESP_ERR_INVALID_SIZE;
        }
    }
    if (err == ESP_ERR_INVALID_SIZE) {
        err = h2_post_json_stream(conn, "/machine/map",
                                  CONFIG_TINYLINK_CONTROL_HOST,
                                  (const uint8_t *)body,
                                  (size_t)body_len,
                                  &status, stream_chunk_cb, &s);
    }
    if (err != ESP_OK) {
        /* A requested recycle (endpoint push, IP change) is no error: its
         * one line is ts2021's "control stream read aborted on request"
         * (round 1.3.5; it logged two E lines here and in h2 before) … */
        if (conn->aborted || conn->req_expired) {
            /* … nor is the push's deadline: ts2021 has its W line. */
            ESP_LOGD(TAG, "map stream left: %s", conn->aborted ? "recycle" : "push deadline");
        } else {
            ESP_LOGE(TAG, "h2_post_json_stream failed: 0x%x", err);
        }
        return err;
    }
    if (status != 200) {
        if (status == 429 || status == 503) {
            ESP_LOGW(TAG, "/machine/map (stream) throttled: HTTP %d "
                          "(Retry-After %s, %d s valid)",
                     status, conn->h2_retry_after_present ? "set" : "absent",
                     conn->h2_retry_after_s);
        } else {
            ESP_LOGE(TAG, "/machine/map (stream) returned HTTP %d", status);
        }
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "/machine/map stream closed cleanly");
    return ESP_OK;
}

esp_err_t mapreq_run_stream(ts2021_conn_t *conn,
                            const tinylink_keys_t *keys,
                            mapreq_handler_t on_netmap, void *ctx,
                            int *push_status)
{
    if (conn == NULL || keys == NULL || on_netmap == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    uint8_t *buf = tl_ctrl_buf_claim("map stream");
    if (buf == NULL) return ESP_ERR_INVALID_STATE;
    esp_err_t err = run_stream_in(conn, keys, on_netmap, ctx, buf, push_status);
    tl_ctrl_buf_release();
    return err;
}

#endif /* ESP_PLATFORM */
