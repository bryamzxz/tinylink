// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "mapreq.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include "esp_log.h"
#include "sdkconfig.h"
#include "h2_client.h"
#endif

#define JSMN_STATIC
#include "jsmn.h"

#ifdef ESP_PLATFORM
static const char *TAG = "mapreq";
#endif

#define REQUEST_BUF_SZ   2048
#define RESPONSE_BUF_SZ  16384  /* a bare /machine/map for one peer fits well under */
#define MAX_TOKENS       1024

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

    /* Token budget: a one-peer + minimal-DERP MapResponse runs ~120 tokens,
     * a 4-peer / 4-region one peaks around ~600. 1024 leaves headroom and
     * still costs only ~16 KiB at sizeof(jsmntok_t)=16 — comparable to the
     * response buffer itself, and freed as soon as parsing returns. */
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

static int build_request_body(const tinylink_keys_t *keys,
                              char *out, size_t out_size)
{
    char node_key_hex[8 + 64 + 1];
    char disco_key_hex[9 + 64 + 1];

    memcpy(node_key_hex, "nodekey:", 8);
    hex_encode(keys->node_pub, 32, node_key_hex + 8);

    memcpy(disco_key_hex, "discokey:", 9);
    hex_encode(keys->disco_pub, 32, disco_key_hex + 9);

    /* MapRequest with Stream:false → server returns one MapResponse and
     * closes. Compress:"" disables zstd (we don't link zstd). Hostinfo is
     * intentionally minimal; the server treats it as informational when
     * we're already registered. */
    int n = snprintf(out, out_size,
        "{"
        "\"Version\":1,"
        "\"Compress\":\"\","
        "\"NodeKey\":\"%s\","
        "\"DiscoKey\":\"%s\","
        "\"Stream\":false,"
        "\"Hostinfo\":{\"OS\":\"esp32\",\"Hostname\":\"%s\",\"IPNVersion\":\"0.1.0-tinylink\"}"
        "}",
        node_key_hex, disco_key_hex,
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

    static char    body[REQUEST_BUF_SZ];
    int body_len = build_request_body(keys, body, sizeof(body));
    if (body_len < 0) return ESP_ERR_INVALID_SIZE;

    static uint8_t resp[RESPONSE_BUF_SZ];
    size_t  resp_len = 0;
    int     status = 0;
    esp_err_t err = h2_post_json(conn, "/machine/map",
                                 CONFIG_TINYLINK_CONTROL_HOST,
                                 (const uint8_t *)body, (size_t)body_len,
                                 &status, resp, sizeof(resp) - 1, &resp_len);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "h2_post_json failed: 0x%x", err);
        return err;
    }
    resp[resp_len] = '\0';
    ESP_LOGI(TAG, "/machine/map status=%d body=%u bytes",
             status, (unsigned)resp_len);
    if (status != 200) {
        ESP_LOGE(TAG, "control plane returned HTTP %d", status);
        return ESP_FAIL;
    }
    return mapresp_parse((const char *)resp, resp_len, out);
}

#endif /* ESP_PLATFORM */
