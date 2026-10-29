// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Host-side smoke test for the MapResponse parser. Feeds a stub JSON
// modeled on a real Tailscale MapResponse (single peer + minimal DERP
// map) and asserts the extracted fields match. The stub deliberately
// includes both v4 and v6 addresses to verify the v6 drop logic, plus
// extra fields the parser should ignore.

/* mapreq.h auto-typedefs esp_err_t and the relevant ESP_ERR_* macros
 * when ESP_PLATFORM isn't defined, and skips the ESP-only declarations,
 * so we can include it directly here. */

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../components/tinylink/src/netmap.h"
#include "../../components/tinylink/src/mapreq.h"
#include "../../components/tinylink/src/ctrl_buf.h"

/* The 1.3.3 whole-body parser (ref/mapresp_133.c), the oracle for the
 * round-1.3.4 streaming splitter (D2). */
esp_err_t ref_mapresp_parse(const char *json, size_t json_len, tl_netmap_t *out);

static int stream_suite(void);

static const char *kStub =
"{"
  "\"Node\":{"
    "\"ID\":42,"
    "\"Name\":\"sensor-cali.tail-scale.ts.net.\","
    "\"Addresses\":[\"100.64.0.7/32\",\"fd7a:115c:a1e0::7/128\"]"
  "},"
  "\"Peers\":["
    "{"
      "\"ID\":99,"
      "\"Key\":\"nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\","
      "\"DiscoKey\":\"discokey:202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\","
      "\"Addresses\":[\"100.64.0.8/32\"],"
      "\"Endpoints\":[\"203.0.113.5:41641\",\"[2001:db8::1]:41641\",\"192.168.1.5:41641\"],"
      "\"HomeDERP\":13"
    "}"
  "],"
  "\"DERPMap\":{"
    "\"Regions\":{"
      "\"13\":{"
        "\"RegionID\":13,"
        "\"RegionCode\":\"par\","
        "\"Nodes\":["
          "{\"Name\":\"13a\",\"RegionID\":13,\"HostName\":\"derp13.tailscale.com\",\"DERPPort\":443}"
        "]"
      "},"
      "\"16\":{"
        "\"RegionID\":16,"
        "\"RegionCode\":\"mia\","
        "\"Nodes\":["
          "{\"Name\":\"16b\",\"RegionID\":16,\"HostName\":\"derp16b.tailscale.com\",\"DERPPort\":443}"
        "]"
      "}"
    "}"
  "},"
  "\"DomainDataPlaneAuditLogID\":\"ignored\""
"}";

/* --- Real-shaped DERPMap (1.3.2: keep only the region in use) -------
 * Tailscale's default map: 28 regions, each with RegionCode/Name,
 * coordinates and 2–4 nodes carrying IPv4/IPv6/CanPort80. Go's
 * encoding/json writes the map[int] keys as sorted STRINGS, so region
 * 16 is the 8th object, not the first — and the parser must keep it by
 * RegionID whatever the order (the 2026-05 cap=4 build kept the first
 * four and lost it). */
static const int kGoKeyOrder[28] = {
    1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 2, 20, 21,
    22, 23, 24, 25, 26, 27, 28, 3, 4, 5, 6, 7, 8, 9,
};
static const char *const kRegionCode[29] = {
    "", "nyc", "sfo", "sin", "fra", "syd", "blr", "tok", "lhr", "dfw",
    "sea", "sao", "ord", "den", "ams", "jnb", "mia", "lax", "par", "mad",
    "hkg", "tor", "waw", "dbi", "hnl", "nai", "iad", "sjc", "bom",
};

/* order: 0 = Go key order, 1 = reversed (16 near the end), 2 = Go order
 * without region 16. */
static size_t build_derpmap(char *out, size_t cap, int order)
{
    size_t o = 0;
    o += (size_t)snprintf(out + o, cap - o, "{\"DERPMap\":{\"Regions\":{");
    int first = 1;
    for (int k = 0; k < 28; k++) {
        const int id = kGoKeyOrder[order == 1 ? 27 - k : k];
        if (order == 2 && id == 16) continue;
        const int nodes = (id == 16) ? 4 : 2 + (id % 2);
        o += (size_t)snprintf(out + o, cap - o,
            "%s\"%d\":{\"RegionID\":%d,\"RegionCode\":\"%s\","
            "\"RegionName\":\"Region %s\",\"Latitude\":%d.25,\"Longitude\":-%d.5,"
            "\"Nodes\":[",
            first ? "" : ",", id, id, kRegionCode[id], kRegionCode[id], id, id + 40);
        first = 0;
        for (int n = 0; n < nodes; n++) {
            o += (size_t)snprintf(out + o, cap - o,
                "%s{\"Name\":\"%d%c\",\"RegionID\":%d,"
                "\"HostName\":\"derp%d%c.tailscale.com\","
                "\"IPv4\":\"198.51.%d.%d\",\"IPv6\":\"2001:db8:%x::%x\","
                "\"CanPort80\":true}",
                n ? "," : "", id, 'b' + n, id, id, 'b' + n, id, n + 1, id, n + 1);
        }
        o += (size_t)snprintf(out + o, cap - o, "]}");
    }
    o += (size_t)snprintf(out + o, cap - o,
        "},\"HomeParams\":{\"RegionScore\":{\"16\":0.8}}},"
        "\"KeepAlive\":false}");
    return o < cap ? o : 0;
}

/* Round 1.3.5: a DERP node's IPv4 and STUNPort (tl_addr.h), the fields
 * the boot uses to reach the home node without DNS. IPv4 is kept only as
 * a dotted quad Go's netip.ParseAddr would take; anything else — "none"
 * (tailcfg's "IPv4 disabled"), IPv6, a name, leading zeros — is none, and
 * the node is dialed by HostName as before. STUNPort: absent / 0 = 3478,
 * -1 or out of range = no STUN. */
static int derp_node_case(const char *name, const char *fields,
                          const uint8_t want_ip[4], unsigned want_stun)
{
    char js[512];
    static tl_netmap_t nm;
    snprintf(js, sizeof(js),
             "{\"DERPMap\":{\"Regions\":{\"16\":{\"RegionID\":16,\"Nodes\":["
             "{\"Name\":\"16b\",\"RegionID\":16,\"HostName\":\"derp16b.example\"%s%s}]}}}}",
             fields[0] ? "," : "", fields);
    static const uint8_t zero[4];
    const uint8_t *w = want_ip ? want_ip : zero;
    memset(&nm, 0xA5, sizeof(nm));
    if (mapresp_parse(js, strlen(js), &nm) != ESP_OK || nm.n_derp_regions != 1 ||
        nm.derp_regions[0].n_nodes != 1 ||
        memcmp(nm.derp_regions[0].nodes[0].ipv4, w, 4) != 0 ||
        nm.derp_regions[0].nodes[0].stun_port != want_stun ||
        strcmp(nm.derp_regions[0].nodes[0].hostname, "derp16b.example") != 0) {
        const tl_derp_node_t *dn = &nm.derp_regions[0].nodes[0];
        printf("[derp/node-addr/%s] FAIL ip=%u.%u.%u.%u stun=%u\n", name,
               dn->ipv4[0], dn->ipv4[1], dn->ipv4[2], dn->ipv4[3], dn->stun_port);
        return 1;
    }
    printf("[derp/node-addr/%s] OK\n", name);
    return 0;
}

static int test_derp_node_addr(void)
{
    static const uint8_t a[4] = { 203, 0, 113, 7 }, lo[4] = { 0, 0, 0, 0 },
                         top[4] = { 255, 255, 255, 255 };
    int f = 0;
    f |= derp_node_case("ipv4", "\"IPv4\":\"203.0.113.7\",\"IPv6\":\"2001:db8::7\"", a, 3478);
    f |= derp_node_case("ipv4-after-ipv6", "\"IPv6\":\"2001:db8::7\",\"IPv4\":\"203.0.113.7\"",
                        a, 3478);
    f |= derp_node_case("no-ipv4", "\"IPv6\":\"2001:db8::7\"", NULL, 3478);
    f |= derp_node_case("ipv4-none", "\"IPv4\":\"none\"", NULL, 3478);
    f |= derp_node_case("ipv4-empty", "\"IPv4\":\"\"", NULL, 3478);
    f |= derp_node_case("ipv4-is-v6", "\"IPv4\":\"2001:db8::7\"", NULL, 3478);
    f |= derp_node_case("ipv4-leading-zero", "\"IPv4\":\"203.0.113.07\"", NULL, 3478);
    f |= derp_node_case("ipv4-octet-256", "\"IPv4\":\"203.0.113.256\"", NULL, 3478);
    f |= derp_node_case("ipv4-five-fields", "\"IPv4\":\"203.0.113.7.1\"", NULL, 3478);
    f |= derp_node_case("ipv4-port", "\"IPv4\":\"203.0.113.7:443\"", NULL, 3478);
    f |= derp_node_case("ipv4-number", "\"IPv4\":3405803783", NULL, 3478);
    f |= derp_node_case("ipv4-edges-kept", "\"IPv4\":\"255.255.255.255\"", top, 3478);
    f |= derp_node_case("ipv4-zero-kept", "\"IPv4\":\"0.0.0.0\"", lo, 3478);
    f |= derp_node_case("stunport-0", "\"IPv4\":\"203.0.113.7\",\"STUNPort\":0", a, 3478);
    f |= derp_node_case("stunport-3479", "\"IPv4\":\"203.0.113.7\",\"STUNPort\":3479", a, 3479);
    f |= derp_node_case("stunport-off", "\"IPv4\":\"203.0.113.7\",\"STUNPort\":-1", a, 0);
    f |= derp_node_case("stunport-65536", "\"STUNPort\":65536", NULL, 0);
    f |= derp_node_case("stunport-string", "\"STUNPort\":\"3478\"", NULL, 3478);
    f |= derp_node_case("stunport-float", "\"STUNPort\":3478.5", NULL, 0);
    return f;
}

static int test_derpmap_real_shaped(void)
{
    static char js[24000];
    static tl_netmap_t nm;
    static const char *const names[3] = {
        "derp/real-map-go-order", "derp/real-map-reversed", "derp/real-map-without-16",
    };
    for (int order = 0; order < 3; order++) {
        size_t len = build_derpmap(js, sizeof(js), order);
        memset(&nm, 0xA5, sizeof(nm));   /* stale garbage must not leak through */
        if (len == 0 || mapresp_parse(js, len, &nm) != ESP_OK || !nm.have_derp_map) {
            printf("[%s] FAIL parse len=%zu\n", names[order], len);
            return 1;
        }
        if (order == 2) {
            if (nm.n_derp_regions != 0 || nm.derp_regions[0].region_id != 0) {
                printf("[%s] FAIL n=%zu\n", names[order], nm.n_derp_regions);
                return 1;
            }
            printf("[%s] OK\n", names[order]);
            continue;
        }
        const tl_derp_region_t *r = &nm.derp_regions[0];
        static const uint8_t ip0[4] = { 198, 51, 16, 1 }, ip2[4] = { 198, 51, 16, 3 };
        if (nm.n_derp_regions != 1 || r->region_id != 16 ||
            r->n_nodes != TL_MAX_DERP_NODES ||          /* 4 nodes, capped at 3 */
            strcmp(r->nodes[0].hostname, "derp16b.tailscale.com") != 0 ||
            strcmp(r->nodes[2].hostname, "derp16d.tailscale.com") != 0 ||
            r->nodes[0].region_id != 16 || r->nodes[0].port != 0 ||
            /* 1.3.5: IPv4 kept, STUNPort absent = 3478 */
            memcmp(r->nodes[0].ipv4, ip0, 4) != 0 || memcmp(r->nodes[2].ipv4, ip2, 4) != 0 ||
            r->nodes[0].stun_port != 3478 || r->nodes[2].stun_port != 3478) {
            printf("[%s] FAIL n=%zu id=%d nodes=%zu host=%s\n", names[order],
                   nm.n_derp_regions, r->region_id, r->n_nodes, r->nodes[0].hostname);
            return 1;
        }
        printf("[%s] OK\n", names[order]);
    }

    /* Selection is by the RegionID inside the object, not by its key. */
    static const char *kKeyMismatch =
        "{\"DERPMap\":{\"Regions\":{"
        "\"16\":{\"RegionID\":61,\"Nodes\":[{\"RegionID\":61,\"HostName\":\"derp61.example\"}]},"
        "\"x\":{\"RegionID\":16,\"Nodes\":[{\"RegionID\":16,\"HostName\":\"derp16.example\","
        "\"DERPPort\":8443}]}}}}";
    if (mapresp_parse(kKeyMismatch, strlen(kKeyMismatch), &nm) != ESP_OK ||
        nm.n_derp_regions != 1 || nm.derp_regions[0].region_id != 16 ||
        strcmp(nm.derp_regions[0].nodes[0].hostname, "derp16.example") != 0 ||
        nm.derp_regions[0].nodes[0].port != 8443) {
        printf("[derp/selected-by-region-id] FAIL\n");
        return 1;
    }
    printf("[derp/selected-by-region-id] OK\n");
    return test_derp_node_addr();
}

int main(void)
{
    tl_netmap_t nm;
    esp_err_t e = mapresp_parse(kStub, strlen(kStub), &nm);
    if (e != ESP_OK) {
        printf("[mapresp_parse] FAIL err=%d\n", e);
        return 1;
    }

    if (!nm.have_self || nm.self_id != 42) {
        printf("[self.id] FAIL got %llu\n", (unsigned long long)nm.self_id);
        return 1;
    }
    if (nm.n_self_addresses != 1 ||
        strcmp(nm.self_addresses[0].str, "100.64.0.7/32") != 0) {
        printf("[self.addresses] FAIL n=%zu\n", nm.n_self_addresses);
        return 1;
    }

    if (nm.n_peers != 1) {
        printf("[peers.n] FAIL n=%zu\n", nm.n_peers);
        return 1;
    }
    const tl_peer_t *p = &nm.peers[0];
    if (p->id != 99) {
        printf("[peer.id] FAIL got %llu\n", (unsigned long long)p->id);
        return 1;
    }
    if (p->node_pub[0] != 0x01 || p->node_pub[31] != 0x20) {
        printf("[peer.key] FAIL first=%02x last=%02x\n",
               p->node_pub[0], p->node_pub[31]);
        return 1;
    }
    if (!p->has_disco_pub || p->disco_pub[0] != 0x20 || p->disco_pub[31] != 0x3f) {
        printf("[peer.disco] FAIL has=%d first=%02x last=%02x\n",
               p->has_disco_pub, p->disco_pub[0], p->disco_pub[31]);
        return 1;
    }
    if (p->home_derp != 13) {
        printf("[peer.derp] FAIL got %d\n", p->home_derp);
        return 1;
    }
    if (p->n_addresses != 1 ||
        strcmp(p->addresses[0].str, "100.64.0.8/32") != 0) {
        printf("[peer.addresses] FAIL\n");
        return 1;
    }
    /* Two v4 endpoints kept, one v6 dropped. */
    if (p->n_endpoints != 2) {
        printf("[peer.endpoints.n] FAIL n=%zu\n", p->n_endpoints);
        return 1;
    }
    if (strcmp(p->endpoints[0].str, "203.0.113.5:41641") != 0 ||
        strcmp(p->endpoints[1].str, "192.168.1.5:41641") != 0) {
        printf("[peer.endpoints.values] FAIL: '%s' '%s'\n",
               p->endpoints[0].str, p->endpoints[1].str);
        return 1;
    }

    /* Only the PreferredDERP region (16) is stored; the peer's HomeDERP
     * region 13 is not. */
    if (!nm.have_derp_map || nm.n_derp_regions != 1) {
        printf("[derp.regions] FAIL n=%zu\n", nm.n_derp_regions);
        return 1;
    }
    if (nm.derp_regions[0].region_id != 16 ||
        nm.derp_regions[0].n_nodes != 1 ||
        strcmp(nm.derp_regions[0].nodes[0].hostname,
               "derp16b.tailscale.com") != 0 ||
        nm.derp_regions[0].nodes[0].port != 443) {
        printf("[derp.node] FAIL\n");
        return 1;
    }

    /* A full map carries no patches and no expiry. */
    if (nm.n_patches != 0 || nm.patches_overflow || nm.self_expired) {
        printf("[full-map/no-patches] FAIL\n");
        return 1;
    }
    printf("[mapresp-stub] OK\n");

    /* --- PeersChangedPatch parsing (round 1.3.0) ----------------------
     * headscale sends peer endpoint/DERP moves (59f3ff12), re-logins and
     * every tailscaled restart (DiscoKey) as PeerChange entries; they are
     * applied by NodeID in tinylink.c merge_peers. */
    static const char *kPatchKey =
        "{\"PeersChangedPatch\":[{\"NodeID\":99,"
        "\"Key\":\"nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\","
        "\"KeyExpiry\":\"2027-01-01T00:00:00Z\"}]}";
    if (mapresp_parse(kPatchKey, strlen(kPatchKey), &nm) != ESP_OK ||
        nm.n_patches != 1 || nm.patches[0].id != 99 || !nm.patches[0].has_key ||
        nm.patches[0].node_pub[0] != 0x01 || nm.patches[0].node_pub[31] != 0x20 ||
        nm.patches[0].has_disco || nm.patches[0].has_endpoints ||
        nm.patches[0].derp_region != 0 || nm.n_peers != 0) {
        printf("[patch/key] FAIL n=%zu\n", nm.n_patches);
        return 1;
    }
    printf("[patch/key] OK\n");

    static const char *kPatchDisco =
        "{\"PeersChangedPatch\":[{\"NodeID\":99,"
        "\"DiscoKey\":\"discokey:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}]}";
    if (mapresp_parse(kPatchDisco, strlen(kPatchDisco), &nm) != ESP_OK ||
        nm.n_patches != 1 || !nm.patches[0].has_disco || nm.patches[0].has_key ||
        nm.patches[0].disco_pub[0] != 0xbb) {
        printf("[patch/disco] FAIL\n");
        return 1;
    }
    printf("[patch/disco] OK\n");

    static const char *kPatchEndpoints =
        "{\"PeersChangedPatch\":[{\"NodeID\":99,"
        "\"Endpoints\":[\"203.0.113.9:41641\",\"[2001:db8::1]:41641\"],\"DERPRegion\":16,"
        "\"Online\":true,\"LastSeen\":\"2026-10-28T10:00:00Z\"}]}";
    if (mapresp_parse(kPatchEndpoints, strlen(kPatchEndpoints), &nm) != ESP_OK ||
        nm.n_patches != 1 || !nm.patches[0].has_endpoints ||
        nm.patches[0].n_endpoints != 1 ||
        strcmp(nm.patches[0].endpoints[0].str, "203.0.113.9:41641") != 0 ||
        nm.patches[0].derp_region != 16 || nm.patches[0].has_key) {
        printf("[patch/endpoints-derp] FAIL\n");
        return 1;
    }
    printf("[patch/endpoints-derp] OK\n");

    /* Malformed key in a patch: the field stays unset (never a partial
     * key); with nothing else usable the entry is dropped, and a valid
     * field next to it survives without the key. */
    static const char *kPatchBadKey =
        "{\"PeersChangedPatch\":[{\"NodeID\":7,\"Key\":\"nodekey:zz\"},"
        "{\"NodeID\":8,\"Key\":\"nodekey:zz\",\"DERPRegion\":4}]}";
    if (mapresp_parse(kPatchBadKey, strlen(kPatchBadKey), &nm) != ESP_OK ||
        nm.n_patches != 1 || nm.patches[0].id != 8 || nm.patches[0].has_key ||
        nm.patches[0].derp_region != 4) {
        printf("[patch/bad-key-unset] FAIL\n");
        return 1;
    }
    printf("[patch/bad-key-unset] OK\n");

    /* Combined frame (headscale 7a2335dc folds a tick into one response):
     * PeersChanged for A + patch for B — both must survive the parse. */
    static const char *kCombined =
        "{\"PeersChanged\":[{\"ID\":1,"
        "\"Key\":\"nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\""
        "}],"
        "\"PeersChangedPatch\":[{\"NodeID\":2,"
        "\"DiscoKey\":\"discokey:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"}],"
        "\"PeersRemoved\":[3]}";
    if (mapresp_parse(kCombined, strlen(kCombined), &nm) != ESP_OK ||
        nm.n_peers != 1 || !nm.peers_is_delta || nm.n_patches != 1 ||
        nm.patches[0].id != 2 || nm.n_removed != 1 || nm.removed_ids[0] != 3) {
        printf("[patch/combined-frame] FAIL peers=%zu patches=%zu removed=%zu\n",
               nm.n_peers, nm.n_patches, nm.n_removed);
        return 1;
    }
    printf("[patch/combined-frame] OK\n");

    /* More patches than TL_MAX_PEER_PATCHES → overflow flag (stream layer
     * recycles for a full map instead of applying a partial delta). */
    static const char *kPatchMany =
        "{\"PeersChangedPatch\":[{\"NodeID\":1,\"DERPRegion\":1},{\"NodeID\":2,\"DERPRegion\":1},"
        "{\"NodeID\":3,\"DERPRegion\":1},{\"NodeID\":4,\"DERPRegion\":1},"
        "{\"NodeID\":5,\"DERPRegion\":1}]}";
    if (mapresp_parse(kPatchMany, strlen(kPatchMany), &nm) != ESP_OK ||
        nm.n_patches != TL_MAX_PEER_PATCHES || !nm.patches_overflow) {
        printf("[patch/overflow] FAIL n=%zu ovf=%d\n", nm.n_patches, nm.patches_overflow);
        return 1;
    }
    printf("[patch/overflow] OK\n");

    /* Online / LastSeen-only patches (headscale: one per peer
     * (dis)connect, folded per tick) carry nothing the data plane uses:
     * not stored, not counted — five of them must not overflow. */
    static const char *kPatchOnlineOnly =
        "{\"PeersChangedPatch\":[{\"NodeID\":1,\"Online\":true},{\"NodeID\":2,\"Online\":false},"
        "{\"NodeID\":3,\"LastSeen\":\"2026-10-28T10:00:00Z\"},{\"NodeID\":4,\"Online\":true},"
        "{\"NodeID\":5,\"KeyExpiry\":\"2027-01-01T00:00:00Z\"}]}";
    if (mapresp_parse(kPatchOnlineOnly, strlen(kPatchOnlineOnly), &nm) != ESP_OK ||
        nm.n_patches != 0 || nm.patches_overflow) {
        printf("[patch/online-only-ignored] FAIL n=%zu ovf=%d\n", nm.n_patches, nm.patches_overflow);
        return 1;
    }
    printf("[patch/online-only-ignored] OK\n");

    /* Same NodeID twice in one frame folds into one entry. */
    static const char *kPatchDup =
        "{\"PeersChangedPatch\":[{\"NodeID\":7,\"DERPRegion\":3},"
        "{\"NodeID\":7,\"Endpoints\":[\"198.51.100.7:41641\"]},"
        "{\"NodeID\":7,\"DERPRegion\":9}]}";
    if (mapresp_parse(kPatchDup, strlen(kPatchDup), &nm) != ESP_OK ||
        nm.n_patches != 1 || nm.patches[0].derp_region != 9 ||
        !nm.patches[0].has_endpoints || nm.patches[0].n_endpoints != 1) {
        printf("[patch/duplicate-folded] FAIL n=%zu\n", nm.n_patches);
        return 1;
    }
    printf("[patch/duplicate-folded] OK\n");

    static const char *kRemovedMany =
        "{\"PeersRemoved\":[1,2,3,4,5,6,7,8,9]}";
    if (mapresp_parse(kRemovedMany, strlen(kRemovedMany), &nm) != ESP_OK ||
        nm.n_removed != TL_MAX_PEERS_REMOVED || !nm.removed_overflow) {
        printf("[removed/overflow] FAIL\n");
        return 1;
    }
    printf("[removed/overflow] OK\n");

    /* --- Self expiry (headscale ≥0.29.4 deleted / expired node) -------
     * The exact frame noise.go writes for an unknown NodeKey on a
     * Stream=true map request. */
    static const char *kExpiredSelf =
        "{\"Node\":{\"Key\":\"nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\","
        "\"KeyExpiry\":\"1970-01-01T00:00:01Z\",\"Expired\":true},"
        "\"Debug\":{\"DisableLogTail\":true}}";
    if (mapresp_parse(kExpiredSelf, strlen(kExpiredSelf), &nm) != ESP_OK ||
        !nm.have_self || !nm.self_expired || nm.self_key_expiry != 1 ||
        nm.n_self_addresses != 0) {
        printf("[self/deleted-frame] FAIL exp=%d key_expiry=%lld\n",
               nm.self_expired, (long long)nm.self_key_expiry);
        return 1;
    }
    printf("[self/deleted-frame] OK\n");

    /* Live self node: future KeyExpiry parsed, not expired; Go zero time
     * means "never expires" → 0; StableTailnetID (capver 148) ignored. */
    static const char *kSelfLive =
        "{\"Node\":{\"ID\":5,\"Addresses\":[\"100.64.0.5/32\"],"
        "\"KeyExpiry\":\"2027-04-26T12:34:56.123456789Z\","
        "\"StableTailnetID\":\"T1234CNTRL\",\"Expired\":false}}";
    if (mapresp_parse(kSelfLive, strlen(kSelfLive), &nm) != ESP_OK ||
        !nm.have_self || nm.self_expired || nm.self_key_expiry != 1808742896 ||
        nm.n_self_addresses != 1) {
        printf("[self/live-expiry] FAIL exp=%d key_expiry=%lld\n",
               nm.self_expired, (long long)nm.self_key_expiry);
        return 1;
    }
    printf("[self/live-expiry] OK\n");

    static const char *kSelfZeroTime =
        "{\"Node\":{\"ID\":5,\"KeyExpiry\":\"0001-01-01T00:00:00Z\"}}";
    if (mapresp_parse(kSelfZeroTime, strlen(kSelfZeroTime), &nm) != ESP_OK ||
        nm.self_key_expiry != 0 || nm.self_expired) {
        printf("[self/zero-time-never-expires] FAIL\n");
        return 1;
    }
    printf("[self/zero-time-never-expires] OK\n");

    /* Removal-only and DERPMap-only frames carry data (headscale sends
     * them alone) — the parse must report them so the stream layer does
     * not mistake them for KeepAlives. */
    static const char *kDerpOnly =
        "{\"DERPMap\":{\"Regions\":{\"1\":{\"RegionID\":1,\"Nodes\":["
        "{\"RegionID\":1,\"HostName\":\"derp1.example\"}]}}}}";
    /* Region 1 is not the preferred one: the frame still counts as data
     * (have_derp_map) but stores nothing — "preferred region absent". */
    if (mapresp_parse(kDerpOnly, strlen(kDerpOnly), &nm) != ESP_OK ||
        !nm.have_derp_map || nm.n_derp_regions != 0 ||
        nm.derp_regions[0].region_id != 0 || nm.derp_regions[0].n_nodes != 0 ||
        nm.have_self || nm.n_peers != 0) {
        printf("[derp-only-frame] FAIL\n");
        return 1;
    }
    printf("[derp-only-frame] OK\n");

    if (test_derpmap_real_shaped() != 0) return 1;

    /* --- Peers vs PeersChanged vs PeersRemoved (M16 merge contract) --- */
    static const char *kFull = "{\"Peers\":[{\"ID\":1},{\"ID\":2}]}";
    if (mapresp_parse(kFull, strlen(kFull), &nm) != ESP_OK ||
        nm.n_peers != 2 || nm.peers_is_delta || nm.n_removed != 0) {
        printf("[peers/full-not-delta] FAIL\n");
        return 1;
    }
    printf("[peers/full-not-delta] OK\n");

    static const char *kDelta = "{\"PeersChanged\":[{\"ID\":3}]}";
    if (mapresp_parse(kDelta, strlen(kDelta), &nm) != ESP_OK ||
        nm.n_peers != 1 || !nm.peers_is_delta || nm.peers[0].id != 3) {
        printf("[peers/changed-is-delta] FAIL\n");
        return 1;
    }
    printf("[peers/changed-is-delta] OK\n");

    static const char *kRemoved =
        "{\"PeersRemoved\":[7,123456789012,\"x\",42],\"KeepAlive\":false}";
    if (mapresp_parse(kRemoved, strlen(kRemoved), &nm) != ESP_OK ||
        nm.n_removed != 3 || nm.removed_ids[0] != 7 ||
        nm.removed_ids[1] != 123456789012ULL || nm.removed_ids[2] != 42 ||
        nm.n_peers != 0) {
        printf("[peers/removed-ids] FAIL n=%zu\n", nm.n_removed);
        return 1;
    }
    printf("[peers/removed-ids] OK\n");

    /* Oversized element is skipped, the rest of the map still parses. */
    {
        static char big[9000];
        size_t o = 0;
        o += (size_t)snprintf(big + o, sizeof(big) - o, "{\"Peers\":[{\"ID\":1,\"Tags\":[");
        for (int i = 0; i < 700; i++) o += (size_t)snprintf(big + o, sizeof(big) - o, "\"t\",");
        o += (size_t)snprintf(big + o, sizeof(big) - o, "\"t\"]},{\"ID\":2}]}");
        if (mapresp_parse(big, o, &nm) != ESP_OK || nm.n_peers != 1 || nm.peers[0].id != 2) {
            printf("[peers/oversized-element-skipped] FAIL n=%zu\n", nm.n_peers);
            return 1;
        }
        printf("[peers/oversized-element-skipped] OK\n");
    }

    /* A member without its colon (round 1.3.4): jsmn counts it as two
     * children, so the pair walks went past the tokens jsmn wrote — into
     * an earlier parse's stale tokens, and with a full table past its end
     * (1.3.3: ASan global-buffer-overflow in tok_eq, read of s_toks[640]).
     * Now refused like any unparseable element. */
    {
        static char big[8192];
        size_t o = 0;
        o += (size_t)snprintf(big + o, sizeof(big) - o, "{\"Peers\":[{\"a\" 1,\"t\":[");
        for (int i = 0; i < 635; i++) o += (size_t)snprintf(big + o, sizeof(big) - o, "%s\"x\"", i ? "," : "");
        o += (size_t)snprintf(big + o, sizeof(big) - o, "]},{\"ID\":2}]}");   /* 640 tokens, then a peer */
        if (mapresp_parse(big, o, &nm) != ESP_OK || nm.n_peers != 1 || nm.peers[0].id != 2) {
            printf("[peers/missing-colon-at-full-table-refused] FAIL n=%zu\n", nm.n_peers);
            return 1;
        }
        printf("[peers/missing-colon-at-full-table-refused] OK\n");
        static const char *kNoColon =
            "{\"Peers\":[{\"ID\" 5,\"HomeDERP\":3},{\"ID\":6}],"
            "\"PeersChangedPatch\":[{\"NodeID\"02,\"DERPRegion\":1}]}";
        if (mapresp_parse(kNoColon, strlen(kNoColon), &nm) != ESP_OK || nm.n_peers != 1 ||
            nm.peers[0].id != 6 || nm.n_patches != 0 || !nm.patches_overflow) {
            printf("[peers/missing-colon-refused] FAIL n=%zu patches=%zu ovf=%d\n",
                   nm.n_peers, nm.n_patches, nm.patches_overflow);
            return 1;
        }
        printf("[peers/missing-colon-refused] OK\n");
    }

    if (stream_suite() != 0) return 1;

    printf("ALL OK\n");
    return 0;
}

/* ======================================================================
 * Streaming splitter (round 1.3.4, D2)
 *
 * Oracle: the 1.3.3 parser, which assembled each frame whole. For every
 * input whose elements fit the element buffer the stream must return the
 * same status and, on success, a byte-identical tl_netmap_t — whatever
 * the chunking of the DATA bytes, the length prefix included.
 * ==================================================================== */

#define FAILF(...) do { printf(__VA_ARGS__); return 1; } while (0)

static uint64_t g_rng = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void)
{
    g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17;
    return (uint32_t)(g_rng >> 16);
}

/* --- fixture builder ---------------------------------------------------- */

typedef struct { char *p; size_t n, cap; size_t elem_max; } sb_t;

static void sb_printf(sb_t *b, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(b->p + b->n, b->cap - b->n, fmt, ap);
    va_end(ap);
    if (k < 0 || (size_t)k >= b->cap - b->n) { printf("fixture overflow\n"); exit(1); }
    b->n += (size_t)k;
}

/* Note the size of an element just written from `start`. */
static void sb_elem(sb_t *b, size_t start)
{
    if (b->n - start > b->elem_max) b->elem_max = b->n - start;
}

static void sb_key(sb_t *b, const char *name, const char *prefix, unsigned seed)
{
    sb_printf(b, "\"%s\":\"%s", name, prefix);
    for (int i = 0; i < 32; i++) sb_printf(b, "%02x", (seed * 2654435761u + (unsigned)i * 40503u) >> 24);
    sb_printf(b, "\"");
}

/* The self node as tailscale.com sends it to a tagged ESP32 (the Hostinfo
 * is ours echoed back; CapMap / Capabilities as control grants them),
 * sized to the 179 tokens the sensor logs for its largest element. */
static size_t put_self(sb_t *b, int ncap)
{
    static const char *const caps[] = {
        "admin", "funnel", "https", "magicdns-aaaa", "probe-udp-lifetime",
        "store-appc-routes", "ssh-behavior-v1", "ssh-env-vars", "drive:share",
        "drive:access", "app-connectors", "disable-captive-portal-detection",
        "https://tailscale.com/cap/file-sharing", "https://tailscale.com/cap/file-send",
        "https://tailscale.com/cap/funnel-ports?ports=443,8443,10000",
        "https://tailscale.com/cap/is-admin", "https://tailscale.com/cap/is-owner",
        "https://tailscale.com/cap/ssh", "https://tailscale.com/cap/tailnet-lock",
        "https://tailscale.com/cap/web-client", "https://tailscale.com/cap/debug-peer",
        "https://tailscale.com/cap/data-plane-audit-logs", "https://tailscale.com/cap/ingress",
        "https://tailscale.com/cap/services-in-desktop-clients",
        "https://tailscale.com/cap/bind-to-interface-by-route",
        "https://tailscale.com/cap/file-sharing-target", "https://tailscale.com/cap/ssh-rule-in",
        "https://tailscale.com/cap/debug-ts-dns-resolution", "https://tailscale.com/cap/mac-ui-v2",
        "https://tailscale.com/cap/debug", "default-auto-update", "tailnet.display-name",
        "nextdns-profile", "user-dial-routes", "debug-disable-upnp", "max-key-duration",
    };
    const int nc = (int)(sizeof(caps) / sizeof(caps[0]));
    size_t s0 = b->n;
    sb_printf(b, "{\"ID\":8150413018412615,\"StableID\":\"nGq4pVdP9611CNTRL\","
                 "\"Name\":\"sensor-cali.tail1234ab.ts.net.\",\"User\":5271734863091011,");
    sb_key(b, "Key", "nodekey:", 1);
    sb_printf(b, ",\"KeyExpiry\":\"0001-01-01T00:00:00Z\",");
    sb_key(b, "Machine", "mkey:", 2); sb_printf(b, ",");
    sb_key(b, "DiscoKey", "discokey:", 3);
    sb_printf(b, ",\"Addresses\":[\"100.67.60.92/32\",\"fd7a:115c:a1e0::8d01:3c5c/128\"],"
                 "\"AllowedIPs\":[\"100.67.60.92/32\",\"fd7a:115c:a1e0::8d01:3c5c/128\"],"
                 "\"Endpoints\":[\"203.0.113.157:56828\",\"192.168.1.50:41641\"],\"HomeDERP\":16,"
                 "\"Hostinfo\":{\"IPNVersion\":\"1.3.3-tinylink\",\"OS\":\"esp32\","
                 "\"Hostname\":\"sensor-cali\",\"NetInfo\":{\"WorkingUDP\":true,\"PreferredDERP\":16}},"
                 "\"Created\":\"2026-05-02T14:21:07.123456789Z\",\"Cap\":131,\"Tags\":[\"tag:sensor\",\"tag:iot\"],"
                 "\"MachineAuthorized\":true,\"Capabilities\":[");
    for (int i = 0; i < 12; i++) sb_printf(b, "%s\"%s\"", i ? "," : "", caps[12 + i]);
    sb_printf(b, "],\"CapMap\":{");
    for (int i = 0; i < ncap; i++) {
        const char *k = caps[i % nc];
        if (i >= nc) sb_printf(b, "%s\"%s/%d\":null", i ? "," : "", k, i);
        else if (strcmp(k, "default-auto-update") == 0) sb_printf(b, ",\"%s\":[true]", k);
        else if (strcmp(k, "tailnet.display-name") == 0) sb_printf(b, ",\"%s\":[\"bryam's tailnet\"]", k);
        else sb_printf(b, "%s\"%s\":null", i ? "," : "", k);
    }
    sb_printf(b, "},\"ComputedName\":\"sensor-cali\",\"ComputedNameWithHost\":\"sensor-cali\","
                 "\"StableTailnetID\":\"T1234CNTRL\"}");
    sb_elem(b, s0);
    return b->n - s0;
}

/* Peers in the shapes tailscale.com sends (trimmed Hostinfo; one with a
 * service list). shape: 0 home Linux server, 1 Windows desktop, 2 phone
 * (offline), 3 tagged subnet router, 4 DERP-only, 5 shared-in node. */
static void put_peer(sb_t *b, int i, int shape)
{
    size_t s0 = b->n;
    sb_printf(b, "{\"ID\":%d%06d,\"StableID\":\"n%dCNTRL\",\"Name\":\"peer-%d.tail1234ab.ts.net.\","
                 "\"User\":5271734863091011,", 7 + i, 4242 + i, i, i);
    if (shape == 5) sb_printf(b, "\"Sharer\":6271734863091099,");
    sb_key(b, "Key", "nodekey:", 100u + (unsigned)i);
    sb_printf(b, ",\"KeyExpiry\":\"2027-04-%02dT12:00:00Z\",", 10 + i);
    sb_key(b, "Machine", "mkey:", 200u + (unsigned)i); sb_printf(b, ",");
    sb_key(b, "DiscoKey", "discokey:", 300u + (unsigned)i);
    sb_printf(b, ",\"Addresses\":[\"100.88.%d.%d/32\",\"fd7a:115c:a1e0::%x/128\"],"
                 "\"AllowedIPs\":[\"100.88.%d.%d/32\",\"fd7a:115c:a1e0::%x/128\"%s],",
              250 - i, 54 + i, 0x1000 + i, 250 - i, 54 + i, 0x1000 + i,
              shape == 3 ? ",\"192.168.10.0/24\",\"10.20.0.0/16\"" : "");
    if (shape != 4) {
        sb_printf(b, "\"Endpoints\":[\"191.89.%d.157:%d\",\"[2800:e2:5c80::%x]:41641\",\"192.168.1.%d:41641\"],",
                  196 + i, 56828 + i, i + 1, 20 + i);
    }
    sb_printf(b, "\"HomeDERP\":%d,", (i % 3) ? 16 : 1);
    sb_printf(b, "\"Hostinfo\":{\"OS\":\"%s\",\"Hostname\":\"peer-%d\"",
              shape == 1 ? "windows" : shape == 2 ? "iOS" : "linux", i);
    if (shape == 0) {
        sb_printf(b, ",\"Services\":[");
        static const char *const svc[] = { "sshd", "nginx", "postgres", "grafana-server",
                                            "prometheus", "node_exporter", "smbd", "tailscaled" };
        for (int k = 0; k < 8; k++)
            sb_printf(b, "%s{\"Proto\":\"%s\",\"Port\":%d,\"Description\":\"%s\"}",
                      k ? "," : "", k == 7 ? "peerapi4" : "tcp", 22 + 1000 * k, svc[k]);
        sb_printf(b, "]");
    }
    sb_printf(b, "},\"Created\":\"2025-11-%02dT08:%02d:00Z\",\"Cap\":%d,", 1 + i, 10 + i, 120 + i);
    if (shape == 3) sb_printf(b, "\"Tags\":[\"tag:router\",\"tag:server\"],\"PrimaryRoutes\":[\"192.168.10.0/24\"],");
    if (shape == 2) sb_printf(b, "\"LastSeen\":\"2026-10-28T22:%02d:41Z\",\"Online\":false,", 10 + i);
    else sb_printf(b, "\"Online\":true,");
    sb_printf(b, "\"MachineAuthorized\":true,\"ComputedName\":\"peer-%d\",\"ComputedNameWithHost\":\"peer-%d\"}", i, i);
    sb_elem(b, s0);
}

/* Tailscale's 28-region DERPMap (see build_derpmap) as a member value. */
static void put_derpmap(sb_t *b, int with16)
{
    sb_printf(b, "{\"Regions\":{");
    int first = 1;
    for (int k = 0; k < 28; k++) {
        const int id = kGoKeyOrder[k];
        if (!with16 && id == 16) continue;
        const int nodes = (id == 16) ? 4 : 2 + (id % 2);
        sb_printf(b, "%s\"%d\":", first ? "" : ",", id);
        first = 0;
        size_t s0 = b->n;
        sb_printf(b, "{\"RegionID\":%d,\"RegionCode\":\"%s\",\"RegionName\":\"Region %s\","
                     "\"Latitude\":%d.25,\"Longitude\":-%d.5,\"Nodes\":[",
                  id, kRegionCode[id], kRegionCode[id], id, id + 40);
        for (int n = 0; n < nodes; n++) {
            sb_printf(b, "%s{\"Name\":\"%d%c\",\"RegionID\":%d,\"HostName\":\"derp%d%c.tailscale.com\","
                         "\"IPv4\":\"198.51.%d.%d\",\"IPv6\":\"2001:db8:%x::%x\",\"CanPort80\":true}",
                      n ? "," : "", id, 'b' + n, id, id, 'b' + n, id, n + 1, id, n + 1);
        }
        sb_printf(b, "]}");
        sb_elem(b, s0);
    }
    sb_printf(b, "},\"HomeParams\":{\"RegionScore\":{\"16\":0.8}}}");
}

/* Everything else of an initial map: skipped by the parser, but it is
 * most of what the stream has to scan past. */
static void put_misc(sb_t *b)
{
    sb_printf(b, "\"DNSConfig\":{\"Resolvers\":[{\"Addr\":\"https://dns.nextdns.io/abc123\"}],"
                 "\"Routes\":{\"ts.net.\":null,\"tail1234ab.ts.net.\":[]},\"Domains\":[\"tail1234ab.ts.net\"],"
                 "\"Proxied\":true,\"CertDomains\":[\"sensor-cali.tail1234ab.ts.net\"],"
                 "\"ExtraRecords\":[{\"Name\":\"peer-0.tail1234ab.ts.net.\",\"Value\":\"100.88.250.54\"}],"
                 "\"ExitNodeFilteredSet\":[\".ts.net\"],\"TempCorpIssue13969\":\"\"},"
                 "\"Domain\":\"bryam@example.com\",\"CollectServices\":true,"
                 "\"PacketFilter\":[");
    for (int r = 0; r < 18; r++) {
        sb_printf(b, "%s{\"SrcIPs\":[\"100.64.0.0/10\",\"fd7a:115c:a1e0::/48\",\"100.88.250.%d\"],"
                     "\"DstPorts\":[{\"IP\":\"*\",\"Ports\":{\"First\":%d,\"Last\":%d}},"
                     "{\"IP\":\"100.67.60.92\",\"Ports\":{\"First\":0,\"Last\":65535}}],"
                     "\"IPProto\":[6,17,1,58]}", r ? "," : "", 50 + r, 1000 * r, 1000 * r + 999);
    }
    sb_printf(b, "],\"UserProfiles\":[");
    for (int u = 0; u < 4; u++) {
        sb_printf(b, "%s{\"ID\":%d,\"LoginName\":\"user%d@example.com\",\"DisplayName\":\"User %d\","
                     "\"ProfilePicURL\":\"https://lh3.googleusercontent.com/a/ACg8ocJ%08dxyz=s96-c\"}",
                  u ? "," : "", 5271734863 + u, u, u, 31337 + u);
    }
    sb_printf(b, "],\"SSHPolicy\":{\"rules\":[{\"principals\":[{\"any\":true}],\"sshUsers\":{\"root\":\"\","
                 "\"*\":\"=\"},\"action\":{\"accept\":true,\"allowAgentForwarding\":true}}]},"
                 "\"ControlTime\":\"2026-10-29T03:32:20.123456789Z\",\"TKAInfo\":null,"
                 "\"Debug\":{\"DisableLogTail\":true},\"ClientVersion\":{\"RunningLatest\":true}");
}

/* An initial netmap like the sensor's (≈ 26 KB, 179-token self node). */
static size_t build_initial(char *out, size_t cap, size_t *elem_max, size_t *self_len)
{
    sb_t b = { out, 0, cap, 0 };
    sb_printf(&b, "{\"KeepAlive\":false,\"Node\":");
    *self_len = put_self(&b, 50);
    sb_printf(&b, ",\"DERPMap\":");
    put_derpmap(&b, 1);
    sb_printf(&b, ",\"PeersChanged\":[");
    for (int i = 0; i < 6; i++) { if (i) sb_printf(&b, ","); put_peer(&b, i, i); }
    sb_printf(&b, "],");
    put_misc(&b);
    sb_printf(&b, "}");
    if (elem_max) *elem_max = b.elem_max;
    return b.n;
}

/* The fixtures every stream test runs over. */
#define NFIX 32
static char   g_fix_store[NFIX][32768];
static size_t g_fix_len[NFIX];
static const char *g_fix_name[NFIX];
static int    g_nfix;

static void fix_add(const char *name, const char *js, size_t len)
{
    if (g_nfix >= NFIX || len > sizeof(g_fix_store[0])) { printf("fixture table full\n"); exit(1); }
    memcpy(g_fix_store[g_nfix], js, len);
    g_fix_len[g_nfix] = len;
    g_fix_name[g_nfix++] = name;
}

static void fix_add_str(const char *name, const char *js) { fix_add(name, js, strlen(js)); }

static size_t g_initial_elem_max, g_initial_self_len;

static void build_fixtures(void)
{
    static char tmp[32768];
    size_t n = build_initial(tmp, sizeof(tmp), &g_initial_elem_max, &g_initial_self_len);
    fix_add("initial-netmap", tmp, n);
    sb_t b = { tmp, 0, sizeof(tmp), 0 };
    /* Deltas as the soak logs size them: a 722-B one-peer PeersChanged, a
     * 65-B Online patch, 102/110-B LastSeen patches, the 18-B KeepAlive. */
    sb_printf(&b, "{\"PeersChanged\":["); put_peer(&b, 7, 1); sb_printf(&b, "]}");
    fix_add("delta/peers-changed", tmp, b.n);
    fix_add_str("delta/keepalive", "{\"KeepAlive\":true}");
    fix_add_str("delta/online", "{\"PeersChangedPatch\":[{\"NodeID\":7004248,\"Online\":true}]}");
    fix_add_str("delta/lastseen",
        "{\"PeersChangedPatch\":[{\"NodeID\":7004248,\"LastSeen\":\"2026-10-29T03:40:12Z\",\"Online\":false}]}");
    fix_add_str("delta/endpoints",
        "{\"PeersChangedPatch\":[{\"NodeID\":7004242,\"DERPRegion\":16,"
        "\"Endpoints\":[\"203.0.113.157:56830\",\"[2800:e2:5c80::1]:41641\"]}],"
        "\"ControlTime\":\"2026-10-29T03:41:00Z\"}");
    fix_add_str("delta/removed", "{\"PeersRemoved\":[7004249,8004250],\"KeepAlive\":false}");
    b.n = 0; sb_printf(&b, "{\"DERPMap\":"); put_derpmap(&b, 1); sb_printf(&b, "}");
    fix_add("delta/derpmap", tmp, b.n);
    b.n = 0; sb_printf(&b, "{\"DERPMap\":"); put_derpmap(&b, 0); sb_printf(&b, "}");
    fix_add("delta/derpmap-without-16", tmp, b.n);
    /* The unit-test stubs above, as frames. */
    fix_add_str("stub/one-peer", kStub);
    fix_add_str("stub/expired-self",
        "{\"Node\":{\"Key\":\"nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\","
        "\"KeyExpiry\":\"1970-01-01T00:00:01Z\",\"Expired\":true},\"Debug\":{\"DisableLogTail\":true}}");
    fix_add_str("stub/combined",
        "{\"PeersChanged\":[{\"ID\":1,"
        "\"Key\":\"nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\"}],"
        "\"PeersChangedPatch\":[{\"NodeID\":2,"
        "\"DiscoKey\":\"discokey:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"}],"
        "\"PeersRemoved\":[3]}");
    fix_add_str("stub/patch-dup",
        "{\"PeersChangedPatch\":[{\"NodeID\":7,\"DERPRegion\":3},"
        "{\"NodeID\":7,\"Endpoints\":[\"198.51.100.7:41641\"]},{\"NodeID\":7,\"DERPRegion\":9}]}");
    fix_add_str("stub/patch-many",
        "{\"PeersChangedPatch\":[{\"NodeID\":1,\"DERPRegion\":1},{\"NodeID\":2,\"DERPRegion\":1},"
        "{\"NodeID\":3,\"DERPRegion\":1},{\"NodeID\":4,\"DERPRegion\":1},{\"NodeID\":5,\"DERPRegion\":1}]}");
    fix_add_str("stub/removed-many", "{\"PeersRemoved\":[1,2,3,4,5,6,7,8,9]}");
    fix_add_str("stub/removed-odd", "{\"PeersRemoved\":[7,123456789012,\"x\",42,123456789012345678901234,{\"a\":1}]}");
    fix_add_str("stub/region-key-mismatch",
        "{\"DERPMap\":{\"Regions\":{"
        "\"16\":{\"RegionID\":61,\"Nodes\":[{\"RegionID\":61,\"HostName\":\"derp61.example\"}]},"
        "\"x\":{\"RegionID\":16,\"Nodes\":[{\"RegionID\":16,\"HostName\":\"derp16.example\","
        "\"DERPPort\":8443}]}}}}");
    /* Repeated members, whitespace, escapes, odd-but-accepted grammar. */
    fix_add_str("odd/peers-then-changed",
        "{\"Peers\":[{\"ID\":1},{\"ID\":2}],\"PeersChanged\":[{\"ID\":3}],\"Peers\":[{\"ID\":4}]}");
    fix_add_str("odd/whitespace",
        " \r\n{ \"Node\" :\t{\"ID\" : 5 , \"Addresses\" : [ \"100.64.0.5/32\" ] } ,\n"
        " \"Peers\" : [ { \"ID\" : 1 } , { \"ID\" : 2 } ] , \"DERPMap\" : { \"Regions\" : {"
        " \"16\" : { \"RegionID\" : 16 , \"Nodes\" : [ { \"HostName\" : \"d16\" } ] } } } }  trailing");
    fix_add_str("odd/escaped-keys",
        "{\"Peer\\u0073\":[{\"ID\":1}],\"No\\\"de\":{\"ID\":9},\"Peers\":[{\"ID\":\"\\\"}]\"},{\"ID\":2}]}");
    fix_add_str("odd/lenient-commas",
        "{\"Peers\":[{\"ID\":1} {\"ID\":2},],\"DERPMap\":{\"Regions\":{\"a\":{\"RegionID\":16} \"b\":1,}}}");
    fix_add_str("odd/scalars-in-containers",
        "{\"Peers\":[1,\"x\",null,{\"ID\":3}],\"PeersChangedPatch\":[1,\"s\",[2],{\"NodeID\":4,\"DERPRegion\":2}],"
        "\"DERPMap\":{\"Regions\":{\"1\":\"no\",\"2\":[1],\"3\":{\"RegionID\":16}},\"Regions\":5}}");
    fix_add_str("odd/wrong-kinds",
        "{\"Node\":[1],\"Peers\":{\"a\":1},\"PeersChanged\":\"x\",\"DERPMap\":[],\"PeersRemoved\":{}}");
    fix_add_str("odd/scalar-with-quote", "{\"PeersRemoved\":[1\"x\"],\"Peers\":[{\"ID\":1}]}");
    fix_add_str("odd/extent-mismatch", "{\"Peers\":[1\"],\"x\":\"y\"]}");
    fix_add_str("bad/unterminated", "{\"Peers\":[{\"ID\":1}");
    fix_add_str("bad/not-object", "[{\"Peers\":[]}]");
    fix_add_str("bad/empty", "");
    fix_add_str("bad/kind-mismatch", "{\"Peers\":[{\"ID\":1}}");
}

/* --- harnesses ----------------------------------------------------------- */

static char g_big_elem[65536];   /* no element of any fixture is cut */
static char g_elem[TL_CTRL_MAPRESP_CAP];

/* Whole body through mapresp_json_* with a given element buffer. */
static esp_err_t stream_parse(const char *js, size_t len, char *elem, size_t cap,
                              tl_netmap_t *out, mapresp_json_t *st)
{
    mapresp_json_begin(st, elem, cap, out);
    mapresp_json_feed(st, js, len);
    return mapresp_json_end(st);
}

static int same_result(esp_err_t ea, const tl_netmap_t *a, esp_err_t eb, const tl_netmap_t *b)
{
    if ((ea == ESP_OK) != (eb == ESP_OK)) return 0;
    return ea != ESP_OK || memcmp(a, b, sizeof(*a)) == 0;
}

/* Stream (big buffer) vs the 1.3.3 parser on one body. */
static int diff_one(const char *js, size_t len, esp_err_t *ref_err)
{
    static tl_netmap_t want, got;
    mapresp_json_t st;
    esp_err_t ew = ref_mapresp_parse(js, len, &want);
    esp_err_t eg = stream_parse(js, len, g_big_elem, sizeof(g_big_elem), &got, &st);
    *ref_err = ew;
    return same_result(ew, &want, eg, &got);
}

/* Frames recorded by on_frame. */
#define MAXF 64
typedef struct {
    int         n;
    int         stop_at;     /* return non-zero at this frame (-1: never) */
    esp_err_t   err[MAXF];
    tl_netmap_t nm[MAXF];
    size_t      elem_peak[MAXF];
    unsigned    oversized[MAXF];
} frames_t;

static int on_frame(const mapresp_stream_t *ms, esp_err_t pe, void *ctx)
{
    frames_t *f = (frames_t *)ctx;
    if (f->n < MAXF) {
        f->err[f->n] = pe;
        f->nm[f->n] = *ms->json.out;
        f->elem_peak[f->n] = ms->json.elem_peak;
        f->oversized[f->n] = ms->json.n_oversized;
    }
    return f->n++ == f->stop_at;
}

static size_t put_frame(uint8_t *out, const char *js, size_t len)
{
    out[0] = (uint8_t)len; out[1] = (uint8_t)(len >> 8);
    out[2] = (uint8_t)(len >> 16); out[3] = (uint8_t)(len >> 24);
    memcpy(out + 4, js, len);
    return len + 4;
}

/* Feed `wire` cut at the given points (chunk sizes from `next_chunk`). */
static int feed_chunked(mapresp_stream_t *ms, const uint8_t *wire, size_t n,
                        size_t (*next_chunk)(void))
{
    size_t off = 0;
    while (off < n) {
        size_t c = next_chunk();
        if (c > n - off) c = n - off;
        if (mapresp_stream_feed(ms, wire + off, c) != 0) return -1;
        off += c;
    }
    return 0;
}

static size_t chunk_1(void)      { return 1; }
static size_t chunk_tiny(void)   { return 1 + rnd() % 7; }
static size_t chunk_small(void)  { return 1 + rnd() % 64; }
static size_t chunk_large(void)  { return 1 + rnd() % 4096; }
static size_t chunk_mixed(void)
{
    uint32_t r = rnd() % 10;
    return r < 5 ? 1 + rnd() % 3 : r < 8 ? 1 + rnd() % 100 : 1 + rnd() % 9000;
}
static size_t g_split_at;   /* two chunks: [0, g_split_at), rest */
static int    g_split_first;
static size_t chunk_split(void)
{
    if (g_split_first) { g_split_first = 0; return g_split_at ? g_split_at : (size_t)-1; }
    return (size_t)-1;
}

/* --- tests ---------------------------------------------------------------- */

static frames_t g_frames;
static uint8_t  g_wire[NFIX * (32768 + 4) + 64];
static tl_netmap_t g_want[NFIX];
static esp_err_t   g_want_err[NFIX];

static int test_fixture_sizes(void)
{
    static tl_netmap_t nm;
    mapresp_json_t st;
    const char *js = g_fix_store[0];
    size_t len = g_fix_len[0];
    if (stream_parse(js, len, g_elem, sizeof(g_elem), &nm, &st) != ESP_OK ||
        !nm.have_self || nm.n_peers != TL_MAX_PEERS || nm.n_derp_regions != 1 ||
        !nm.peers_is_delta || st.n_oversized != 0)
        FAILF("[stream/initial-netmap] FAIL\n");
    /* Calibrated to the device: 179 tokens for the largest element, the
     * self node, which is also the largest in bytes. */
    if (st.tok_peak != 179 || st.elem_peak != g_initial_self_len ||
        g_initial_elem_max != g_initial_self_len)
        FAILF("[stream/initial-netmap] FAIL tokens=%d elem=%zu (self %zu, max %zu)\n",
              st.tok_peak, st.elem_peak, g_initial_self_len, g_initial_elem_max);
    printf("  initial netmap: body=%zu B, largest element %zu B / %d tokens, buffer %u B\n",
           len, st.elem_peak, st.tok_peak, (unsigned)TL_CTRL_MAPRESP_CAP);
    if (len < 24000 || len > 28000 || 2 * st.elem_peak > TL_CTRL_MAPRESP_CAP)
        FAILF("[stream/initial-netmap] FAIL body %zu, element %zu: below 2x headroom\n",
              len, st.elem_peak);
    printf("[stream/initial-netmap-real-shaped] OK\n");
    return 0;
}

static int test_differential(void)
{
    /* Whole bodies: stream (both buffers) == 1.3.3 parser. */
    for (int i = 0; i < g_nfix; i++) {
        static tl_netmap_t a, b;
        mapresp_json_t st;
        esp_err_t ew = ref_mapresp_parse(g_fix_store[i], g_fix_len[i], &a);
        esp_err_t eg = stream_parse(g_fix_store[i], g_fix_len[i], g_elem, sizeof(g_elem), &b, &st);
        if (!same_result(ew, &a, eg, &b) || st.n_oversized != 0)
            FAILF("[stream/same-as-1.3.3 %s] FAIL ref=%d stream=%d\n", g_fix_name[i], ew, eg);
        g_want[i] = a;
        g_want_err[i] = ew;
    }
    printf("[stream/same-as-1.3.3-whole-body] OK\n");
    /* The mapresp_parse wrapper is the same parser. */
    for (int i = 0; i < g_nfix; i++) {
        static tl_netmap_t a;
        esp_err_t e = mapresp_parse(g_fix_store[i], g_fix_len[i], &a);
        if (!same_result(e, &a, g_want_err[i], &g_want[i]))
            FAILF("[stream/mapresp-parse-wrapper %s] FAIL\n", g_fix_name[i]);
    }
    printf("[stream/mapresp-parse-wrapper] OK\n");
    return 0;
}

/* Every fixture as one frame of a stream, cut in every way. */
static int check_frames(const char *what)
{
    if (g_frames.n != g_nfix) FAILF("[%s] FAIL frames=%d\n", what, g_frames.n);
    for (int i = 0; i < g_nfix; i++) {
        if (!same_result(g_frames.err[i], &g_frames.nm[i], g_want_err[i], &g_want[i]))
            FAILF("[%s] FAIL frame %d (%s)\n", what, i, g_fix_name[i]);
    }
    return 0;
}

static size_t build_wire(void)
{
    size_t n = 0;
    for (int i = 0; i < g_nfix; i++) n += put_frame(g_wire + n, g_fix_store[i], g_fix_len[i]);
    return n;
}

static int test_chunking(void)
{
    const size_t n = build_wire();
    static size_t (*const modes[])(void) = { chunk_1, chunk_tiny, chunk_small, chunk_large, chunk_mixed };
    static mapresp_stream_t ms;
    static tl_netmap_t nm;
    for (int run = 0; run < 100; run++) {
        memset(&g_frames, 0, sizeof(g_frames));
        g_frames.stop_at = -1;
        mapresp_stream_init(&ms, g_elem, sizeof(g_elem), &nm, on_frame, &g_frames);
        if (feed_chunked(&ms, g_wire, n, modes[run % 5]) != 0) FAILF("[stream/chunking] FAIL stop\n");
        if (check_frames("stream/chunking")) return 1;
    }
    printf("[stream/random-chunks-1B-to-9KB-100-runs] OK\n");
    /* Two chunks, cut at every byte of every frame under 2 KB and of the
     * first 64 of the others, inside every length prefix, and every 211th
     * byte elsewhere (the random runs above cover the rest). */
    static size_t cuts[40000]; size_t nc = 0;
    for (int i = 0, off = 0; i < g_nfix; off += (int)g_fix_len[i] + 4, i++) {
        const size_t fl = g_fix_len[i] + 4;
        for (size_t k = 0; k < fl; k++)
            if (fl < 2048 || k < 64 || k % 211 == 0) cuts[nc++] = (size_t)off + k;
    }
    for (size_t c = 0; c < nc; c++) {
        memset(&g_frames, 0, sizeof(g_frames));
        g_frames.stop_at = -1;
        mapresp_stream_init(&ms, g_elem, sizeof(g_elem), &nm, on_frame, &g_frames);
        g_split_at = cuts[c]; g_split_first = 1;
        if (feed_chunked(&ms, g_wire, n, chunk_split) != 0) FAILF("[stream/split] FAIL stop\n");
        if (check_frames("stream/split-every-byte")) return 1;
    }
    printf("[stream/two-chunks-every-cut-and-every-prefix-byte] OK\n");
    return 0;
}

/* Truncated at every byte: the same failure as the 1.3.3 parser (which
 * only succeeds once the top-level object is complete), and the stream
 * is back in sync for the frame after it. */
static int test_truncation(void)
{
    for (int i = 0; i < g_nfix; i++) {
        const char *js = g_fix_store[i];
        const size_t len = g_fix_len[i];
        static tl_netmap_t got, want;
        mapresp_json_t st, end;
        mapresp_json_begin(&st, g_big_elem, sizeof(g_big_elem), &got);
        for (size_t l = 0; l <= len; l++) {
            if (l > 0) mapresp_json_feed(&st, js + l - 1, 1);
            end = st;                          /* end a copy: every prefix in one pass */
            esp_err_t eg = mapresp_json_end(&end);
            /* The oracle on every prefix of the small fixtures, every
             * 61st of the big ones (it is quadratic). */
            if (len < 2048 || l % 61 == 0 || l + 64 > len) {
                esp_err_t ew = ref_mapresp_parse(js, l, &want);
                if (!same_result(ew, &want, eg, &got))
                    FAILF("[stream/truncation] FAIL %s at %zu of %zu\n", g_fix_name[i], l, len);
            } else if (eg == ESP_OK && !st.done) {
                FAILF("[stream/truncation] FAIL %s accepted at %zu\n", g_fix_name[i], l);
            }
        }
    }
    printf("[stream/truncated-at-every-byte-same-as-1.3.3] OK\n");

    /* Resync: a truncated frame followed by the full one, through the
     * framing layer with tiny chunks. */
    static mapresp_stream_t ms;
    static tl_netmap_t nm;
    static uint8_t wire[2 * 32768 + 8];
    for (int i = 0; i < g_nfix; i++) {
        const size_t len = g_fix_len[i];
        const size_t step = len < 2048 ? 1 : 97;
        for (size_t l = 0; l < len; l += step) {
            size_t n = put_frame(wire, g_fix_store[i], l);
            n += put_frame(wire + n, g_fix_store[i], len);
            memset(&g_frames, 0, sizeof(g_frames));
            g_frames.stop_at = -1;
            mapresp_stream_init(&ms, g_elem, sizeof(g_elem), &nm, on_frame, &g_frames);
            if (feed_chunked(&ms, wire, n, chunk_tiny) != 0 || g_frames.n != 2 ||
                !same_result(g_frames.err[1], &g_frames.nm[1], g_want_err[i], &g_want[i]))
                FAILF("[stream/resync] FAIL %s at %zu\n", g_fix_name[i], l);
            static tl_netmap_t want;
            esp_err_t ew = ref_mapresp_parse(g_fix_store[i], l, &want);
            if (!same_result(ew, &want, g_frames.err[0], &g_frames.nm[0]))
                FAILF("[stream/resync] FAIL %s prefix %zu\n", g_fix_name[i], l);
        }
    }
    printf("[stream/truncated-frame-then-resync] OK\n");
    return 0;
}

/* Random edits (structural characters, deletions, insertions): the stream
 * still returns exactly what the 1.3.3 parser returns. */
static int test_mutations(void)
{
    static const char alpha[] = "{}[]\",:\\ \t\n0a-";
    static char buf[32768 + 16];
    long n_ok = 0, n_err = 0;
    for (int i = 0; i < g_nfix; i++) {
        const int iters = g_fix_len[i] > 4096 ? 400 : 1500;
        for (int t = 0; t < iters; t++) {
            size_t len = g_fix_len[i];
            memcpy(buf, g_fix_store[i], len);
            const int edits = 1 + (int)(rnd() % 3);
            for (int e = 0; e < edits && len > 0; e++) {
                size_t p = rnd() % len;
                const uint32_t op = rnd() % 4;
                char c = (rnd() % 4) ? alpha[rnd() % (sizeof(alpha) - 1)] : (char)(32 + rnd() % 95);
                if (op <= 1) {
                    buf[p] = c;
                } else if (op == 2) {
                    memmove(buf + p, buf + p + 1, len - p - 1); len--;
                } else if (len < sizeof(buf) - 1) {
                    memmove(buf + p + 1, buf + p, len - p); buf[p] = c; len++;
                }
            }
            esp_err_t ew;
            if (!diff_one(buf, len, &ew))
                FAILF("[stream/mutations] FAIL %s iter %d: %.*s\n", g_fix_name[i], t,
                      (int)(len < 300 ? len : 300), buf);
            if (ew == ESP_OK) n_ok++; else n_err++;
        }
    }
    printf("  mutations: %ld parsed, %ld rejected, all as 1.3.3\n", n_ok, n_err);
    printf("[stream/random-mutations-same-as-1.3.3] OK\n");
    return 0;
}

/* --- elements larger than the buffer -------------------------------------- */

/* A peer of exactly `total` bytes: a long Hostinfo string, few tokens. */
static size_t put_big_peer(char *out, size_t total, int id)
{
    int k = snprintf(out, total + 1, "{\"ID\":%d,\"Hostinfo\":{\"Hostname\":\"", id);
    size_t fill = total - (size_t)k - 3;
    memset(out + k, 'h', fill);
    memcpy(out + k + fill, "\"}}", 4);   /* and the NUL */
    return total;
}

static int expect_frame(const char *name, const char *with, size_t with_len,
                        const char *without, size_t without_len,
                        unsigned want_oversized, int patch_overflow)
{
    static tl_netmap_t got, want;
    mapresp_json_t st;
    esp_err_t eg = stream_parse(with, with_len, g_elem, sizeof(g_elem), &got, &st);
    esp_err_t ew = ref_mapresp_parse(without, without_len, &want);
    if (patch_overflow) want.patches_overflow = true;
    if (eg != ESP_OK || !same_result(eg, &got, ew, &want) || st.n_oversized != want_oversized)
        FAILF("[%s] FAIL err=%d oversized=%u\n", name, eg, st.n_oversized);
    /* Same through the framing layer, byte by byte, then a frame after it. */
    static mapresp_stream_t ms;
    static tl_netmap_t nm;
    static uint8_t wire[2 * 32768 + 16];
    size_t n = put_frame(wire, with, with_len);
    n += put_frame(wire + n, kStub, strlen(kStub));
    memset(&g_frames, 0, sizeof(g_frames));
    g_frames.stop_at = -1;
    mapresp_stream_init(&ms, g_elem, sizeof(g_elem), &nm, on_frame, &g_frames);
    static tl_netmap_t stub;
    esp_err_t es = ref_mapresp_parse(kStub, strlen(kStub), &stub);
    if (feed_chunked(&ms, wire, n, chunk_1) != 0 || g_frames.n != 2 ||
        !same_result(g_frames.err[0], &g_frames.nm[0], ew, &want) ||
        !same_result(g_frames.err[1], &g_frames.nm[1], es, &stub) ||
        g_frames.elem_peak[0] < TL_CTRL_MAPRESP_CAP)
        FAILF("[%s] FAIL through the stream\n", name);
    printf("[%s] OK\n", name);
    return 0;
}

static int test_oversized(void)
{
    static char with[32768], without[32768], big[20000];
    const size_t cap = TL_CTRL_MAPRESP_CAP;
    size_t bl, wl, ol;

    /* Peer of cap + 1 bytes between two normal ones: skipped, the rest of
     * the map (the DERPMap after it) parsed, the stream in sync. */
    bl = put_big_peer(big, cap + 1, 77);
    wl = (size_t)snprintf(with, sizeof(with),
        "{\"Peers\":[{\"ID\":1},%.*s,{\"ID\":2}],\"DERPMap\":{\"Regions\":{\"16\":"
        "{\"RegionID\":16,\"Nodes\":[{\"HostName\":\"d16\"}]}}}}", (int)bl, big);
    ol = (size_t)snprintf(without, sizeof(without),
        "{\"Peers\":[{\"ID\":1},{\"ID\":2}],\"DERPMap\":{\"Regions\":{\"16\":"
        "{\"RegionID\":16,\"Nodes\":[{\"HostName\":\"d16\"}]}}}}");
    if (expect_frame("stream/oversized-peer-skipped", with, wl, without, ol, 1, 0)) return 1;

    /* Exactly the buffer: parsed like 1.3.3 does. */
    bl = put_big_peer(big, cap, 77);
    wl = (size_t)snprintf(with, sizeof(with), "{\"Peers\":[{\"ID\":1},%.*s]}", (int)bl, big);
    if (expect_frame("stream/element-of-exactly-the-buffer-parsed", with, wl, with, wl, 0, 0)) return 1;

    /* Self node over the buffer: no self (as 1.3.3 without the member). */
    bl = put_big_peer(big, cap + 500, 5);
    wl = (size_t)snprintf(with, sizeof(with), "{\"Node\":%.*s,\"Peers\":[{\"ID\":1}]}", (int)bl, big);
    ol = (size_t)snprintf(without, sizeof(without), "{\"Peers\":[{\"ID\":1}]}");
    if (expect_frame("stream/oversized-node-skipped", with, wl, without, ol, 1, 0)) return 1;

    /* The kept DERP region over the buffer: no region, have_derp_map set. */
    {
        size_t o = (size_t)snprintf(big, sizeof(big), "{\"RegionID\":16,\"RegionName\":\"");
        memset(big + o, 'r', cap); o += cap;
        o += (size_t)snprintf(big + o, sizeof(big) - o, "\",\"Nodes\":[{\"HostName\":\"d16\"}]}");
        wl = (size_t)snprintf(with, sizeof(with),
            "{\"DERPMap\":{\"Regions\":{\"1\":{\"RegionID\":1},\"16\":%.*s}}}", (int)o, big);
        ol = (size_t)snprintf(without, sizeof(without),
            "{\"DERPMap\":{\"Regions\":{\"1\":{\"RegionID\":1}}}}");
        if (expect_frame("stream/oversized-region-skipped", with, wl, without, ol, 1, 0)) return 1;
    }

    /* A patch over the buffer may hide a key change: patches_overflow
     * (the stream recycles for a full map), the other patch kept. */
    {
        size_t o = (size_t)snprintf(big, sizeof(big), "{\"NodeID\":9,\"Cap\":\"");
        memset(big + o, 'c', cap); o += cap;
        o += (size_t)snprintf(big + o, sizeof(big) - o, "\"}");
        wl = (size_t)snprintf(with, sizeof(with),
            "{\"PeersChangedPatch\":[%.*s,{\"NodeID\":4,\"DERPRegion\":2}]}", (int)o, big);
        ol = (size_t)snprintf(without, sizeof(without),
            "{\"PeersChangedPatch\":[{\"NodeID\":4,\"DERPRegion\":2}]}");
        if (expect_frame("stream/oversized-patch-overflows", with, wl, without, ol, 1, 1)) return 1;
    }

    /* PeersRemoved: an element of ≥ 24 bytes was never a NodeID — skipped
     * silently, exactly as before (no oversize count, same result). */
    {
        size_t o = 0;
        big[o++] = '"'; memset(big + o, 'x', cap * 2); o += cap * 2; big[o++] = '"';
        wl = (size_t)snprintf(with, sizeof(with), "{\"PeersRemoved\":[5,%.*s,6]}", (int)o, big);
        static tl_netmap_t got, want;
        mapresp_json_t st;
        if (stream_parse(with, wl, g_elem, sizeof(g_elem), &got, &st) != ESP_OK ||
            ref_mapresp_parse(with, wl, &want) != ESP_OK || memcmp(&got, &want, sizeof(got)) != 0 ||
            got.n_removed != 2 || st.n_oversized != 0)
            FAILF("[stream/long-removed-entry-skipped] FAIL\n");
        printf("[stream/long-removed-entry-skipped] OK\n");
    }
    return 0;
}

/* --- framing --------------------------------------------------------------- */

static int test_framing(void)
{
    static mapresp_stream_t ms;
    static tl_netmap_t nm;
    uint8_t wire[64];

    /* A zero-length frame is a malformed MapResponse, not a stop; the
     * next frame parses. */
    size_t n = put_frame(wire, "", 0);
    n += put_frame(wire + n, "{\"KeepAlive\":true}", 18);
    memset(&g_frames, 0, sizeof(g_frames)); g_frames.stop_at = -1;
    mapresp_stream_init(&ms, g_elem, sizeof(g_elem), &nm, on_frame, &g_frames);
    if (mapresp_stream_feed(&ms, wire, n) != 0 || g_frames.n != 2 ||
        g_frames.err[0] == ESP_OK || g_frames.err[1] != ESP_OK)
        FAILF("[stream/zero-length-frame] FAIL\n");
    printf("[stream/zero-length-frame] OK\n");

    /* Over MAPRESP_FRAME_MAX: stop (long-poll reconnects), no frame. */
    const uint32_t big = MAPRESP_FRAME_MAX + 1u;
    uint8_t hdr[5] = { (uint8_t)big, (uint8_t)(big >> 8), (uint8_t)(big >> 16), (uint8_t)(big >> 24), '{' };
    memset(&g_frames, 0, sizeof(g_frames)); g_frames.stop_at = -1;
    mapresp_stream_init(&ms, g_elem, sizeof(g_elem), &nm, on_frame, &g_frames);
    if (mapresp_stream_feed(&ms, hdr, 2) != 0 || mapresp_stream_feed(&ms, hdr + 2, 3) != -1 ||
        g_frames.n != 0)
        FAILF("[stream/frame-over-cap-stops] FAIL\n");
    /* A desynchronised stream reading JSON as a length stops at once. */
    mapresp_stream_init(&ms, g_elem, sizeof(g_elem), &nm, on_frame, &g_frames);
    if (mapresp_stream_feed(&ms, (const uint8_t *)"{\"Pe", 4) != -1)
        FAILF("[stream/frame-over-cap-stops] FAIL desync\n");
    /* Exactly at the cap is accepted (the header alone, no body yet). */
    const uint32_t at = MAPRESP_FRAME_MAX;
    uint8_t hdr2[4] = { (uint8_t)at, (uint8_t)(at >> 8), (uint8_t)(at >> 16), (uint8_t)(at >> 24) };
    mapresp_stream_init(&ms, g_elem, sizeof(g_elem), &nm, on_frame, &g_frames);
    if (mapresp_stream_feed(&ms, hdr2, 4) != 0) FAILF("[stream/frame-over-cap-stops] FAIL at cap\n");
    printf("[stream/frame-over-cap-stops] OK\n");

    /* on_frame asking to stop (recycle) ends the feed in that chunk; the
     * bytes after it are not parsed. */
    n = put_frame(wire, "{\"KeepAlive\":true}", 18);
    n += put_frame(wire + n, "{\"KeepAlive\":true}", 18);
    memset(&g_frames, 0, sizeof(g_frames)); g_frames.stop_at = 0;
    mapresp_stream_init(&ms, g_elem, sizeof(g_elem), &nm, on_frame, &g_frames);
    if (mapresp_stream_feed(&ms, wire, n) != -1 || g_frames.n != 1)
        FAILF("[stream/handler-stop] FAIL\n");
    printf("[stream/handler-stop] OK\n");

    /* Several frames in one chunk, a frame split over three. */
    n = put_frame(wire, "{\"KeepAlive\":true}", 18);
    n += put_frame(wire + n, "{\"PeersRemoved\":[7]}", 20);
    memset(&g_frames, 0, sizeof(g_frames)); g_frames.stop_at = -1;
    mapresp_stream_init(&ms, g_elem, sizeof(g_elem), &nm, on_frame, &g_frames);
    if (mapresp_stream_feed(&ms, wire, 3) != 0 || mapresp_stream_feed(&ms, wire + 3, 20) != 0 ||
        mapresp_stream_feed(&ms, wire + 23, n - 23) != 0 || g_frames.n != 2 ||
        g_frames.err[1] != ESP_OK || g_frames.nm[1].n_removed != 1 || g_frames.nm[1].removed_ids[0] != 7)
        FAILF("[stream/frames-across-chunks] FAIL\n");
    printf("[stream/frames-across-chunks] OK\n");
    return 0;
}

static int stream_suite(void)
{
    build_fixtures();
    if (test_fixture_sizes()) return 1;
    if (test_differential()) return 1;
    if (test_chunking()) return 1;
    if (test_truncation()) return 1;
    if (test_mutations()) return 1;
    if (test_oversized()) return 1;
    if (test_framing()) return 1;
    return 0;
}
