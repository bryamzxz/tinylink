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
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../components/tinylink/src/netmap.h"
#include "../../components/tinylink/src/mapreq.h"

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
      "}"
    "}"
  "},"
  "\"DomainDataPlaneAuditLogID\":\"ignored\""
"}";

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

    if (!nm.have_derp_map || nm.n_derp_regions != 1) {
        printf("[derp.regions] FAIL n=%zu\n", nm.n_derp_regions);
        return 1;
    }
    if (nm.derp_regions[0].region_id != 13 ||
        nm.derp_regions[0].n_nodes != 1 ||
        strcmp(nm.derp_regions[0].nodes[0].hostname,
               "derp13.tailscale.com") != 0 ||
        nm.derp_regions[0].nodes[0].port != 443) {
        printf("[derp.node] FAIL\n");
        return 1;
    }

    /* Full-map frames must never request a patch-driven refetch. */
    if (nm.patch_identity_changed) {
        printf("[patch/full-map-clear] FAIL\n");
        return 1;
    }
    printf("[mapresp-stub] OK\n");

    /* --- PeersChangedPatch identity detection (2026-07 audit) --------
     * headscale ≥0.29.2 / tailscale.com deliver a peer's re-login (new
     * NodeKey + DiscoKey) as a PeersChangedPatch. tinylink doesn't merge
     * patches; it must FLAG identity-bearing ones so the stream layer
     * recycles for a full map, and must keep ignoring endpoint-only
     * churn (covered by DISCO). */
    static const char *kPatchKey =
        "{\"PeersChangedPatch\":[{\"NodeID\":99,"
        "\"Key\":\"nodekey:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
        "\"KeyExpiry\":\"2027-01-01T00:00:00Z\"}]}";
    if (mapresp_parse(kPatchKey, strlen(kPatchKey), &nm) != ESP_OK ||
        !nm.patch_identity_changed || nm.n_peers != 0) {
        printf("[patch/key-flagged] FAIL flag=%d peers=%zu\n",
               nm.patch_identity_changed, nm.n_peers);
        return 1;
    }
    printf("[patch/key-flagged] OK\n");

    static const char *kPatchDisco =
        "{\"PeersChangedPatch\":[{\"NodeID\":99,"
        "\"DiscoKey\":\"discokey:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}]}";
    if (mapresp_parse(kPatchDisco, strlen(kPatchDisco), &nm) != ESP_OK ||
        !nm.patch_identity_changed) {
        printf("[patch/disco-flagged] FAIL\n");
        return 1;
    }
    printf("[patch/disco-flagged] OK\n");

    /* Endpoint/DERP-only patch: routine churn, must NOT trigger. */
    static const char *kPatchEndpoints =
        "{\"PeersChangedPatch\":[{\"NodeID\":99,"
        "\"Endpoints\":[\"203.0.113.9:41641\"],\"DERPRegion\":16,"
        "\"Online\":true}]}";
    if (mapresp_parse(kPatchEndpoints, strlen(kPatchEndpoints), &nm) != ESP_OK ||
        nm.patch_identity_changed) {
        printf("[patch/endpoints-ignored] FAIL\n");
        return 1;
    }
    printf("[patch/endpoints-ignored] OK\n");

    /* Mixed frame: full peer list + identity patch. The flag is set but
     * the stream layer gates the recycle on n_peers==0, because the full
     * list in the same frame already delivers the fresh keys. Lock both
     * halves of that contract here. */
    static const char *kMixed =
        "{\"Peers\":[{\"ID\":99,"
        "\"Key\":\"nodekey:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\""
        "}],"
        "\"PeersChangedPatch\":[{\"NodeID\":99,"
        "\"DiscoKey\":\"discokey:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"}]}";
    if (mapresp_parse(kMixed, strlen(kMixed), &nm) != ESP_OK ||
        !nm.patch_identity_changed || nm.n_peers != 1) {
        printf("[patch/mixed-frame] FAIL flag=%d peers=%zu\n",
               nm.patch_identity_changed, nm.n_peers);
        return 1;
    }
    printf("[patch/mixed-frame] OK\n");

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

    printf("ALL OK\n");
    return 0;
}
