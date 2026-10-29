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
    if (mapresp_parse(kDerpOnly, strlen(kDerpOnly), &nm) != ESP_OK ||
        !nm.have_derp_map || nm.n_derp_regions != 1 || nm.have_self || nm.n_peers != 0) {
        printf("[derp-only-frame] FAIL\n");
        return 1;
    }
    printf("[derp-only-frame] OK\n");

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
