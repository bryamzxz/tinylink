// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "tinylink.h"

#include <errno.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "mbedtls/platform_util.h"
#include "nvs.h"
#include "sdkconfig.h"

#include "control_key.h"
#include "derp_client.h"
#include "disco.h"
#include "disco_handler.h"
#include "disco_prober.h"
#include "keys.h"
#include "esp_random.h"

#ifdef ESP_PLATFORM
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#endif
#include "mapreq.h"
#include "netmap.h"
#include "register.h"
#include "stun.h"
#include "stun_probe.h"
#include "telemetry.h"
#include "ts2021_client.h"
#include "wg_dataplane.h"
#include "wg_netif.h"
#include "wg_proto.h"

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

static const char *TAG = "tinylink";

static const char k_version[] =
    STR(TINYLINK_VERSION_MAJOR) "."
    STR(TINYLINK_VERSION_MINOR) "."
    STR(TINYLINK_VERSION_PATCH);

static tinylink_keys_t s_keys;
static uint8_t         s_control_pub[32];
static bool            s_initialized;

/* M4 STUN probe result. Populated by tinylink_stun_probe(); read by
 * mapreq.c when building HostInfo.Endpoints. The accessor below is
 * the only way out — the global is private. */
static stun_probe_result_t s_stun_result;

/* Persistent ts2021/Noise channel to the control plane, mirroring
 * upstream's controlclient.Direct.noiseClient (one client reused for
 * register, map and map-stream). Avoids the heap-corruption assert we
 * hit when ts2021_close+ts2021_connect cycles ran back-to-back, AND
 * saves a Noise IK + TLS handshake on every long-poll reconnect. */
static ts2021_conn_t   s_conn;
static bool            s_conn_open;

static esp_err_t ensure_control_conn(void)
{
    if (s_conn_open) return ESP_OK;
    esp_err_t err = ts2021_connect(&s_conn, s_keys.machine_priv,
                                   s_keys.machine_pub, s_control_pub);
    if (err == ESP_OK) s_conn_open = true;
    return err;
}

static void drop_control_conn(void)
{
    if (!s_conn_open) return;
    ts2021_close(&s_conn);
    s_conn_open = false;
}

const char *tinylink_version_string(void)
{
    return k_version;
}

esp_err_t tinylink_init(void)
{
    esp_err_t err = keys_load_or_generate(&s_keys);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "keys_load_or_generate failed: 0x%x", err);
        return err;
    }
    err = control_key_get(s_control_pub);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "control_key_get failed: 0x%x", err);
        return err;
    }
    s_initialized = true;
    return ESP_OK;
}

esp_err_t tinylink_get_keys(tinylink_keys_t *out)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    memcpy(out, &s_keys, sizeof(*out));
    return ESP_OK;
}

/* TAI64N reservation lives in its own NVS namespace so wear from
 * boot-time writes is isolated from credentials and pinned keys. */
#define TAI64N_NVS_NS    "tl_state"
#define TAI64N_NVS_KEY   "tai_floor"

static int tai64n_persist_cb(uint64_t reservation_secs)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(TAI64N_NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "tai64n: nvs_open(%s) failed: 0x%x",
                 TAI64N_NVS_NS, err);
        return -1;
    }
    err = nvs_set_u64(h, TAI64N_NVS_KEY, reservation_secs);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "tai64n: nvs_set/commit failed: 0x%x", err);
        return -1;
    }
    return 0;
}

esp_err_t tinylink_tai64n_floor_init(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(TAI64N_NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "tai64n_floor_init: nvs_open(%s) failed 0x%x — "
                      "falling back to legacy unprotected behavior",
                 TAI64N_NVS_NS, err);
        wg_tai64n_init(0, 0, NULL);
        return err;
    }

    uint64_t persisted = 0;
    err = nvs_get_u64(h, TAI64N_NVS_KEY, &persisted);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        persisted = 0;
        err = ESP_OK;
    }
    nvs_close(h);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "tai64n_floor_init: nvs_get_u64 failed 0x%x — "
                      "falling back to legacy unprotected behavior", err);
        wg_tai64n_init(0, 0, NULL);
        return err;
    }

    /* Pre-reserve a chunk forward so the inline extend in
     * wg_tai64n_now does NOT fire on every boot's first handshake.
     * If the persist write fails here we still install the loaded
     * floor (cross-boot monotonicity preserved within the chunk we
     * already wrote on the previous boot) but mark s_persist_fn NULL
     * so the inline extend doesn't keep retrying a broken NVS. */
    uint64_t reservation = persisted + WG_TAI64N_RESERVE_CHUNK_SECS;
    int prst = tai64n_persist_cb(reservation);
    if (prst != 0) {
        ESP_LOGW(TAG, "tai64n_floor_init: pre-reserve persist failed — "
                      "in-RAM floor only; next reboot may rewind");
        wg_tai64n_init(persisted, persisted, NULL);
        return ESP_FAIL;
    }

    wg_tai64n_init(persisted, reservation, tai64n_persist_cb);
    ESP_LOGI(TAG, "tai64n_floor: persisted=%llu reservation=%llu (chunk=%llu)",
             (unsigned long long)persisted,
             (unsigned long long)reservation,
             (unsigned long long)WG_TAI64N_RESERVE_CHUNK_SECS);
    return ESP_OK;
}

static esp_err_t read_auth_key(char *out, size_t out_size)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open("tl_creds", NVS_READONLY, &h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open(tl_creds) failed: 0x%x", err);
        return err;
    }
    size_t len = out_size;
    err = nvs_get_str(h, "auth_key", out, &len);
    nvs_close(h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "auth_key missing from NVS: 0x%x", err);
    }
    return err;
}

esp_err_t tinylink_register(void)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;

    char auth_key[128];
    esp_err_t err = read_auth_key(auth_key, sizeof(auth_key));
    if (err != ESP_OK) return err;

    err = ensure_control_conn();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ts2021_connect failed: 0x%x", err);
        mbedtls_platform_zeroize(auth_key, sizeof(auth_key));
        return err;
    }

    err = register_emit(&s_conn, &s_keys, auth_key);

    /* Scrub the auth key in stack memory. mbedtls_platform_zeroize is a
     * compiler-barrier'd zero (won't be optimized out as a dead store the
     * way a plain memset on a no-longer-read buffer can). */
    mbedtls_platform_zeroize(auth_key, sizeof(auth_key));

    /* Drop the conn after register. Reusing the same ts2021 channel for
     * /machine/map fails because our h2_drive_request creates+destroys
     * a fresh nghttp2 session per request, and the GOAWAY emitted on
     * the first session_del causes the SECOND submit to land on a
     * half-closed transport (server returns HTTP 0).
     *
     * Until h2_client is refactored to keep ONE persistent nghttp2
     * session per ts2021 conn (matching upstream's go-http2 behavior),
     * the safe pattern is one ts2021 conn per request. The 24 KiB
     * long-poll stack now absorbs the second handshake without
     * blowing — see tinylink_long_poll_start. */
    drop_control_conn();
    return err;
}

esp_err_t tinylink_dataplane_start(void)
{
    /* The streaming /machine/map (Stream=true) request delivers the
     * initial netmap as its first frame, but per upstream tailcfg.go
     * (lines 1408-1436) the server treats Stream=true MapRequests as
     * READ-ONLY at Version >= 68 — Hostinfo and top-level Endpoints
     * are silently discarded. Verified 2026-05-07 against
     * controlplane.tailscale.com: a peer's `tailscale status` showed
     * `Addrs: null, Relay: ""` for sensor-cali after multiple
     * Stream=true cycles that included Endpoints + NetInfo.
     *
     * Push the device's current endpoints + NetInfo via a one-shot
     * Stream=false MapRequest before the long-poll grabs the conn.
     * This is the "fresh state upload" that updates the server's
     * cached Hostinfo/Endpoints record so peers see real dial
     * candidates and a HomeDERP region in their MapResponse. The
     * response (a full netmap) is parsed for status only — the
     * long-poll will redeliver it as its first stream frame. */
    if (!s_initialized) return ESP_ERR_INVALID_STATE;

    esp_err_t err = ensure_control_conn();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "dataplane_start: ensure_conn failed: 0x%x — "
                      "long-poll will retry the connect anyway", err);
        return ESP_OK;  /* not fatal — long-poll task handles reconnect */
    }

    /* Observability: was the STUN-discovered endpoint available when
     * we built the MapRequest body? STUN runs synchronously before
     * tinylink_register() in main.c::bringup so by the time we get
     * here it should be populated; log the actual state to surface
     * any future boot-race regression and to give a clear breadcrumb
     * when an admin-panel "Endpoints" field comes up empty. */
    uint8_t  ep_addr[4];
    uint16_t ep_port;
    bool stun_ready = tinylink_get_public_endpoint(ep_addr, &ep_port);
    if (stun_ready) {
        ESP_LOGI(TAG, "dataplane_start: pushing endpoint %u.%u.%u.%u:%u",
                 ep_addr[0], ep_addr[1], ep_addr[2], ep_addr[3],
                 (unsigned)ep_port);
    } else {
        ESP_LOGW(TAG, "dataplane_start: no STUN endpoint cached yet — "
                      "Stream=false MapRequest will land NetInfo only; "
                      "subsequent reprobe results never reach the server "
                      "while the long-poll's Stream=true cycle ignores "
                      "Hostinfo (followup PR: trigger fetch_once on "
                      "stun_reprobe endpoint-change)");
    }

    err = mapreq_push_endpoints(&s_conn, &s_keys);
    if (err != ESP_OK) {
        /* Drop the conn so the long-poll's next ensure_control_conn
         * gets a fresh one. Don't fail bringup — the long-poll path
         * will keep trying and may eventually succeed (or surface a
         * different error). */
        ESP_LOGW(TAG, "dataplane_start: mapreq_push_endpoints: 0x%x — "
                      "endpoints not pushed; long-poll will run anyway", err);
        drop_control_conn();
        return ESP_OK;
    }
    ESP_LOGI(TAG, "dataplane_start: pushed lite MapRequest "
                  "(Stream=false, OmitPeers=true, stun=%s)",
             stun_ready ? "ready" : "missing");
    /* Keep s_conn open — the long-poll will reuse it for the
     * Stream=true cycle. */
    return ESP_OK;
}

/* ---- long-poll MapRequest task ----------------------------------------- */

static bool s_dataplane_started;

/* ---- DERP smoke test (M5 step 2a) --------------------------------------
 *
 * One-shot synchronous connect+login against a configured DERP server.
 * Designed to run BEFORE tinylink_long_poll_start so only one TLS conn
 * is in flight — running it AFTER the long-poll grabs heap (we
 * observed 10 KiB largest-free-block while the long-poll's TLS conn
 * is alive, which is below mbedtls's ~12 KiB cert chain verify
 * peak) deterministically failed with TLS-connect ESP_FAIL.
 *
 * Step 2b will turn this into a long-running supervised connection
 * with packet relay; for step 2a we only prove the upgrade dance +
 * login frame exchange land cleanly against a real production DERP
 * server. */

esp_err_t tinylink_derp_smoke(void)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    const char *host = CONFIG_TINYLINK_DERP_SMOKE_HOST;
    if (host == NULL || host[0] == '\0') {
        ESP_LOGI(TAG, "DERP smoke disabled (empty host config)");
        return ESP_OK;
    }
    ESP_LOGI(TAG, "DERP smoke: target=%s heap_free=%u largest_block=%u",
             host,
             (unsigned)esp_get_free_heap_size(),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));

    derp_client_t c = {0};
    esp_err_t err = derp_client_connect_login(&c, host, 443,
                                              s_keys.node_priv,
                                              s_keys.node_pub);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "DERP smoke OK: %s server-version=%d",
                 host, c.server_version);
    } else {
        ESP_LOGW(TAG, "DERP smoke failed: 0x%x", err);
    }
    derp_client_close(&c);
    return err;
}

/* ---- DERP supervised recv-loop task (M5 step 2b) -----------------------
 *
 * Long-running task: connect+login → run recv loop → close → backoff →
 * repeat. Coexists with the long-poll's TLS conn at steady state but
 * the second handshake competes with mbedtls cert-chain-verify heap,
 * so connect failures are logged and retried with backoff (not fatal).
 *
 * Recv events are currently logged only — wiring relayed WireGuard
 * packets back into wg_demux is M5 step 3 work (depends on DISCO peer
 * registration to know which DERP src maps to which peer index). */

#if CONFIG_TINYLINK_DERP_SUPERVISED

/* Frame buffer sized for typical WG packets (<1500 B) plus the 32-byte
 * src-pub prefix and slack. */
#define DERP_SUP_FRAME_CAP 1600

/* Single DERP client owned by the supervisor task. File-scope so
 * tinylink_derp_supervised_start can establish it synchronously
 * before the long-poll claims heap, then hand ownership to the task. */
static derp_client_t s_derp_sup;

/* Latest DERP host the supervisor should connect to. Populated from
 * the netmap's derp_regions[] using CONFIG_TINYLINK_PREFERRED_DERP as
 * the region selector, so the supervisor lands at the same region we
 * advertise as our HomeDERP — peers send traffic to that region; if
 * we're connected elsewhere the relay can't route it.
 *
 * Initialized to the Kconfig fallback so the first connect attempt
 * (which races against the long-poll's first netmap) doesn't see an
 * empty string. Updated in-place from long_poll_handler each frame. */
static char s_derp_host[TL_DERP_HOSTNAME_LEN] = CONFIG_TINYLINK_DERP_SMOKE_HOST;

typedef struct {
    uint64_t recv_packets;
    uint64_t pings_answered;
    uint64_t keepalives;
    uint64_t peer_present;
    uint64_t peer_gone;
    uint64_t disco_pings_answered;
    uint64_t disco_pongs_seen;
    uint64_t disco_cmms_seen;
    uint64_t disco_send_errors;
} derp_sup_stats_t;

/* Detect if a 16-byte DISCO addr is the v4-mapped IPv6 form
 * `::ffff:a.b.c.d` (the only form our v4-only netif can dial). */
static bool disco_addr_is_v4_mapped(const uint8_t addr[16])
{
    static const uint8_t v4_mapped_prefix[12] = {
        0,0,0,0, 0,0,0,0, 0,0, 0xff, 0xff,
    };
    return memcmp(addr, v4_mapped_prefix, 12) == 0;
}

/* When a peer sends us a CallMeMaybe via DERP they're saying: "I want a
 * direct path; here are the endpoints I'm probing — please probe them
 * back so our NATs both open mappings simultaneously." Without this
 * handler, the peer's inbound DISCO Pings are dropped at one of the two
 * NATs and the direct path never establishes — `tailscale ping` stays
 * stuck on `via DERP(...)` forever.
 *
 * For each v4-mapped endpoint in the CMM we emit a fresh DISCO Ping
 * sealed against the peer's DiscoKey, sourced from the WG netif's UDP
 * socket so the source AddrPort is the same one our boot-time STUN
 * advertised — that's the AddrPort the peer's magicsock is targeting,
 * so its NAT mapping aligns with ours.
 *
 * On the peer's reply (our wg_netif RX task answers their inbound
 * Ping with a Pong; we currently don't track our outbound Pongs to
 * confirm a path is up, but the peer's magicsock tracks its own —
 * hence `tailscale ping` will report direct once any one of these
 * makes it through). */
/* Pre-punch DISCO ping to each WG peer's advertised v4 endpoints, fired
 * on every (non-KeepAlive) netmap that arrives. Counterpart to
 * send_disco_pings_to_cmm_endpoints, which only fires when the peer
 * sends us a CallMeMaybe — that path requires the peer to learn our
 * endpoint first (a DERP-relayed round-trip) before they can ask us to
 * punch. By the time the peer's first inbound DISCO ping reaches us,
 * our NAT mapping for the WG socket may not exist yet (cold boot) or
 * may have aged out (idle window > NAT timeout). Pre-punching here
 * means every netmap arrival opens or refreshes mappings on our side
 * to all peer endpoints we know, so an inbound first packet is much
 * more likely to find a still-open path.
 *
 * No filtering on RFC1918 / hairpin: matches the CMM-driven path's
 * behavior, where same-LAN endpoints are reachable and worth probing.
 * Endpoints we can't reach (LAN advertised by an off-LAN peer) just
 * fail silently in the WiFi default route — cheap. */
/* Refactored from `(const tl_netmap_t *nm)` so the path-stale callback
 * can cache JUST the peers array (~1 KiB) instead of the full netmap
 * struct (~7.5 KiB; derp_regions[28] dominates). The function only
 * ever reads n_peers + peers[] anyway. */
static void prepunch_pings_to_peers(const tl_peer_t *peers, size_t n_peers)
{
    if (peers == NULL || n_peers == 0) return;

    int sock = wg_netif_get_socket();
    if (sock < 0) return;  /* WG netif not yet bound: nothing to punch from */

    size_t total_sent = 0;
    for (size_t pi = 0; pi < n_peers; pi++) {
        const tl_peer_t *peer = &peers[pi];
        if (!peer->has_disco_pub) continue;        /* can't seal without DiscoKey */
        if (peer->n_endpoints == 0) continue;

        for (size_t ei = 0; ei < peer->n_endpoints; ei++) {
            /* "ip:port" → split. Mirror of wg_dataplane.c::parse_endpoint
             * (kept private to that TU; duplicating ~10 lines is cheaper
             * than extending the public header for one more caller). */
            const char *ep = peer->endpoints[ei].str;
            const char *colon = strrchr(ep, ':');
            if (colon == NULL) continue;
            char host[64];
            size_t hlen = (size_t)(colon - ep);
            if (hlen == 0 || hlen + 1 > sizeof(host)) continue;
            memcpy(host, ep, hlen);
            host[hlen] = '\0';
            int port = atoi(colon + 1);
            if (port <= 0 || port > 65535) continue;

            uint32_t v4_be = 0;
#ifdef ESP_PLATFORM
            if (inet_pton(AF_INET, host, &v4_be) != 1) continue;
#else
            (void)v4_be;
            continue;
#endif

            /* Build a sealed DISCO ping. NodeKey is included so the peer's
             * magicsock can correlate this probe with our WG peer entry
             * even when its DiscoKey-to-NodeKey mapping is sparse. */
            disco_ping_t ping = {0};
            esp_fill_random(ping.txid, DISCO_TXID_LEN);
            memcpy(ping.node_key, s_keys.node_pub, DISCO_NODEKEY_LEN);
            ping.has_node_key = true;

            uint8_t inner[DISCO_HANDLER_REPLY_MAX];
            size_t inner_len = disco_encode_ping(inner, sizeof(inner), &ping);
            if (inner_len == 0) continue;

            uint8_t nonce[DISCO_NONCE_LEN];
            esp_fill_random(nonce, sizeof(nonce));

            uint8_t wire[DISCO_HANDLER_REPLY_MAX];
            size_t wire_len = disco_seal(wire, sizeof(wire),
                                         inner, inner_len, nonce,
                                         s_keys.disco_pub, peer->disco_pub,
                                         s_keys.disco_priv);
            if (wire_len == 0) continue;

#ifdef ESP_PLATFORM
            struct sockaddr_in dst = {
                .sin_family = AF_INET,
                .sin_port   = htons((uint16_t)port),
            };
            dst.sin_addr.s_addr = v4_be;
            ssize_t n = sendto(sock, wire, wire_len, 0,
                               (struct sockaddr *)&dst, sizeof(dst));
            if (n < 0) {
                ESP_LOGW(TAG, "prepunch sendto: errno=%d (peer=%zu ep=%s)",
                         errno, pi, ep);
                continue;
            }
            /* Record the outbound probe so handle_disco_direct can
             * match the resulting Pong's txid (M3-step-3 binding). */
            disco_prober_record(ping.txid, v4_be, (uint16_t)port,
                                esp_timer_get_time());
#endif
            total_sent++;
            ESP_LOGI(TAG, "prepunch ping → %s txid=%02x%02x%02x%02x..",
                     ep, ping.txid[0], ping.txid[1],
                     ping.txid[2], ping.txid[3]);
        }
    }
    if (total_sent > 0) {
        ESP_LOGI(TAG, "prepunch on netmap-receive: sent %zu pings across %zu peers",
                 total_sent, n_peers);
    }
}

/* Thin wrapper for callers that already have a tl_netmap_t handy. */
static inline void prepunch_pings_to_peer_endpoints(const tl_netmap_t *nm)
{
    if (nm == NULL) return;
    prepunch_pings_to_peers(nm->peers, nm->n_peers);
}

static void send_disco_pings_to_cmm_endpoints(const derp_event_t *e)
{
    /* Re-decrypt + re-parse: handle_disco_relayed already did this
     * through disco_handle_recv, but that helper doesn't expose the
     * parsed CallMeMaybe payload. Doing it twice is a few KB of
     * NaCl-box CPU per CMM, which is rare enough to not matter. */
    uint8_t pt[256];
    uint8_t peer_disco_pub[DISCO_KEY_LEN];
    size_t pt_len = disco_open(pt, sizeof(pt), peer_disco_pub,
                               e->data, e->data_len, s_keys.disco_priv);
    if (pt_len == 0) return;

    disco_msg_t msg;
    if (disco_parse(pt, pt_len, &msg) != 0) return;
    if (msg.type != DISCO_TYPE_CALLMEMAYBE) return;

    int sock = wg_netif_get_socket();
    if (sock < 0) {
        ESP_LOGW(TAG, "cmm: wg socket not up — cannot punch");
        return;
    }

    size_t sent = 0;
    for (size_t i = 0; i < msg.u.cmm.n; i++) {
        const disco_addrport_t *ep = &msg.u.cmm.endpoints[i];
        if (!disco_addr_is_v4_mapped(ep->addr)) continue;

        /* Build a fresh ping inner. Includes our NodeKey so the peer's
         * magicsock can correlate this probe with the right peer entry
         * when its DiscoKey-to-NodeKey mapping is sparse. */
        disco_ping_t ping = {0};
        esp_fill_random(ping.txid, DISCO_TXID_LEN);
        memcpy(ping.node_key, s_keys.node_pub, DISCO_NODEKEY_LEN);
        ping.has_node_key = true;

        uint8_t inner[DISCO_HANDLER_REPLY_MAX];
        size_t inner_len = disco_encode_ping(inner, sizeof(inner), &ping);
        if (inner_len == 0) continue;

        uint8_t nonce[DISCO_NONCE_LEN];
        esp_fill_random(nonce, sizeof(nonce));

        uint8_t wire[DISCO_HANDLER_REPLY_MAX];
        size_t wire_len = disco_seal(wire, sizeof(wire),
                                     inner, inner_len, nonce,
                                     s_keys.disco_pub, peer_disco_pub,
                                     s_keys.disco_priv);
        if (wire_len == 0) continue;

#ifdef ESP_PLATFORM
        struct sockaddr_in dst = {
            .sin_family = AF_INET,
            .sin_port   = htons(ep->port),
        };
        memcpy(&dst.sin_addr.s_addr, &ep->addr[12], 4);
        ssize_t n = sendto(sock, wire, wire_len, 0,
                           (struct sockaddr *)&dst, sizeof(dst));
        if (n < 0) {
            ESP_LOGW(TAG, "cmm ping sendto: errno=%d", errno);
            continue;
        }
        /* Record the outbound CMM-punch probe so the Pong's txid is
         * matchable (M3-step-3). */
        disco_prober_record(ping.txid, dst.sin_addr.s_addr, ep->port,
                            esp_timer_get_time());
#endif
        sent++;
        ESP_LOGI(TAG, "cmm punch ping → %u.%u.%u.%u:%u txid=%02x%02x%02x%02x..",
                 ep->addr[12], ep->addr[13], ep->addr[14], ep->addr[15],
                 (unsigned)ep->port,
                 ping.txid[0], ping.txid[1], ping.txid[2], ping.txid[3]);
    }
    if (sent == 0 && msg.u.cmm.n > 0) {
        ESP_LOGW(TAG, "cmm: %u endpoints but none v4-mapped",
                 (unsigned)msg.u.cmm.n);
    }
}

/* Try to decrypt+answer the relayed packet as DISCO. If it's not a
 * DISCO frame the handler short-circuits cheap; if it's a Ping we
 * build a sealed Pong and ship it back via derp_client_send_packet.
 *
 * The DERP src_pub is the originator's NodePublic (DERP routes by
 * NodeKey); reusing it as the dst for our Pong sends the reply back
 * along the same DERP route. The DiscoKey lives in the encrypted
 * frame's cleartext header — disco_handle_recv extracts it for us. */
static void handle_disco_relayed(const derp_event_t *e,
                                 derp_sup_stats_t *st)
{
    uint8_t reply[DISCO_HANDLER_REPLY_MAX];
    disco_msg_type_t type = (disco_msg_type_t)0;
    uint8_t peer_disco_pub[DISCO_KEY_LEN] = {0};
    uint8_t txid[DISCO_TXID_LEN] = {0};

    size_t reply_len = disco_handle_recv(reply, sizeof(reply),
                                         e->data, e->data_len,
                                         s_keys.disco_priv, s_keys.disco_pub,
                                         &type, peer_disco_pub, txid);
    switch (type) {
    case DISCO_TYPE_PING:
        if (reply_len > 0) {
            esp_err_t err = derp_client_send_packet(
                &s_derp_sup, e->src_pub, reply, reply_len);
            if (err == ESP_OK) {
                st->disco_pings_answered++;
                ESP_LOGI(TAG,
                    "disco ping→pong: peer=%02x%02x..%02x%02x txid=%02x%02x%02x%02x..",
                    e->src_pub[0], e->src_pub[1],
                    e->src_pub[DERP_KEY_LEN - 2], e->src_pub[DERP_KEY_LEN - 1],
                    txid[0], txid[1], txid[2], txid[3]);
            } else {
                st->disco_send_errors++;
                ESP_LOGW(TAG, "disco pong send failed: 0x%x", err);
            }
        }
        break;
    case DISCO_TYPE_PONG:
        st->disco_pongs_seen++;
        ESP_LOGD(TAG, "disco pong received (no outbound prober yet)");
        break;
    case DISCO_TYPE_CALLMEMAYBE:
        st->disco_cmms_seen++;
        ESP_LOGI(TAG, "disco call-me-maybe — punching endpoints");
        send_disco_pings_to_cmm_endpoints(e);
        break;
    default: {
        /* Not a DISCO frame for us — could be a relayed WireGuard
         * handshake response or transport packet from the active
         * peer. Hand it to wg_netif's inject path so the existing
         * demux + handler chain treats it identically to a UDP recv.
         * Mismatched src_pub (a peer we don't have a session with)
         * is dropped inside the inject API. */
        esp_err_t ie = wg_netif_inject_packet(e->src_pub, e->data, e->data_len);
        if (ie == ESP_ERR_INVALID_RESPONSE) {
            ESP_LOGD(TAG, "relayed pkt from non-active peer dropped (len=%u)",
                     (unsigned)e->data_len);
        } else if (ie != ESP_OK) {
            ESP_LOGW(TAG, "wg_netif_inject_packet: 0x%x", ie);
        }
        break;
    }
    }
}

static int derp_sup_event_cb(const derp_event_t *e, void *ctx)
{
    derp_sup_stats_t *st = (derp_sup_stats_t *)ctx;
    switch (e->kind) {
    case DERP_EVT_RECV_PACKET:
        st->recv_packets++;
        ESP_LOGI(TAG, "derp recv: src=%02x%02x..%02x%02x len=%u (total=%llu)",
                 e->src_pub[0], e->src_pub[1],
                 e->src_pub[DERP_KEY_LEN - 2], e->src_pub[DERP_KEY_LEN - 1],
                 (unsigned)e->data_len,
                 (unsigned long long)st->recv_packets);
        handle_disco_relayed(e, st);
        break;
    case DERP_EVT_KEEPALIVE:
        st->keepalives++;
        ESP_LOGD(TAG, "derp keepalive (total=%llu)",
                 (unsigned long long)st->keepalives);
        break;
    case DERP_EVT_PEER_PRESENT:
        st->peer_present++;
        ESP_LOGI(TAG, "derp peer-present: %02x%02x..%02x%02x",
                 e->src_pub[0], e->src_pub[1],
                 e->src_pub[DERP_KEY_LEN - 2], e->src_pub[DERP_KEY_LEN - 1]);
        break;
    case DERP_EVT_PEER_GONE:
        st->peer_gone++;
        ESP_LOGI(TAG, "derp peer-gone: %02x%02x..%02x%02x reason=%u",
                 e->src_pub[0], e->src_pub[1],
                 e->src_pub[DERP_KEY_LEN - 2], e->src_pub[DERP_KEY_LEN - 1],
                 (unsigned)e->peer_gone_reason);
        break;
    case DERP_EVT_HEALTH:
        ESP_LOGW(TAG, "derp health: %.*s",
                 (int)(e->data_len > 80 ? 80 : e->data_len),
                 (const char *)e->data);
        break;
    case DERP_EVT_RESTARTING:
        ESP_LOGW(TAG, "derp restarting: reconnect_ms=%u total_ms=%u",
                 (unsigned)e->restart_reconnect_ms,
                 (unsigned)e->restart_total_ms);
        break;
    }
    return 0;
}

/* Task entry: own the connect + recv-loop + close + backoff cycle
 * end-to-end. Initial connect lives here (not in the start() caller)
 * so a transient heap shortage at bringup time doesn't tear the
 * supervisor down for the rest of the session — the task simply
 * loops on backoff until heap settles enough for the mbedtls cert
 * chain verify (~12 KiB contiguous). With the post-#32 budget
 * (DYNAMIC_BUFFER=y, SESSION_TICKETS=n) the supervisor's connect
 * peak slips below the largest free block once the long-poll's
 * first reconnect cycle frees its handshake scratch. */
static void derp_supervised_task(void *arg)
{
    (void)arg;
    /* Exponential backoff: start at the Kconfig base, double on each
     * consecutive connect failure, cap at 30 s (per WG/Tailscale
     * convention — long enough that we don't hammer a server that's
     * down, short enough that recovery from a transient outage feels
     * snappy). Reset to base on a successful login so the *next*
     * outage starts fresh instead of inheriting hours of accumulated
     * doubling. */
    const TickType_t base_backoff =
        pdMS_TO_TICKS(CONFIG_TINYLINK_DERP_SUPERVISED_BACKOFF_MS);
    const TickType_t max_backoff = pdMS_TO_TICKS(30000);
    TickType_t backoff = base_backoff;

    derp_sup_stats_t stats = {0};
    static uint8_t frame_buf[DERP_SUP_FRAME_CAP];
    unsigned attempt = 0;

    for (;;) {
        /* Connect with backoff — runs at boot too, not just on
         * reconnect. Re-read s_derp_host every iteration so a netmap
         * update that changes the preferred region's host steers the
         * NEXT reconnect to the right relay. */
        for (;;) {
            attempt++;
            const char *host = s_derp_host;
            ESP_LOGI(TAG, "derp supervisor: connect attempt #%u to %s "
                          "(heap_free=%u largest=%u)",
                     attempt, host,
                     (unsigned)esp_get_free_heap_size(),
                     (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));
            esp_err_t cerr = derp_client_connect_login(&s_derp_sup, host, 443,
                                                       s_keys.node_priv,
                                                       s_keys.node_pub);
            if (cerr == ESP_OK) {
                ESP_LOGI(TAG, "derp supervisor: login OK server-v=%d "
                              "(after %u attempts)",
                         s_derp_sup.server_version, attempt);
                attempt = 0;
                backoff = base_backoff;
                break;
            }
            ESP_LOGW(TAG, "derp supervisor: connect attempt #%u failed 0x%x — "
                          "backoff %u ms",
                     attempt, cerr,
                     (unsigned)pdTICKS_TO_MS(backoff));
            derp_client_close(&s_derp_sup);
            vTaskDelay(backoff);
            /* Double for the next attempt, cap at max. The wrap guard
             * (next < backoff) is paranoia — at 100 Hz tick rate the
             * cap kicks in after 13 doublings, far below uint32 wrap. */
            TickType_t next = backoff * 2;
            backoff = (next > max_backoff || next < backoff)
                      ? max_backoff : next;
        }

        ESP_LOGI(TAG, "derp supervisor: entering recv loop server-v=%d",
                 s_derp_sup.server_version);
        esp_err_t err = derp_client_run(&s_derp_sup, frame_buf, sizeof(frame_buf),
                                        derp_sup_event_cb, &stats);
        if (err == ESP_ERR_INVALID_RESPONSE) {
            ESP_LOGW(TAG, "derp supervisor: server restarting — backoff");
        } else {
            ESP_LOGW(TAG, "derp supervisor: stream ended 0x%x — "
                          "stats recv=%llu disco_pongs=%llu "
                          "disco_pings_seen=%llu disco_cmms=%llu "
                          "send_err=%llu keepalives=%llu wg_tx_drops=%llu",
                     err,
                     (unsigned long long)stats.recv_packets,
                     (unsigned long long)stats.disco_pings_answered,
                     (unsigned long long)stats.disco_pongs_seen,
                     (unsigned long long)stats.disco_cmms_seen,
                     (unsigned long long)stats.disco_send_errors,
                     (unsigned long long)stats.keepalives,
                     (unsigned long long)wg_netif_get_tx_drops());
        }
        derp_client_close(&s_derp_sup);
        vTaskDelay(backoff);
    }
}

#endif /* CONFIG_TINYLINK_DERP_SUPERVISED */

esp_err_t tinylink_derp_supervised_start(void)
{
#if CONFIG_TINYLINK_DERP_SUPERVISED
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    /* s_derp_host is initialized from the Kconfig fallback at file
     * scope and updated to the netmap-derived hostname for our
     * advertised PreferredDERP region by long_poll_handler. */
    const char *host = s_derp_host;
    if (host == NULL || host[0] == '\0') {
        ESP_LOGI(TAG, "derp supervisor: disabled (empty host)");
        return ESP_OK;
    }

    /* Spawn the task. 12 KiB stack: mbedtls handshake peak is the
     * dominant frame (~6 KiB stack) plus the derp recv loop's small
     * frames. The long-poll task ships at 24 KiB but holds a static
     * tl_netmap_t in its frame; the supervisor doesn't, so half the
     * budget is enough.
     *
     * On stock ESP32-WROOM-32E the heap at this point of bringup is
     * already claimed by the long-poll's TLS conn + nghttp2 session
     * + WG netif state, leaving < 12 KiB largest contiguous block.
     * xTaskCreate returning ESP_ERR_NO_MEM here is the expected
     * failure mode and the function returns the error so main.c
     * can log + continue. The retry/backoff inside
     * derp_supervised_task only fires once xTaskCreate succeeds —
     * spawning the task itself requires heap we may not have. The
     * static-stack alternative was tested on-device 2026-05-06 and
     * pushed BSS past the DRAM threshold, crashing startup with
     * `esp_startup_start_app: res == pdTRUE` assertion. Fixing this
     * properly needs BSS shrink (streaming JSON parser frees ~48
     * KiB) or PSRAM. */
    BaseType_t ok = xTaskCreate(derp_supervised_task, "tinylink_derp",
                                12288, NULL, tskIDLE_PRIORITY + 3, NULL);
    if (ok != pdPASS) {
        ESP_LOGE(TAG, "xTaskCreate(derp supervisor) failed — "
                      "heap_free=%u largest=%u (need 12 KiB contiguous)",
                 (unsigned)esp_get_free_heap_size(),
                 (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "derp supervisor: task spawned (host=%s, backoff=%u ms)",
             host, (unsigned)CONFIG_TINYLINK_DERP_SUPERVISED_BACKOFF_MS);
    return ESP_OK;
#else
    return ESP_OK;
#endif
}

#if CONFIG_TINYLINK_DERP_SUPERVISED
/* Walk the netmap's DERP region table for the region matching our
 * advertised PreferredDERP and copy the first node's hostname into
 * s_derp_host. No-op if PreferredDERP isn't represented in the
 * parsed netmap (region_id mismatch or region has no nodes). The
 * supervisor task reads s_derp_host on every connect attempt so the
 * next reconnect picks up the change. */
static void update_derp_host_from_netmap(const tl_netmap_t *nm)
{
    const int want = CONFIG_TINYLINK_PREFERRED_DERP;
    if (want <= 0) return;
    for (size_t i = 0; i < nm->n_derp_regions; i++) {
        const tl_derp_region_t *r = &nm->derp_regions[i];
        if (r->region_id != want || r->n_nodes == 0) continue;
        const char *h = r->nodes[0].hostname;
        if (h[0] == '\0') continue;
        if (strcmp(s_derp_host, h) == 0) return;  /* unchanged */
        snprintf(s_derp_host, sizeof(s_derp_host), "%s", h);
        ESP_LOGI(TAG, "derp host updated to region %d node: %s",
                 want, s_derp_host);
        return;
    }
}
#endif

/* Cache the latest netmap PEERS for path-stale active probing.
 * tl_peer_t[TL_MAX_PEERS] is ~1 KiB; the full tl_netmap_t is ~7.5 KiB
 * (derp_regions[28] dominates). Caching just the peers BSS keeps the
 * total static-allocation footprint inside the DRAM budget WiFi init
 * needs contiguous (verified: caching the full netmap pushed boot
 * into vApplicationGetTimerTaskMemory pvPortMalloc-NULL asserts).
 *
 * Updated under no lock — long_poll_handler is the only writer, and
 * the path-stale callback tolerates a torn array: at worst it sends
 * DISCO to a half-old, half-new endpoint list, which is harmless
 * (mismatched entries fail to elicit a sealed pong). */
static tl_peer_t  s_last_peers[TL_MAX_PEERS];
static size_t     s_last_peers_count;

/* Called from wg_netif's rx_task when the WG transport has been silent
 * past WG_RX_STALE_THRESHOLD_MS. Re-runs prepunch against the latest
 * known peer endpoints — any peer that's now reachable via a different
 * AddrPort (e.g. post-reboot with a fresh NAT mapping) will reply with
 * a DISCO pong from the new AddrPort, and wg_netif's handle_disco_direct
 * will roam g.peer.peer_endpoint to it before the next handshake INIT
 * goes out. */
static void on_wg_path_stale(void *user)
{
    (void)user;
    if (s_last_peers_count == 0) return;
    prepunch_pings_to_peers(s_last_peers, s_last_peers_count);
}

static esp_err_t long_poll_handler(const tl_netmap_t *nm, void *ctx)
{
    (void)ctx;
    /* Snapshot just the peer array for the path-stale probe. */
    size_t n = nm->n_peers;
    if (n > TL_MAX_PEERS) n = TL_MAX_PEERS;
    if (n > 0) {
        memcpy(s_last_peers, nm->peers, n * sizeof(tl_peer_t));
    }
    s_last_peers_count = n;
#if CONFIG_TINYLINK_DERP_SUPERVISED
    update_derp_host_from_netmap(nm);
#endif
    if (!s_dataplane_started) {
        ESP_LOGI(TAG, "netmap (initial): self.id=%llu peers=%u derp_regions=%u",
                 (unsigned long long)nm->self_id,
                 (unsigned)nm->n_peers,
                 (unsigned)nm->n_derp_regions);
        esp_err_t err = wg_dataplane_start(&s_keys, nm);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "wg_dataplane_start failed: 0x%x", err);
            return err;
        }
        s_dataplane_started = true;
        /* Now that the WG netif is up and the 100.64.0.0/10 route
         * exists, it's safe to start telemetry (it sendto's to a
         * tailnet IP that would otherwise punt into the WiFi
         * default route). */
        esp_err_t terr = telemetry_start();
        if (terr != ESP_OK) {
            ESP_LOGW(TAG, "telemetry_start failed: 0x%x — continuing", terr);
        }
        /* Pre-punch immediately after dataplane up: opens our NAT mapping
         * to every peer endpoint advertised in the bootstrap netmap so a
         * cold-start `tailscale ping` from any peer has a fresh path
         * available without waiting for a DERP-relayed CMM round trip. */
        prepunch_pings_to_peer_endpoints(nm);
        return ESP_OK;
    }
    ESP_LOGI(TAG, "netmap (update): peers=%u derp_regions=%u",
             (unsigned)nm->n_peers, (unsigned)nm->n_derp_regions);
    /* wg_dataplane_update_peer already guards on n_peers==0 (rare server
     * push during a tailnet reconfigure). */
    esp_err_t err = wg_dataplane_update_peer(&s_keys, nm);
    /* Refresh NAT mappings on every netmap update too. Idle ages out
     * mappings (typical UDP timeout 30-120 s); without a periodic punch
     * the peer's first packet after silence finds a closed path and
     * forces DERP fallback. Cheap to repeat — ~50-200 bytes per peer
     * endpoint, fires only on non-KeepAlive netmaps (every minute or
     * two on the Tailscale control plane). */
    prepunch_pings_to_peer_endpoints(nm);
    return err;
}

static void long_poll_task(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "long-poll task: starting");
    for (;;) {
        esp_err_t err = ensure_control_conn();
        if (err == ESP_OK) {
            err = mapreq_run_stream(&s_conn, &s_keys, long_poll_handler, NULL);
            /* Stream ended: either the server closed it (idle / ping
             * failure / restart) or our side errored. Drop the conn so
             * the next iteration brings up a fresh one. */
            ESP_LOGW(TAG, "long-poll stream ended: 0x%x — reconnecting", err);
            drop_control_conn();
        } else {
            ESP_LOGW(TAG, "long-poll connect failed: 0x%x — backing off", err);
        }
        vTaskDelay(pdMS_TO_TICKS(CONFIG_TINYLINK_REGISTER_RETRY_MS));
    }
}

esp_err_t tinylink_long_poll_start(void)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    /* 24 KiB stack — same budget as CONFIG_ESP_MAIN_TASK_STACK_SIZE.
     * The earlier 8 KiB note was wrong: ts2021_connect builds an
     * mbedtls TLS handshake (cert chain verification, ECDSA, X.509
     * parsing, ~12 KiB peak) PLUS our Noise IK init (~2 KiB) on the
     * task stack. Running this in 8 KiB blew the stack and looked
     * like random heap corruption / alignment / load-prohibited
     * panics depending on what the overflow happened to overwrite. */
    BaseType_t ok = xTaskCreate(long_poll_task, "tinylink_lp",
                                24576, NULL, tskIDLE_PRIORITY + 4, NULL);
    if (ok != pdPASS) {
        ESP_LOGE(TAG, "xTaskCreate(long_poll) failed");
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

esp_err_t tinylink_wait_dataplane_ms(uint32_t timeout_ms)
{
    /* Cooperative poll: long-poll task runs at higher priority so it
     * gets to do its handshake + first MapResponse without us blocking
     * it. We just sleep in coarse 100 ms chunks until the flag flips. */
    const uint32_t step_ms = 100;
    uint32_t waited = 0;
    while (!s_dataplane_started) {
        if (waited >= timeout_ms) return ESP_ERR_TIMEOUT;
        vTaskDelay(pdMS_TO_TICKS(step_ms));
        waited += step_ms;
    }
    return ESP_OK;
}

esp_err_t tinylink_telemetry_start(void)
{
    /* Telemetry now starts implicitly from the long-poll handler the
     * first time the control plane delivers a netmap (so we don't
     * sendto a 100.64.x.y destination before the WG netif exists).
     * This entry point is a no-op kept for boot-sequence backward
     * compatibility with main.c. */
    return ESP_OK;
}

esp_err_t tinylink_wg_socket_init(void)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    struct wg_netif_local_config local = {0};
    memcpy(local.static_priv, s_keys.node_priv,  TINYLINK_KEY_LEN);
    memcpy(local.static_pub,  s_keys.node_pub,   TINYLINK_KEY_LEN);
    memcpy(local.disco_priv,  s_keys.disco_priv, TINYLINK_KEY_LEN);
    memcpy(local.disco_pub,   s_keys.disco_pub,  TINYLINK_KEY_LEN);
    local.bind_port = 0;  /* kernel picks; STUN learns whatever it is */
    esp_err_t err = wg_netif_init(&local);
    if (err != ESP_OK) return err;

    /* Wire the path-stale probe. Done here (not later) because wg_netif's
     * rx_task may start as soon as wg_netif_start (called from
     * wg_dataplane_start) runs, and that can fire the stale watchdog
     * before any later registration. The callback reads s_last_netmap;
     * until the first netmap arrives s_last_netmap_valid is false and
     * the callback is a no-op — safe. */
    wg_netif_set_path_stale_callback(on_wg_path_stale, NULL);
    return ESP_OK;
}

/* --- Persistent endpoint-updater task ---------------------------------
 *
 * After a STUN re-probe finds a new public AddrPort, we need to tell
 * the control plane via a Stream=false MapRequest. The long-poll's
 * Stream=true cycle is read-only (tailcfg.go:1408+1436), and we can't
 * multiplex our lite request over s_conn because the h2_client tracks
 * a single stream_id per ts2021_conn (see h2_client.c, conn->h2_stream_id).
 *
 * Pattern mirrors upstream tailscale `controlclient.Auto.updateRoutine`
 * (control/controlclient/auto.go:55-99): one persistent worker that
 * sleeps on a signal, with a monotonic generation counter that coalesces
 * rapid changes — only the latest state is pushed.
 *
 * Why persistent: the legacy `endpoint_push_task` was spawned per
 * re-probe with a 24 KiB stack. After hours of operation with mbedtls +
 * nghttp2 + long-poll churn, heap fragmentation prevented
 * `xTaskCreate` from finding a contiguous 24 KiB block. The push then
 * never fired, the control plane kept the stale endpoint, the peer kept
 * sending WG to a dead NAT mapping, and the device entered an indefinite
 * handshake-retry loop. Reproduced in serial capture
 * /tmp/tinylink_capture_2026-05-11_0233_longrun.log around uptime 2716 s.
 *
 * The persistent task allocates its stack ONCE at boot (when heap is
 * plenty), so the spawn-failure path is eliminated.
 *
 * --- HOW WE HANDLE s_conn NOT-YET-ESTABLISHED ---
 *
 * When this task wakes and `s_conn_open == false` (the long-poll task
 * has not yet established the control-plane TLS+Noise channel, either
 * at cold boot or during a long-poll backoff after a network error),
 * we DO NOT open our own ts2021 connection. Two reasons:
 *
 *   1. If long-poll can't bring s_conn up, the network path to the
 *      control plane is probably also unreachable from here. Opening
 *      our own TLS handshake would just burn ~12 KiB of heap peak and
 *      ~5 s of wall time only to fail with the same error long-poll
 *      keeps hitting.
 *
 *   2. Once long-poll comes back up, the next STUN re-probe (or a
 *      manually-bumped gen) will signal us and we'll push then —
 *      cheaper and more likely to succeed.
 *
 * So in that case we re-enqueue: brief vTaskDelay, give the semaphore
 * back to ourselves, and loop. The wait is bounded by long-poll's own
 * reconnect backoff (CONFIG_TINYLINK_REGISTER_RETRY_MS, default 30 s).
 *
 * When `s_conn_open == true` we still open our own ts2021 conn for the
 * push (cannot share s_conn — single-stream h2_client; see above). The
 * difference vs the legacy code is reliability: we're running in a
 * persistent task, so the stack is already there. */

/* Stack: 12 KiB. ts2021_connect peak (~10 KiB mbedtls cert verify +
 * ~1 KiB Noise IK + locals) fits with ~1 KiB margin. Tighter than the
 * legacy 24 KiB but adequate because this task ONLY does
 * connect+push+close — no nghttp2 streaming state, no concurrent work.
 * 12 KiB also keeps the BSS impact bounded (every KiB we lock in BSS
 * comes directly out of the DRAM heap arena WiFi init draws from —
 * verified 2026-05-11_validate_optB_v2 where 16 KiB tipped DRAM under
 * the WiFi driver's contiguous-block requirement and the boot CPU
 * asserted in esp_startup_start_app). */
#define TINYLINK_EP_PUSH_TASK_STACK    12288
#define TINYLINK_EP_PUSH_WAIT_MS        2000
#define TINYLINK_EP_PUSH_ERR_BACKOFF_MS 3000

/* Stack + TCB in BSS — keeps the 12 KiB out of the heap arena that
 * long-poll's nghttp2 + mbedtls session init competes for. The only
 * post-boot heap cost is the semaphore (~80 B). xTaskCreateStatic can
 * never return NULL on memory grounds — predictable boot. */
static StaticTask_t s_endpoint_push_tcb;
static StackType_t  s_endpoint_push_stack[TINYLINK_EP_PUSH_TASK_STACK / sizeof(StackType_t)];

static SemaphoreHandle_t s_endpoint_push_sem;
static volatile uint32_t s_endpoint_push_gen;
static uint32_t          s_endpoint_push_last_informed;

static void endpoint_updater_task(void *arg)
{
    (void)arg;
    for (;;) {
        xSemaphoreTake(s_endpoint_push_sem, portMAX_DELAY);

        const uint32_t gen = s_endpoint_push_gen;
        if (gen == s_endpoint_push_last_informed) {
            /* Stale signal: latest gen already pushed (coalesce). */
            continue;
        }

        if (!s_conn_open) {
            ESP_LOGI(TAG, "endpoint_push: s_conn not yet established — "
                          "re-enqueueing (waiting for long_poll, gen=%u)",
                     (unsigned)gen);
            vTaskDelay(pdMS_TO_TICKS(TINYLINK_EP_PUSH_WAIT_MS));
            xSemaphoreGive(s_endpoint_push_sem);
            continue;
        }

        /* s_conn is up but owned by long_poll_task in a blocking stream
         * read; open our own ts2021 conn for the lite request. */
        ts2021_conn_t conn;
        esp_err_t err = ts2021_connect(&conn, s_keys.machine_priv,
                                       s_keys.machine_pub, s_control_pub);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "endpoint_push: ts2021_connect failed: 0x%x "
                          "— retrying gen=%u",
                     err, (unsigned)gen);
            vTaskDelay(pdMS_TO_TICKS(TINYLINK_EP_PUSH_ERR_BACKOFF_MS));
            xSemaphoreGive(s_endpoint_push_sem);
            continue;
        }

        err = mapreq_push_endpoints(&conn, &s_keys);
        ts2021_close(&conn);

        if (err != ESP_OK) {
            ESP_LOGW(TAG, "endpoint_push: mapreq_push_endpoints failed: "
                          "0x%x — retrying gen=%u",
                     err, (unsigned)gen);
            vTaskDelay(pdMS_TO_TICKS(TINYLINK_EP_PUSH_ERR_BACKOFF_MS));
            xSemaphoreGive(s_endpoint_push_sem);
            continue;
        }

        s_endpoint_push_last_informed = gen;
        uint8_t  ep_addr[4];
        uint16_t ep_port = 0;
        if (tinylink_get_public_endpoint(ep_addr, &ep_port)) {
            ESP_LOGI(TAG, "endpoint_push: pushed %u.%u.%u.%u:%u (gen=%u)",
                     ep_addr[0], ep_addr[1], ep_addr[2], ep_addr[3],
                     (unsigned)ep_port, (unsigned)gen);
        }
    }
}

esp_err_t tinylink_endpoint_updater_start(void)
{
    if (s_endpoint_push_sem != NULL) return ESP_OK;  /* idempotent */

    s_endpoint_push_sem = xSemaphoreCreateBinary();
    if (s_endpoint_push_sem == NULL) {
        ESP_LOGE(TAG, "endpoint_updater: xSemaphoreCreateBinary failed");
        return ESP_ERR_NO_MEM;
    }

    /* Static allocation: stack/TCB live in BSS, NOT in the heap arena
     * that long-poll's TLS+nghttp2 init draws from. Can never fail
     * (no allocator involved). */
    TaskHandle_t h = xTaskCreateStatic(endpoint_updater_task,
                                       "tinylink_ep_up",
                                       sizeof(s_endpoint_push_stack) / sizeof(StackType_t),
                                       NULL,
                                       tskIDLE_PRIORITY + 2,
                                       s_endpoint_push_stack,
                                       &s_endpoint_push_tcb);
    if (h == NULL) {
        ESP_LOGE(TAG, "endpoint_updater: xTaskCreateStatic returned NULL");
        vSemaphoreDelete(s_endpoint_push_sem);
        s_endpoint_push_sem = NULL;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

/* Signal the updater that the public endpoint has changed. Coalesces
 * rapid concurrent calls via the gen counter (non-blocking semaphore
 * give; if the updater is already pending the second give is a no-op). */
static void tinylink_endpoint_push_async(void)
{
    if (s_endpoint_push_sem == NULL) {
        ESP_LOGW(TAG, "endpoint_push: updater task not started — "
                      "endpoint change ignored");
        return;
    }
    s_endpoint_push_gen++;
    xSemaphoreGive(s_endpoint_push_sem);
}

/* --- STUN reprobe via the live WG socket -------------------------------
 *
 * Once rx_task owns g.sock, we cannot recvfrom on it from another task
 * without racing. The legacy reprobe path opened an ephemeral socket,
 * which works but its source port is NOT the WG socket's, so the
 * AddrPort the STUN server learns can't be advertised back to peers.
 *
 * Option B: split send/receive across the existing tasks.
 *   - The reprobe task `sendto`s the STUN binding request directly on
 *     g.sock (sendto is thread-safe in lwIP, no ownership transfer).
 *   - rx_task already classifies WG_DEMUX_STUN; we hook it via
 *     wg_netif_set_stun_callback() to a parser that matches the
 *     in-flight txid and signals a semaphore.
 *   - The reprobe task waits on that semaphore with a 3 s timeout.
 *
 * No race: rx_task remains the only recvfrom-er. No data loss: rx_task
 * keeps dispatching DISCO/transport packets normally; STUN is just
 * routed to a new arm.
 *
 * The pending-probe slot (s_stun_pending) is single-writer (the reprobe
 * task) and single-reader (the rx_task callback runs on rx_task);
 * concurrent probes are not possible because the reprobe task takes
 * a mutex around the entire build/sendto/wait sequence. */
static struct {
    SemaphoreHandle_t   mutex;        /* serializes concurrent reprobes */
    SemaphoreHandle_t   done_sem;     /* given by handler on txid match */
    uint8_t             txid[STUN_TXID_LEN];
    bool                in_flight;
    stun_probe_result_t result;       /* filled by handler on success */
} s_stun_pending;

static void stun_response_handler(const uint8_t *buf, size_t len, void *user)
{
    (void)user;
    if (!s_stun_pending.in_flight) {
        /* No probe expected — late response from a previous attempt
         * or a stray STUN frame. Drop. */
        return;
    }
    uint8_t got_txid[STUN_TXID_LEN];
    stun_addr_t addr;
    int rc = stun_parse_response(buf, len, got_txid, &addr);
    if (rc != 0) {
        /* Malformed / not-success / no-mapped-addr — let it slide;
         * the reprobe task will time out and try again next cycle. */
        return;
    }
    if (memcmp(got_txid, s_stun_pending.txid, STUN_TXID_LEN) != 0) {
        return;  /* response to a stale probe — ignore */
    }
    if (addr.is_v6) {
        return;  /* v6 mapped — we asked for v4 */
    }
    s_stun_pending.result.addr_v4[0] = addr.addr[12];
    s_stun_pending.result.addr_v4[1] = addr.addr[13];
    s_stun_pending.result.addr_v4[2] = addr.addr[14];
    s_stun_pending.result.addr_v4[3] = addr.addr[15];
    s_stun_pending.result.port  = addr.port;
    s_stun_pending.result.valid = true;
    xSemaphoreGive(s_stun_pending.done_sem);
}

/* Lazily build the once-per-process pending-probe state and register
 * the rx_task callback. Idempotent. Returns false on allocation
 * failure — caller falls back to the ephemeral-socket legacy path. */
static bool stun_pending_init_once(void)
{
    if (s_stun_pending.mutex != NULL) return true;
    SemaphoreHandle_t m = xSemaphoreCreateMutex();
    if (m == NULL) return false;
    SemaphoreHandle_t d = xSemaphoreCreateBinary();
    if (d == NULL) {
        vSemaphoreDelete(m);
        return false;
    }
    s_stun_pending.mutex    = m;
    s_stun_pending.done_sem = d;
    wg_netif_set_stun_callback(stun_response_handler, NULL);
    return true;
}

/* Re-probe over the live WG socket. Builds a STUN binding request,
 * arms the pending-probe slot, sendto's it via g.sock, and waits up
 * to timeout_ms for the rx_task callback to signal a matching
 * response. The result populates *out on success. */
static esp_err_t stun_reprobe_via_wg_socket(uint32_t timeout_ms,
                                            stun_probe_result_t *out)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    out->valid = false;

    int sock = wg_netif_get_socket();
    if (sock < 0) return ESP_ERR_INVALID_STATE;

    if (!stun_pending_init_once()) {
        return ESP_ERR_NO_MEM;
    }

    /* DNS-resolve the STUN server. lwIP getaddrinfo can block briefly
     * — the reprobe task is the only caller and runs at IDLE+1, so a
     * synchronous DNS lookup here is safe. */
    struct addrinfo hints = {
        .ai_family   = AF_INET,
        .ai_socktype = SOCK_DGRAM,
    };
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u",
             (unsigned)CONFIG_TINYLINK_STUN_PORT);
    struct addrinfo *res = NULL;
    if (getaddrinfo(CONFIG_TINYLINK_STUN_HOST, port_str, &hints, &res) != 0
        || res == NULL) {
        ESP_LOGW(TAG, "stun reprobe: DNS resolve failed for %s",
                 CONFIG_TINYLINK_STUN_HOST);
        if (res) freeaddrinfo(res);
        return ESP_FAIL;
    }
    struct sockaddr_in dest;
    memcpy(&dest, res->ai_addr, sizeof(dest));
    freeaddrinfo(res);

    /* Take the mutex for the whole build/send/wait sequence so a
     * second reprobe call can't smash the txid out from under us. */
    if (xSemaphoreTake(s_stun_pending.mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    esp_fill_random(s_stun_pending.txid, STUN_TXID_LEN);
    memset(&s_stun_pending.result, 0, sizeof(s_stun_pending.result));
    /* Drain any stale signal from a prior cycle that timed out after
     * the handler had already given the sem. */
    (void)xSemaphoreTake(s_stun_pending.done_sem, 0);
    s_stun_pending.in_flight = true;

    uint8_t req[STUN_REQUEST_LEN];
    if (stun_build_request(req, s_stun_pending.txid) != STUN_REQUEST_LEN) {
        s_stun_pending.in_flight = false;
        xSemaphoreGive(s_stun_pending.mutex);
        return ESP_FAIL;
    }
    ssize_t sent = sendto(sock, req, sizeof(req), 0,
                          (const struct sockaddr *)&dest, sizeof(dest));
    if (sent != (ssize_t)sizeof(req)) {
        ESP_LOGW(TAG, "stun reprobe sendto: ret=%d errno=%d",
                 (int)sent, errno);
        s_stun_pending.in_flight = false;
        xSemaphoreGive(s_stun_pending.mutex);
        return ESP_FAIL;
    }

    esp_err_t err;
    if (xSemaphoreTake(s_stun_pending.done_sem,
                       pdMS_TO_TICKS(timeout_ms)) == pdTRUE) {
        *out = s_stun_pending.result;
        err = (out->valid) ? ESP_OK : ESP_FAIL;
    } else {
        err = ESP_ERR_TIMEOUT;
    }
    s_stun_pending.in_flight = false;
    xSemaphoreGive(s_stun_pending.mutex);
    return err;
}

esp_err_t tinylink_stun_probe(void)
{
    /* Probe into a LOCAL result first, only commit to the cached
     * global on success. This way a transient probe failure (DNS
     * blip, NAT dropping our send, etc.) does NOT wipe a previously
     * good endpoint — the next MapRequest keeps advertising the
     * old-but-still-correct value. Boot-time initial probe also
     * works the same way: s_stun_result is zero-initialized so
     * .valid stays false until the first success.
     *
     * 3 s timeout is generous — Google STUN typically answers in
     * <100 ms. Worst case adds 3 s of boot delay if the configured
     * server is dead. */
    stun_probe_result_t local = {0};
    esp_err_t err;
    int wg_sock = wg_netif_get_socket();
    bool rx_running = wg_netif_rx_running();

    if (wg_sock >= 0 && !rx_running) {
        /* Boot-time path: probe via the WG socket so the public
         * AddrPort we advertise lines up with the WG NAT mapping that
         * keepalives keep pinned. Peers dialing this AddrPort actually
         * reach our WG socket. */
        err = stun_probe_run_on_socket(wg_sock,
                                       CONFIG_TINYLINK_STUN_HOST,
                                       (uint16_t)CONFIG_TINYLINK_STUN_PORT,
                                       3000, &local);
        if (err == ESP_OK && local.valid) {
            if (s_stun_result.valid &&
                (memcmp(s_stun_result.addr_v4, local.addr_v4, 4) != 0 ||
                 s_stun_result.port != local.port)) {
                ESP_LOGI(TAG, "stun: endpoint changed %u.%u.%u.%u:%u → %u.%u.%u.%u:%u",
                         s_stun_result.addr_v4[0], s_stun_result.addr_v4[1],
                         s_stun_result.addr_v4[2], s_stun_result.addr_v4[3],
                         (unsigned)s_stun_result.port,
                         local.addr_v4[0], local.addr_v4[1],
                         local.addr_v4[2], local.addr_v4[3],
                         (unsigned)local.port);
            }
            s_stun_result = local;
        }
        return err;
    }

    /* Re-probe path: RX task owns g.sock, so we send the STUN request
     * via sendto (thread-safe in lwIP) and let rx_task dispatch the
     * response back to us via the wg_netif_set_stun_callback hook.
     * The result's source-port is now the WG socket's bound port, so
     * a port change between boot and now can be propagated to the
     * control plane. */
    err = stun_reprobe_via_wg_socket(3000, &local);
    if (err != ESP_OK || !local.valid) return err;
    ESP_LOGI(TAG, "stun re-probe ok via wg socket: %u.%u.%u.%u:%u",
             local.addr_v4[0], local.addr_v4[1],
             local.addr_v4[2], local.addr_v4[3],
             (unsigned)local.port);

    if (s_stun_result.valid) {
        const bool addr_changed =
            memcmp(s_stun_result.addr_v4, local.addr_v4, 4) != 0;
        const bool port_changed = s_stun_result.port != local.port;
        if (addr_changed || port_changed) {
            ESP_LOGI(TAG, "stun re-probe: endpoint changed "
                          "%u.%u.%u.%u:%u → %u.%u.%u.%u:%u",
                     s_stun_result.addr_v4[0], s_stun_result.addr_v4[1],
                     s_stun_result.addr_v4[2], s_stun_result.addr_v4[3],
                     (unsigned)s_stun_result.port,
                     local.addr_v4[0], local.addr_v4[1],
                     local.addr_v4[2], local.addr_v4[3],
                     (unsigned)local.port);
            s_stun_result = local;
            /* Push the new endpoint to the control plane. The push runs
             * in the reprobe task's context (4 KiB stack — too small
             * for a TLS handshake) so we spawn a one-shot task with
             * adequate stack instead. Best-effort: a failed push just
             * means the next reprobe will retry. */
            tinylink_endpoint_push_async();
        }
    } else {
        /* Boot probe failed and this is the first valid sample. */
        s_stun_result = local;
        tinylink_endpoint_push_async();
    }
    return ESP_OK;
}

bool tinylink_get_public_endpoint(uint8_t addr_v4[4], uint16_t *port)
{
    if (!s_stun_result.valid) return false;
    if (addr_v4 == NULL || port == NULL) return false;
    memcpy(addr_v4, s_stun_result.addr_v4, 4);
    *port = s_stun_result.port;
    return true;
}

static void stun_reprobe_task(void *arg)
{
    (void)arg;
    /* Sleep before the first iteration: the boot-time probe ran in
     * tinylink_stun_probe() before this task was even spawned, so
     * doing a second probe immediately would just burn bandwidth. */
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(CONFIG_TINYLINK_STUN_REPROBE_MS));
        esp_err_t err = tinylink_stun_probe();
        if (err != ESP_OK) {
            /* Don't escalate: the cached value (if any) is still in
             * use. ESP_LOGD instead of W to avoid spamming the log
             * when, e.g., the user briefly loses internet. */
            ESP_LOGD(TAG, "stun re-probe transient failure: 0x%x", err);
        }
    }
}

/* Retry-spawn shape for stun_reprobe_task. Boot-time heap pressure
 * (TLS handshake transient + supervisor connect peak still settling)
 * can fail the initial xTaskCreate with ESP_ERR_NO_MEM, and the prior
 * handler logged "continuing static" and gave up — leaving the
 * boot-pushed endpoint permanently stale if the NAT later rebound,
 * which manifested as "direct connection not established" on the peer
 * side. The retry timer fires every 30 s and tries again; once spawn
 * succeeds the timer is one-shot-stopped and the task takes over. */
#define STUN_RE_SPAWN_RETRY_US (30 * 1000 * 1000)

static esp_timer_handle_t s_reprobe_retry_timer = NULL;

static BaseType_t stun_reprobe_try_spawn(void)
{
    /* 4 KiB stack: stun_probe_run does one DNS lookup + one
     * sendto + one recvfrom; no TLS or crypto. Same budget as the
     * WG RX task. Priority IDLE+1 — explicitly below the long-poll
     * (IDLE+4) and the WG dataplane so neither gets preempted by a
     * background probe. */
    return xTaskCreate(stun_reprobe_task, "tinylink_stun_re",
                       4096, NULL, tskIDLE_PRIORITY + 1, NULL);
}

static void stun_reprobe_retry_cb(void *arg)
{
    (void)arg;
    if (stun_reprobe_try_spawn() == pdPASS) {
        ESP_LOGI(TAG, "stun_reprobe spawn OK on retry "
                      "(heap_free=%u largest=%u)",
                 (unsigned)esp_get_free_heap_size(),
                 (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));
        /* Timer is one-shot — do not rearm. */
        return;
    }
    ESP_LOGW(TAG, "stun_reprobe spawn retry still failing "
                  "(heap_free=%u largest=%u) — retry in %d s",
             (unsigned)esp_get_free_heap_size(),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT),
             STUN_RE_SPAWN_RETRY_US / 1000000);
    esp_err_t err = esp_timer_start_once(s_reprobe_retry_timer,
                                         STUN_RE_SPAWN_RETRY_US);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_timer_start_once(retry) failed: 0x%x — giving up",
                 err);
    }
}

esp_err_t tinylink_stun_reprobe_start(void)
{
    if (stun_reprobe_try_spawn() == pdPASS) return ESP_OK;

    /* Boot-time spawn failed. Schedule a retry via esp_timer (which
     * runs on the system esp_timer task — no per-call xTaskCreate
     * required, sidesteps the chicken-and-egg of "we have no heap to
     * spawn the worker that watches for heap"). Returning ESP_OK
     * tells the caller the re-probe loop *will* run; it just hasn't
     * spawned yet. */
    ESP_LOGW(TAG, "xTaskCreate(stun_reprobe) failed at boot "
                  "(heap_free=%u largest=%u) — scheduling retry in %d s",
             (unsigned)esp_get_free_heap_size(),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT),
             STUN_RE_SPAWN_RETRY_US / 1000000);

    if (s_reprobe_retry_timer == NULL) {
        const esp_timer_create_args_t targs = {
            .callback = stun_reprobe_retry_cb,
            .name     = "stun_re_retry",
        };
        esp_err_t terr = esp_timer_create(&targs, &s_reprobe_retry_timer);
        if (terr != ESP_OK) {
            ESP_LOGE(TAG, "esp_timer_create(retry) failed: 0x%x", terr);
            return terr;
        }
    }
    esp_err_t terr = esp_timer_start_once(s_reprobe_retry_timer,
                                          STUN_RE_SPAWN_RETRY_US);
    if (terr != ESP_OK) {
        ESP_LOGE(TAG, "esp_timer_start_once(retry) failed: 0x%x", terr);
        return terr;
    }
    return ESP_OK;
}
