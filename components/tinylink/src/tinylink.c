// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "tinylink.h"

#include <errno.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs.h"
#include "sdkconfig.h"

#include "control_key.h"
#include "derp_client.h"
#include "disco.h"
#include "disco_handler.h"
#include "keys.h"
#include "esp_random.h"

#ifdef ESP_PLATFORM
#include "lwip/sockets.h"
#endif
#include "mapreq.h"
#include "netmap.h"
#include "register.h"
#include "stun_probe.h"
#include "telemetry.h"
#include "ts2021_client.h"
#include "wg_dataplane.h"
#include "wg_netif.h"

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
        memset(auth_key, 0, sizeof(auth_key));
        return err;
    }

    err = register_emit(&s_conn, &s_keys, auth_key);

    /* Best-effort scrub of the auth key in stack memory. */
    memset(auth_key, 0, sizeof(auth_key));

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
    const TickType_t backoff =
        pdMS_TO_TICKS(CONFIG_TINYLINK_DERP_SUPERVISED_BACKOFF_MS);

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
                break;
            }
            ESP_LOGW(TAG, "derp supervisor: connect attempt #%u failed 0x%x — "
                          "backoff %u ms",
                     attempt, cerr,
                     (unsigned)CONFIG_TINYLINK_DERP_SUPERVISED_BACKOFF_MS);
            derp_client_close(&s_derp_sup);
            vTaskDelay(backoff);
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

static esp_err_t long_poll_handler(const tl_netmap_t *nm, void *ctx)
{
    (void)ctx;
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
         * 100.64.0.1 address that would otherwise punt into the WiFi
         * default route). */
        esp_err_t terr = telemetry_start();
        if (terr != ESP_OK) {
            ESP_LOGW(TAG, "telemetry_start failed: 0x%x — continuing", terr);
        }
        return ESP_OK;
    }
    ESP_LOGI(TAG, "netmap (update): peers=%u derp_regions=%u",
             (unsigned)nm->n_peers, (unsigned)nm->n_derp_regions);
    /* wg_dataplane_update_peer already guards on n_peers==0 (rare server
     * push during a tailnet reconfigure). */
    return wg_dataplane_update_peer(&s_keys, nm);
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
    return wg_netif_init(&local);
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

    /* Re-probe path: RX task owns the WG socket, so we can't recvfrom
     * on it without racing. Probe on an ephemeral socket — but its
     * source port is NOT the WG socket's, so the port we'd learn is
     * wrong relative to inbound WG transport. Use this only to detect
     * WAN-address changes; do NOT overwrite the cached good port. */
    err = stun_probe_run(CONFIG_TINYLINK_STUN_HOST,
                         (uint16_t)CONFIG_TINYLINK_STUN_PORT,
                         3000, &local);
    if (err == ESP_OK && local.valid && s_stun_result.valid) {
        if (memcmp(s_stun_result.addr_v4, local.addr_v4, 4) != 0) {
            ESP_LOGW(TAG, "stun re-probe: WAN address changed "
                          "%u.%u.%u.%u → %u.%u.%u.%u — cached port now "
                          "stale; followup PR re-probes via wg socket",
                     s_stun_result.addr_v4[0], s_stun_result.addr_v4[1],
                     s_stun_result.addr_v4[2], s_stun_result.addr_v4[3],
                     local.addr_v4[0], local.addr_v4[1],
                     local.addr_v4[2], local.addr_v4[3]);
        }
    } else if (err == ESP_OK && local.valid && !s_stun_result.valid) {
        /* No cached value yet (boot probe failed?). Stash this even
         * though the port is ephemeral-not-WG — better than nothing,
         * and dataplane_start log will flag it. */
        s_stun_result = local;
    }
    return err;
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

esp_err_t tinylink_stun_reprobe_start(void)
{
    /* 4 KiB stack: stun_probe_run does one DNS lookup + one
     * sendto + one recvfrom; no TLS or crypto. Same budget as the
     * WG RX task. Priority IDLE+1 — explicitly below the long-poll
     * (IDLE+4) and the WG dataplane so neither gets preempted by a
     * background probe. */
    BaseType_t ok = xTaskCreate(stun_reprobe_task, "tinylink_stun_re",
                                4096, NULL, tskIDLE_PRIORITY + 1, NULL);
    if (ok != pdPASS) {
        ESP_LOGE(TAG, "xTaskCreate(stun_reprobe) failed");
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
