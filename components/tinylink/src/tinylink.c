// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "tinylink.h"

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
#include "disco_handler.h"
#include "keys.h"
#include "mapreq.h"
#include "netmap.h"
#include "register.h"
#include "stun_probe.h"
#include "telemetry.h"
#include "ts2021_client.h"
#include "wg_dataplane.h"

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
    /* Mirrors upstream's controlclient.Direct: there is NO separate
     * "fetch one MapResponse, then start streaming" call. The streaming
     * /machine/map request itself delivers the initial netmap as its
     * first frame and subsequent updates as follow-up frames on the same
     * stream. So this entry point now only validates state — the actual
     * WG bring-up happens inside long_poll_handler on the first netmap
     * the stream emits. Kept in the API for backward compatibility with
     * the boot sequence in main.c. */
    return s_initialized ? ESP_OK : ESP_ERR_INVALID_STATE;
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
        ESP_LOGI(TAG, "disco call-me-maybe (M5 step 3 territory)");
        break;
    default:
        /* Either non-DISCO bytes (handler returned 0 with type
         * untouched) or a relayed WG transport packet. M5 step 3
         * will route those into wg_demux. */
        break;
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

/* Task entry: the conn is already live (established by
 * tinylink_derp_supervised_start). Run the recv loop until error,
 * then reconnect with backoff. Reconnect attempts may face heap
 * pressure once the long-poll's TLS conn is alive (~10 KiB largest
 * free block vs ~12 KiB mbedtls handshake peak); we tolerate by
 * retrying — eventually long-poll's stream ends and frees room. */
static void derp_supervised_task(void *arg)
{
    (void)arg;
    const char *host = CONFIG_TINYLINK_DERP_SMOKE_HOST;
    const TickType_t backoff =
        pdMS_TO_TICKS(CONFIG_TINYLINK_DERP_SUPERVISED_BACKOFF_MS);

    derp_sup_stats_t stats = {0};
    static uint8_t frame_buf[DERP_SUP_FRAME_CAP];

    for (;;) {
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
                          "send_err=%llu keepalives=%llu",
                     err,
                     (unsigned long long)stats.recv_packets,
                     (unsigned long long)stats.disco_pings_answered,
                     (unsigned long long)stats.disco_pongs_seen,
                     (unsigned long long)stats.disco_cmms_seen,
                     (unsigned long long)stats.disco_send_errors,
                     (unsigned long long)stats.keepalives);
        }
        derp_client_close(&s_derp_sup);
        vTaskDelay(backoff);

        /* Reconnect. Loop here (not the outer for) so a second
         * connect failure doesn't fall through to derp_client_run
         * with a closed client. */
        for (;;) {
            ESP_LOGI(TAG, "derp supervisor: reconnect attempt to %s "
                          "(heap_free=%u largest=%u)",
                     host,
                     (unsigned)esp_get_free_heap_size(),
                     (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));
            err = derp_client_connect_login(&s_derp_sup, host, 443,
                                            s_keys.node_priv, s_keys.node_pub);
            if (err == ESP_OK) break;
            ESP_LOGW(TAG, "derp supervisor: reconnect failed 0x%x — backoff", err);
            derp_client_close(&s_derp_sup);
            vTaskDelay(backoff);
        }
    }
}

#endif /* CONFIG_TINYLINK_DERP_SUPERVISED */

esp_err_t tinylink_derp_supervised_start(void)
{
#if CONFIG_TINYLINK_DERP_SUPERVISED
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    const char *host = CONFIG_TINYLINK_DERP_SMOKE_HOST;
    if (host == NULL || host[0] == '\0') {
        ESP_LOGI(TAG, "derp supervisor: disabled (empty host)");
        return ESP_OK;
    }

    /* Synchronous first connect: returning success implies the conn
     * is up and the heap budget for one DERP TLS session is taken.
     * The caller (main.c bringup) sequences this BEFORE the long-poll
     * so the second handshake (long-poll's) finds enough contiguous
     * heap; the inverse order deterministically fails per the heap
     * fragmentation pattern documented in our config notes. */
    ESP_LOGI(TAG, "derp supervisor: initial connect host=%s "
                  "heap_free=%u largest=%u",
             host,
             (unsigned)esp_get_free_heap_size(),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));

    esp_err_t err = derp_client_connect_login(&s_derp_sup, host, 443,
                                              s_keys.node_priv,
                                              s_keys.node_pub);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "derp supervisor: initial connect failed 0x%x", err);
        derp_client_close(&s_derp_sup);
        return err;
    }
    ESP_LOGI(TAG, "derp supervisor: initial login OK server-v=%d",
             s_derp_sup.server_version);

    /* 24 KiB stack — same budget as the long-poll task. The recv loop
     * itself is small but esp_tls handshake on reconnect needs the
     * same ~12 KiB peak the long-poll already budgeted for. */
    BaseType_t ok = xTaskCreate(derp_supervised_task, "tinylink_derp",
                                24576, NULL, tskIDLE_PRIORITY + 3, NULL);
    if (ok != pdPASS) {
        ESP_LOGE(TAG, "xTaskCreate(derp supervisor) failed");
        derp_client_close(&s_derp_sup);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
#else
    return ESP_OK;
#endif
}

static esp_err_t long_poll_handler(const tl_netmap_t *nm, void *ctx)
{
    (void)ctx;
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

esp_err_t tinylink_telemetry_start(void)
{
    /* Telemetry now starts implicitly from the long-poll handler the
     * first time the control plane delivers a netmap (so we don't
     * sendto a 100.64.x.y destination before the WG netif exists).
     * This entry point is a no-op kept for boot-sequence backward
     * compatibility with main.c. */
    return ESP_OK;
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
    esp_err_t err = stun_probe_run(CONFIG_TINYLINK_STUN_HOST,
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
