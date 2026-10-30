// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "tinylink.h"

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "esp_attr.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "mbedtls/platform_util.h"
#include "nvs.h"
#include "sdkconfig.h"

#include "backoff.h"
#include "h2_client.h"        /* h2_client_set_lb */
#include "h2_retry_after.h"
#include "tl_wdt.h"
#include "tl_time.h"
#include "control_key.h"
#include "crypto/nacl_box.h"
#include "crypto/secure_zero.h"
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
#if CONFIG_TINYLINK_POWER_DIAG
#include "pwr_diag.h"
#endif
#include "register.h"
#include "register_json.h"   /* register_retry_with_auth */
#include "stun.h"
#include "stun_boot.h"
#include "stun_probe.h"
#include "telemetry.h"
#include "tl_addr.h"
#include "tls_resume.h"
#include "tl_bootstat.h"
#include "ts2021_client.h"
#include "wg_dataplane.h"
#include "wg_netif.h"
#include "wg_proto.h"

static const char *TAG = "tinylink";

static const char k_version[] = TINYLINK_VERSION_STRING;

static tinylink_keys_t s_keys;
static bool            s_keys_loaded;   /* by tinylink_preload or tinylink_init */
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

/* The control plane's last good address (round 1.3.5: s_conn.peer_v4 of
 * the last conn that came up), packed for an atomic hand-over to the
 * telemetry task's NVS write (tinylink_addr_persist_poll); 0 = none.
 * ts2021_client.c dials it first on its own. */
static uint32_t        s_ctl_addr;

static esp_err_t ensure_control_conn(void)
{
    if (s_conn_open) return ESP_OK;
    esp_err_t err = ts2021_connect(&s_conn, s_keys.machine_priv,
                                   s_keys.machine_pub, s_control_pub,
                                   control_key_pinned());
    if (err == ESP_OK) {
        s_conn_open = true;
        /* Every request on it names the node for control's load
         * balancer, as upstream's (round 1.3.8, h2_client_set_lb). */
        h2_client_set_lb(s_keys.node_pub);
        /* For the next boot (round 1.3.5): the telemetry housekeeping
         * stores it when it differs from NVS (tl_addr.h). An unknown peer
         * (0) leaves the record alone. */
        uint32_t v;
        memcpy(&v, s_conn.peer_v4, sizeof(v));
        if (v != 0) __atomic_store_n(&s_ctl_addr, v, __ATOMIC_RELAXED);
        /* A completed TLS + Noise IK handshake proves the control plane
         * is reachable and our local stack is not wedged — exactly what
         * the wedge-restart last resort exists to detect. Feed it here
         * too (not only from stream bytes), so a node the server keeps
         * rejecting with 4xx (deleted / expired) retries via the
         * re-register ladder instead of rebooting every
         * CONFIG_TINYLINK_CONTROL_WEDGE_RESTART_S, which cannot help. */
        tinylink_control_mark_alive();
    }
    return err;
}

static void drop_control_conn(void)
{
    if (!s_conn_open) return;
    ts2021_close(&s_conn);
    s_conn_open = false;
}

/* Rate-limit wait for the response currently on s_conn (capver 147):
 * 0 unless control answered 429, or 503 with a Retry-After. */
static uint32_t control_rate_limit_ms(void)
{
    return h2_rate_limit_wait_ms(s_conn.h2_status, s_conn.h2_retry_after_present,
                                 s_conn.h2_retry_after_s, esp_random());
}

/* Snapshotted inside tinylink_register, before drop_control_conn tears
 * the conn down. Lets the boot register loop (main.c) and the in-loop
 * re-register read it without a reference to the live conn. */
static uint32_t s_last_register_wait_ms;

uint32_t tinylink_last_rate_limit_ms(void)
{
    return s_last_register_wait_ms;
}

const char *tinylink_version_string(void)
{
    return k_version;
}

void tinylink_diag_dump_stacks(void)
{
    /* MAX_TASKS sized for the IDF default startup set (15-20 tasks:
     * FreeRTOS internals + lwIP tcpip_thread + WiFi MAC + esp_timer +
     * idle task per core + our 6-7 app tasks + esp_event loop). 32
     * gives slack. If uxTaskGetSystemState returns 0 the buffer was
     * too small — log a warning so we know to bump this constant
     * rather than silently truncating the dump. */
    enum { TL_DIAG_MAX_TASKS = 20 };   /* 13 tasks live (round 1.3.3, B18) */
    static TaskStatus_t snap[TL_DIAG_MAX_TASKS];
    UBaseType_t n = uxTaskGetSystemState(snap, TL_DIAG_MAX_TASKS, NULL);
    if (n == 0) {
        ESP_LOGW(TAG, "stack diag: uxTaskGetSystemState overflow "
                      "(>%d tasks — bump TL_DIAG_MAX_TASKS)",
                 TL_DIAG_MAX_TASKS);
        return;
    }
    ESP_LOGI(TAG, "stack diag: tasks=%u heap_free=%lu largest=%lu",
             (unsigned)n,
             (unsigned long)esp_get_free_heap_size(),
             (unsigned long)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));
    for (UBaseType_t i = 0; i < n; i++) {
        /* usStackHighWaterMark is in StackType_t units. The ESP-IDF
         * Xtensa port defines StackType_t = uint8_t (1 B), so the
         * returned value is already in bytes — DO NOT multiply by
         * sizeof(StackType_t) / sizeof(unsigned long) etc. Verified
         * empirically against on-target stack allocations: e.g.
         * tinylink_tlm (alloc=4 KiB) reports hwm ≤ 4096; wg_tx
         * (alloc=8 KiB) ≤ 8192; tinylink_lp (alloc=24 KiB) ≤ 24576. */
        ESP_LOGI(TAG, "stack diag:   %-16s hwm=%5u B free",
                 snap[i].pcTaskName,
                 (unsigned)snap[i].usStackHighWaterMark);
    }
#if CONFIG_TINYLINK_POWER_DIAG
    tl_pwr_diag_dump(snap, (unsigned)n);   /* round 1.3.7, pwr_diag.h */
#endif
}

static void reg_hint_load(void);
static void addr_cache_load(void);

/* Round 1.3.7, B2: the boot's static key work while Wi-Fi associates
 * (main.c calls this between starting Wi-Fi and waiting for it; 3–9 s of
 * idle CPU on the sensor) instead of in the first ~90 ms after got-ip:
 * the three public keys derived from NVS (3 X25519 — the 40 ms between
 * "sntp started" and the control-key line on the 1.3.6 logs) and, with a
 * control key pinned in NVS, the first connect's Noise msg1 DH (ss, e,
 * es: 3 more; ts2021_precompute). No network, nothing logged on
 * success; a failure here is retried and reported by tinylink_init. */
esp_err_t tinylink_preload(void)
{
    if (!s_keys_loaded) {
        if (keys_load_or_generate(&s_keys) != ESP_OK) return ESP_FAIL;
        s_keys_loaded = true;
    }
    uint8_t pub[32];
    if (control_key_peek(pub) == ESP_OK) {
        ts2021_precompute(s_keys.machine_priv, s_keys.machine_pub, pub);
    }
    return ESP_OK;
}

esp_err_t tinylink_init(void)
{
    /* Task-WDT feed for every blocking TLS poll (see tl_wdt.h). */
    tls_io_set_poll_hook(tl_wdt_feed);
    esp_err_t err = ESP_OK;
    if (!s_keys_loaded) {
        err = keys_load_or_generate(&s_keys);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "keys_load_or_generate failed: 0x%x", err);
            return err;
        }
        s_keys_loaded = true;
    }
    err = control_key_get(s_control_pub);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "control_key_get failed: 0x%x", err);
        return err;
    }
    reg_hint_load();
    addr_cache_load();
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
    /* TAI64N timestamps span 64 bits genuinely (nanoseconds since the
     * TAI epoch); high/low hex split is the canonical NEWLIB_NANO_FORMAT-
     * compatible way to log them without dragging in full %llu. */
    ESP_LOGI(TAG, "tai64n_floor: persisted=0x%08lx%08lx reservation=0x%08lx%08lx (chunk=%lu)",
             (unsigned long)(persisted    >> 32),
             (unsigned long)(persisted    & 0xFFFFFFFFul),
             (unsigned long)(reservation  >> 32),
             (unsigned long)(reservation  & 0xFFFFFFFFul),
             (unsigned long)WG_TAI64N_RESERVE_CHUNK_SECS);
    return ESP_OK;
}

/* Same lookup order as main/app_nvs.c (keep in sync): the dedicated
 * `nvs_creds` partition first (docs/PROVISIONING.md flashes it there),
 * then the default `nvs` partition, both under namespace "tl_creds". The
 * partition is mounted by app_nvs_init(); if it was not (absent / not
 * provisioned) nvs_open_from_partition fails and we fall through. */
static esp_err_t read_auth_key(char *out, size_t out_size)
{
    esp_err_t err = ESP_ERR_NVS_NOT_FOUND;
    for (int tier = 0; tier < 2; tier++) {
        nvs_handle_t h;
        err = (tier == 0)
            ? nvs_open_from_partition("nvs_creds", "tl_creds", NVS_READONLY, &h)
            : nvs_open("tl_creds", NVS_READONLY, &h);
        if (err != ESP_OK) continue;
        size_t len = out_size;
        err = nvs_get_str(h, "auth_key", out, &len);
        nvs_close(h);
        if (err == ESP_OK) return ESP_OK;
    }
    ESP_LOGE(TAG, "auth_key missing from NVS (nvs_creds:tl_creds, nvs:tl_creds): 0x%x",
             err);
    return err;
}

/* B22 (round 1.3.3): the keys control last authorized — machine_pub ‖
 * node_pub, so a regenerated key of either kind misses — in the TAI64N
 * namespace. While they match, a register sends no Auth, the way a
 * restarted tailscaled re-registers: control answers with the node's
 * current state instead of re-running the auth-key login (a node-record
 * write on its side) on every boot, and the auth key is not even read
 * out of NVS. Written only when the verdict changes. */
#define REG_NVS_KEY "reg_keys"
static bool s_reg_known;   /* NVS reg_keys == this device's keys */

static void reg_hint_load(void)
{
    nvs_handle_t h;
    if (nvs_open(TAI64N_NVS_NS, NVS_READONLY, &h) != ESP_OK) return;
    uint8_t blob[2 * TINYLINK_KEY_LEN];
    size_t  len = sizeof(blob);
    s_reg_known = nvs_get_blob(h, REG_NVS_KEY, blob, &len) == ESP_OK &&
                  len == sizeof(blob) &&
                  memcmp(blob, s_keys.machine_pub, TINYLINK_KEY_LEN) == 0 &&
                  memcmp(blob + TINYLINK_KEY_LEN, s_keys.node_pub,
                         TINYLINK_KEY_LEN) == 0;
    nvs_close(h);
}

/* RAM follows the verdict even when NVS fails: worst case the next boot
 * pays one extra register round trip (or sends Auth it did not need). */
static void reg_hint_store(bool known)
{
    if (s_reg_known == known) return;
    s_reg_known = known;
    nvs_handle_t h;
    esp_err_t err = nvs_open(TAI64N_NVS_NS, NVS_READWRITE, &h);
    if (err == ESP_OK) {
        if (known) {
            uint8_t blob[2 * TINYLINK_KEY_LEN];
            memcpy(blob, s_keys.machine_pub, TINYLINK_KEY_LEN);
            memcpy(blob + TINYLINK_KEY_LEN, s_keys.node_pub, TINYLINK_KEY_LEN);
            err = nvs_set_blob(h, REG_NVS_KEY, blob, sizeof(blob));
        } else {
            err = nvs_erase_key(h, REG_NVS_KEY);
            if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;
        }
        if (err == ESP_OK) err = nvs_commit(h);
        nvs_close(h);
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "register hint: nvs %s failed: 0x%x",
                 known ? "set" : "erase", err);
    }
}

/* force_auth: the long-poll recovery ladder (node expired / deleted /
 * map rejected) — control already refused this node, so go straight to
 * the auth key, as before B22. */
static esp_err_t register_node(bool force_auth)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;

    /* Reset the per-attempt wait so a TLS / NVS / network failure path
     * doesn't surface a stale value from a previous 429. */
    s_last_register_wait_ms = 0;

    /* Read before connecting when it is going to be sent: a missing key
     * then fails without a TLS + Noise handshake per retry. */
    const bool known = s_reg_known && !force_auth;
    char auth_key[128];
    esp_err_t err;
    if (!known) {
        err = read_auth_key(auth_key, sizeof(auth_key));
        if (err != ESP_OK) return err;
    }

    err = ensure_control_conn();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ts2021_connect failed: 0x%x", err);
        if (!known) mbedtls_platform_zeroize(auth_key, sizeof(auth_key));
        return err;
    }

    int status = 0;
    if (known) {
        err = register_emit(&s_conn, &s_keys, NULL, &status);
        if (register_retry_with_auth(status, err)) {
            ESP_LOGW(TAG, "register without auth refused (HTTP %d, 0x%x) — "
                          "retrying with the stored auth key", status, err);
            reg_hint_store(false);
            err = read_auth_key(auth_key, sizeof(auth_key));
            if (err == ESP_OK) {
                err = register_emit(&s_conn, &s_keys, auth_key, &status);
                mbedtls_platform_zeroize(auth_key, sizeof(auth_key));
            }
        }
    } else {
        err = register_emit(&s_conn, &s_keys, auth_key, &status);
        /* Scrub the auth key in stack memory. mbedtls_platform_zeroize is
         * a compiler-barrier'd zero (won't be optimized out as a dead
         * store the way a plain memset on a no-longer-read buffer can). */
        mbedtls_platform_zeroize(auth_key, sizeof(auth_key));
    }

    /* Snapshot before drop_control_conn — the status + Retry-After live
     * on s_conn; drop_control_conn calls ts2021_close which may zero
     * per-conn state on a future change. */
    s_last_register_wait_ms = control_rate_limit_ms();

    /* An authorized node is known from now on; one control answered
     * without authorizing is not (a throttle or a lost answer says
     * nothing either way). */
    if (err == ESP_OK) {
        reg_hint_store(true);
    } else if (register_retry_with_auth(status, err)) {
        reg_hint_store(false);
    }

    /* Keep the conn on success: since M5-2c the HTTP/2 session is
     * persistent per ts2021 conn, so the next request (the boot-time
     * endpoint push, then the map stream — or, on the in-place
     * re-register path, the push the long-poll runs right after) rides
     * the same channel. The old "one conn per request" teardown here
     * dated from the per-request session_new/del era and cost one full
     * TLS + Noise IK handshake (~5 s, ~12 KiB heap transient) per boot
     * and per re-register. A failed register still drops the conn so a
     * half-broken channel is never reused. */
    if (err != ESP_OK) drop_control_conn();
    return err;
}

esp_err_t tinylink_register(void)
{
    return register_node(false);
}

static void stun_boot_join(void);
static volatile bool s_ep_push_pending;   /* the long-poll's push request, below */

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
     * So the device's endpoints + NetInfo go up in a Stream=false,
     * OmitPeers=true lite MapRequest — the "fresh state upload" that
     * updates the server's cached Hostinfo/Endpoints record, so peers
     * see real dial candidates and a HomeDERP region in their
     * MapResponse. Until round 1.3.7 it ran here, a round trip on its
     * own (~0.19 s on the sensor) between the register and the map
     * stream. Now it is the long-poll's first push: a second HTTP/2
     * stream in the same burst as the map stream (mapreq_run_stream),
     * as upstream's updateRoutine sends its lite updates alongside the
     * poll — the netmap no longer waits for it, and the endpoint is
     * read when the burst is built, ~0.2 s later than here. */
    if (!s_initialized) return ESP_ERR_INVALID_STATE;

    /* The boot STUN probe ran alongside the register (round 1.3.5):
     * take its result, or give up on it after STUN_BOOT_WAIT_MS — first,
     * before any return, because from here on it must stay off the WG
     * socket (stun_boot.h). */
    stun_boot_join();

    /* Observability: was the STUN-discovered endpoint available when
     * the boot handed over? The push body is built from the same
     * accessor a moment later; an admin-panel "Endpoints" field that
     * comes up empty starts here. */
    uint8_t  ep_addr[4];
    uint16_t ep_port;
    if (tinylink_get_public_endpoint(ep_addr, &ep_port)) {
        ESP_LOGI(TAG, "dataplane_start: endpoint %u.%u.%u.%u:%u goes up "
                      "with the map stream",
                 ep_addr[0], ep_addr[1], ep_addr[2], ep_addr[3],
                 (unsigned)ep_port);
    } else {
        ESP_LOGW(TAG, "dataplane_start: no STUN endpoint yet — the "
                      "lite MapRequest lands NetInfo only; the "
                      "re-probe pushes the endpoint once the data plane "
                      "is up");
    }
    s_ep_push_pending = true;
    /* s_conn stays open (the register's) — the long-poll's first cycle
     * rides it. */
    return ESP_OK;
}

/* ---- long-poll MapRequest task ----------------------------------------- */

/* Set by long_poll_handler (long-poll task) once the first netmap has
 * started the data plane; read by the DERP task (handle_disco_relayed). */
static volatile bool s_dataplane_started;

/* ---- Last-known server addresses (round 1.3.5, tl_addr.h) ---------------
 *
 * The home DERP node: the node of CONFIG_TINYLINK_PREFERRED_DERP the
 * netmap last named — host, DERPPort, its IPv4 and STUN port — restored
 * from NVS `derp_node` by tinylink_init, else the Kconfig host with no
 * address. The supervisor dials it (the address first, the name if that
 * fails) and both STUN probes ask its STUN service, so a boot with a
 * record does neither through DNS. Written by the long-poll task (each
 * netmap), read by the DERP, STUN-boot and telemetry tasks: under
 * s_home_derp_mux, with s_derp_host_gen (bumped when the node moves). */
static tl_derp_addr_t    s_home_derp;
static bool              s_home_derp_named;   /* by a netmap (not the boot record) */
static volatile uint32_t s_derp_host_gen;
static portMUX_TYPE      s_home_derp_mux = portMUX_INITIALIZER_UNLOCKED;

/* What NVS holds for each record (tl_addr_store compares against it). */
static tl_addr_blob_t s_derp_nvs;
static tl_addr_blob_t s_ctl_nvs;

static void home_derp_get(tl_derp_addr_t *out, uint32_t *gen)
{
    portENTER_CRITICAL(&s_home_derp_mux);
    *out = s_home_derp;
    if (gen != NULL) *gen = s_derp_host_gen;
    portEXIT_CRITICAL(&s_home_derp_mux);
}

static void blob_load(nvs_handle_t h, const char *key, tl_addr_blob_t *m)
{
    size_t n = sizeof(m->b);
    m->len = (nvs_get_blob(h, key, m->b, &n) == ESP_OK && n <= sizeof(m->b)) ? (uint8_t)n : 0;
}

/* tinylink_init: the records → RAM. Read-only; a missing namespace or
 * key (first boot with 1.3.5) is the Kconfig DERP host and no addresses. */
static void addr_cache_load(void)
{
    nvs_handle_t h;
    if (nvs_open(TAI64N_NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        blob_load(h, TL_ADDR_KEY_DERP, &s_derp_nvs);
        blob_load(h, TL_ADDR_KEY_CTL, &s_ctl_nvs);
        nvs_close(h);
    }
    tl_derp_addr_boot(s_derp_nvs.b, s_derp_nvs.len, CONFIG_TINYLINK_PREFERRED_DERP,
                      CONFIG_TINYLINK_DERP_SMOKE_HOST, &s_home_derp);
    char a[TL_IPV4_STRLEN] = "none";
    if (tl_ipv4_usable(s_home_derp.ipv4)) tl_ipv4_str(s_home_derp.ipv4, a);
    ESP_LOGI(TAG, "address cache: home DERP node %s (address %s, STUN %u)%s",
             s_home_derp.host, a, (unsigned)s_home_derp.stun_port,
             s_derp_nvs.len > 0 ? "" : " — Kconfig, nothing stored");

    uint8_t ip[4];
    if (tl_ctl_addr_decode(s_ctl_nvs.b, s_ctl_nvs.len, CONFIG_TINYLINK_CONTROL_HOST, ip)) {
        ts2021_set_addr(ip);
        uint32_t v;
        memcpy(&v, ip, sizeof(v));
        __atomic_store_n(&s_ctl_addr, v, __ATOMIC_RELAXED);
        tl_ipv4_str(ip, a);
        ESP_LOGI(TAG, "address cache: control %s at %s", CONFIG_TINYLINK_CONTROL_HOST, a);
    }
}

static int addr_nvs_write(const uint8_t *b, size_t n, const void *ctx)
{
    const char *key = (const char *)ctx;
    nvs_handle_t h;
    esp_err_t err = nvs_open(TAI64N_NVS_NS, NVS_READWRITE, &h);
    if (err == ESP_OK) {
        err = nvs_set_blob(h, key, b, n);
        if (err == ESP_OK) err = nvs_commit(h);
        nvs_close(h);
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "address cache: nvs %s write failed: 0x%x — next boot resolves",
                 key, err);
    }
    return err == ESP_OK ? 0 : -1;
}

/* Telemetry housekeeping (every 60 s, first ~60 s after the first
 * netmap): write the records whose bytes changed. Never on the boot path
 * — an NVS write may erase a 4-KB sector and stall both CPUs for up to
 * ~0.5 s (tl_time.c) — and only for a change: the DERP record moves
 * with the DERP map, the control one when its cached address stopped
 * answering and the name led elsewhere. */
void tinylink_addr_persist_poll(void)
{
    uint8_t b[TL_ADDR_BLOB_MAX];
    tl_derp_addr_t d;
    bool named;
    portENTER_CRITICAL(&s_home_derp_mux);
    d = s_home_derp;
    named = s_home_derp_named;
    portEXIT_CRITICAL(&s_home_derp_mux);
    size_t n = named ? tl_derp_addr_encode(&d, b, sizeof(b)) : 0;
    if (n > 0 && tl_addr_store(&s_derp_nvs, b, n, addr_nvs_write, TL_ADDR_KEY_DERP) == 1) {
        ESP_LOGI(TAG, "address cache: home DERP node %s stored", d.host);
    }
    const uint32_t v = __atomic_load_n(&s_ctl_addr, __ATOMIC_RELAXED);
    uint8_t ip[4];
    memcpy(ip, &v, sizeof(ip));
    n = tl_ctl_addr_encode(ip, CONFIG_TINYLINK_CONTROL_HOST, b, sizeof(b));
    if (n > 0 && tl_addr_store(&s_ctl_nvs, b, n, addr_nvs_write, TL_ADDR_KEY_CTL) == 1) {
        char a[TL_IPV4_STRLEN];
        tl_ipv4_str(ip, a);
        ESP_LOGI(TAG, "address cache: control address %s stored", a);
    }
}

/* The netmap's home node → s_home_derp (long-poll task, every netmap
 * that carries the region). A new host or port moves the supervisor
 * (s_derp_host_gen; derp_sup_event_cb leaves the stream at the next
 * DERP frame); a new address or STUN port only applies from the next
 * connect / probe — the live stream to that host is fine. The NVS copy
 * follows in tinylink_addr_persist_poll. Not inlined: its ~130-B frame
 * (the record, a log buffer) would otherwise sit in long_poll_handler's,
 * under wg_dataplane_start — the long-poll's static worst case
 * (tools/stack_worst.py: 4 864 → 4 992 B inlined). */
static __attribute__((noinline)) void update_derp_host_from_netmap(const tl_netmap_t *nm)
{
    tl_derp_addr_t next;
    if (!tl_derp_addr_from_netmap(nm, CONFIG_TINYLINK_PREFERRED_DERP, &next)) return;
    portENTER_CRITICAL(&s_home_derp_mux);
    const unsigned diff = tl_derp_addr_diff(&s_home_derp, &next);
    s_home_derp = next;
    s_home_derp_named = true;
    if (diff & TL_DERP_MOVED) s_derp_host_gen++;
    const uint32_t gen = s_derp_host_gen;
    portEXIT_CRITICAL(&s_home_derp_mux);
    if (diff & TL_DERP_MOVED) {
        ESP_LOGI(TAG, "derp host updated to region %d node: %s:%u (gen %u)",
                 CONFIG_TINYLINK_PREFERRED_DERP, next.host,
                 next.port ? next.port : 443u, (unsigned)gen);
    }
    if (diff & TL_DERP_ADDR) {
        char a[TL_IPV4_STRLEN] = "none";
        if (tl_ipv4_usable(next.ipv4)) tl_ipv4_str(next.ipv4, a);
        ESP_LOGI(TAG, "derp node %s: address %s, STUN %u (DERP map)",
                 next.host, a, (unsigned)next.stun_port);
    }
}

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
    esp_err_t err = derp_client_connect_login(&c, host, 443, NULL,
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

/* ---- The first INIT waits for the relay (round 1.3.7) -------------------
 *
 * At boot the first INIT reaches the peer directly, and the peer, with
 * no validated direct path to our new NAT mapping yet, answers via DERP.
 * If our DERP login is still under way that answer is lost, and the copy
 * re-queued at the login (WG_NETIF_KICK_RELAY_UP) is the same INIT — a
 * TAI64N replay to the peer: the session waits for the new INIT of
 * WG_FIRST_RETRY_MS. In the 1.3.5 reboot series the 8 boots whose login
 * came 0.21 s or more after the first INIT had the session up 1.2-2.2 s
 * after the netmap (two far later); all others but one, 0.16-0.54 s.
 * 1.3.6 had the login first in all six boots, by 40-390 ms: a margin
 * the ~0.28 s earlier netmap of 1.3.7 (the push rides with the map
 * stream, Noise DH ahead) eats in two of them. So the first netmap waits
 * for the outcome of the supervisor's first connect attempt, at most
 * RELAY_BOOT_WAIT_MS — in those boots the login was 0.3 s away or less.
 * A stalled attempt (TCP to a dead cached address took 4.6 s in one
 * 1.3.5 boot) costs the cap, then the 1.3.6 order applies. One-shot: a
 * failed first attempt, later netmaps and reconnects never wait. */
#define RELAY_BOOT_WAIT_MS   1000
#define RELAY_BOOT_LOGIN_OK  BIT0
#define RELAY_BOOT_FAILED    BIT1

static volatile bool s_relay_boot_pending;   /* the first attempt is running */
static EventGroupHandle_t s_relay_boot;

#if CONFIG_TINYLINK_DERP_SUPERVISED
static StaticEventGroup_t s_relay_boot_buf;

/* Supervisor, after its first connect attempt. The kick that precedes
 * it is a no-op before the dataplane exists, so the INIT this releases
 * carries its own DERP copy — no second one from the kick. */
static void relay_boot_done(bool login_ok)
{
    if (!s_relay_boot_pending) return;
    s_relay_boot_pending = false;
    xEventGroupSetBits(s_relay_boot, login_ok ? RELAY_BOOT_LOGIN_OK
                                              : RELAY_BOOT_FAILED);
}
#endif

/* long_poll_handler, before the first INIT (wg_dataplane_start). */
static void relay_boot_join(void)
{
    if (!s_relay_boot_pending) return;   /* no supervisor, or it is done */
    const int64_t t0 = esp_timer_get_time();
    /* The bits stay set: an outcome that lands between the check above
     * and this wait returns at once. */
    const EventBits_t got = xEventGroupWaitBits(
        s_relay_boot, RELAY_BOOT_LOGIN_OK | RELAY_BOOT_FAILED, pdFALSE,
        pdFALSE, pdMS_TO_TICKS(RELAY_BOOT_WAIT_MS));
    const unsigned waited_ms = (unsigned)((esp_timer_get_time() - t0) / 1000);
    if (got & RELAY_BOOT_LOGIN_OK) {
        ESP_LOGI(TAG, "first INIT waited %u ms for the DERP login", waited_ms);
    } else if (got & RELAY_BOOT_FAILED) {
        ESP_LOGI(TAG, "first INIT waited %u ms: DERP connect failed", waited_ms);
    } else {
        ESP_LOGW(TAG, "DERP login still pending after %u ms — first INIT "
                      "goes ahead", waited_ms);
    }
}

/* ---- DERP supervised recv-loop task (M5 step 2b) -----------------------
 *
 * Long-running task: connect+login → run recv loop → close → backoff →
 * repeat, from boot (round 1.3.5: alongside the register, see
 * derp_supervised_task). Connect failures are logged and retried with
 * backoff (not fatal). Relayed frames: DISCO is answered / acted on
 * here (handle_disco_relayed), WireGuard goes to wg_netif's inject path;
 * wg_tx sends through it (tinylink_relay_via_derp). */

#if CONFIG_TINYLINK_DERP_SUPERVISED

/* Frame buffer sized for typical WG packets (<1500 B) plus the 32-byte
 * src-pub prefix and slack. */
#define DERP_SUP_FRAME_CAP 1600

/* Single DERP client owned by the supervisor task. File-scope: wg_tx
 * sends through it (tinylink_relay_via_derp) and the GOT_IP handler
 * aborts its reads. */
static derp_client_t s_derp_sup;

/* The supervisor connects to s_home_derp (above): the node of
 * CONFIG_TINYLINK_PREFERRED_DERP, the region we advertise as our
 * HomeDERP — peers send traffic to that region; if we're connected
 * elsewhere the relay can't route it. Before any netmap it is the NVS
 * record or the Kconfig host, a node of that region: the first connect
 * runs at boot (round 1.3.5). s_derp_conn_gen is the s_derp_host_gen
 * captured at connect; the event callback stops the stream when the
 * two differ, so a control-plane reroute reaches a LIVE connection
 * within one server keepalive instead of waiting for the stream to die
 * on its own (2026-09). */
static uint32_t          s_derp_conn_gen;


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
 * struct (~2.5 KiB since 1.3.2 keeps one DERP region; ~8 KiB before). The function only
 * ever reads n_peers + peers[] anyway. */
/* Each peer's pings are sealed with one NaCl box key K (round 1.3.7,
 * B2): the active WG peer's cached one (no X25519), else computed once
 * for the peer — every ping was a full nacl_box before, one X25519 per
 * endpoint (12 at the 1.3.6 boots: 12 pings across 4 peers, ~150 ms of
 * the long-poll task right after the first netmap; 3 now). */
static void prepunch_pings_to_peers(const tl_peer_t *peers, size_t n_peers)
{
    if (peers == NULL || n_peers == 0) return;

    int sock = wg_netif_get_socket();
    if (sock < 0) return;  /* WG netif not yet bound: nothing to punch from */

    disco_peer_key_t active;
    memset(&active, 0, sizeof(active));
    active.has_pub = wg_netif_get_peer_disco_k(active.pub, active.k, &active.k_valid);

    size_t total_sent = 0;
    for (size_t pi = 0; pi < n_peers; pi++) {
        const tl_peer_t *peer = &peers[pi];
        if (!peer->has_disco_pub) continue;        /* can't seal without DiscoKey */
        if (peer->n_endpoints == 0) continue;

        uint8_t k[NACL_BOX_KEY_LEN];
        if (active.has_pub && active.k_valid &&
            memcmp(peer->disco_pub, active.pub, DISCO_KEY_LEN) == 0) {
            memcpy(k, active.k, sizeof(k));
        } else if (nacl_box_compute_shared(k, peer->disco_pub, s_keys.disco_priv) != 0) {
            continue;                              /* low-order DiscoKey */
        }

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
            size_t wire_len = disco_seal_with_shared(wire, sizeof(wire),
                                                     inner, inner_len, nonce,
                                                     s_keys.disco_pub, k);
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
                ESP_LOGW(TAG, "prepunch sendto: errno=%d (peer=%u ep=%s)",
                         errno, (unsigned)pi, ep);
                continue;
            }
            /* Record the outbound probe so handle_disco_direct can
             * match the resulting Pong's txid (M3-step-3 binding). */
            disco_prober_record(ping.txid, v4_be, (uint16_t)port,
                                esp_timer_get_time());
#endif
            total_sent++;
            ESP_LOGD(TAG, "prepunch ping → %s txid=%02x%02x%02x%02x..",
                     ep, ping.txid[0], ping.txid[1],
                     ping.txid[2], ping.txid[3]);
        }
        tl_secure_zero(k, sizeof(k));
    }
    tl_secure_zero(&active, sizeof(active));
    if (total_sent > 0) {
        /* %u + casts: newlib-nano printf has no %zu (it printed "zu"). */
        ESP_LOGI(TAG, "prepunch on netmap-receive: sent %u pings across %u peers",
                 (unsigned)total_sent, (unsigned)n_peers);
    }
}

/* `peer`: the gate's view of the sender (handle_disco_relayed). */
static void send_disco_pings_to_cmm_endpoints(const derp_event_t *e,
                                              const disco_peer_key_t *peer)
{
    /* Re-decrypt + re-parse: handle_disco_relayed already did this
     * through disco_handle_recv_from_peer, but that helper doesn't
     * expose the parsed CallMeMaybe payload. With one key K for the
     * sender — the active peer's cached one, else computed once — the
     * second open and the punch pings cost no X25519 (round 1.3.7, B2:
     * the open was one more, and each ping one per endpoint). */
    uint8_t k[NACL_BOX_KEY_LEN];
    if (disco_gate(e->data, e->data_len, peer) == DISCO_GATE_K) {
        memcpy(k, peer->k, sizeof(k));
    } else if (e->data_len < DISCO_MIN_WIRE_LEN ||
               nacl_box_compute_shared(k, e->data + DISCO_MAGIC_LEN,
                                       s_keys.disco_priv) != 0) {
        return;
    }
    uint8_t pt[256];
    uint8_t peer_disco_pub[DISCO_KEY_LEN];
    size_t pt_len = disco_open_with_shared(pt, sizeof(pt), peer_disco_pub,
                                           e->data, e->data_len, k);
    disco_msg_t msg;
    int sock = -1;
    if (pt_len == 0 || disco_parse(pt, pt_len, &msg) != 0 ||
        msg.type != DISCO_TYPE_CALLMEMAYBE) {
        tl_secure_zero(k, sizeof(k));
        return;
    }
    sock = wg_netif_get_socket();
    if (sock < 0) {
        ESP_LOGW(TAG, "cmm: wg socket not up — cannot punch");
        tl_secure_zero(k, sizeof(k));
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
        size_t wire_len = disco_seal_with_shared(wire, sizeof(wire),
                                                 inner, inner_len, nonce,
                                                 s_keys.disco_pub, k);
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
        ESP_LOGD(TAG, "cmm punch ping → %u.%u.%u.%u:%u txid=%02x%02x%02x%02x..",
                 ep->addr[12], ep->addr[13], ep->addr[14], ep->addr[15],
                 (unsigned)ep->port,
                 ping.txid[0], ping.txid[1], ping.txid[2], ping.txid[3]);
    }
    tl_secure_zero(k, sizeof(k));
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
    /* Before the first netmap (the relay connects at boot since round
     * 1.3.5) no peer is known, so no DISCO sender can be one: drop it
     * unopened, like magicsock does for a DiscoKey outside its peer map
     * — without paying the X25519 to open it (any DERP client that knows
     * our NodeKey can send us frames), and without answering pings from,
     * or punching the endpoints of, a node the gate below could not
     * check yet. A WG frame goes on: wg_netif_inject_packet drops it
     * until wg_netif_start has configured the peer. */
    if (!s_dataplane_started && disco_looks_like(e->data, e->data_len)) {
        ESP_LOGD(TAG, "relayed DISCO before the first netmap dropped");
        return;
    }

    uint8_t reply[DISCO_HANDLER_REPLY_MAX];
    disco_msg_type_t type = (disco_msg_type_t)0;
    uint8_t peer_disco_pub[DISCO_KEY_LEN] = {0};
    uint8_t txid[DISCO_TXID_LEN] = {0};

    /* knownPeerDiscoKey gate (mirrors the direct-UDP path's gate in
     * wg_netif.c handle_disco_direct). Opening a frame only proves it
     * was sealed TO us — any tailnet node can do that. Before we answer
     * a PING or, worse, punch the endpoints in a CallMeMaybe (a UDP ping
     * flood to attacker-chosen addresses), the sender's DiscoKey must be
     * the active WG peer's. Since round 1.3.7 (B2) it is read off the
     * cleartext header before any crypto — another key cost an X25519
     * to open (two for a PING: the pong was sealed before the gate) —
     * and the peer's frames are opened and answered with its cached box
     * key K, no X25519 at all (1–2 per relayed frame before; the
     * relay's CallMeMaybe burst after each session up was ~60 ms of this
     * task). Only DISCO frames are gated; anything else (type 0) is
     * relayed WireGuard traffic, which wg_netif_inject_packet gates
     * separately by src NodeKey. When the WG peer has no DiscoKey the
     * gate is permissive, same as the direct path (before the first
     * netmap DISCO never gets here). */
    disco_peer_key_t peer;
    memset(&peer, 0, sizeof(peer));
    peer.has_pub = wg_netif_get_peer_disco_k(peer.pub, peer.k, &peer.k_valid);
    bool gated = false;
    size_t reply_len = disco_handle_recv_from_peer(reply, sizeof(reply),
                                                   e->data, e->data_len, &peer,
                                                   s_keys.disco_priv, s_keys.disco_pub,
                                                   &type, peer_disco_pub, txid, &gated);
    if (gated) {
        tl_secure_zero(&peer, sizeof(peer));
        ESP_LOGD(TAG, "drop relayed DISCO from unknown DiscoKey (pre-AEAD)");
        return;
    }

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
        send_disco_pings_to_cmm_endpoints(e, &peer);
        /* The peer is punching towards us: if our handshake is still
         * pending, its INIT can get through now (B7). */
        wg_netif_handshake_kick(WG_NETIF_KICK_CALL_ME_MAYBE);
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
    tl_secure_zero(&peer, sizeof(peer));
}

static int derp_sup_event_cb(const derp_event_t *e, void *ctx)
{
    derp_sup_stats_t *st = (derp_sup_stats_t *)ctx;
    switch (e->kind) {
    case DERP_EVT_RECV_PACKET:
        st->recv_packets++;
        ESP_LOGD(TAG, "derp recv: src=%02x%02x..%02x%02x len=%u (total=%lu)",
                 e->src_pub[0], e->src_pub[1],
                 e->src_pub[DERP_KEY_LEN - 2], e->src_pub[DERP_KEY_LEN - 1],
                 (unsigned)e->data_len,
                 (unsigned long)st->recv_packets);
        handle_disco_relayed(e, st);
        break;
    case DERP_EVT_KEEPALIVE:
        st->keepalives++;
        ESP_LOGD(TAG, "derp keepalive (total=%lu)",
                 (unsigned long)st->keepalives);
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
    if (s_derp_host_gen != s_derp_conn_gen) {
        tl_derp_addr_t node;
        home_derp_get(&node, NULL);
        ESP_LOGI(TAG, "derp supervisor: preferred relay changed — leaving for %s",
                 node.host);
        return 1;   /* derp_client_run returns ESP_OK; supervisor reconnects */
    }
    return 0;
}

/* A DERP stream that lived at least this long counts as healthy for the
 * reconnect ladder (mirrors LP_HEALTHY_MS for the control stream). */
#define DERP_SUP_HEALTHY_MS 10000

/* Task entry: own the connect + recv-loop + close + backoff cycle
 * end-to-end. Initial connect lives here (not in the start() caller)
 * so a failed first connect (DNS, TLS, a relay restarting) doesn't tear
 * the supervisor down for the rest of the session — the task simply
 * loops on backoff. */
static void derp_supervised_task(void *arg)
{
    (void)arg;

    /* Connect at once (round 1.3.5), alongside the register, instead of
     * after the first netmap. 1.3.4 logged the login ~1.8 s after the
     * netmap, so the first WG INIT went out with no relay, the peer's
     * answer via DERP was lost and the session came up on attempt 2,
     * ~1.9 s after the netmap — every boot. Now the relay is up first
     * and the INIT's own DERP copy (B7, wg_netif.c build_and_send_init)
     * reaches the peer.
     *
     * The wait (tinylink_wait_dataplane_ms, 30-s cap, gone) kept two
     * invariants of the 2026-05 tree; neither holds any more:
     *
     *   1. Heap order: with ~11 KiB free then, opening this TLS conn
     *      first fragmented the arena below the ~12 KiB contiguous the
     *      long-poll's cert verify needed. 1.3.4 has ~159 KB free and a
     *      110 KB largest block with every conn up (60-s stack diag;
     *      163 KB / 110 KB when this task connected after the netmap),
     *      a handshake's transient is ~12 KiB, and the long-poll's first
     *      stream rides the register's conn — no long-poll handshake at
     *      boot is left to protect. This handshake now overlaps the
     *      register's; the connect line below logs the heap.
     *   2. Region: our home region is CONFIG_TINYLINK_PREFERRED_DERP,
     *      compiled in and advertised by us in every MapRequest — known
     *      before any netmap. The netmap only names its node, and the
     *      Kconfig host is a node of it (on the sensor the very node the
     *      DERPMap names: no "derp host updated" line in 1.3.4 boots). If
     *      the netmap names another node, update_derp_host_from_netmap
     *      bumps s_derp_host_gen and derp_sup_event_cb leaves the stream
     *      at the next DERP frame (server keepalive, about once a
     *      minute) for an immediate reconnect there.
     *
     * The login itself only proves the node key (tinylink_init loaded it;
     * fixed for the boot) — DERP needs no registered node. Nothing on
     * the receive side needs the netmap either: relayed WG frames are
     * dropped by wg_netif_inject_packet until wg_netif_start configures
     * the peer (zero key, IDLE state), relayed DISCO before the first
     * netmap by handle_disco_relayed. */
    tl_wdt_subscribe();

    /* Exponential backoff: start at the Kconfig base, double on each
     * consecutive connect failure, cap at 30 s (per WG/Tailscale
     * convention — long enough that we don't hammer a server that's
     * down, short enough that recovery from a transient outage feels
     * snappy). Reset to base on a successful login so the *next*
     * outage starts fresh instead of inheriting hours of accumulated
     * doubling. */
    /* Backoff ladder shared with the long-poll (backoff.h): capped
     * exponential with ±25 % jitter, counted in consecutive FAILURES —
     * connect failures, or streams that died before DERP_SUP_HEALTHY_MS
     * of service. A healthy stream resets the ladder so the next blip
     * recovers from the base, not the cap. Replaces the unjittered
     * TickType_t doubling (15 s → 30 s, effectively one step) that
     * synchronised a fleet into a thundering herd on every relay blip.
     * Envelope unchanged: base = CONFIG_TINYLINK_DERP_SUPERVISED_BACKOFF_MS,
     * cap = 30 s. */
    const uint32_t base_ms = CONFIG_TINYLINK_DERP_SUPERVISED_BACKOFF_MS;
    const uint32_t cap_ms  = 30000u;
    uint32_t fail = 0;

    derp_sup_stats_t stats = {0};
    static uint8_t frame_buf[DERP_SUP_FRAME_CAP];
    unsigned attempt = 0;

    for (;;) {
        /* Connect with backoff — runs at boot too, not just on
         * reconnect. Re-read the home node every iteration so a netmap
         * update that changes the preferred region's host (or the
         * node's address) steers the NEXT reconnect to the right relay.
         * Host and generation are read together: a move that lands after
         * this snapshot still differs from s_derp_conn_gen. */
        for (;;) {
            attempt++;
            tl_derp_addr_t node;
            home_derp_get(&node, &s_derp_conn_gen);
            char a[TL_IPV4_STRLEN] = "no address";
            if (tl_ipv4_usable(node.ipv4)) tl_ipv4_str(node.ipv4, a);
            ESP_LOGI(TAG, "derp supervisor: connect attempt #%u to %s (%s) "
                          "(heap_free=%u largest=%u)",
                     attempt, node.host, a,
                     (unsigned)esp_get_free_heap_size(),
                     (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));
            esp_err_t cerr = derp_client_connect_login(&s_derp_sup, node.host,
                                                       node.port, node.ipv4,
                                                       s_keys.node_priv,
                                                       s_keys.node_pub);
            if (cerr == ESP_OK) {
                ESP_LOGI(TAG, "derp supervisor: login OK server-v=%d "
                              "(after %u attempts)",
                         s_derp_sup.server_version, attempt);
                attempt = 0;
                /* A handshake still pending — a relay reconnect during a
                 * rekey, or a boot whose login took longer than register
                 * + netmap (1.3.4: every boot, the INIT went out ~2 s
                 * before this login) — gets its INIT relayed now instead
                 * of after REKEY_TIMEOUT (B7). Before the first netmap
                 * there is none: a no-op — and since 1.3.7 a first netmap
                 * that lands during this attempt holds its INIT until
                 * here (relay_boot_join). */
                wg_netif_handshake_kick(WG_NETIF_KICK_RELAY_UP);
                relay_boot_done(true);
                break;
            }
            relay_boot_done(false);
            const uint32_t delay_ms = tl_backoff_ms(fail, base_ms, cap_ms,
                                                    esp_random());
            if (fail < 1000u) fail++;              /* saturate the counter */
            ESP_LOGW(TAG, "derp supervisor: connect attempt #%u failed 0x%x — "
                          "backoff %u ms",
                     attempt, cerr, (unsigned)delay_ms);
            derp_client_close(&s_derp_sup);
            tl_wdt_sleep_ms(delay_ms);
        }

        ESP_LOGI(TAG, "derp supervisor: entering recv loop server-v=%d",
                 s_derp_sup.server_version);
        const int64_t t0 = esp_timer_get_time();
        esp_err_t err = derp_client_run(&s_derp_sup, frame_buf, sizeof(frame_buf),
                                        derp_sup_event_cb, &stats);
        if (err == ESP_ERR_INVALID_RESPONSE) {
            ESP_LOGW(TAG, "derp supervisor: server restarting — backoff");
        } else {
            ESP_LOGW(TAG, "derp supervisor: stream ended 0x%x — "
                          "stats recv=%lu disco_pings_answered=%lu "
                          "disco_pongs_seen=%lu disco_cmms=%lu "
                          "send_err=%lu keepalives=%lu wg_tx_drops=%lu",
                     err,
                     (unsigned long)stats.recv_packets,
                     (unsigned long)stats.disco_pings_answered,
                     (unsigned long)stats.disco_pongs_seen,
                     (unsigned long)stats.disco_cmms_seen,
                     (unsigned long)stats.disco_send_errors,
                     (unsigned long)stats.keepalives,
                     (unsigned long)wg_netif_get_tx_drops());
        }
        derp_client_close(&s_derp_sup);
        if (s_derp_host_gen != s_derp_conn_gen) {
            continue;   /* deliberate relay switch: reconnect right away */
        }
        /* A stream that served for a while was a healthy relay — recover
         * from the base; a stream that died young climbs the ladder. */
        const int64_t up_us = esp_timer_get_time() - t0;
        if (up_us >= (int64_t)DERP_SUP_HEALTHY_MS * 1000LL) {
            fail = 0;
        } else if (fail < 1000u) {
            fail++;
        }
        const uint32_t delay_ms = tl_backoff_ms(fail, base_ms, cap_ms,
                                                esp_random());
        ESP_LOGI(TAG, "derp supervisor: reconnecting in %u ms", (unsigned)delay_ms);
        tl_wdt_sleep_ms(delay_ms);
    }
}

#endif /* CONFIG_TINYLINK_DERP_SUPERVISED */

esp_err_t tinylink_relay_via_derp(const uint8_t *dst_node_pub,
                                  const uint8_t *packet,
                                  size_t len,
                                  bool best_effort,
                                  void *user)
{
    (void)user;  /* registered with user=NULL; supervisor lives in BSS */
#if CONFIG_TINYLINK_DERP_SUPERVISED
    if (dst_node_pub == NULL || packet == NULL || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    /* derp_client_send_packet returns ESP_ERR_INVALID_STATE itself
     * when the supervisor isn't connected; we short-circuit ahead of
     * it here so the wg_netif TX worker can read the state in a
     * single field-load and skip the function-call cost on the hot
     * path when DERP isn't usable. The flag is set by the supervisor at
     * login and cleared by a close or a failed write (an atomic load
     * here, derp_wlock.h); the window is harmless — at worst we attempt
     * one extra send (which fails fast inside derp_client_send_packet's
     * own state guard) or skip one send that was about to be accepted
     * (which the next packet picks up). */
    if (!derp_client_is_connected(&s_derp_sup)) {
        return ESP_ERR_INVALID_STATE;
    }
    return best_effort
        ? derp_client_try_send_packet(&s_derp_sup, dst_node_pub, packet, len)
        : derp_client_send_packet(&s_derp_sup, dst_node_pub, packet, len);
#else
    (void)dst_node_pub; (void)packet; (void)len; (void)best_effort;
    return ESP_ERR_NOT_SUPPORTED;
#endif
}

#if CONFIG_TINYLINK_DERP_SUPERVISED
/* wg_netif's relay state (wg_netif_set_relay_state_callback): an INIT is
 * held behind a re-send only while the supervisor is connected. The same
 * racy-but-harmless read of the flag as above. */
static bool relay_connected(void *user)
{
    (void)user;
    return derp_client_is_connected(&s_derp_sup);
}
#endif

esp_err_t tinylink_derp_supervised_start(void)
{
#if CONFIG_TINYLINK_DERP_SUPERVISED
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    /* An empty Kconfig host disables the relay, whatever NVS holds. The
     * task dials s_home_derp: the NVS record or this host until a
     * netmap names our PreferredDERP region's node (long_poll_handler). */
    if (CONFIG_TINYLINK_DERP_SMOKE_HOST[0] == '\0') {
        ESP_LOGI(TAG, "derp supervisor: disabled (empty host)");
        return ESP_OK;
    }
    tl_derp_addr_t node;
    home_derp_get(&node, NULL);
    const char *host = node.host;

    /* Spawn the task. 8 KiB stack (round 1.3.3, B18; 10 KiB before):
     * tools/stack_worst.py puts the static worst case at 5 424 B — the
     * TLS handshake's certificate verify through esp_crt_verify_callback
     * into an RSA-PSS signature check (mbedtls_rsa_rsassa_pss_verify_ext
     * → mpi_exp_mod), i.e. covering an RSA chain as well as the
     * ECDSA one the measurements saw (PR #97: 4 920 B peak on
     * 2026-05-12; 5 028 B over the 6-h 1.3.2 soak). C1-S's relayed-packet
     * input on this task is shallower (5 024 B). 8 KiB = 2.8 KB over the
     * static worst case.
     *
     * Called before the first TLS handshake (main.c::bringup: ahead of
     * tinylink_register), which since round 1.3.5 is also when the task
     * connects — its handshake overlaps the register's (see
     * derp_supervised_task). Spawning here also keeps the 8 KiB stack on
     * a pristine heap: in the 2026-05 tree, spawned after the
     * long-poll, xTaskCreate failed with ESP_ERR_NO_MEM in 3 soaks and
     * every DERP-dependent feature stayed dead. */
    /* Armed before the spawn: a netmap can only come later (the
     * register follows this call), but the flag must not trail it. */
    s_relay_boot = xEventGroupCreateStatic(&s_relay_boot_buf);
    s_relay_boot_pending = true;
    BaseType_t ok = xTaskCreate(derp_supervised_task, "tinylink_derp",
                                8192, NULL, tskIDLE_PRIORITY + 3, NULL);
    if (ok != pdPASS) {
        s_relay_boot_pending = false;
        ESP_LOGE(TAG, "xTaskCreate(derp supervisor) failed — "
                      "heap_free=%u largest=%u (need 8 KiB contiguous)",
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

/* Cache the latest netmap PEERS for path-stale active probing.
 * tl_peer_t[TL_MAX_PEERS] is ~1 KiB; the full tl_netmap_t was ~7.5 KiB
 * (derp_regions[28]; one region since 1.3.2). Caching just the peers BSS keeps the
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

/* Self Addresses from the latest frame that carried the self node. The
 * data plane starts from this + the merged peer table, not from a single
 * frame (headscale sends removals, DERPMap updates and endpoint patches
 * as frames of their own). */
static tl_cidr_t s_self_addrs[TL_MAX_PEER_ADDRESSES];
static size_t    s_self_addrs_count;

/* Set by long_poll_handler when control marks this node expired or
 * deleted / when a frame carried a live (non-expired) self node;
 * consumed by long_poll_task (same task — no lock). The rejection
 * schedule only resets on the latter, so an expired node that keeps
 * "registering" fine still backs off. */
static bool s_self_expired;
static bool s_self_live;

/* Index of a peer in s_last_peers by NodeID (the stable handle; upstream
 * keys its peer map by it), or by NodeKey when the ID is 0. */
static size_t peer_index(uint64_t id, const uint8_t *node_pub)
{
    for (size_t j = 0; j < s_last_peers_count; j++) {
        if (id != 0 ? s_last_peers[j].id == id
                    : (node_pub != NULL &&
                       memcmp(s_last_peers[j].node_pub, node_pub,
                              TINYLINK_KEY_LEN) == 0)) {
            return j;
        }
    }
    return SIZE_MAX;
}

/* Merge one frame into the canonical peer table, in upstream's order
 * (control/controlclient/map.go updatePeersStateFromResponse):
 *   Peers             → replace; no other delta in the frame applies;
 *   PeersRemoved      → delete by NodeID;
 *   PeersChanged      → upsert by NodeID (append while there is room);
 *   PeersChangedPatch → patch Key / DiscoKey / Endpoints / DERPRegion of
 *                       a known NodeID in place (unknown IDs ignored).
 * Returns true when the table changed. KeepAlive frames never get here.
 * Patches used to be ignored (a Key/DiscoKey patch recycled the stream),
 * so peer endpoint moves, re-logins and tailscaled restarts reported by
 * headscale as patches never reached the data plane. */
static bool merge_peers(const tl_netmap_t *nm)
{
    if (nm->n_peers > 0 && !nm->peers_is_delta) {
        size_t n = nm->n_peers > TL_MAX_PEERS ? TL_MAX_PEERS : nm->n_peers;
        memcpy(s_last_peers, nm->peers, n * sizeof(tl_peer_t));
        s_last_peers_count = n;
        return true;
    }
    bool changed = false;
    for (size_t r = 0; r < nm->n_removed; r++) {
        if (nm->removed_ids[r] == 0) continue;
        size_t j = peer_index(nm->removed_ids[r], NULL);
        if (j == SIZE_MAX) continue;
        ESP_LOGI(TAG, "peer removed from netmap: id=0x%08lx%08lx",
                 (unsigned long)(s_last_peers[j].id >> 32),
                 (unsigned long)(s_last_peers[j].id & 0xFFFFFFFFul));
        for (size_t k = j + 1; k < s_last_peers_count; k++) {
            s_last_peers[k - 1] = s_last_peers[k];
        }
        s_last_peers_count--;
        changed = true;
    }
    for (size_t i = 0; i < nm->n_peers; i++) {
        const tl_peer_t *p = &nm->peers[i];
        size_t j = peer_index(p->id, p->node_pub);
        if (j == SIZE_MAX) {
            if (s_last_peers_count >= TL_MAX_PEERS) {
                ESP_LOGW(TAG, "peer table full (%d) — delta peer dropped",
                         TL_MAX_PEERS);
                continue;
            }
            j = s_last_peers_count++;
        }
        s_last_peers[j] = *p;
        changed = true;
    }
    for (size_t i = 0; i < nm->n_patches; i++) {
        const tl_peer_patch_t *pc = &nm->patches[i];
        size_t j = peer_index(pc->id, NULL);
        if (j == SIZE_MAX) continue;
        tl_peer_t *t = &s_last_peers[j];
        if (pc->has_key &&
            memcmp(t->node_pub, pc->node_pub, TINYLINK_KEY_LEN) != 0) {
            memcpy(t->node_pub, pc->node_pub, TINYLINK_KEY_LEN);
            changed = true;
        }
        if (pc->has_disco &&
            (!t->has_disco_pub ||
             memcmp(t->disco_pub, pc->disco_pub, TINYLINK_KEY_LEN) != 0)) {
            memcpy(t->disco_pub, pc->disco_pub, TINYLINK_KEY_LEN);
            t->has_disco_pub = true;
            changed = true;
        }
        if (pc->has_endpoints &&
            (t->n_endpoints != pc->n_endpoints ||
             memcmp(t->endpoints, pc->endpoints,
                    pc->n_endpoints * sizeof(tl_endpoint_t)) != 0)) {
            t->n_endpoints = pc->n_endpoints;
            memcpy(t->endpoints, pc->endpoints, sizeof(t->endpoints));
            changed = true;
        }
        if (pc->derp_region != 0 && t->home_derp != pc->derp_region) {
            t->home_derp = pc->derp_region;
            changed = true;
        }
    }
    /* `changed` only when a value actually moved: each true costs a
     * data-plane update + a prepunch round (one X25519 per endpoint). */
    return changed;
}

/* True when control says this node is expired or deleted: an explicit
 * Expired, or a KeyExpiry not after now. time(NULL) is floored at the
 * build epoch / last NTP time (tl_time.c), both ≤ real time, so an
 * unsynced clock can report an expiry late but never early — and
 * headscale's deleted-node marker (1970-01-01T00:00:01Z) is always in
 * the past. */
static bool self_node_expired(const tl_netmap_t *nm)
{
    if (!nm->have_self) return false;
    if (nm->self_expired) return true;
    return nm->self_key_expiry > 0 &&
           nm->self_key_expiry <= (int64_t)time(NULL);
}

/* "a.b.c.d/nn" → network-order IPv4, 0 if not parseable. */
static uint32_t cidr_host_v4(const tl_cidr_t *c)
{
    char host[16];
    const char *slash = strchr(c->str, '/');
    size_t n = slash ? (size_t)(slash - c->str) : strlen(c->str);
    if (n >= sizeof(host)) return 0;
    memcpy(host, c->str, n);
    host[n] = '\0';
    uint32_t v4_be = 0;
    return inet_pton(AF_INET, host, &v4_be) == 1 ? v4_be : 0;
}

static esp_err_t long_poll_handler(const tl_netmap_t *nm, void *ctx)
{
    (void)ctx;
    if (self_node_expired(nm)) {
        /* headscale ≥0.29.4 answers a deleted node's stream with HTTP
         * 200 + this frame and an expired node's with Expired set — no
         * 4xx ever reaches the re-register path, and the bytes keep the
         * wedge clock fed. Upstream clients go to NeedsLogin; we have the
         * authkey, so long_poll_task re-registers. */
        ESP_LOGW(TAG, "control marks this node %s — leaving the stream to "
                      "re-register",
                 nm->self_expired ? "expired/deleted" : "key-expired");
        s_self_expired = true;
        return MAPREQ_STREAM_RECYCLE;
    }
    if (nm->have_self) s_self_live = true;
    if (nm->have_self && nm->n_self_addresses > 0) {
        memcpy(s_self_addrs, nm->self_addresses,
               nm->n_self_addresses * sizeof(tl_cidr_t));
        s_self_addrs_count = nm->n_self_addresses;
        if (s_dataplane_started) {
            /* A deleted-and-re-registered node can come back with a new
             * tailnet address; the lwIP tunnel netif, the TSMP advert
             * source and the peers' AllowedIPs for us would all disagree.
             * Rare (admin deleted the node) — restart into the boot path,
             * which brings everything up against the new address. */
            const uint32_t now_v4 = cidr_host_v4(&s_self_addrs[0]);
            if (now_v4 != 0 && now_v4 != wg_dataplane_self_v4()) {
                ESP_LOGW(TAG, "self address changed to %s — restarting to "
                              "re-attach the tunnel", s_self_addrs[0].str);
                esp_restart();
            }
        }
    }
    const bool peers_changed = merge_peers(nm);
    update_derp_host_from_netmap(nm);   /* STUN uses it without the supervisor too */
    if (!s_dataplane_started) {
        if (s_self_addrs_count == 0 || s_last_peers_count == 0) {
            return ESP_OK;   /* wait for self + peers (first full map) */
        }
        /* Tailscale node ID is genuinely 64-bit (random server-assigned);
         * high/low hex split keeps it printable under NEWLIB_NANO_FORMAT
         * without dragging in full %llu. */
        ESP_LOGI(TAG, "netmap (initial): self.id=0x%08lx%08lx peers=%u derp_regions=%u",
                 (unsigned long)(nm->self_id >> 32),
                 (unsigned long)(nm->self_id & 0xFFFFFFFFul),
                 (unsigned)s_last_peers_count,
                 (unsigned)nm->n_derp_regions);
        relay_boot_join();
        esp_err_t err = wg_dataplane_start(&s_keys, s_self_addrs, s_self_addrs_count,
                                           s_last_peers, s_last_peers_count);
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
        prepunch_pings_to_peers(s_last_peers, s_last_peers_count);
        return ESP_OK;
    }
    ESP_LOGI(TAG, "netmap (update): peers=%u%s removed=%u patches=%u "
                  "derp_regions=%u table=%u",
             (unsigned)nm->n_peers, nm->peers_is_delta ? " (delta)" : "",
             (unsigned)nm->n_removed, (unsigned)nm->n_patches,
             (unsigned)nm->n_derp_regions, (unsigned)s_last_peers_count);
    if (!peers_changed) return ESP_OK;
    /* Apply the merged table to the data plane: endpoint roam and peer
     * NodeKey/DiscoKey rotation of the WG peer (a removed WG peer leaves
     * the live session alone). Then refresh NAT mappings towards the
     * merged endpoints — idle ages them out (typical UDP timeout
     * 30-120 s) and the peer's first packet after silence would find a
     * closed path and fall back to DERP. ~50-200 bytes per endpoint. */
    esp_err_t err = wg_dataplane_update_peers(&s_keys, s_last_peers, s_last_peers_count);
    prepunch_pings_to_peers(s_last_peers, s_last_peers_count);
    return err;
}

/* RC-2 reconnect backoff. Base is deliberately small so a clean
 * stream-end (server idle/ping-rotation/restart) reconnects promptly
 * instead of leaving the device 30 s without netmap updates; the cap
 * preserves the previous worst-case interval. A stream that stayed up
 * at least HEALTHY_MS counts as a working connection and resets the
 * attempt counter, so only genuine connect failures / instant-drop
 * flapping climb the backoff. */
#define LP_BACKOFF_BASE_MS 1000u
#define LP_BACKOFF_CAP_MS  ((uint32_t)CONFIG_TINYLINK_REGISTER_RETRY_MS)
#define LP_HEALTHY_MS      10000LL
/* After such a stream the redial goes at once (round 1.3.8, C2), the
 * backoff only from its failure on: upstream's mapRoutine resets its
 * backoff with every netmap and then waits n² × 10 ms × [0.5, 1.5] —
 * 5–15 ms — before the next poll; 0.75–1.25 s here was most of the
 * 1.4 s from a stream's end to the next connect's handshake on the 1.3.7
 * sensor (stream end 647.86 s → init sent 649.26 s). */
#define LP_REDIAL_MS       10u

/* Endpoint-push request flag, consumed by long_poll_task right after
 * each control (re)connect. Set from the STUN re-probe path (any task)
 * and from the in-place re-register path below; single consumer. See
 * the "Endpoint push" section further down for the design + history. */
static volatile bool s_ep_push_pending;
static void tinylink_endpoint_push_async(void);

/* Last time any control-plane byte reached us on the map stream. Set
 * from mapreq.c's chunk callback, which runs inside mapreq_run_stream
 * — i.e. in this task's context. Single writer + single reader, no
 * lock. Basis for the wedge-restart last resort below. */
static int64_t s_control_last_rx_us;

void tinylink_control_mark_alive(void)
{
    s_control_last_rx_us = esp_timer_get_time();
}

/* Counters for the /stats snapshot. */
static uint32_t s_stat_lp_reconnects;
static uint32_t s_stat_ep_pushes;

/* A push the server throttled (429 / 503), reset, or left unanswered
 * while the map stream it rides with runs (round 1.3.7 review; one a
 * GOAWAY refused goes with the reconnect, at once). Until
 * 1.3.6 a failed push went again before the next stream, after the
 * server's Retry-After; riding with the stream it would wait for the
 * stream's end — hours on a healthy conn. So: one recycle of the stream
 * after the server's wait (at least EP_PUSH_RETRY_MS), with the push held
 * until then (a reconnect in between runs its stream without it). One
 * per failure streak — a push the retry does not get through goes with
 * the next stream, as does any other refusal (a server that rejects the
 * lite update sees it once per reconnect); a 200 ends the streak. */
#define EP_PUSH_RETRY_MS 30000u

static esp_timer_handle_t s_ep_push_timer;   /* tinylink_long_poll_start */
static volatile bool s_ep_push_waiting;      /* armed: the push is held */
static bool s_ep_push_retried;               /* this streak had its recycle */
static bool s_ep_push_resolved;              /* the stream's push has an outcome */

static void ep_push_timer_cb(void *arg)
{
    (void)arg;
    s_ep_push_waiting = false;
    tinylink_endpoint_push_async();
}

/* mapreq_run_stream's on_push: long-poll task, mid-stream. */
static void ep_push_done(int status, uint32_t wait_ms)
{
    s_ep_push_resolved = true;
    if (status == 200) {
        s_stat_ep_pushes++;
        s_ep_push_retried = false;
        uint8_t  ep_addr[4];
        uint16_t ep_port = 0;
        if (tinylink_get_public_endpoint(ep_addr, &ep_port)) {
            ESP_LOGI(TAG, "endpoint push: pushed %u.%u.%u.%u:%u",
                     ep_addr[0], ep_addr[1], ep_addr[2], ep_addr[3],
                     (unsigned)ep_port);
        }
        return;
    }
    s_ep_push_pending = true;   /* owed — with the next stream at the latest */
    if (status == MAPREQ_PUSH_GOAWAY) {
        /* Not processed and the conn is ending: with the reconnect. */
        ESP_LOGI(TAG, "endpoint push: again with the reconnect");
        return;
    }
    const bool transient = status == 0 || status == 429 || status == 503;
    const char *what = status > 0 ? "refused" : "reset or unanswered";
    const uint32_t ms = wait_ms > EP_PUSH_RETRY_MS ? wait_ms : EP_PUSH_RETRY_MS;
    if (transient && !s_ep_push_retried && s_ep_push_timer != NULL) {
        s_ep_push_waiting = true;
        if (esp_timer_start_once(s_ep_push_timer, (uint64_t)ms * 1000u) == ESP_OK) {
            s_ep_push_retried = true;
            ESP_LOGW(TAG, "endpoint push %s (HTTP %d) — again in %u ms (one "
                          "stream recycle)", what, status, (unsigned)ms);
            return;
        }
        s_ep_push_waiting = false;
    }
    ESP_LOGW(TAG, "endpoint push %s (HTTP %d) — again with the next stream",
             what, status);
}

/* noinline: tools/stack_worst.py takes every function whose address the
 * caller of esp_timer_create takes for a timer callback — inlined into
 * tinylink_long_poll_start, that would be long_poll_task too. */
static __attribute__((noinline)) void ep_push_timer_init(void)
{
    if (s_ep_push_timer != NULL) return;
    const esp_timer_create_args_t ta = { .callback = ep_push_timer_cb,
                                         .name = "ep_push" };
    if (esp_timer_create(&ta, &s_ep_push_timer) != ESP_OK) {
        s_ep_push_timer = NULL;   /* failed pushes go with the next stream */
    }
}

static void long_poll_task(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "long-poll task: starting");
    uint32_t fail_attempt = 0;
    /* Consecutive map cycles the server REJECTED with a non-throttle
     * HTTP 4xx. Distinct from transport failures: a 4xx means the
     * control plane is reachable but no longer accepts our node state
     * (node deleted/expired server-side, control migrated). The
     * upstream client never re-registers from the map loop — it
     * surfaces NeedsLogin to a human. A headless sensor has no human,
     * but it does have the authkey in NVS, so the equivalent recovery
     * is an in-place re-register (the exact path every boot exercises). */
    uint32_t consec_rejected = 0;
    tinylink_control_mark_alive();  /* arm the wedge clock from task start */
    tl_wdt_subscribe();
    for (;;) {
        tl_wdt_feed();
        uint32_t rate_limit_ms = 0;
        int      http_status   = 0;
        bool     redial_now    = false;
        esp_err_t err = ensure_control_conn();
        if (err == ESP_OK) {
            /* Endpoint push (Stream=false lite MapRequest) on the freshly
             * connected s_conn — since round 1.3.7 as a second HTTP/2
             * stream in the same burst as the read-only Stream=true
             * request, not a round trip before it (the boot's push is
             * this one too). This task has the stack the ts2021 path
             * needs; the old dedicated ep_up task did not (see the
             * "Endpoint push" section). Taken now: a request raised
             * during the stream is a new one (and recycles it). Held
             * while a refused push waits for its retry (ep_push_done). */
            const bool push = s_ep_push_pending && !s_ep_push_waiting;
            if (push) s_ep_push_pending = false;
            s_ep_push_resolved = false;
            const int64_t t0 = esp_timer_get_time();
            err = mapreq_run_stream(&s_conn, &s_keys, long_poll_handler, NULL,
                                    push ? ep_push_done : NULL);
            /* Stream ended: either the server closed it (idle / ping
             * failure / restart), our side errored, the push went
             * unanswered within the one-shot deadline, or the handler
             * left an expired-node frame. Capture the rate-limit wait and
             * the HTTP status before drop_control_conn clears the conn. */
            rate_limit_ms = control_rate_limit_ms();
            http_status   = s_conn.h2_status;
            const int64_t up_us = esp_timer_get_time() - t0;
            if (s_ep_push_pending && s_conn.aborted) {
                ESP_LOGI(TAG, "long-poll stream recycled for endpoint push "
                              "(0x%x) — reconnecting", err);
            } else if (s_conn.resp_expired) {
                /* ts2021 has the W line (round 1.3.8, C1) */
                ESP_LOGI(TAG, "long-poll stream recycled (no response) — reconnecting");
            } else {
                ESP_LOGW(TAG, "long-poll stream ended: 0x%x — reconnecting", err);
            }
            if (push && !s_ep_push_resolved) {
                /* Still unanswered when the stream ended or failed (its
                 * deadline before the stream's answer, the conn lost):
                 * again with the next connect's stream, as in 1.3.6. The
                 * other outcomes are ep_push_done's. */
                ESP_LOGW(TAG, "endpoint push unanswered — retrying with the "
                              "next stream");
                s_ep_push_pending = true;
            }
            drop_control_conn();
            s_stat_lp_reconnects++;
            /* The stream was a healthy working connection — recover fast:
             * redial now, the backoff from base if that fails. */
            if (up_us >= LP_HEALTHY_MS * 1000LL) {
                fail_attempt = 0;
                redial_now = true;
            }
        } else {
            ESP_LOGW(TAG, "long-poll connect failed: 0x%x — backing off", err);
        }

        const bool rejected_4xx = (err != ESP_OK &&
                                   http_status >= 400 && http_status < 500 &&
                                   http_status != 429);
        const bool expired = s_self_expired;
        const bool self_live = s_self_live;
        s_self_expired = false;
        s_self_live = false;
        if (rejected_4xx || expired) {
            consec_rejected++;   /* 32-bit: ~4 000 years of 30-s cycles */
            /* Power-of-two schedule (1|2, 4, 8, ... 1024 cycles, then every
             * 1024th) so a control plane that keeps rejecting us isn't
             * hammered with one register per reconnect cycle, yet a
             * transient server-side state loss recovers within a couple
             * of cycles. (It used to saturate at 1024 — a power of two —
             * and then re-register on every cycle.) A self node marked
             * expired/deleted is definitive (headscale sends it once,
             * then ends the stream) → re-register on the first; a bare
             * 4xx may be transient → from the second. */
            const bool due = (consec_rejected <= 1024u)
                ? (consec_rejected & (consec_rejected - 1u)) == 0u
                : (consec_rejected % 1024u) == 0u;
            if (due && (expired || consec_rejected >= 2u)) {
                if (expired) {
                    ESP_LOGW(TAG, "node expired/deleted server-side — "
                                  "re-registering with stored authkey");
                } else {
                    ESP_LOGW(TAG, "map rejected %u consecutive times (HTTP %d) — "
                                  "re-registering with stored authkey",
                             (unsigned)consec_rejected, http_status);
                }
                esp_err_t rr = register_node(true);
                if (rr == ESP_OK) {
                    ESP_LOGI(TAG, "re-register OK — refreshing endpoints");
                    /* Stream=true is read-only server-side; make sure the
                     * fresh node record gets our current endpoint. We ARE
                     * the long-poll task, so just flag it: the next
                     * ensure_control_conn below runs the push. */
                    s_ep_push_pending = true;
                    /* consec_rejected is NOT reset here: only a stream that
                     * delivers a live self node proves the re-register
                     * worked (see s_self_live). */
                } else {
                    ESP_LOGW(TAG, "re-register failed: 0x%x — map retry "
                                  "continues", rr);
                    /* A throttled register paces the next cycle too. */
                    if (s_last_register_wait_ms > rate_limit_ms) {
                        rate_limit_ms = s_last_register_wait_ms;
                    }
                }
            }
        } else if (self_live || err == ESP_OK) {
            /* A cycle that got a live self node (or ran a clean stream)
             * ends the rejection streak; a bare transport failure in
             * between neither extends nor ends it. */
            consec_rejected = 0;
        }

#if CONFIG_TINYLINK_CONTROL_WEDGE_RESTART_S > 0
        /* Last resort: nothing from the control plane for the whole
         * wedge window despite bounded timeouts + reconnects. Restart
         * into the known-good boot path (register + map) rather than
         * stay wedged forever — the failure classes that land here
         * (heap fragmentation starving TLS, lwIP/DNS wedges) all
         * recover with a reboot, and a reboot costs ~30 s of telemetry
         * against an already hour-long control outage. */
        const int64_t silent_us = esp_timer_get_time() - s_control_last_rx_us;
        if (silent_us >
            (int64_t)CONFIG_TINYLINK_CONTROL_WEDGE_RESTART_S * 1000000LL) {
            ESP_LOGE(TAG, "control plane silent for %lu s (limit %d s) — "
                          "restarting as last resort",
                     (unsigned long)(silent_us / 1000000LL),
                     CONFIG_TINYLINK_CONTROL_WEDGE_RESTART_S);
            tinylink_diag_dump_stacks();
            esp_restart();
        }
#endif

        uint32_t delay_ms;
        if (rate_limit_ms > 0) {
            /* Rate limited (429, or 503 + Retry-After): the server's
             * delay replaces our backoff, which — like upstream's — is
             * neither advanced nor reset by it. */
            delay_ms = rate_limit_ms;
            ESP_LOGI(TAG, "long-poll: rate limited by control — waiting %u ms",
                     (unsigned)delay_ms);
        } else if (redial_now) {
            delay_ms = tl_backoff_ms(0, LP_REDIAL_MS, LP_REDIAL_MS, esp_random());
        } else {
            delay_ms = tl_backoff_ms(fail_attempt, LP_BACKOFF_BASE_MS,
                                     LP_BACKOFF_CAP_MS, esp_random());
            if (fail_attempt < 1000u) fail_attempt++;  /* saturate the counter */
        }
        tl_wdt_sleep_ms(delay_ms);   /* Retry-After may be minutes; keep feeding */
    }
}

esp_err_t tinylink_long_poll_start(void)
{
    if (!s_initialized) return ESP_ERR_INVALID_STATE;
    /* The long-poll's first netmap spawns wg_rx: the boot STUN probe
     * must be off the WG socket by then (a no-op after
     * tinylink_dataplane_start, which joins it first). */
    stun_boot_join();
    /* 7 KiB stack (round 1.3.4, D4; 12 KiB since 1.3.3's B18, 24 KiB
     * from #99's revert until then).
     *
     * History: a 20 KiB trim (#99, sized off a 100 s smoke that peaked
     * at 11 040 B) met a 20 004-B lifetime peak ~18 min into a soak and
     * was reverted; the path was never pinpointed and every later trim
     * attempt was blocked on it. tools/stack_worst.py (round 1.3.3, static
     * worst case per task from GCC's -fcallgraph-info=su, the blobs' and
     * the ROM's disassembly, plus 368 B of fixed overhead) found it on
     * that May build: 20 528 B static against 20 004 measured — the LP
     * task's first ts2021 RE-connect (ts2021_connect's 9.9 KB frame →
     * nghttp2_session_recv with a 4 KiB inbound buffer → the Noise record
     * decrypt), which the boot smoke never ran on this task (boot connects
     * on the main task). 92c09dd (connect reuses the idle h2_rx buffer)
     * and 1.3.1's 512-B nghttp2 inbound buffer removed both frames. 1.3.3
     * then had 7 856 B static (map stream → nghttp2 → the record
     * decrypt's 4 144-B frame, `ct[4096]`), 7 284 B measured over the 6-h
     * 1.3.2 soak (the tool is ≥ measured on every task of 1.3.2).
     *
     * Today: D4 decrypts each record in place in h2_rx and seals sends
     * there in ≤ 2 KiB records, so neither `ct` nor the 4 096-B send
     * record is on any stack. Static worst case 4 864 B (1.3.4 with D1,
     * D2, D4: map stream → long_poll_handler → wg_dataplane_start →
     * netif / lwIP → the Wi-Fi TX path → a driver log); a reconnect's
     * TLS handshake reaches 4 672 B, and the recursions the tool costs
     * once stay under it at their bounds (jsmn_skip_d's 65 levels:
     * 3 472 B; the ESP MPI multiply split, ≤ 2 levels deep: 4 832 B).
     * 7 KiB = 2.3 KB over the static worst case. */
    ep_push_timer_init();
    BaseType_t ok = xTaskCreate(long_poll_task, "tinylink_lp",
                                7168, NULL, tskIDLE_PRIORITY + 4, NULL);
    if (ok != pdPASS) {
        ESP_LOGE(TAG, "xTaskCreate(long_poll) failed");
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

bool tinylink_session_up(void)
{
    return wg_netif_is_up();
}

esp_err_t tinylink_time_start(void)
{
    esp_err_t err = tl_time_init();
    esp_err_t serr = tl_time_start_sntp();
    return (err != ESP_OK) ? err : serr;
}

/* Boot counters (/stats, 1.3.2). RTC slow memory survives every reset
 * but a power loss and is never cleared by the startup code; the record
 * validates itself (tl_bootstat.h). Light sleep keeps RTC slow memory
 * powered because it is in use (.rtc.force_slow already was). */
static RTC_NOINIT_ATTR tl_bootstat_t s_bootstat;
static bool                          s_bootstat_done;

_Static_assert(TL_RST_PANIC == ESP_RST_PANIC && TL_RST_INT_WDT == ESP_RST_INT_WDT &&
               TL_RST_TASK_WDT == ESP_RST_TASK_WDT && TL_RST_BROWNOUT == ESP_RST_BROWNOUT,
               "tl_bootstat.h reset-reason values drifted from esp_reset_reason_t");

void tinylink_bootstat_record(void)
{
    if (s_bootstat_done) return;
    s_bootstat_done = true;
    /* The warm-reset TLS sessions' boot sweep (round 1.3.8, tls_rtc.h)
     * belongs here too, before anything can restart: a boot that is not
     * a warm reset must scrub them now. Left to the first TLS connect, a
     * cold boot that never got that far (no Wi-Fi: bringup fails, and 60 s
     * later esp_restart) would hand them to a software-reset boot, which
     * restores — a secret from before an RTC-timer restart, its age
     * counted from that restart (review 138b). */
    tls_resume_boot();
    const bool kept = tl_bootstat_count(&s_bootstat, (int)esp_reset_reason());
    ESP_LOGI(TAG, "boots=%u (brown-out %u, panic %u, task WDT %u, int WDT %u)%s",
             (unsigned)s_bootstat.boots, (unsigned)s_bootstat.brownout,
             (unsigned)s_bootstat.panic, (unsigned)s_bootstat.task_wdt,
             (unsigned)s_bootstat.int_wdt,
             kept ? "" : " — RTC record restarted");
}

void tinylink_get_stats(tinylink_stats_t *out)
{
    if (out == NULL) return;
    tinylink_bootstat_record();
    memset(out, 0, sizeof(*out));
    const int64_t now = esp_timer_get_time();
    out->uptime_s     = (uint32_t)(now / 1000000LL);
    out->reset_reason = (int)esp_reset_reason();
    out->boots          = s_bootstat.boots;
    out->boots_brownout = s_bootstat.brownout;
    out->boots_panic    = s_bootstat.panic;
    out->boots_task_wdt = s_bootstat.task_wdt;
    out->boots_int_wdt  = s_bootstat.int_wdt;
    out->heap_free    = (uint32_t)esp_get_free_heap_size();
    out->heap_min     = (uint32_t)esp_get_minimum_free_heap_size();
    out->heap_largest = (uint32_t)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT);
    out->ntp_synced   = tl_time_synced();
    out->control_open = s_conn_open;
    out->control_alive_age_s =
        (uint32_t)((now - s_control_last_rx_us) / 1000000LL);
    out->control_reconnects = s_stat_lp_reconnects;
    out->endpoint_pushes    = s_stat_ep_pushes;
#if CONFIG_TINYLINK_DERP_SUPERVISED
    out->derp_connected = derp_client_is_connected(&s_derp_sup);
    tl_derp_addr_t node;
    home_derp_get(&node, NULL);
    _Static_assert(sizeof(out->derp_host) == sizeof(node.host), "derp_host size");
    memcpy(out->derp_host, node.host, sizeof(out->derp_host));
#endif
    out->public_valid = tinylink_get_public_endpoint(out->public_v4, &out->public_port);
    wg_netif_stats_t ws;
    wg_netif_get_stats(&ws);
    out->wg_state           = ws.state;
    out->wg_rekeys          = ws.rekeys;
    out->wg_cold_handshakes = ws.cold_handshakes;
    out->wg_rx_stale_events = ws.rx_stale_events;
    out->wg_roams           = ws.roams;
    out->wg_disco_adverts   = ws.disco_adverts;
    out->wg_tx_drops        = (uint32_t)ws.tx_drops;
    out->wg_relayed_stale   = (uint32_t)ws.relayed_stale;
    out->wg_relay_errors    = (uint32_t)ws.relay_errors;
    out->wg_path            = ws.path_mode;
    out->wg_path_lapses     = ws.path_lapses;
    out->wg_last_rx_age_s   = ws.last_transport_recv_us > 0
        ? (uint32_t)((now - ws.last_transport_recv_us) / 1000000LL) : 0u;
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

    /* Wire DERP TX relay as the wg_netif TX-worker fallback. The
     * callback short-circuits to ESP_ERR_INVALID_STATE when the
     * supervisor isn't yet connected, so registering this BEFORE
     * tinylink_derp_supervised_start has spawned the supervisor task
     * is safe — the TX worker will just continue with direct sendto.
     * Once the supervisor's login completes (at boot, alongside the
     * register, since round 1.3.5), the callback starts accepting WG
     * frames — the first INIT's DERP copy included — and the TX
     * worker switches transports when the path-stale watchdog or
     * sendto errno indicates direct UDP is broken. */
#if CONFIG_TINYLINK_DERP_SUPERVISED
    wg_netif_set_relay_callback(tinylink_relay_via_derp, NULL);
    wg_netif_set_relay_state_callback(relay_connected, NULL);
#endif

    return ESP_OK;
}

/* --- Endpoint push (post-boot endpoint changes) ----------------------
 *
 * After a STUN re-probe finds a new public AddrPort we must tell the
 * control plane via a Stream=false MapRequest — the long-poll's
 * Stream=true cycle is read-only server-side (tailcfg.go:1408+1436).
 *
 * History. The 2026-05 design ran the push on a dedicated persistent
 * task ("tinylink_ep_up", 12 KiB static stack in BSS) that opened its
 * OWN ts2021 conn: `ts2021_conn_t conn` as a stack local (8 648 B) and
 * then ts2021_connect (9 888 B frame) → recv_record_plaintext (4 176 B)
 * → the mbedTLS handshake (~5 KiB). That chain needs ~28 KiB; the
 * long-poll task, which runs the SAME chain without the local conn,
 * measured a 20 KiB lifetime peak (PR #103). The 12 KiB task therefore
 * overflowed its static stack by ~16 KiB on every real push, straight
 * into the BSS neighbours below it (the DERP frame buffer, FreeRTOS
 * ready lists, WiFi driver tables). It only appeared to work because
 * the path runs solely on NAT rebind / WiFi re-association /
 * re-register — and the one soak that forced a rebind (PR #102,
 * 2026-05-13) panicked with an InstructionFetchError at a DRAM PC, the
 * signature of exactly this overflow, attributed at the time to a 1 KiB
 * stack trim. Verified 2026-09 from the compiled `entry` frame sizes
 * (objdump of the release objects) and -fstack-usage.
 *
 * Now: the push runs on the long-poll task, on s_conn, right after the
 * (re)connect — since round 1.3.7 as a second HTTP/2 stream in the same
 * burst as the map stream (mapreq_run_stream; the boot's push is the
 * first one). tinylink_endpoint_push_async()
 * records the request and kicks the long-poll out of its blocking
 * stream read (ts2021_abort_reads); the reconnect then follows the
 * normal healthy-stream backoff (~1 s), so a push lands within one 30 s
 * socket poll + one Noise handshake. That latency is fine: the direct
 * path recovers via DISCO regardless (RX-stale probe + roaming); the
 * control-plane endpoint refresh is what lets PEERS initiate towards
 * us. Cost vs the old design: one extra control reconnect per endpoint
 * change (rare), in exchange for −12.6 KiB of BSS (stack + TCB), no
 * second Noise/TLS conn (−8.6 KiB peak stack, ~−12 KiB TLS heap
 * transient) and no overflow. Upstream sends its lite update over the
 * shared HTTP/2 client (controlclient.Auto.updateRoutine) while the
 * poll runs; tinylink's opens its side stream only together with a map
 * stream (the long-poll task sits in the stream's read loop), so a push
 * after the boot still recycles the stream. */

/* Signal that the public endpoint changed. Idempotent; callable from
 * any task (STUN re-probe on the telemetry task, event handlers). */
static void tinylink_endpoint_push_async(void)
{
    s_ep_push_pending = true;
    if (s_ep_push_waiting) {
        /* A throttled push's retry is armed (ep_push_done): it recycles
         * the stream when the server's wait is over, this one with it. */
        ESP_LOGI(TAG, "endpoint push: queued — after the server's wait");
    } else if (s_conn_open) {
        ESP_LOGI(TAG, "endpoint push: queued — recycling the map stream");
        ts2021_abort_reads();
    } else {
        ESP_LOGI(TAG, "endpoint push: queued — runs on the next control connect");
    }
}

/* Answer budget of one STUN probe (boot or re-probe). Generous — Google
 * STUN answers the sensor in ~40 ms; a dead server costs this much. */
#define STUN_PROBE_TIMEOUT_MS 3000

/* Where a STUN probe goes (round 1.3.5): the home DERP node's STUN
 * service (UDP 3478, tailcfg STUNPort) at the address the DERP map gave
 * — no DNS, and the server netcheck itself asks — else
 * CONFIG_TINYLINK_STUN_HOST, resolved: when no record has the address
 * yet (the first boot with 1.3.5, a map without IPv4) or the last probe
 * to the DERP node went unanswered (UDP 3478 filtered on the way?). An
 * unanswered probe sends the next one to the other server and an answer
 * keeps it, so both probes stay on one server — on a NAT whose mapping
 * depends on the destination, switching servers would read as an
 * endpoint change and push it (a control-stream recycle). The boot task
 * and then the telemetry task use it; an abandoned boot probe can still
 * be finishing during the first re-probe, which at worst sends one probe
 * to the other server. */
static volatile bool s_stun_use_kconfig;

static esp_err_t stun_server_pick(struct sockaddr_in *out, bool *derp)
{
    tl_derp_addr_t node;
    home_derp_get(&node, NULL);
    uint8_t  ip[4];
    uint16_t port = 0;
    *derp = !s_stun_use_kconfig && tl_derp_addr_stun(&node, ip, &port);
    if (*derp) {
        memset(out, 0, sizeof(*out));
        out->sin_family = AF_INET;
        out->sin_port   = htons(port);
        memcpy(&out->sin_addr.s_addr, ip, sizeof(ip));
        return ESP_OK;
    }
    return stun_probe_resolve(CONFIG_TINYLINK_STUN_HOST,
                              (uint16_t)CONFIG_TINYLINK_STUN_PORT, out);
}

static void stun_server_note(bool derp, bool answered)
{
    /* answered: stay on this server; unanswered: the other one next. A
     * first boot thus stays on the Kconfig server after its boot probe
     * answered, even once the netmap gives the DERP node's address. */
    s_stun_use_kconfig = answered ? !derp : derp;
}

/* --- STUN reprobe via the live WG socket -------------------------------
 *
 * Once rx_task owns g.sock, we cannot recvfrom on it from another task
 * without racing. The legacy reprobe path opened an ephemeral socket,
 * which works but its source port is NOT the WG socket's, so the
 * AddrPort the STUN server learns can't be advertised back to peers.
 *
 * Option B: split send/receive across the existing tasks.
 *   - The re-probe (telemetry task) `sendto`s the STUN binding request
 *     directly on g.sock (sendto is thread-safe in lwIP, no ownership
 *     transfer).
 *   - rx_task already classifies WG_DEMUX_STUN; we hook it via
 *     wg_netif_set_stun_callback() to a parser that matches the
 *     in-flight txid and signals a semaphore.
 *   - The re-probe waits on that semaphore with a 3 s timeout.
 *
 * No race: rx_task remains the only recvfrom-er. No data loss: rx_task
 * keeps dispatching DISCO/transport packets normally; STUN is just
 * routed to a new arm.
 *
 * The pending-probe slot (s_stun_pending) is single-writer (the re-probe
 * on the telemetry task) and single-reader (the rx_task callback runs on
 * rx_task); concurrent probes are not possible because the re-probe
 * takes a mutex around the entire build/sendto/wait sequence. */
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
    /* Malformed / not-success / no-mapped-addr, a stale probe's txid or
     * a v6 answer: let it slide; the re-probe times out and tries again
     * next cycle. */
    if (stun_match_v4(buf, len, s_stun_pending.txid,
                      s_stun_pending.result.addr_v4,
                      &s_stun_pending.result.port) != 0) {
        return;
    }
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

    /* The home DERP node's STUN, or the Kconfig server resolved (lwIP
     * getaddrinfo can block — the re-probe on the telemetry task
     * (IDLE+2) is the only caller, so a synchronous DNS lookup here is
     * safe). */
    struct sockaddr_in dest;
    bool derp = false;
    if (stun_server_pick(&dest, &derp) != ESP_OK) {
        stun_server_note(false, false);
        return ESP_FAIL;
    }

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
    stun_server_note(derp, err == ESP_OK);
    return err;
}

esp_err_t tinylink_stun_probe(void)
{
    /* Probe into a LOCAL result first, only commit to the cached
     * global on success. This way a transient probe failure (DNS
     * blip, NAT dropping our send, etc.) does NOT wipe a previously
     * good endpoint — the next MapRequest keeps advertising the
     * old-but-still-correct value. */
    stun_probe_result_t local = {0};

    /* Only through wg_rx: RX task owns g.sock, so we send the STUN
     * request via sendto (thread-safe in lwIP) and let rx_task dispatch
     * the response back to us via the wg_netif_set_stun_callback hook.
     * The result's source-port is the WG socket's bound port, so a port
     * change between boot and now can be propagated to the control
     * plane. Before wg_rx exists the boot probe reads the socket itself
     * (tinylink_stun_probe_start, stun_boot.h) and nothing else may. */
    if (!wg_netif_rx_running()) return ESP_ERR_INVALID_STATE;
    esp_err_t err = stun_reprobe_via_wg_socket(STUN_PROBE_TIMEOUT_MS, &local);
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
            /* Push the new endpoint to the control plane. Only flagged
             * here: the push itself runs on the long-poll task after its
             * next (re)connect (tinylink_endpoint_push_async). */
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

/* Periodic STUN re-probe (since 1.3.2 on the telemetry task — telemetry.c
 * calls tinylink_stun_reprobe_poll once per loop; it had its own 3 KiB
 * task, "tinylink_stun_re", before). Armed by tinylink_stun_reprobe_start;
 * the first re-probe is due one period later, because the boot probe
 * (tinylink_stun_probe_start) ran just before — at once when it gave the
 * endpoint push nothing (stun_boot_join). Volatile: the long-poll can
 * spawn the telemetry task (first netmap) before main arms this, so the
 * task may poll concurrently; due_us is stored before armed. */
static volatile bool    s_stun_reprobe_armed;
static volatile int64_t s_stun_reprobe_due_us;
/* ROAM-2: set by the IP_EVENT_STA_GOT_IP handler when the device's own
 * L3 identity changes (WiFi (re)connect / DHCP renew) so the next poll
 * re-probes at once instead of at the period. Without it a local network
 * change left the STUN-learned public AddrPort — and the endpoint
 * advertised to peers — stale for up to CONFIG_TINYLINK_STUN_REPROBE_MS
 * (5 min). Mirrors magicsock's netmon linkChange → Rebind+ReSTUN. */
static volatile bool    s_stun_reprobe_now;

static void stun_reprobe_on_got_ip(void *arg, esp_event_base_t base,
                                   int32_t id, void *data)
{
    (void)arg; (void)base; (void)id;
    /* Several GOT_IP events before the poll runs collapse into one
     * immediate re-probe. The kick wakes the telemetry task right away
     * while it is not serving /stats (before the WG netif is up, or a
     * build without it); a /stats select() takes it within one ≤ 5-s
     * wait slice (≤ 6 s when a sample stretches it, telemetry.c). */
    s_stun_reprobe_now = true;
    telemetry_kick();
    /* A new L3 identity (DHCP handed us a different address after a
     * re-association) leaves the control and DERP TCP conns half-open:
     * their packets now leave from an address the servers never saw, so
     * nothing comes back and they only die on the 120-s idle budget.
     * Recycle both right away (2026-09). The endpoint push that the
     * re-probe queues normally rides the same reconnect: the control
     * read only sees the abort at its next 30-s SO_RCVTIMEO boundary,
     * and the reconnect adds ~1 s backoff + the TLS/Noise handshake on
     * top. If that boundary falls in the first second or so, the push
     * costs one more recycle — still correct, just later. */
    const ip_event_got_ip_t *ev = (const ip_event_got_ip_t *)data;
    if (ev != NULL && ev->ip_changed) {
        ESP_LOGI(TAG, "ip changed — recycling control + DERP conns");
        ts2021_abort_reads();
#if CONFIG_TINYLINK_DERP_SUPERVISED
        s_derp_sup.abort_reads = true;
#endif
    }
}

int64_t tinylink_stun_reprobe_poll(int64_t now_us, int64_t early_us)
{
    if (!s_stun_reprobe_armed) return INT64_MAX;
    /* Up to early_us ahead of time: the telemetry task is awake for a
     * sample then (round 1.3.7, tlm_sched.h). */
    if (!s_stun_reprobe_now && now_us + early_us < s_stun_reprobe_due_us) {
        return s_stun_reprobe_due_us;
    }
    /* A re-probe goes through wg_rx (tinylink_stun_probe), which the
     * first netmap starts. A request before that — the boot probe's
     * "push it later" (stun_boot_join), a GOT_IP — waits for it in 1-s
     * steps instead of being spent on a refused probe and pushed a whole
     * period out. */
    if (!wg_netif_rx_running()) return now_us + 1000000LL;
    s_stun_reprobe_now = false;
    /* Blocks for one STUN round trip normally; worst case ≈ 24 s (lwIP
     * DNS: 1+1+2+3 s × 3 servers, then the 3-s response wait) — inside
     * the 60-s task-WDT budget with a feed on each side. */
    tl_wdt_feed();
    esp_err_t err = tinylink_stun_probe();
    tl_wdt_feed();
    if (err != ESP_OK) {
        /* Don't escalate: the cached value (if any) is still in
         * use. ESP_LOGD instead of W to avoid spamming the log
         * when, e.g., the user briefly loses internet. */
        ESP_LOGD(TAG, "stun re-probe transient failure: 0x%x", err);
    }
    /* Next one a full period after this probe ended, like the old task's
     * take-with-timeout loop. */
    s_stun_reprobe_due_us = esp_timer_get_time() +
                            (int64_t)CONFIG_TINYLINK_STUN_REPROBE_MS * 1000LL;
    return s_stun_reprobe_due_us;
}

esp_err_t tinylink_stun_reprobe_start(void)
{
    /* ROAM-2: subscribe to local IP changes. The esp_event default loop
     * is already created by app_wifi_start(). Idempotent. */
    if (!s_stun_reprobe_armed) {
        s_stun_reprobe_due_us = esp_timer_get_time() +
                                (int64_t)CONFIG_TINYLINK_STUN_REPROBE_MS * 1000LL;
        s_stun_reprobe_armed = true;
        esp_err_t eerr = esp_event_handler_instance_register(
            IP_EVENT, IP_EVENT_STA_GOT_IP, &stun_reprobe_on_got_ip, NULL, NULL);
        if (eerr != ESP_OK) {
            ESP_LOGW(TAG, "stun_reprobe: GOT_IP subscribe failed: 0x%x "
                          "— falling back to periodic-only reprobe", eerr);
        }
    }
    /* The probes run on the telemetry task, which exists in every build
     * (with CONFIG_TINYLINK_TELEMETRY_ENABLE=n it only does this and the
     * 60-s housekeeping). Spawn it now, where the re-probe task used to
     * be spawned; a NO_MEM spawn is retried every 30 s inside, and
     * ESP_OK means the re-probe loop *will* run. */
    return telemetry_task_start();
}

/* --- Boot STUN probe, concurrent with the register (round 1.3.5) ------
 *
 * 1.3.4 probed on the main task between the WG socket bind and the
 * register: got-ip → "public endpoint" took 0.04 / 0.34 / 2.10 / 7.09 s
 * over four boots of the 1.3.4 reboot series, every millisecond of it
 * ahead of the register. Only the endpoint push after the register uses
 * the result, so the probe now runs on a short-lived task while the
 * register runs (≥ 2.4 s on the sensor), and tinylink_dataplane_start
 * waits at most STUN_BOOT_WAIT_MS for it. A later probe is abandoned and
 * the push goes without an endpoint — the old probe-failure outcome —
 * and the re-probe then runs as soon as wg_rx exists and pushes the
 * endpoint through tinylink_endpoint_push_async (a control-stream
 * recycle after the first netmap, off the boot path). A failed probe
 * takes the same way: before 1.3.5 it left the endpoint unadvertised
 * until the first periodic re-probe, 5 min later.
 *
 * Socket ownership is in stun_boot.h: until wg_rx exists the probe reads
 * the WG socket itself, blocking only in select() and reading with
 * MSG_DONTWAIT under s_stun_boot_mx, which the give-up takes too — so
 * the give-up never waits on a blocked read, and from then on the probe
 * neither reads nor publishes. */

/* After the register: how long the endpoint push waits for the probe.
 * With the home DERP node's address cached (round 1.3.5, the normal
 * boot) the probe needs no DNS: its request leaves right after the WG
 * socket bind and the answer is one RTT away, while the register over
 * :80 answers ~0.7 s after got-ip — so the probe has normally finished
 * when this wait starts (no "waited" line). What 300 ms still covers: an
 * answer to the 500-ms retransmission on a fast register, and a cold
 * boot (no record yet: CONFIG_TINYLINK_STUN_HOST through DNS, which on
 * the sensor's network lost answers in 12 of 30 boots — lwIP resends
 * after 1, 2, 4, 7 s — and those probes are abandoned, as in 1.3.5
 * before the cache). Raising it would only buy those tails back on the
 * boot path. */
#define STUN_BOOT_WAIT_MS  300

/* One select() of the probe at most: how late an abandoned probe
 * notices (it holds nothing meanwhile) and its task-WDT feed cadence. */
#define STUN_BOOT_SLICE_MS 100

/* Retransmissions of the boot request (RFC 5389 §7.2.1: RTO 500 ms,
 * doubling) inside the STUN_PROBE_TIMEOUT_MS answer budget, same txid —
 * a lost request or answer used to cost the whole budget and the
 * endpoint (one send, then a 3-s wait). */
static const uint16_t k_stun_boot_resend_ms[] = { 500, 1500 };

/* getaddrinfo + the select / sendto / recvfrom exchange on a UDP-only
 * task: tools/stack_worst.py puts the static worst case at 3 616 B
 * (stun_boot_exchange's 432-B frame → sendto → UDP / IP → the Wi-Fi TX
 * path → a driver log; the DNS lookup reaches 3 232 B). 5 KiB = 1.5 KB
 * over it. The task lives for one probe — 0.04–3 s, up to ~27 s with
 * dead DNS servers — and its stack goes back to the heap. */
#define STUN_BOOT_TASK_STACK 5120

static SemaphoreHandle_t s_stun_boot_mx;     /* s_stun_boot + the socket reads */
static stun_boot_state_t s_stun_boot;        /* under s_stun_boot_mx once the task runs */
static SemaphoreHandle_t s_stun_boot_done;   /* main task only: the joiner's handle */
static bool              s_stun_boot_joined; /* main task only */

/* Send the binding request (and its retransmissions) to `server` and
 * read the WG socket for the answer while the probe is its reader.
 * Publishes s_stun_result on a match. */
static esp_err_t stun_boot_exchange(int sock, const struct sockaddr_in *server)
{
    uint8_t txid[STUN_TXID_LEN];
    uint8_t req[STUN_REQUEST_LEN];
    esp_fill_random(txid, sizeof(txid));
    if (stun_build_request(req, txid) != STUN_REQUEST_LEN) return ESP_FAIL;

    const size_t  n_resend = sizeof(k_stun_boot_resend_ms) / sizeof(k_stun_boot_resend_ms[0]);
    const int64_t t0       = esp_timer_get_time();
    const int64_t deadline = t0 + (int64_t)STUN_PROBE_TIMEOUT_MS * 1000LL;
    size_t sends = 0;
    /* An answer is 32–100 B; a bigger datagram is not ours anyway. */
    uint8_t buf[256];
    for (;;) {
        const int64_t now = esp_timer_get_time();
        if (now >= deadline) return ESP_ERR_TIMEOUT;
        if (sends == 0 ||
            (sends <= n_resend &&
             now - t0 >= (int64_t)k_stun_boot_resend_ms[sends - 1] * 1000LL)) {
            if (sendto(sock, req, sizeof(req), 0, (const struct sockaddr *)server,
                       sizeof(*server)) != (ssize_t)sizeof(req)) {
                ESP_LOGW(TAG, "stun probe: sendto errno=%d", errno);
            }
            sends++;
        }
        int64_t wake = now + (int64_t)STUN_BOOT_SLICE_MS * 1000LL;
        if (sends <= n_resend) {
            const int64_t resend = t0 + (int64_t)k_stun_boot_resend_ms[sends - 1] * 1000LL;
            if (resend < wake) wake = resend;
        }
        if (deadline < wake) wake = deadline;
        struct timeval tv = { .tv_sec = 0, .tv_usec = (suseconds_t)(wake - now) };
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        const int sel = select(sock + 1, &rfds, NULL, NULL, &tv);
        tl_wdt_feed();
        if (sel < 0) {
            ESP_LOGW(TAG, "stun probe: select errno=%d", errno);
            return ESP_FAIL;
        }
        if (sel == 0) continue;

        bool reader, matched = false;
        stun_probe_result_t r = { .valid = true };
        xSemaphoreTake(s_stun_boot_mx, portMAX_DELAY);
        reader = stun_boot_may_read(&s_stun_boot);
        if (reader) {
            const ssize_t n = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT, NULL, NULL);
            if (n > 0 && stun_match_v4(buf, (size_t)n, txid, r.addr_v4, &r.port) == 0 &&
                stun_boot_publish(&s_stun_boot)) {
                s_stun_result = r;
                matched = true;
            }
        }
        xSemaphoreGive(s_stun_boot_mx);
        if (!reader) return ESP_ERR_TIMEOUT;   /* given up on; wg_rx may be next */
        if (matched) {
            ESP_LOGI("stun_probe", "public endpoint: %u.%u.%u.%u:%u (%u ms, %u sent)",
                     r.addr_v4[0], r.addr_v4[1], r.addr_v4[2], r.addr_v4[3],
                     (unsigned)r.port,
                     (unsigned)((esp_timer_get_time() - t0) / 1000), (unsigned)sends);
            return ESP_OK;
        }
        /* Anything else on the socket predates the netmap and wg_rx —
         * nothing is configured to take it yet: dropped, as before. */
    }
}

/* The probe: the server (the home DERP node's STUN at its cached
 * address, else DNS — stun_server_pick), then the exchange while still
 * wanted. Runs on the boot task, or inline on main if that could not be
 * spawned. */
static void stun_boot_run(SemaphoreHandle_t done)
{
    struct sockaddr_in server;
    bool derp = false;
    esp_err_t err = stun_server_pick(&server, &derp);
    tl_wdt_feed();
    if (derp) {
        const uint8_t *ip = (const uint8_t *)&server.sin_addr.s_addr;
        ESP_LOGI(TAG, "stun probe: home DERP node at %u.%u.%u.%u:%u (no DNS)",
                 ip[0], ip[1], ip[2], ip[3], (unsigned)ntohs(server.sin_port));
    }
    if (err == ESP_OK) {
        xSemaphoreTake(s_stun_boot_mx, portMAX_DELAY);
        const bool mine = stun_boot_claim(&s_stun_boot);
        xSemaphoreGive(s_stun_boot_mx);
        err = mine ? stun_boot_exchange(wg_netif_get_socket(), &server)
                   : ESP_ERR_TIMEOUT;
    }
    /* Abandoned counts as unanswered: the re-probe then asks the other
     * server once wg_rx runs. */
    stun_server_note(derp, err == ESP_OK);
    xSemaphoreTake(s_stun_boot_mx, portMAX_DELAY);
    const bool awaited = stun_boot_finish(&s_stun_boot);
    xSemaphoreGive(s_stun_boot_mx);
    if (!awaited) {
        /* The push went without us (stun_boot_join logged it) and
         * nobody takes the signal any more. */
        vSemaphoreDelete(done);
        return;
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "stun probe failed: 0x%x — continuing without endpoint", err);
    }
    xSemaphoreGive(done);
}

static void stun_boot_task(void *arg)
{
    tl_wdt_subscribe();
    stun_boot_run((SemaphoreHandle_t)arg);
    tl_wdt_unsubscribe();
    vTaskDelete(NULL);
}

esp_err_t tinylink_stun_probe_start(void)
{
    if (!s_initialized || wg_netif_get_socket() < 0 || wg_netif_rx_running() ||
        s_stun_boot != STUN_BOOT_IDLE) {
        return ESP_ERR_INVALID_STATE;
    }
    if (s_stun_boot_mx == NULL) s_stun_boot_mx = xSemaphoreCreateMutex();
    SemaphoreHandle_t done = xSemaphoreCreateBinary();
    if (s_stun_boot_mx == NULL || done == NULL) {
        if (done != NULL) vSemaphoreDelete(done);
        return ESP_ERR_NO_MEM;   /* no probe: the push goes without one */
    }
    s_stun_boot      = STUN_BOOT_RESOLVING;
    s_stun_boot_done = done;
    /* IDLE+2: above main (1), whose register TLS handshake would
     * otherwise hold it off CPU0 while the DERP one (IDLE+3) has CPU1. */
    if (xTaskCreate(stun_boot_task, "tinylink_stun", STUN_BOOT_TASK_STACK,
                    done, tskIDLE_PRIORITY + 2, NULL) != pdPASS) {
        ESP_LOGW(TAG, "stun probe: task spawn failed — probing inline");
        stun_boot_run(done);   /* the 1.3.4 order; stun_boot_join finds it done */
    }
    return ESP_OK;
}

/* Called first by tinylink_dataplane_start (and again, a no-op, by
 * tinylink_long_poll_start, the only way to wg_rx): once it returns the
 * boot probe never reads the WG socket again. Main task only. */
static void stun_boot_join(void)
{
    if (s_stun_boot_joined) return;
    s_stun_boot_joined = true;
    SemaphoreHandle_t done = s_stun_boot_done;
    s_stun_boot_done = NULL;
    if (done != NULL) {
        const int64_t t0 = esp_timer_get_time();
        bool finished = xSemaphoreTake(done, pdMS_TO_TICKS(STUN_BOOT_WAIT_MS)) == pdTRUE;
        if (!finished) {
            xSemaphoreTake(s_stun_boot_mx, portMAX_DELAY);
            finished = stun_boot_give_up(&s_stun_boot);
            xSemaphoreGive(s_stun_boot_mx);
            /* Finished just now: its signal follows its finish at once. */
            if (finished) (void)xSemaphoreTake(done, portMAX_DELAY);
        }
        const unsigned waited_ms = (unsigned)((esp_timer_get_time() - t0) / 1000);
        if (finished) {
            vSemaphoreDelete(done);
            if (waited_ms > 0) {
                ESP_LOGI(TAG, "dataplane_start: waited %u ms for the STUN probe",
                         waited_ms);
            }
        } else {
            /* The task frees `done` when it ends. */
            ESP_LOGW(TAG, "stun probe: still running %u ms after the "
                          "register — abandoned", waited_ms);
        }
    }
    if (!s_stun_result.valid) {
        s_stun_reprobe_now = true;
        ESP_LOGI(TAG, "stun: no endpoint for the push — re-probing once the "
                      "data plane is up");
    }
}
