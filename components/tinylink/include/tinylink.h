// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TINYLINK_VERSION_MAJOR 1
#define TINYLINK_VERSION_MINOR 3
#define TINYLINK_VERSION_PATCH 7

/* String forms derived from the integer components above so a future
 * bump only touches the three #defines. Adjacent-string-literal
 * concatenation lets these be used inside printf-style format strings
 * too (see mapreq.c HostInfo template).
 *
 * Control-plane side effect: tailscale derives `tsReleaseTrack` from
 * the MINOR component via `version.IsUnstableBuild` in
 * tailscale/version/prop.go — minor%2==1 → unstable, even → stable. So
 * a MINOR bump 1→0 (or any even value) flips the admin panel from
 * "unstable" to "stable" automatically. Release line (owner, 2026-10):
 * 1.3.x is the work line (upstream sync + optimization rounds, shown as
 * unstable on purpose), 1.4.0 the next stable release. */
#define TINYLINK_STR_HELPER(x) #x
#define TINYLINK_STR(x) TINYLINK_STR_HELPER(x)
#define TINYLINK_VERSION_STRING                                         \
    TINYLINK_STR(TINYLINK_VERSION_MAJOR) "."                            \
    TINYLINK_STR(TINYLINK_VERSION_MINOR) "."                            \
    TINYLINK_STR(TINYLINK_VERSION_PATCH)
#define TINYLINK_IPN_VERSION TINYLINK_VERSION_STRING "-tinylink"

/* tailcfg.CurrentCapabilityVersion advertised to the control plane.
 * SINGLE SOURCE OF TRUTH — every place that announces our capability
 * version derives it from this macro so the four wire sites can never
 * silently diverge:
 *   1. ts2021 Noise initiation: BE16 header field + prologue string
 *      (ts2021_client.h TS2021_PROTOCOL_VERSION). This is the gate
 *      headscale enforces FIRST, in earlyNoise, before any JSON is
 *      read — a value below its MinSupportedCapabilityVersion aborts
 *      the /ts2021 upgrade outright.
 *   2. RegisterRequest.Version  (register.c)
 *   3. MapRequest.Version       (mapreq.c)
 *   4. GET /key?v=<n>            (control_key.c) — since 2026-09; headscale
 *      5b6e1e17 gates /key on the same floor as the Noise handshake, so
 *      the old fixed "v=100" now gets a 400 there.
 *
 * Floor check (verify on every upstream-audit round): headscale main
 * enforces MinSupportedCapabilityVersion = 116 (= Tailscale v1.84) as of
 * 2d220b2e (audit 2026-10-28; 0.29.x releases still enforce 113; the
 * floor is "latest 10 minor versions" and moves with every capver regen)
 * and has no upper bound. Its capver table maps up to 148 (= v1.104).
 *
 * Value policy (owner): claim only a capver that maps to an even-minor
 * (stable) Tailscale release, never a sentinel from an odd -pre line.
 * 148 = v1.104 since round 1.3.0 (2026-10-28), every step honoured:
 *   143  control stops sending conn25 attrs below it — nothing to do
 *        (CapMap / DNSConfig are skipped);
 *   144  client SENDS a TSMPDiscoKeyAdvertisement on every new keypair —
 *        implemented (wg_netif.c send_disco_advert, tsmp.h);
 *   145  macOS quad-100 DNS scoping — n/a;
 *   146  debug-conn-reject attr + c2n /debug/rejects: a local aggregator
 *        only, nothing to enforce; c2n is ignored like 127/128/138/142;
 *   147  Retry-After on /machine/register + /machine/map with upstream's
 *        exact rules (h2_retry_after.h);
 *   148  Node.StableTailnetID — an unknown key, skipped.
 * 149 (upstream CurrentCapabilityVersion as of f7c1b8e52, a sentinel
 * asking control to enable cache-network-maps on the odd 1.105-pre line)
 * is not claimed. Peers only gate on a remote's capver ≥ 121 (relay) and
 * ≥ 26 (DNS proxy). Bumping the value changes the Noise prologue hash,
 * so every bump requires a hardware A/B smoke against the live control
 * plane per the repo's verify-regression rule. */
#define TINYLINK_CAPVER 148

#define TINYLINK_KEY_LEN 32

/* The three Curve25519 identities a Tailscale node carries. They are
 * persisted in the encrypted NVS namespace "tl_keys" so they survive
 * reboots and re-authentications. */
typedef struct {
    uint8_t machine_priv[TINYLINK_KEY_LEN]; /* ts2021 Noise IK static (M1)  */
    uint8_t machine_pub[TINYLINK_KEY_LEN];
    uint8_t node_priv[TINYLINK_KEY_LEN];    /* WireGuard static (M2+)       */
    uint8_t node_pub[TINYLINK_KEY_LEN];
    uint8_t disco_priv[TINYLINK_KEY_LEN];   /* DISCO box (M3+)              */
    uint8_t disco_pub[TINYLINK_KEY_LEN];
} tinylink_keys_t;

/* One-time setup: load or generate node identities, fetch + pin the control
 * plane public key. Must be called after WiFi is up so that:
 *   1. esp_random() / esp_fill_random() return CSPRNG output (the RF
 *      subsystem seeds the entropy pool).
 *   2. DNS/TLS to controlplane.tailscale.com is reachable.
 */
/* Optional, before tinylink_init (round 1.3.7): load the identity keys
 * and, with a control key pinned in NVS, precompute the first control
 * connect's Noise IK DH work — CPU only, no network, so it can run while
 * Wi-Fi associates instead of after got-ip (~75 ms of X25519 off the
 * boot path). Only once the radio is on (after esp_wifi_start): a
 * missing key is generated here and the ephemeral is drawn, and
 * esp_fill_random is a true RNG only with RF enabled (point 1 below).
 * tinylink_init does whatever this did not. */
esp_err_t tinylink_preload(void);

esp_err_t tinylink_init(void);

/* Floor the wall clock (build time / last NTP sync persisted in NVS)
 * and start SNTP. Call once WiFi has an address and BEFORE
 * tinylink_init(): the TLS clients enforce certificate validity dates
 * as soon as the first sync lands, and tolerate them until then. */
esp_err_t tinylink_time_start(void);

/* Read-only runtime snapshot, served as JSON by the telemetry task's
 * /stats responder (CONFIG_TINYLINK_STATS_PORT) and usable from any
 * task. All counters are since boot, except boots*. */
typedef struct {
    uint32_t uptime_s;
    int      reset_reason;           /* esp_reset_reason_t of this boot */
    /* Boot counters (RTC no-init memory, tl_bootstat.h): boots since the
     * record last restarted — normally the last power-on — this one
     * included, and how many followed each kind of reset. */
    uint32_t boots;
    uint32_t boots_brownout;
    uint32_t boots_panic;
    uint32_t boots_task_wdt;
    uint32_t boots_int_wdt;
    uint32_t heap_free;
    uint32_t heap_min;               /* lowest heap_free since boot */
    uint32_t heap_largest;
    bool     ntp_synced;
    /* control plane */
    bool     control_open;
    uint32_t control_alive_age_s;
    uint32_t control_reconnects;
    uint32_t endpoint_pushes;
    /* DERP */
    bool     derp_connected;
    char     derp_host[64];
    /* public endpoint (STUN) */
    uint8_t  public_v4[4];
    uint16_t public_port;
    bool     public_valid;
    /* WireGuard (wg_netif) */
    int      wg_state;               /* 0 idle, 1 handshake pending, 2 up */
    uint32_t wg_rekeys;
    uint32_t wg_cold_handshakes;
    uint32_t wg_rx_stale_events;
    uint32_t wg_roams;
    uint32_t wg_disco_adverts;       /* TSMP disco-key adverts (capver 144) */
    uint32_t wg_tx_drops;
    uint32_t wg_relayed_stale;
    uint32_t wg_relay_errors;
    uint32_t wg_last_rx_age_s;
    uint8_t  wg_path;                /* 0 direct + DERP, 1 direct, 2 DERP only (1.3.6) */
    uint32_t wg_path_lapses;         /* direct → direct + DERP since boot */
} tinylink_stats_t;

void tinylink_get_stats(tinylink_stats_t *out);

/* Count this boot in the RTC boot counters (by esp_reset_reason()) and
 * log them. Call first thing in app_main, before anything that can
 * reset again, so a boot that dies early still records why the previous
 * one ended. Idempotent; tinylink_get_stats calls it too. */
void tinylink_bootstat_record(void);

/* Load the persisted TAI64N floor from NVS namespace "tl_state" key
 * "tai_floor" (default 0 on first ever boot), pre-reserve a 1-day
 * chunk forward, persist that, and install it into wg_proto.c so the
 * first post-reboot handshake's TAI64N timestamp is strictly greater
 * than what the responder saw before reboot. Without this, a reboot
 * rewinds monotonic_seconds to 0 and the responder rejects our next
 * handshake as out-of-order against the peer that knew us pre-reboot.
 * Idempotent. Must be called after app_nvs_init() and before any
 * code path that fires a WG handshake (i.e. before
 * tinylink_dataplane_start). Returns ESP_OK on success or the NVS
 * error otherwise; on NVS failure wg_tai64n_now() falls back to the
 * pre-fix legacy behavior so a transient NVS error doesn't brick the
 * device. */
esp_err_t tinylink_tai64n_floor_init(void);

/* Run the ts2021 Noise IK handshake and POST /machine/register. A node
 * control authorized before (NVS "tl_state"/"reg_keys" matches the
 * device keys) registers without Auth, like a restarted tailscaled;
 * otherwise, or when control refuses that, it sends the Tailscale auth
 * key from NVS namespace "tl_creds", key "auth_key" (round 1.3.3, B22).
 * Blocks until either MachineAuthorized=true (returns ESP_OK) or a hard
 * failure (returns an esp_err_t describing the failure). The caller is
 * expected to retry on transient failures; tinylink_register() does not
 * retry internally.
 */
esp_err_t tinylink_register(void);

/* Rate-limit wait, in ms, from the last tinylink_register() attempt
 * (capver 147): non-zero only when control answered 429, or 503 with a
 * Retry-After — the server's delay when valid (capped at 5 min), else
 * 5–10 s. 0 means "not rate limited": use your own retry cadence.
 * main.c's boot register loop paces itself with it. */
uint32_t tinylink_last_rate_limit_ms(void);

/* Read-only view of the current node identities, useful for debugging and
 * for M2+ which needs the NodeKey for the WireGuard data plane. The output
 * struct is filled even if tinylink_register() has not been called yet —
 * identities are stable from tinylink_init() onward. */
esp_err_t tinylink_get_keys(tinylink_keys_t *out);

/* M2 — fetch one MapResponse from the control plane and bring up the
 * WireGuard data plane against the first peer it announces. Internally:
 * Today (round 1.3.7): takes the boot STUN probe's result (waiting
 * ≤ 300 ms for it) and queues the endpoint push, which the long-poll's
 * first cycle sends as a second HTTP/2 stream with the map stream; the
 * data plane comes up from that stream's first netmap. Nothing goes on
 * the wire here.
 *
 * History: it opened a fresh ts2021 channel, POSTed a `Stream:false`
 * MapRequest and brought the WireGuard netif up from that one
 * MapResponse (M2); from M3 the long-poll's first frame did that and
 * this pushed the endpoints, a round trip of its own, until 1.3.7.
 */
esp_err_t tinylink_dataplane_start(void);

/* Spawn the long-poll MapRequest task. After this returns ESP_OK a
 * dedicated FreeRTOS task is running `POST /machine/map` with
 * `Stream:true`; each non-KeepAlive MapResponse refreshes the in-memory
 * netmap and (if the peer endpoint moved) reconfigures the WG peer.
 *
 * The task supervises its own ts2021 connection: on stream EOF or
 * transport error, it closes the connection, sleeps the configured
 * retry backoff, and re-opens. Callable only after a successful
 * `tinylink_dataplane_start()` so the WG netif already exists.
 */
esp_err_t tinylink_long_poll_start(void);

/* True once the WG session has transport keys (a handshake response
 * was accepted). Non-blocking, callable from any task or an esp_timer
 * callback; app_wifi.c polls it to end the modem-awake boot window. */
bool tinylink_session_up(void);

/* M5 step 2a — best-effort DERP smoke test. Opens a TLS connection
 * to CONFIG_TINYLINK_DERP_SMOKE_HOST:443, runs the HTTP Upgrade dance,
 * exchanges the login frames (FrameServerKey ← / FrameClientInfo → /
 * FrameServerInfo ←), logs the server version on success, then closes.
 *
 * Synchronous: blocks the calling task for ~3–5 s while the TLS
 * handshake + DERP login completes. Designed to run BEFORE
 * tinylink_long_poll_start() so only one TLS conn is alive — the
 * long-poll's persistent TLS state would otherwise compete for ~12 KiB
 * of mbedtls cert-chain-verify heap and the smoke would fail with
 * ESP_FAIL.
 *
 * Returns ESP_OK on a successful login, an esp_err_t on any failure.
 * Failure is non-fatal — the rest of the stack stays up exactly like
 * the pre-M5 baseline. */
esp_err_t tinylink_derp_smoke(void);

/* M5 step 2b — spawn the supervised DERP recv-loop task. Call before
 * the register (the stack wants a pristine heap). The task:
 *   1. Connects to CONFIG_TINYLINK_DERP_SMOKE_HOST:443 (the netmap's
 *      node of CONFIG_TINYLINK_PREFERRED_DERP once known) and runs the
 *      login handshake (same as derp_smoke) — at once, alongside the
 *      register, since round 1.3.5 (it waited for the first netmap
 *      before), so the relay is up for the first WG handshake INIT.
 *   2. Drives derp_client_run() until the stream errors or the server
 *      sends FrameRestarting.
 *   3. Sleeps the configured backoff and reconnects.
 *
 * Opt-in: callable only when CONFIG_TINYLINK_DERP_SUPERVISED=y. When
 * disabled, returns ESP_OK without doing anything (so main.c can call
 * unconditionally). Connect failures are retried with backoff rather
 * than treated as fatal. Relayed DISCO is answered / acted on in the
 * task, relayed WireGuard goes to the data plane (wg_netif inject). */
esp_err_t tinylink_derp_supervised_start(void);

/* Ship an opaque encrypted packet to `dst_node_pub` via the DERP
 * supervisor's TLS conn. The caller (wg_netif's TX worker) treats the
 * relay as fallback transport when the direct UDP path looks broken
 * (RX-stale path or sendto errno). The packet bytes are NOT touched —
 * they are already encrypted with the active WG session keys, and the
 * DERP server treats them as opaque payload to forward to the peer's
 * NodeKey.
 *
 * Returns:
 *   ESP_OK on successful enqueue at the DERP TLS layer
 *   ESP_ERR_INVALID_STATE if the supervisor isn't currently connected
 *   ESP_ERR_NOT_SUPPORTED if CONFIG_TINYLINK_DERP_SUPERVISED=n
 *   ESP_FAIL on TLS write error
 *
 * `best_effort` = a redundant copy (wg_netif_relay_fn): never blocks,
 * ESP_ERR_TIMEOUT when the DERP conn cannot take it at once.
 *
 * Wired into wg_netif via wg_netif_set_relay_callback at startup. The
 * signature matches wg_netif_relay_fn so it can be registered
 * directly. Safe to call from any task; serialized by the DERP client's
 * write_lock mutex internally. */
esp_err_t tinylink_relay_via_derp(const uint8_t *dst_node_pub,
                                  const uint8_t *packet,
                                  size_t len,
                                  bool best_effort,
                                  void *user);

/* Bring up the WireGuard UDP socket early — bind only, no handshake.
 * Must be called after tinylink_init (so the local node identity is
 * loaded from NVS) and before tinylink_stun_probe_start (so STUN can
 * probe through the same socket). Without this prologue, STUN runs on its
 * own ephemeral socket and the public AddrPort the control plane
 * advertises to peers does NOT match the WG socket's NAT mapping, so
 * inbound DISCO/transport from peers never reaches the device.
 *
 * Idempotent: subsequent calls (e.g. via tinylink_dataplane_start's
 * later wg_netif_init) are no-ops. */
esp_err_t tinylink_wg_socket_init(void);

/* M4 — best-effort STUN binding probe to discover the device's public
 * AddrPort. Result is cached and uploaded to the control plane via
 * Hostinfo.Endpoints by the endpoint push, so peers learn an address
 * they can try to dial directly. Failure is non-fatal; the device just
 * operates without a reflexive endpoint advertised, exactly like the
 * pre-M4 baseline. Call after tinylink_wg_socket_init, before the
 * register.
 *
 * Since round 1.3.5 the probe runs on its own short-lived task
 * (`tinylink_stun`) while the register runs, through the WireGuard
 * socket, which it reads itself until wg_rx exists: it used to cost the
 * boot its whole duration (0.04–7.1 s on the sensor) ahead of the
 * register. tinylink_dataplane_start waits for it ≤ 300 ms, and the
 * push goes without it after that; the STUN re-probe pushes the
 * endpoint once the data plane is up. ESP_OK when the probe runs (inline on this task if
 * the spawn fails — the 1.3.4 order); once per boot. */
esp_err_t tinylink_stun_probe_start(void);

/* One STUN re-probe through the running WireGuard socket: the request is
 * sent on it and wg_rx hands the answer back (ESP_ERR_INVALID_STATE
 * before the first netmap has started wg_rx — the boot probe is
 * tinylink_stun_probe_start). A changed endpoint (or the first one)
 * queues a control-plane push. The STUN re-probe loop calls this. */
esp_err_t tinylink_stun_probe(void);

/* Re-run the STUN probe every CONFIG_TINYLINK_STUN_REPROBE_MS
 * milliseconds — and at once when IP_EVENT_STA_GOT_IP reports a new
 * local address — refreshing the cached public AddrPort so subsequent
 * MapRequests advertise the current NAT mapping (which can drift when
 * the NAT rebinds an idle port or the WAN address changes). A changed
 * endpoint queues a control-plane push. A failed re-probe leaves the
 * previously cached endpoint untouched — losing the cache only on
 * confirmed change would require explicit "this is invalid" signaling
 * we don't have a way to receive. The probes run on the telemetry task
 * (since 1.3.2; it had its own task before), which this call spawns if
 * needed in every build. Best-effort; ESP_OK means the re-probe loop
 * runs or will (a NO_MEM spawn retries every 30 s). */
esp_err_t tinylink_stun_reprobe_start(void);

/* Endpoint changes found by the STUN re-probe are pushed to the control
 * plane by the long-poll task itself (Stream=false lite MapRequest on the
 * control conn right after its next reconnect, which the re-probe path
 * triggers). No separate task since 2026-09 — the previous dedicated
 * `tinylink_ep_up` task overflowed its 12 KiB stack on every push; see
 * the "Endpoint push" section in tinylink.c. */

/* Read-only accessor for the cached STUN result. Returns true and
 * fills *addr_v4 / *port if a successful probe has run; returns false
 * otherwise. mapreq.c queries this when building the HostInfo block. */
bool tinylink_get_public_endpoint(uint8_t addr_v4[4], uint16_t *port);

/* Control-plane liveness note. Called by mapreq.c's streaming chunk
 * callback (long_poll_task context) every time bytes arrive from the
 * control plane — including KeepAlive frames. Feeds the wedge-restart
 * last resort (CONFIG_TINYLINK_CONTROL_WEDGE_RESTART_S): if this stops
 * being called for that long, the long-poll task concludes the device
 * cannot reach the control plane by any means available to it and
 * esp_restart()s back to the known-good boot path. Single writer +
 * single reader (both long_poll_task), so no locking. */
void tinylink_control_mark_alive(void);

const char *tinylink_version_string(void);

/* --- Diag / soak-instrumentation API -------------------------------------
 *
 * Periodic stack high-water-mark dump driven from telemetry_task. Walks
 * all live FreeRTOS tasks via uxTaskGetSystemState() (requires
 * CONFIG_FREERTOS_USE_TRACE_FACILITY=y, already on for this build) and
 * logs one line per task with `pcTaskName` + `usStackHighWaterMark`
 * (StackType_t units = 4 B on Xtensa LX6) + a converted bytes-free
 * field. Plus one summary line with heap_free + largest_free_block
 * (MALLOC_CAP_DEFAULT) so soak analysis can correlate stack pressure
 * with heap fragmentation.
 *
 * Cost: ~1.2 KiB static BSS for the TaskStatus_t snapshot buffer +
 * one ESP_LOGI line per task per call. Called every 60 s from
 * telemetry_task (its own deadline since 1.3.2; every 12th sample
 * before), with or without CONFIG_TINYLINK_TELEMETRY_ENABLE.
 *
 * Intended audience: this is the data source for the deferred audit
 * items "task stack trim" and (via correlation with the mapresp parse
 * logs added in the same PR) "jsmn / body_buf trim". Once those land
 * the diag dump can be Kconfig-gated off for production. */
void tinylink_diag_dump_stacks(void);

/* An application record to persist from the 60-s housekeeping (round
 * 1.3.7: the Wi-Fi association hint, app_wifi.c), after the address
 * cache: the place where NVS writes may stall both CPUs without landing
 * on the boot path. `fn` runs on the telemetry task (≈ 2.5 KB of its
 * 4.5 KiB stack free there) and must write only what changed. One hook;
 * NULL clears it. Any task, any time. */
void tinylink_set_persist_hook(void (*fn)(void));

#ifdef __cplusplus
}
#endif
