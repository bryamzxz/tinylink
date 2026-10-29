// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#ifdef ESP_PLATFORM

#include "wg_netif.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif_types.h"
#include "esp_random.h"
#include "esp_timer.h"

#include "lwip/inet.h"
#include "lwip/sockets.h"

#include "crypto/nacl_box.h"
#include "crypto/secure_zero.h"
#include "tl_wdt.h"
#include "disco_handler.h"
#include "disco_prober.h"
#include "tsmp.h"
#include "wg_demux.h"
#include "wg_handshake.h"
#include "wg_timers.h"
#include "wg_transport.h"

static const char *TAG = "wg_netif";

/* Handshake retry policy: WG whitepaper §6.5 prescribes
 * REKEY_TIMEOUT = 5 s with a max of 18 retries (REJECT_AFTER_TIME =
 * 180 s). For first-version tinylink we use a slightly tighter budget
 * (5 s × 12 = 60 s) — long enough that a slow network completes,
 * short enough that the user notices a dead peer. */
#define WG_REKEY_TIMEOUT_MS  5000
#define WG_HANDSHAKE_MAX_RETRIES 12

/* First retry of a cold handshake burst (B7c, 1.3.2). At boot the first
 * INIT goes out right after the netmap, before the peer has validated a
 * direct path to our (per-boot, new) NAT mapping, so it answers via
 * DERP — and our DERP is usually not logged in yet: the response is
 * lost and the peer then treats copies of that INIT as replays (see
 * WG_INIT_FRESH_AFTER_MS). Seen on the sensor: WG up 5 s after the
 * netmap, every boot. The netmap-time prepunch pings validate the
 * direct path within ~0.3 s, so a NEW INIT 2 s later is answered
 * directly. One extra INIT per burst — responders accept 50/s — and
 * every later retry, rekeys included, keeps REKEY_TIMEOUT. */
#define WG_FIRST_RETRY_MS 2000

/* Proactive rekey threshold. WG spec: the *responder* hits
 * REKEY_AFTER_TIME = 120 s and starts initiating a new handshake; if
 * we don't respond (we're initiator-only — incoming HANDSHAKE_INIT is
 * dropped on purpose), the responder hits REJECT_AFTER_TIME = 180 s
 * and invalidates our transport keys. From that moment our outbound
 * encrypts with keys the peer no longer accepts (silent black hole).
 *
 * Fix: initiate our own rekey just before the responder's 120 s mark,
 * so the new session is established while the old one is still live.
 * 110 s leaves a 10 s budget for the round trip — the same retry path
 * (5 s × 12) covers transient losses. Keep this strictly below 120 s. */
#define WG_REKEY_AFTER_MS    110000

/* RX-stale watchdog threshold. Closes the "peer restarted" silent
 * black-hole gap that the age-based proactive rekey above does NOT
 * cover. Scenario: peer (e.g. Servidor1) reboots its tailscaled. The
 * new process has fresh session keys but the same DiscoKey / NodeKey;
 * our existing g.transport keys are now garbage to the peer. Outbound
 * WG transport still encrypts and sendto's successfully (the wire
 * works), but the peer drops every datagram on decrypt. We don't
 * notice until WG_REKEY_AFTER_MS fires (worst case 110 s of silent
 * loss after a peer restart that happens right after a rekey).
 *
 * Trigger: in steady-state (state == UP, no rekey in flight), if no
 * successful transport decrypt has happened in WG_RX_STALE_THRESHOLD_MS,
 * force a fresh handshake. 30 s is well above WG persistent-keepalive
 * (25 s in the wireguard.conf default) and Tailscale's typical DISCO
 * cadence (~3 s direct, ~1 s DERP), so 30 s of true RX silence is
 * abnormal in practice. Below WG_REKEY_AFTER_MS so the watchdog wins
 * the race when both would fire. Above WG_REKEY_TIMEOUT_MS (5 s) so
 * a single packet loss doesn't trigger spurious rekey storms. */
#define WG_RX_STALE_THRESHOLD_MS  30000

/* Cooldown between active DISCO probes of the peer's alternate
 * endpoints. Fires from rx_task when WG transport stays silent past
 * WG_RX_STALE_THRESHOLD_MS — but only once per cooldown window so a
 * persistent outage doesn't burst-spam DISCO at every rx_task tick.
 *
 * 10 s matches upstream tailscale's "endpoint heartbeat" cadence for
 * an unhealthy session (heartbeatInterval ~3-15 s in
 * wgengine/magicsock/endpoint.go). Short enough to react quickly when
 * the peer comes back via a new NAT mapping, long enough that 10 min
 * of total outage produces ~60 probes, not 3000. */
#define WG_PATH_PROBE_COOLDOWN_MS 10000

/* INIT re-send on path events (round 1.3.2, B7). The first INIT of every
 * boot used to be lost: it goes out direct at netmap time, before the
 * peer has punched its side and before the DERP relay is up, and the
 * retry waited REKEY_TIMEOUT + the old 1-s RX tick (WG-up − netmap =
 * 5.2–6.2 s on the sensor). Now, while a handshake is pending, the INIT
 * of the attempt in flight is re-sent when a path becomes usable — DERP
 * login (wg_netif_handshake_kick), a CallMeMaybe from the peer, a
 * solicited DISCO pong — and every INIT also goes via DERP while no
 * direct path is confirmed (magicsock sends to UDP and DERP while
 * bestAddr is untrusted, and queues DERP writes until the relay is up).
 * It is the SAME message, not a new attempt: the responder consumes the
 * first copy that arrives and drops the rest as a TAI64N replay, so the
 * whitepaper's one-new-INIT-per-REKEY_TIMEOUT rule holds (wireguard-go
 * and the kernel rate-limit new INITs unconditionally; the old fast
 * INIT on a pong roam built a new one 500 ms apart). A response from
 * any path matches the one attempt. Per path, a re-send needs
 * WG_INIT_RESEND_MIN_MS since that path last carried this INIT, unless
 * the direct destination changed or the relay just came up — this
 * coalesces pong bursts (one per probed endpoint). */
#define WG_INIT_RESEND_MIN_MS 500

/* …except when the path that just became usable is the DERP relay
 * coming up or a solicited pong, and the pending INIT is older than
 * this: then a NEW INIT replaces it (B7b, found on the sensor
 * 2026-10-28). At boot the first INIT does reach the peer, which
 * answers via DERP before our DERP login (dropped, "peer gone") and
 * direct to our previous NAT mapping (the router hands out a new port
 * per boot); every copy of that same INIT is then a TAI64N replay to
 * the peer, and only the REKEY_TIMEOUT retry got through. A new INIT
 * carries a new timestamp. Responders only rate-limit initiations
 * (wireguard-go HandshakeInitationRate = 50/s), and these two events
 * are one-offs per path change, so this stays far below any flood.
 * Younger than this, a response may still be in flight — re-send. */
#define WG_INIT_FRESH_AFTER_MS 1000

/* Upper bound on one RX wait. The RX task sleeps until its next timer
 * deadline (wg_timers.h) but no longer than this, so a deadline another
 * task moves earlier is honoured at most this late. Equal to
 * REKEY_TIMEOUT (B21): the only deadline another task creates that must
 * not slip — the retry of a cold INIT kicked by wg_netif_update_peer_keys
 * — lies a full REKEY_TIMEOUT ahead, so a wait that started before the
 * kick ends before that retry is due and re-plans; the others (errno
 * path probe, stop: close() wakes recvfrom) tolerate it. Idle wakes drop
 * from 1/s to 0.2/s; the 60-s task WDT is fed on every wake. */
#define WG_RX_MAX_WAIT_MS WG_REKEY_TIMEOUT_MS

/* Idle wait of the TX worker (B21): it wakes for every frame anyway and
 * wg_netif_stop wakes it with a sentinel, so this only paces the WDT
 * feed (60-s budget). Was a 500-ms poll: two light-sleep exits per
 * second for nothing. */
#define WG_TX_IDLE_WAIT_MS 10000

/* Feed the task WDT at most once per second (B21) instead of on every
 * packet: esp_task_wdt_reset takes a spinlock and walks the subscriber
 * list, and the budget is 60 s. */
#define WG_WDT_FEED_EVERY_US 1000000LL

/* WG persistent keepalive cadence (host-order ms). When the device has
 * been UP and silent on the outbound transport for this long, we send
 * a zero-byte WG transport packet to refresh the NAT mapping at our
 * upstream NAT and any intermediate stateful firewall (CGNAT, ISP
 * carrier-grade router). Tailscale defaults to 25 s for the same
 * reason; matches the typical wireguard.conf PersistentKeepalive
 * recommendation. Above the 5 s telemetry cadence so it normally
 * never fires (sensor app keeps the path warm). Active only when
 * telemetry pauses (sensor disabled / I²C error) and we'd otherwise
 * burn the NAT mapping after CGNAT's 30-60 s UDP idle timeout. */
#define WG_PERSISTENT_KEEPALIVE_MS 25000

/* Cool-down between handshake bursts after a budget exhaustion. The
 * "12 × 5 s = 60 s" attempt budget covers transient packet loss but
 * is too tight for a peer that's offline for longer (e.g. a full OS
 * reboot of the peer machine takes 60-180 s for BIOS + kernel +
 * service start). Pre-watchdog firmware would give up after the
 * budget and stay in WG_NETIF_FAILED forever, requiring an ESP32
 * reboot to recover.
 *
 * Instead of giving up, after exhaustion we wait this long and start
 * a new burst. This gives unbounded recovery time — peer can be down
 * for any duration and the firmware re-establishes the session
 * automatically on its next handshake burst after peer returns.
 *
 * 30 s strikes a balance: long enough that a power-of-2 backoff
 * during a 30-min outage doesn't spam (60 attempts in 30 min vs
 * 360 attempts at 5 s each), short enough that peer-recovery is
 * detected within ~30 s of when it actually returns. */
#define WG_HANDSHAKE_BACKOFF_MS   30000

/* RX task stack: WG decrypt path alone fits in 4 KiB, but the DISCO
 * direct branch adds NaCl-box open + a sealed Pong build + sendto on
 * the same socket — verified 2026-05-07 to overflow 4 KiB ("stack
 * overflow in task wg_rx" reset on every inbound CMM-punched ping).
 * 8 KiB has comfortable headroom for the deepest path (handle_disco_direct
 * → disco_handle_recv → disco_open → NaCl box_open with curve25519/salsa20
 * crypto on the stack → disco_seal → sendto into WiFi TX). Since round
 * 1.3.2 (B10) the cached-K branch seals with K and never reaches X25519;
 * the uncached fallback, the INIT build and the path-stale prepunch
 * still do (since 1.3.3 curve25519_fiat32: 848 B frame + 160 B for the
 * field multiply under it; donna's frame was 2.7 KiB). */
#define WG_RX_TASK_STACK_BYTES 8192
#define WG_RX_TASK_PRIO        (tskIDLE_PRIORITY + 3)

/* TX worker task: drains the outbound queue and runs sendto outside
 * the lwIP TCPIP context (calling sendto from there re-enters the
 * lwIP socket API and posts a tcpip_callback that the TCPIP task
 * itself would have to drain — guaranteed deadlock). One step below
 * the RX task so packet decode wins under load.
 *
 * Stack: 7 KiB (conservative trim from 8 KiB; soak-instrumentation
 * #97 + #98 + #99 + #100 measured the lifetime peak at 2 176 B used
 * in steady-state across a 420 s passive soak — i.e. WG session
 * stays up the whole window, sendto cascades happen only for
 * keepalives + telemetry tx + DISCO pong, NOT for the post-outage
 * recovery scenario that historically blew the stack).
 *
 * Earlier budget was 4 KiB (sendto recursing into the WiFi driver
 * TX callback chain measured >2 KiB; canary tripped at 3 KiB on
 * first sizing). That margin was marginal pre-PR-#65 and
 * insufficient post-#65 where the tinylink + main + mbedcrypto
 * components compile at -O2: aggressive inlining grew the effective
 * stack frame of the sendto path (lwIP linkoutput → wg_transport
 * encrypt → sendto → WiFi driver TX queue) past the 4 KiB ceiling.
 * Caught 2026-05-11 in /tmp/tinylink_capture_2026-05-11_validate_v2.log
 * at uptime 880578 ms: `wg_netif: session up` (a single legitimate
 * telemetry packet hitting the path after a 9-minute outage)
 * immediately followed by
 * `***ERROR*** A stack overflow in task wg_tx has been detected.`
 * + SW_CPU_RESET.
 *
 * The post-outage cascade IS the deepest path, and the passive
 * 420 s soak did NOT exercise it. So the actual post-outage peak
 * under -O2 is still UNKNOWN, only bounded:
 *   lower: > 4 096 B (the historical overflow at 4 KiB stack)
 *   upper: < 8 192 B (8 months stable operation at this size)
 *
 * 7 KiB sits 75 % above the lower bound while still leaving 2 KiB
 * heap headroom vs the 8 KiB baseline. Further tightening (6 KiB,
 * 5 KiB) requires a forced-flap soak — iptables-DROP on Servidor1
 * per the CHANGELOG.md:107-117 recipe — that exercises the post-
 * outage recovery + first-telemetry-after-handshake cascade
 * directly and produces a measured peak from `stack diag:` dumps
 * during the recovery window.
 *
 * The queue length (WG_TX_QUEUE_LEN=3) makes a real flood
 * impossible — a frame is dropped when no TX slot is free. The
 * 1.5 KiB slots live on the heap (g.tx_slots), never on this stack. */
#define WG_TX_TASK_STACK_BYTES 7168
#define WG_TX_TASK_PRIO        (tskIDLE_PRIORITY + 2)

/* Outbound TX queue depth: frames that may wait while the worker is
 * busy with one more. Telemetry ticks every 5 s and ICMP responses are
 * sporadic; realistic burst depth is 1–2. Three gives margin without
 * waste. If this ever fills under steady-state operation it shows up
 * in wg_netif_get_tx_drops + the throttled drop log below. */
#define WG_TX_QUEUE_LEN        3

/* TX ring (round 1.3.2, B14). Until 1.3.1 a 1 556-B item was encrypted
 * into a BSS scratch, copied into a FreeRTOS queue of whole items and
 * copied out again into the worker's BSS scratch (two memcpy of ~1.5 KB
 * per packet, 4.7 KiB of queue storage + 3.1 KiB of scratch). Now the
 * frame is encrypted straight into a slot and only its one-byte index
 * travels: tx_free_q holds the free slot indices, tx_ready_q the filled
 * ones in wire order. WG_TX_QUEUE_LEN + 1 slots keep the old capacity
 * exactly — three waiting plus the one the worker is sending (it used to
 * sit in the worker scratch) — and a frame is dropped exactly when the
 * old queue was full. tx_ready_q has one spare entry for the stop
 * sentinel. A slot is owned by whoever dequeued its index; the queues
 * are the only shared state, so the worker needs no g.lock. */
#define WG_TX_SLOTS            (WG_TX_QUEUE_LEN + 1)
#define WG_TX_SLOT_STOP        0xFFu   /* tx_ready_q sentinel: worker exits */

/* Drop-on-full log throttle. Print one warning per N drops so the
 * UART doesn't spam if the worker is stuck for an extended window. */
#define WG_TX_DROP_LOG_EVERY   64

/* Largest WG datagram we accept on the wire. WG transport packets are
 * usually MTU-bounded; with our 1.5 KiB upper bound we have plenty of
 * headroom for IPv4 over WG. */
#define WG_RX_BUF_LEN 1536

/* TX slot filled by wg_netif_send_plaintext (lwIP TCPIP context, or
 * wg_rx for keepalives/adverts) for the TX worker task. Carries the
 * already-encrypted wire bytes plus a snapshot of the destination
 * sockaddr — snapshotting avoids racing wg_netif_update_peer_endpoint
 * between encrypt and send (the WG spec tolerates a short trailing
 * window of packets to the old endpoint during roaming, so the old
 * snapshot landing is fine). buf is word-aligned (offset 20 in a
 * heap block) so the AEAD writes the ciphertext at buf+16 on its
 * l32i/s32i fast path. */
typedef struct {
    size_t              len;
    struct sockaddr_in  dst;
    uint8_t             buf[WG_RX_BUF_LEN];
    bool                relay_only;   /* B7 INIT copy: DERP relay, no sendto */
} wg_tx_item_t;

typedef enum {
    WG_NETIF_IDLE = 0,
    WG_NETIF_HANDSHAKE_PENDING,
    WG_NETIF_UP,
} wg_netif_state_t;

static struct {
    bool                    initialized;
    wg_netif_state_t        state;

    int                     sock;
    uint16_t                bind_port_actual;

    struct wg_netif_local_config local;
    struct wg_netif_peer_config  peer;
    struct sockaddr_in            peer_addr;

    /* Cached NaCl-box shared key K = HSalsa20(X25519(local.disco_priv,
     * peer.peer_disco_pub), 0^16). Computed once in wg_netif_start when
     * the peer is configured with a DiscoKey, reused for every inbound
     * DISCO frame on the direct path — skipping the per-frame X25519 +
     * HSalsa20 chain. Invalidated in wg_netif_stop. AEAD CPU-DoS
     * defense follows upstream tailscale's pattern of caching shared
     * keys per known peer (`wgengine/magicsock/magicsock.go`
     * discoInfoForKnownPeerLocked at 2631-2642, sharedKey via
     * `Shared` -> `box.Precompute`). */
    uint8_t                       peer_disco_shared_k[WG_KEY_LEN];
    bool                          peer_disco_shared_k_valid;

    struct wg_handshake_state    handshake;
    struct wg_transport_session  transport;

    uint32_t                local_index;
    int64_t                 last_handshake_us;
    int                     handshake_attempt;

    /* Make-before-break rekey. While `rekey_in_flight` is true the
     * transport session in g.transport keeps serving inbound + outbound
     * with the OLD keys; only when the response to our fresh INIT lands
     * does wg_transport_session_init swap in the new keys. State stays
     * WG_NETIF_UP throughout — no observable downtime for app traffic.
     * `last_handshake_completed_us` ages from the most recent successful
     * RESPONSE, not from the most recent INIT (the difference matters
     * during retries — we don't want to delay rekey just because the
     * boot handshake took a few attempts). */
    int64_t                 last_handshake_completed_us;
    bool                    rekey_in_flight;
    int                     rekey_attempt;

    /* RX-stale watchdog: timestamp of the last successful WG transport
     * decrypt. Updated in handle_transport(). Compared against
     * WG_RX_STALE_THRESHOLD_MS in the rx_task tick to detect a peer
     * that has restarted (DiscoKey survives, transport keys don't, so
     * outbound transport silently black-holes). Initialized to now_us()
     * on session-up so the watchdog has a 30 s grace before it can fire
     * on a fresh session. */
    int64_t                 last_transport_recv_us;

    /* Timestamp of the most recent successful outbound transport send
     * (telemetry, ICMP echo replies, persistent keepalive). Drives the
     * WG persistent-keepalive trigger: when state == UP and no
     * outbound has happened in WG_PERSISTENT_KEEPALIVE_MS, the rx_task
     * tick sends a zero-byte transport packet to refresh the NAT
     * mapping. Stays 0 until the first send so the keepalive logic
     * doesn't fire spuriously before any real traffic. */
    int64_t                 last_tx_us;

    TaskHandle_t            rx_task;
    SemaphoreHandle_t       lock;
    /* Serializes the handshake state machine (g.handshake, state,
     * rekey flags, attempt counters, the pending INIT): rx_task's timer
     * blocks, the DISCO-pong INIT re-send, the DERP task's
     * wg_netif_handshake_kick and DERP-relayed response path
     * (wg_netif_inject_packet), and wg_netif_update_peer_keys (long-poll
     * task) all mutate it. Never taken while g.lock is held (order
     * hs_lock → g.lock), never held across rx_cb or a DERP/TLS call.
     * (M16, 2026-09; 1.3.2) */
    SemaphoreHandle_t       hs_lock;
    /* /stats counters (since boot). */
    uint32_t                stat_rekeys;
    uint32_t                stat_cold_handshakes;
    uint32_t                stat_rx_stale;
    uint32_t                stat_roams;
    uint32_t                stat_disco_adverts;   /* TSMP adverts queued */

    /* Outbound TX ring + worker (see WG_TX_SLOTS). The worker drains in
     * non-TCPIP context so sendto can re-enter lwIP safely. tx_done_sem
     * is given by the worker as the last thing it does before
     * vTaskDelete(NULL); wg_netif_stop takes it (with timeout) so
     * vQueueDelete cannot race against an in-flight xQueueReceive. */
    wg_tx_item_t           *tx_slots;      /* WG_TX_SLOTS, heap, never on a stack */
    QueueHandle_t           tx_free_q;     /* uint8_t slot indices, free */
    QueueHandle_t           tx_ready_q;    /* uint8_t slot indices, to send */
    TaskHandle_t            tx_task;
    SemaphoreHandle_t       tx_done_sem;
    uint64_t                tx_drops;

    wg_netif_rx_cb_t        rx_cb;
    void                   *rx_cb_user;

    /* Periodic STUN re-probe dispatch. tinylink.c arms this with a
     * callback that parses the response, matches the in-flight txid,
     * and signals the reprobe task. NULL = drop (legacy behavior). */
    wg_netif_stun_cb_t      stun_cb;
    void                   *stun_cb_user;

    /* Path-stale probe dispatch. Tinylink registers a handler that
     * sends DISCO pings to all known peer endpoints (from the latest
     * netmap). Fires from rx_task when transport stays silent past
     * WG_RX_STALE_THRESHOLD_MS, throttled by last_path_probe_us +
     * WG_PATH_PROBE_COOLDOWN_MS. NULL = no probe (legacy behavior:
     * just retry handshakes against the current stale endpoint). */
    wg_netif_path_stale_cb_t path_stale_cb;
    void                    *path_stale_cb_user;
    int64_t                  last_path_probe_us;

    /* DERP-relay TX callback. When non-NULL and direct UDP looks
     * unusable (RX-stale path OR sendto errno), the TX worker ships
     * the encrypted WG transport frame through this callback instead
     * of (or in addition to) direct sendto. See wg_netif.h for the
     * full callback contract. */
    wg_netif_relay_fn        relay_cb;
    void                    *relay_cb_user;
    uint64_t                 relayed_stale;
    uint64_t                 relayed_errno;
    uint64_t                 relay_errors;

    /* The INIT of the attempt in flight (B7, see WG_INIT_RESEND_MIN_MS):
     * public wire bytes, re-sent verbatim on path events. Valid from a
     * successful build until its response is accepted or the next INIT
     * replaces it. All five fields under hs_lock. */
    struct wg_msg_initiation init_msg;
    bool                     init_valid;
    int64_t                  init_direct_us;   /* last direct send of init_msg */
    struct sockaddr_in       init_direct_dst;  /* ...and where it went */
    int64_t                  init_relay_us;    /* last DERP copy queued, 0 = none */

    /* Direct-path confirmation (B7): last authenticated datagram that
     * came in on the UDP socket — transport, handshake response, or a
     * prober-matched pong from the peer. Older than the RX-stale window =
     * no confirmed direct path: INITs then also go via DERP. Written by
     * wg_rx; read unlocked elsewhere (a torn read misroutes one copy). */
    int64_t                  last_direct_rx_us;
    /* The session in g.transport came up on a DERP-relayed response.
     * Until a direct datagram authenticates after that, the TX worker
     * sends every frame on both paths (magicsock: UDP + DERP while
     * bestAddr is untrusted). Under hs_lock, read unlocked by wg_tx. */
    bool                     session_via_relay;
    /* Wi-Fi came back (IP_EVENT_STA_GOT_IP): rx_task re-sends a pending
     * INIT at its next wake. Set by the event task. */
    volatile bool            link_up_pending;

    bool                    stop_requested;
} g;

/* --- Helpers --------------------------------------------------------- */

static int64_t now_us(void) { return esp_timer_get_time(); }

static void wdt_feed_throttled(int64_t now, int64_t *last_feed_us)
{
    if (now - *last_feed_us >= WG_WDT_FEED_EVERY_US) {
        tl_wdt_feed();
        *last_feed_us = now;
    }
}

/* The peer's static key under g.lock: wg_netif_update_peer_keys (long-poll
 * task) rewrites it on a peer re-login; wg_tx (DERP relay destination) and
 * tinylink_derp (inject source check) read it. */
static void peer_static_snapshot(uint8_t out[WG_KEY_LEN])
{
    xSemaphoreTake(g.lock, portMAX_DELAY);
    memcpy(out, g.peer.peer_static_pub, WG_KEY_LEN);
    xSemaphoreGive(g.lock);
}

static uint32_t fresh_local_index(void)
{
    /* WG sender_index is "non-zero, never-reused (within a session
     * lifetime)". esp_random() is seeded from the WiFi RF subsystem
     * post-WiFi-up which is the only context wg_netif starts in. */
    uint32_t v;
    do { v = esp_random(); } while (v == 0);
    return v;
}

static void rebuild_peer_sockaddr(void)
{
    memset(&g.peer_addr, 0, sizeof(g.peer_addr));
    g.peer_addr.sin_family      = AF_INET;
    g.peer_addr.sin_port        = htons(g.peer.peer_endpoint_port);
    g.peer_addr.sin_addr.s_addr = g.peer.peer_endpoint_v4_be;
}

/* g.peer_addr under g.lock — roam_to / update_peer_endpoint rewrite it
 * from other tasks. Callers may hold hs_lock (order hs_lock → g.lock). */
static struct sockaddr_in peer_addr_snapshot(void)
{
    xSemaphoreTake(g.lock, portMAX_DELAY);
    const struct sockaddr_in a = g.peer_addr;
    xSemaphoreGive(g.lock);
    return a;
}

static int send_to_peer(const uint8_t *buf, size_t len,
                        const struct sockaddr_in *dst)
{
    ssize_t n = sendto(g.sock, buf, len, 0,
                       (const struct sockaddr *)dst, sizeof(*dst));
    if (n < 0) {
        ESP_LOGW(TAG, "sendto: errno=%d", errno);
        /* Kernel-level negative signal: ENETUNREACH means there is no
         * route at all to the destination (Wi-Fi disconnected, default
         * gateway gone). EHOSTUNREACH means the destination host did
         * not respond to ARP / IPv6 ND. Either way the current
         * g.peer.peer_endpoint is dead; the existing 30 s
         * WG_RX_STALE_THRESHOLD_MS wait is wasted. Backdate
         * last_transport_recv_us and zero the path-probe cooldown so
         * rx_task fires path_stale_cb on its next wake (at once when
         * this send ran on wg_rx, within WG_RX_MAX_WAIT_MS from another
         * task), triggering DISCO probes of the peer's alternate
         * endpoints.
         * Models upstream tailscale magicsock noteBadEndpoint
         * (endpoint.go:1634-1641). */
        if (errno == ENETUNREACH || errno == EHOSTUNREACH) {
            /* Under g.lock: since 1.3.2 this also runs on the DERP task
             * (call-me-maybe re-send), racing handle_transport's locked
             * write of the same 64-bit field. Callers hold at most
             * hs_lock (order hs_lock → g.lock). */
            xSemaphoreTake(g.lock, portMAX_DELAY);
            g.last_transport_recv_us =
                now_us() - (WG_RX_STALE_THRESHOLD_MS + 1) * 1000LL;
            g.last_path_probe_us = 0;
            xSemaphoreGive(g.lock);
        }
        return -1;
    }
    return (int)n;
}

/* A direct path is confirmed while something authenticated arrived on
 * the UDP socket within the RX-stale window (B7). */
static bool direct_path_confirmed(int64_t now)
{
    return g.last_direct_rx_us > 0 &&
           !wg_timer_due(now, g.last_direct_rx_us,
                         (int64_t)WG_RX_STALE_THRESHOLD_MS * 1000LL);
}

/* An authenticated datagram arrived on the UDP socket (wg_rx only). */
static void note_direct_rx(int64_t now, const char *what)
{
    if (g.session_via_relay && g.state == WG_NETIF_UP &&
        g.last_direct_rx_us < g.last_handshake_completed_us) {
        ESP_LOGI(TAG, "direct path confirmed (%s) — DERP copies stop", what);
    }
    g.last_direct_rx_us = now;
}

/* A handshake attempt is in flight: cold (PENDING) or make-before-break
 * rekey. */
static bool handshake_pending(void)
{
    return g.state == WG_NETIF_HANDSHAKE_PENDING ||
           (g.state == WG_NETIF_UP && g.rekey_in_flight);
}

/* Direct copy of g.init_msg to the live endpoint. Caller holds hs_lock. */
static void init_send_direct(int64_t now)
{
    const struct sockaddr_in dst = peer_addr_snapshot();
    (void)send_to_peer((const uint8_t *)&g.init_msg, sizeof(g.init_msg), &dst);
    g.init_direct_us  = now;
    g.init_direct_dst = dst;
}

/* DERP copy of g.init_msg: queued on the TX ring for the worker, which
 * owns every call into the relay — no wg lock is ever held across the
 * TLS write. Best effort, like magicsock's DERP write channel: no relay
 * registered or no free slot = no copy (the direct copy and the
 * REKEY_TIMEOUT retry stand). Caller holds hs_lock. */
static bool init_queue_relay(int64_t now)
{
    if (g.relay_cb == NULL || g.tx_slots == NULL) return false;
    uint8_t slot;
    if (xQueueReceive(g.tx_free_q, &slot, 0) != pdTRUE) return false;
    wg_tx_item_t *it = &g.tx_slots[slot];
    memcpy(it->buf, &g.init_msg, sizeof(g.init_msg));
    it->len        = sizeof(g.init_msg);
    it->relay_only = true;
    (void)xQueueSend(g.tx_ready_q, &slot, 0);   /* never full */
    g.init_relay_us = now;
    return true;
}

/* Build a fresh INIT for a NEW attempt, keep it in g.init_msg and send
 * it: direct, plus a DERP copy while no direct path is confirmed.
 * Mutates g.handshake (new ephemeral + chain key) and g.local_index;
 * does NOT touch g.state or g.transport — callers decide what the
 * attempt means (cold start vs. proactive rekey).
 *
 * g.last_handshake_us is stamped first, so the attempt counts even if
 * the build or the send fails and the next try is one REKEY_TIMEOUT
 * away (wireguard-go stamps lastSentHandshake before
 * CreateMessageInitiation too). Until 1.3.1 a failed sendto returned
 * before the stamp and the retry fired on the next 1-s tick; with the
 * deadline-based RX wait that would spin. A failed direct send is not a
 * failed attempt: the DERP copy may still deliver it. Returns -1 only if
 * the INIT could not be built. Caller holds hs_lock. */
static int build_and_send_init(void)
{
    const int64_t now = now_us();
    g.last_handshake_us = now;
    g.init_valid = false;
    if (wg_handshake_init(&g.handshake,
                          g.local.static_priv,
                          g.local.static_pub,
                          g.peer.peer_static_pub,
                          g.peer.preshared_key) != 0) {
        ESP_LOGE(TAG, "handshake_init failed (low-order peer pub?)");
        return -1;
    }

    g.local_index = fresh_local_index();

    if (wg_handshake_create_initiation(&g.handshake, g.local_index,
                                       &g.init_msg) != 0) {
        ESP_LOGE(TAG, "create_initiation failed");
        return -1;
    }
    g.init_valid    = true;
    g.init_relay_us = 0;
    init_send_direct(now);
    if (!direct_path_confirmed(now)) {
        (void)init_queue_relay(now);
    }
    return 0;
}

/* Re-send the INIT of the attempt in flight (B7) — the same bytes, see
 * WG_INIT_RESEND_MIN_MS. `force_relay`: the relay just came up, so an
 * earlier copy queued while it was down was dropped. Caller holds
 * hs_lock. */
static void init_resend(bool direct, bool relay, bool force_relay,
                        const char *why)
{
    if (!g.init_valid || !handshake_pending()) return;
    const int64_t now = now_us();
    const int64_t min_us = (int64_t)WG_INIT_RESEND_MIN_MS * 1000LL;
    bool sent_direct = false, sent_relay = false;
    if (direct) {
        const struct sockaddr_in dst = peer_addr_snapshot();
        const bool moved =
            dst.sin_addr.s_addr != g.init_direct_dst.sin_addr.s_addr ||
            dst.sin_port        != g.init_direct_dst.sin_port;
        if (moved || wg_timer_due(now, g.init_direct_us, min_us)) {
            (void)send_to_peer((const uint8_t *)&g.init_msg,
                               sizeof(g.init_msg), &dst);
            g.init_direct_us  = now;
            g.init_direct_dst = dst;
            sent_direct = true;
        }
    }
    if (relay && (force_relay || g.init_relay_us == 0 ||
                  wg_timer_due(now, g.init_relay_us, min_us))) {
        sent_relay = init_queue_relay(now);
    }
    if (sent_direct || sent_relay) {
        ESP_LOGI(TAG, "handshake init re-sent via %s%s%s (%s, idx=0x%08x)",
                 sent_direct ? "direct" : "",
                 sent_direct && sent_relay ? " + " : "",
                 sent_relay ? "DERP" : "", why, (unsigned)g.local_index);
    }
}

/* Cold start: send INIT and transition to HANDSHAKE_PENDING. App
 * traffic is paused until the response lands. Used at boot and as the
 * fallback path when proactive rekey exhausts its budget. The attempt
 * counts even if the INIT could not be built (see build_and_send_init),
 * so a persistent failure walks the retry budget and backoff instead of
 * looping. */
static int kick_off_handshake(void)
{
    const int rc = build_and_send_init();
    g.handshake_attempt++;
    g.state = WG_NETIF_HANDSHAKE_PENDING;
    if (rc == 0) {
        ESP_LOGI(TAG, "handshake init sent (attempt %d, idx=0x%08x)",
                 g.handshake_attempt, (unsigned)g.local_index);
    }
    return rc;
}

/* Path just became usable (DERP login, solicited pong) while a handshake
 * is pending: past WG_INIT_FRESH_AFTER_MS build a new INIT — a new
 * attempt of the cold handshake or of the rekey — else re-send the one
 * in flight. Caller holds hs_lock. */
static void init_refresh_or_resend(bool direct, bool relay, bool force_relay,
                                   const char *why)
{
    if (!g.init_valid || !handshake_pending()) return;
    if (!wg_timer_due(now_us(), g.last_handshake_us,
                      (int64_t)WG_INIT_FRESH_AFTER_MS * 1000LL)) {
        init_resend(direct, relay, force_relay, why);
        return;
    }
    const bool rekey = (g.state == WG_NETIF_UP);
    const int rc = build_and_send_init();
    if (rekey) g.rekey_attempt++; else g.handshake_attempt++;
    if (rc == 0) {
        ESP_LOGI(TAG, "%s init sent (attempt %d, idx=0x%08x, fresh: %s)",
                 rekey ? "rekey" : "handshake",
                 rekey ? g.rekey_attempt : g.handshake_attempt,
                 (unsigned)g.local_index, why);
    }
}

/* Proactive rekey: send a fresh INIT while keeping g.state == UP and
 * the existing g.transport session live. The new keys land only when
 * handle_handshake_response sees the matching reply and calls
 * wg_transport_session_init to swap them in atomically. Until then,
 * outbound app traffic continues to encrypt with the OLD keys (which
 * the responder still accepts up to its REJECT_AFTER_TIME = 180 s).
 * Sets rekey_in_flight whatever the outcome, so the rekey-retry timer
 * (REKEY_TIMEOUT) owns the next try. */
static void start_rekey(void)
{
    const int rc = build_and_send_init();
    g.rekey_attempt++;
    g.rekey_in_flight = true;
    if (rc == 0) {
        ESP_LOGI(TAG, "rekey init sent (attempt %d, idx=0x%08x, age=%lds)",
                 g.rekey_attempt, (unsigned)g.local_index,
                 (long)((now_us() - g.last_handshake_completed_us) / 1000000LL));
    }
}

/* Process a MessageResponse arriving on the socket. Two valid paths:
 *
 *  - Cold path: state == HANDSHAKE_PENDING. Boot or post-budget-exhaustion retry.
 *    App traffic was paused until now; transition to UP.
 *  - Rekey path: state == UP && rekey_in_flight. Old transport session
 *    is still serving traffic; we atomically install the new keys and
 *    drop the rekey-in-flight flag.
 *
 * wg_transport_session_init overwrites g.transport IN PLACE — it installs
 * the new send_key AND resets send_counter to 0. That swap MUST be mutually
 * exclusive with wg_transport_encrypt (which read-modify-writes the same
 * g.transport.send_counter and reads g.transport.send_key, under g.lock, on
 * the lwIP-TCPIP task). wg_rx is unpinned and TCPIP is pinned to CPU0, so on
 * the dual-core LX6 they run truly in parallel: without the lock a concurrent
 * encrypt could latch the OLD high counter, then read the NEWLY installed
 * send_key, emitting (new_key, old_counter) — a counter the fresh session
 * re-uses as it climbs from 0, i.e. catastrophic ChaCha20-Poly1305 nonce
 * reuse. So we take the SAME g.lock send_plaintext uses around the swap.
 *
 * `via_relay`: the response came through DERP (wg_netif_inject_packet),
 * which proves nothing about the direct path — see session_via_relay. */
static bool handle_handshake_response_locked(const uint8_t *buf, size_t len,
                                             bool via_relay)
{
    if (len != sizeof(struct wg_msg_response)) return false;
    const bool cold_path  = (g.state == WG_NETIF_HANDSHAKE_PENDING);
    const bool rekey_path = (g.state == WG_NETIF_UP && g.rekey_in_flight);
    if (!cold_path && !rekey_path) {
        ESP_LOGD(TAG, "handshake response in state=%d rekey=%d ignored",
                 g.state, (int)g.rekey_in_flight);
        return false;
    }
    const struct wg_msg_response *resp = (const struct wg_msg_response *)buf;

    uint8_t send_key[WG_KEY_LEN], recv_key[WG_KEY_LEN];
    uint32_t remote_index = 0;
    if (wg_handshake_process_response(&g.handshake, resp,
                                      send_key, recv_key, &remote_index) != 0) {
        ESP_LOGW(TAG, "handshake response rejected (path=%s)",
                 cold_path ? "cold" : "rekey");
        tl_secure_zero(send_key, sizeof(send_key));
        tl_secure_zero(recv_key, sizeof(recv_key));
        return false;
    }

    xSemaphoreTake(g.lock, portMAX_DELAY);
    wg_transport_session_init(&g.transport, g.local_index, remote_index,
                              send_key, recv_key);
    xSemaphoreGive(g.lock);
    /* Scrub once the keys are copied into the session. The live Noise
     * material goes; the per-peer cache (static-static DH, mac1 keys)
     * stays for the next rekey (B11) — wg_handshake_init recomputes it
     * when the peer static key changes (wg_netif_update_peer_keys), and
     * wg_netif_stop wipes all of it. */
    tl_secure_zero(send_key, sizeof(send_key));
    tl_secure_zero(recv_key, sizeof(recv_key));
    wg_handshake_scrub_live(&g.handshake);

    const int64_t now = now_us();
    g.last_handshake_completed_us = now;
    /* The attempt is answered: no more re-sends of its INIT (B7). A
     * direct response confirms the direct path at the same instant the
     * session starts, so the TX worker's dual send stays off. */
    g.init_valid = false;
    g.session_via_relay = via_relay;
    if (!via_relay) g.last_direct_rx_us = now;
    /* Reset RX-stale watchdog clock on handshake (cold or rekey).
     * A fresh session starts with no transport packets seen yet —
     * setting last_transport_recv_us to now gives the watchdog a
     * 30 s grace before it can fire on this session. Without this
     * a peer-initiated rekey would immediately satisfy the stale
     * predicate (last_transport_recv_us would be 0 or stale from
     * the prior session). */
    g.last_transport_recv_us = now;
    const char *path = via_relay ? " (via DERP)" : "";
    if (cold_path) {
        g.state = WG_NETIF_UP;
        g.handshake_attempt = 0;
        g.stat_cold_handshakes++;
        ESP_LOGI(TAG, "session up: remote_idx=0x%08x%s",
                 (unsigned)remote_index, path);
    } else {
        g.rekey_in_flight = false;
        g.rekey_attempt = 0;
        g.stat_rekeys++;
        ESP_LOGI(TAG, "session rekeyed: remote_idx=0x%08x%s",
                 (unsigned)remote_index, path);
    }
    return true;
}

/* Capver 144: tailscaled advertises its disco key in-tunnel on every new
 * keypair (wireguard-go receive.go → magicsock sendTSMPDiscoAdvertisement,
 * tailscale 3799eaf26 + b87203b83). tinylink is initiator-only, so every
 * completed handshake — cold or rekey, direct or DERP-relayed response —
 * is a new keypair. The advert is also the first transport packet under
 * the new keys, so the peer confirms the keypair at once instead of on
 * the next telemetry frame. Best effort like upstream: a full TX queue
 * drops it. Skipped when either tailnet address is unknown or the peer
 * has no DiscoKey (WireGuard-only peers never get one). */
static void send_disco_advert(void)
{
    if (!g.peer.has_peer_disco_pub ||
        g.peer.self_tailnet_v4_be == 0 || g.peer.peer_tailnet_v4_be == 0) {
        return;
    }
    uint8_t __attribute__((aligned(4))) pkt[TSMP_DISCO_ADVERT_LEN];
    const size_t n = tsmp_build_disco_advert(pkt, sizeof(pkt),
                                             g.peer.self_tailnet_v4_be,
                                             g.peer.peer_tailnet_v4_be,
                                             g.local.disco_pub);
    if (wg_netif_send_plaintext(pkt, n) == ESP_OK) {
        g.stat_disco_adverts++;
    }
}

/* Serialized entry point — see g.hs_lock. Returns true when the response
 * was accepted (session up / rekeyed); the caller then roams if needed
 * and calls send_disco_advert(), so the advert's destination snapshot is
 * the endpoint that just authenticated (it only needs g.lock). */
static bool handle_handshake_response(const uint8_t *buf, size_t len,
                                      bool via_relay)
{
    xSemaphoreTake(g.hs_lock, portMAX_DELAY);
    const bool ok = handle_handshake_response_locked(buf, len, via_relay);
    xSemaphoreGive(g.hs_lock);
    return ok;
}

/* Process a MessageTransport from the peer.
 *
 * WGN-1 (rx side): wg_transport_decrypt does a non-atomic read-modify-write
 * of the replay window (g.transport.replay.highest + .bitmap) and reads
 * g.transport.recv_key. handle_transport is reachable from TWO unpinned
 * FreeRTOS tasks that run in parallel on the dual-core LX6: the wg_rx UDP
 * task (rx_task) and the tinylink_derp relay task (via
 * wg_netif_inject_packet). Whenever a direct-UDP session and a DERP relay
 * are simultaneously active (the normal NAT-traversal transition + every
 * path-stale -> DERP fallback) two transport packets can be decrypted
 * concurrently -> racing RMWs on the replay bitmap (lost update could
 * ACCEPT a replayed packet or corrupt the window across a rekey) and a
 * recv_key read racing the session_init writer in
 * handle_handshake_response. The #105 fix locked only that writer; this
 * locks the reader so the mutual exclusion actually holds. Lock scope is
 * the decrypt + watchdog-clock update ONLY: g.rx_cb re-enters lwIP, which
 * calls back into wg_netif_send_plaintext (takes g.lock), so holding the
 * lock across it would deadlock. */
static bool handle_transport(const uint8_t *buf, size_t len)
{
    if (g.state != WG_NETIF_UP) return false;

    /* Decrypt straight into a stack buffer; max payload bounded by
     * WG_RX_BUF_LEN - WG_TRANSPORT_OVERHEAD. Word-aligned so the AEAD's
     * XOR loop takes its l32i/s32i fast path (chacha20.c) — GCC gives a
     * uint8_t[] on the Xtensa stack no alignment guarantee otherwise. */
    uint8_t __attribute__((aligned(4))) plaintext[WG_RX_BUF_LEN];
    size_t   plen = 0;

    xSemaphoreTake(g.lock, portMAX_DELAY);
    int drc = wg_transport_decrypt(&g.transport, buf, len,
                                   plaintext, sizeof(plaintext), &plen);
    if (drc == 0) {
        /* Successful decrypt = peer's session keys still match ours.
         * Update the RX-stale watchdog clock under the same lock for both
         * data packets AND zero-length keepalives, since both prove the
         * WG transport keys are mutually valid. The watchdog cares about
         * session liveness, not payload direction. */
        g.last_transport_recv_us = now_us();
    }
    xSemaphoreGive(g.lock);

    if (drc != 0) {
        return false;  /* Replay / tamper / wrong index — silent drop. */
    }
    if (plen == 0) {
        /* WG keepalive (zero plaintext) — peer is alive, nothing to
         * deliver upstream. */
        return true;
    }
    if (g.rx_cb) {
        g.rx_cb(plaintext, plen, g.rx_cb_user);
    }
    /* Best-effort scrub — plaintext might be sensitive (passwords,
     * tokens) and the buffer is on the stack of a long-lived task. */
    tl_secure_zero(plaintext, plen);
    return true;
}

/* Handle a DISCO datagram that arrived on the shared UDP socket. The
 * source AddrPort is whatever the peer used to dial us — for direct UDP
 * this is the peer's reflexive endpoint behind their NAT. We sendto the
 * reply on g.sock back to that exact src so the response traverses the
 * same NAT mappings as the request (which is how peer A learns its own
 * public AddrPort works to reach us). */
/* The WG peer's DISCO identity, snapshotted under g.lock per frame: the
 * long-poll task swaps it when control reports a new DiscoKey
 * (wg_netif_update_peer_keys — every peer tailscaled restart). */
typedef struct {
    bool    has_pub;
    bool    k_valid;
    uint8_t pub[WG_KEY_LEN];
    uint8_t k[WG_KEY_LEN];
} disco_peer_snap_t;

static void handle_disco_direct_snap(const uint8_t *buf, size_t len,
                                     const struct sockaddr_in *src,
                                     const disco_peer_snap_t *peer);

static void handle_disco_direct(const uint8_t *buf, size_t len,
                                const struct sockaddr_in *src)
{
    disco_peer_snap_t peer;
    xSemaphoreTake(g.lock, portMAX_DELAY);
    peer.has_pub = g.peer.has_peer_disco_pub;
    peer.k_valid = g.peer_disco_shared_k_valid;
    memcpy(peer.pub, g.peer.peer_disco_pub, WG_KEY_LEN);
    memcpy(peer.k, g.peer_disco_shared_k, WG_KEY_LEN);
    xSemaphoreGive(g.lock);
    handle_disco_direct_snap(buf, len, src, &peer);
    tl_secure_zero(peer.k, sizeof(peer.k));
}

static void handle_disco_direct_snap(const uint8_t *buf, size_t len,
                                     const struct sockaddr_in *src,
                                     const disco_peer_snap_t *peer)
{
    uint8_t reply[DISCO_HANDLER_REPLY_MAX];
    disco_msg_type_t type = (disco_msg_type_t)0;
    uint8_t peer_disco_pub[WG_KEY_LEN] = {0};
    uint8_t txid[DISCO_TXID_LEN] = {0};
    /* peer_disco_pub used below as the roaming gate. */

    /* Pre-AEAD DiscoKey gate. The DISCO wire format places the sender's
     * 32-byte DiscoKey in the cleartext header at offset 6 (after the
     * magic). When we know the WG peer's DiscoKey, drop frames sealed
     * by any other key BEFORE running the Curve25519 + HSalsa20 +
     * XSalsa20 + Poly1305 stack — those frames cannot legitimately
     * roam the WG transport target and would only burn ~5-10 ms of CPU
     * per packet under a UDP flood at our public AddrPort. Models
     * upstream tailscale's `c.peerMap.knownPeerDiscoKey(sender)` check
     * at `wgengine/magicsock/magicsock.go:2170-2177`. */
    if (peer->has_pub &&
        len >= DISCO_MAGIC_LEN + DISCO_KEY_LEN) {
        const uint8_t *sender_pub = buf + DISCO_MAGIC_LEN;
        if (memcmp(sender_pub, peer->pub, DISCO_KEY_LEN) != 0) {
            ESP_LOGD(TAG,
                "drop DISCO from unknown DiscoKey (pre-AEAD)");
            return;
        }
    }

    /* Hot path: use the cached shared K if available — both the open
     * and the Pong seal skip X25519 + HSalsa20 (B10: ~20 ms → ~50 µs per
     * direct ping, and no X25519 frame on this stack). The snapshot holds
     * K and the DiscoKey it was derived from together (both swapped under
     * g.lock by wg_netif_update_peer_keys), and the pre-AEAD gate above
     * already dropped any other sender. Falls back to the per-frame
     * compute path for the (rare) bringup where peer_disco_pub wasn't
     * supplied. */
    size_t reply_len;
    if (peer->k_valid) {
        reply_len = disco_handle_recv_with_shared(
            reply, sizeof(reply), buf, len,
            peer->k, g.local.disco_pub,
            &type, peer_disco_pub, txid);
    } else {
        reply_len = disco_handle_recv(
            reply, sizeof(reply), buf, len,
            g.local.disco_priv, g.local.disco_pub,
            &type, peer_disco_pub, txid);
    }
    if (type == 0) {
        /* Decrypt failed: someone sealed against the wrong DiscoKey, or
         * the bytes weren't actually a DISCO frame. Silent drop — magic
         * prefix already matched so spam is bounded. */
        return;
    }

    /* Roaming gate: only DISCO frames sealed by OUR WG peer's DiscoKey
     * may roam g.peer.peer_endpoint. The same UDP socket also receives
     * DISCO from other Tailscale peers in the netmap (e.g. a laptop
     * we're not WG-connected to but whose call-me-maybe punches still
     * reach us). Without this gate, those frames would flap our WG
     * transport target between unrelated peers. has_peer_disco_pub is
     * false on legacy bringups that didn't pass the DiscoKey through
     * — there we fall back to permissive (legacy) behavior.
     *
     * The pre-AEAD gate above (when has_peer_disco_pub is true) already
     * dropped non-peer DiscoKeys before disco_handle_recv, so this
     * post-decrypt check is now mostly belt-and-suspenders — useful
     * during the legacy permissive boot window before peer config has
     * propagated. */
    const bool roam_allowed =
        !peer->has_pub ||
        memcmp(peer_disco_pub, peer->pub, WG_KEY_LEN) == 0;

    if (type == DISCO_TYPE_PING && reply_len > 0) {
        /* Reply to the peer's Ping with our sealed Pong on the same UDP
         * socket. Note: this does NOT trigger a WG endpoint roam —
         * since M3-step-3 (this PR) the roam decision lives in the
         * PONG branch, gated by disco_prober_match_and_remove, so only
         * Pongs we actually solicited can roam. Replying to a Ping
         * remains valuable (lets the peer discover that our AddrPort
         * is reachable), but accepting a Ping as a roam trigger was
         * the weaker primary control upstream tailscale never had.
         * Models upstream `endpoint.handlePingLocked` (endpoint.go) —
         * answer the ping, defer the bestAddr decision to the round-
         * trip pong. */
        ssize_t n = sendto(g.sock, reply, reply_len, 0,
                           (const struct sockaddr *)src, sizeof(*src));
        if (n < 0) {
            ESP_LOGW(TAG, "disco pong sendto: errno=%d", errno);
        } else {
            char src_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src->sin_addr, src_ip, sizeof(src_ip));
            ESP_LOGD(TAG, "disco ping→pong (direct): src=%s:%u txid=%02x%02x%02x%02x..",
                     src_ip, (unsigned)ntohs(src->sin_port),
                     txid[0], txid[1], txid[2], txid[3]);
        }
        return;
    }
    if (type == DISCO_TYPE_PONG) {
        /* Peer responded to one of our outbound Pings (prepunch /
         * CMM-driven). The disco_prober txid table records every
         * outbound Ping we send; a Pong whose txid is NOT in the
         * table is either a replay of a captured frame or a probe
         * we never sent — either way, do NOT roam. */
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src->sin_addr, src_ip, sizeof(src_ip));
        ESP_LOGD(TAG, "disco pong (direct): src=%s:%u txid=%02x%02x%02x%02x..",
                 src_ip, (unsigned)ntohs(src->sin_port),
                 txid[0], txid[1], txid[2], txid[3]);
        /* Bind the match to the AddrPort we actually probed: a captured
         * Pong replayed from a spoofed source fails the source check and
         * cannot roam the WG endpoint to the attacker's address (ROAM-3).
         * On success src == the probed dst, so the roam below is the
         * magicsock `sentPing.to` model, not roam-to-arbitrary-source. */
        if (!disco_prober_match_and_remove(
                txid, (uint32_t)src->sin_addr.s_addr, ntohs(src->sin_port),
                now_us())) {
            ESP_LOGD(TAG,
                "disco pong: txid/source not in prober table — ignoring "
                "(replay, spoofed source, or stale)");
            return;
        }
        if (roam_allowed) {
            uint32_t src_v4_be = (uint32_t)src->sin_addr.s_addr;
            uint16_t src_port  = ntohs(src->sin_port);
            /* A pong we solicited, from the peer, at the address we
             * probed: the direct path works both ways right now
             * (magicsock trusts bestAddr on exactly this). */
            note_direct_rx(now_us(), "pong");
            if (src_v4_be != g.peer.peer_endpoint_v4_be ||
                src_port  != g.peer.peer_endpoint_port) {
                ESP_LOGI(TAG, "WG endpoint roam (via pong) → %s:%u",
                         src_ip, (unsigned)src_port);
                xSemaphoreTake(g.lock, portMAX_DELAY);
                g.peer.peer_endpoint_v4_be = src_v4_be;
                g.peer.peer_endpoint_port  = src_port;
                rebuild_peer_sockaddr();
                g.stat_roams++;
                xSemaphoreGive(g.lock);
            }

            /* Handshake pending (cold or rekey): re-send its INIT down
             * the path that just answered instead of waiting out
             * REKEY_TIMEOUT against a stale or not-yet-punched endpoint
             * (B7). Same message, so this is not a new attempt; the
             * per-path gate coalesces a burst of pongs, a roam to a new
             * address always goes. Replaces the 1.3.1 "fast INIT",
             * which built a NEW INIT 500 ms apart and only on a roam —
             * the boot case (peer endpoint right, just not punched yet)
             * never roams. */
            xSemaphoreTake(g.hs_lock, portMAX_DELAY);
            init_refresh_or_resend(true, false, false, "pong");
            xSemaphoreGive(g.hs_lock);
        }
        return;
    }
    if (type == DISCO_TYPE_CALLMEMAYBE) {
        ESP_LOGD(TAG, "disco call-me-maybe (direct path)");
        return;
    }
}

/* Move the WG peer endpoint to `src` under g.lock (the TX worker
 * snapshots g.peer_addr under the same lock, so it never sees a torn
 * sockaddr). Counted for /stats. */
static void roam_to(const struct sockaddr_in *src, const char *why)
{
    char ip[16];
    inet_ntoa_r(src->sin_addr, ip, sizeof(ip));
    xSemaphoreTake(g.lock, portMAX_DELAY);
    g.peer.peer_endpoint_v4_be = (uint32_t)src->sin_addr.s_addr;
    g.peer.peer_endpoint_port  = ntohs(src->sin_port);
    rebuild_peer_sockaddr();
    g.stat_roams++;
    xSemaphoreGive(g.lock);
    ESP_LOGI(TAG, "WG endpoint roam (%s) → %s:%u", why, ip,
             (unsigned)ntohs(src->sin_port));
}

/* Earliest instant one of rx_task's timer blocks can fire, from the same
 * (timestamp, period) pairs and the same state conditions — keep the two
 * in sync (a deadline here that no block acts on would make the RX wait
 * spin at one tick; a block missing here would fire up to
 * WG_RX_MAX_WAIT_MS late). Caller holds hs_lock, like the blocks. */
/* Retry interval of the handshake in flight: WG_FIRST_RETRY_MS after
 * the first INIT of a cold burst, REKEY_TIMEOUT otherwise (rekeys, and
 * attempt 0 — the post-backoff wait, whose back-dated stamp assumes
 * REKEY_TIMEOUT). */
static int64_t handshake_retry_us(void)
{
    const int ms = (g.state == WG_NETIF_HANDSHAKE_PENDING &&
                    g.handshake_attempt == 1)
                       ? WG_FIRST_RETRY_MS : WG_REKEY_TIMEOUT_MS;
    return (int64_t)ms * 1000LL;
}

static int64_t rx_next_deadline_us(void)
{
    int64_t d = INT64_MAX;
#define RX_DEADLINE(t, ms) do {                                            \
        const int64_t at_ = wg_timer_at((t), (int64_t)(ms) * 1000LL);      \
        if (at_ < d) d = at_;                                              \
    } while (0)
    if (g.state == WG_NETIF_HANDSHAKE_PENDING || g.rekey_in_flight) {
        const int64_t at = wg_timer_at(g.last_handshake_us,
                                       handshake_retry_us());
        if (at < d) d = at;
    }
    if (g.state == WG_NETIF_UP && !g.rekey_in_flight) {
        if (g.last_handshake_completed_us > 0) {
            RX_DEADLINE(g.last_handshake_completed_us, WG_REKEY_AFTER_MS);
        }
        if (g.last_transport_recv_us > 0) {
            RX_DEADLINE(g.last_transport_recv_us, WG_RX_STALE_THRESHOLD_MS);
        }
    }
    if ((g.state == WG_NETIF_UP || g.state == WG_NETIF_HANDSHAKE_PENDING) &&
        g.path_stale_cb != NULL && g.last_transport_recv_us > 0) {
        /* Both conditions of the probe block: the later instant. */
        const int64_t stale = wg_timer_at(g.last_transport_recv_us,
                                          WG_RX_STALE_THRESHOLD_MS * 1000LL);
        const int64_t cool  = wg_timer_at(g.last_path_probe_us,
                                          WG_PATH_PROBE_COOLDOWN_MS * 1000LL);
        const int64_t at = stale > cool ? stale : cool;
        if (at < d) d = at;
    }
    if (g.state == WG_NETIF_UP && g.last_tx_us > 0) {
        RX_DEADLINE(g.last_tx_us, WG_PERSISTENT_KEEPALIVE_MS);
    }
#undef RX_DEADLINE
    return d;
}

/* Wi-Fi is back. While it was down every INIT copy failed in sendto
 * and still counted as an attempt (build_and_send_init), so a long
 * outage ends in the 30-s budget backoff; without this the tunnel would
 * wait for the next burst. Re-send the pending INIT — it never left the
 * device, so this is still not a new attempt — direct and via DERP.
 * 1.3.1 rebuilt an INIT on every 1-s tick while sends failed (~60 ms of
 * X25519 a second) and so recovered within a tick; this recovers within
 * one RX wait (≤ WG_RX_MAX_WAIT_MS) without the rebuilds. */
static __attribute__((noinline)) void rx_link_up_resend(void)
{
    xSemaphoreTake(g.hs_lock, portMAX_DELAY);
    init_resend(true, true, true, "link up");
    xSemaphoreGive(g.hs_lock);
}

static void on_sta_got_ip(void *arg, esp_event_base_t base, int32_t id,
                          void *data)
{
    (void)arg; (void)base; (void)id; (void)data;
    g.link_up_pending = true;
}

/* The next RX wait in ms. Planned from a fresh clock read, not the
 * iteration's `now`: the iteration may have spent ~0.3 s in a path-stale
 * prepunch (one X25519 per ping) since. noinline keeps its locals off
 * rx_task's frame, the base of every wg_rx call chain. */
static __attribute__((noinline)) uint32_t rx_plan_wait_ms(void)
{
    xSemaphoreTake(g.hs_lock, portMAX_DELAY);
    const int64_t deadline = rx_next_deadline_us();
    xSemaphoreGive(g.hs_lock);
    return wg_recv_timeout_ms(now_us(), deadline, WG_RX_MAX_WAIT_MS,
                              portTICK_PERIOD_MS);
}

/* RX task: blocks on recvfrom, classifies, dispatches. */
static void rx_task(void *arg)
{
    (void)arg;
    /* Word-aligned: the WG transport ciphertext starts at offset 16, so
     * an aligned packet buffer means an aligned AEAD input (fast path in
     * chacha20.c / poly1305_donna_32.h). */
    uint8_t __attribute__((aligned(4))) buf[WG_RX_BUF_LEN];
    /* The receive timeout is the time to the next timer deadline (B7,
     * computed at the end of every iteration); it starts at the cap. */
    uint32_t rcv_ms = WG_RX_MAX_WAIT_MS;
    struct timeval tv = {.tv_sec = rcv_ms / 1000, .tv_usec = (rcv_ms % 1000) * 1000};
    setsockopt(g.sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    tl_wdt_subscribe();
    /* Off the stack: rx_task's frame is the base of every wg_rx chain
     * (the tightest stack); there is one RX task. */
    static int64_t last_feed_us;
    last_feed_us = 0;
    while (!g.stop_requested) {
        struct sockaddr_in src;
        socklen_t srclen = sizeof(src);
        ssize_t n = recvfrom(g.sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &srclen);
        /* One clock read for the WDT, the stamps and the timers below
         * (B21; was ~12 esp_timer reads, now this + the wait plan).
         * Packet handling may run ~40 ms of handshake crypto first; a
         * stale `now` only makes a timer fire that much later. */
        const int64_t now = now_us();
        wdt_feed_throttled(now, &last_feed_us);
        if (g.link_up_pending) {
            g.link_up_pending = false;
            rx_link_up_resend();
        }
        if (n < 0) {
            /* EAGAIN/EWOULDBLOCK on timeout — fall through to retry
             * timer below. Other errors get logged but don't kill the
             * task. */
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                ESP_LOGW(TAG, "recvfrom: errno=%d", errno);
            }
        } else if (n > 0) {
            /* Classify FIRST, then apply the source filter only to
             * WG-protocol kinds. DISCO frames legitimately arrive from
             * a peer's reflexive endpoint (which is by definition NOT
             * the same AddrPort the WG handshake currently targets —
             * that's the whole point of direct-path discovery). */
            wg_demux_kind_t kind = wg_demux_classify(buf, (size_t)n);
            const bool is_wg_proto =
                (kind == WG_DEMUX_HANDSHAKE_INIT ||
                 kind == WG_DEMUX_HANDSHAKE_RESP ||
                 kind == WG_DEMUX_HANDSHAKE_COOKIE ||
                 kind == WG_DEMUX_TRANSPORT);
            const bool from_peer =
                (src.sin_addr.s_addr == g.peer_addr.sin_addr.s_addr &&
                 src.sin_port        == g.peer_addr.sin_port);
            /* WireGuard roaming (M16, 2026-09): a TRANSPORT or handshake
             * RESPONSE from an unexpected source is authenticated FIRST
             * (AEAD + replay window / Noise response verification) and,
             * if genuine, the peer endpoint follows it — the whitepaper's
             * "update endpoint on any authenticated packet". Before this,
             * a peer NAT rebind blackholed every inbound datagram until
             * the 30-s RX-stale probe elicited a pong. INIT / COOKIE from a
             * non-peer source are still dropped unauthenticated. */
            if (is_wg_proto && !from_peer &&
                kind != WG_DEMUX_TRANSPORT && kind != WG_DEMUX_HANDSHAKE_RESP) {
                ESP_LOGD(TAG, "drop WG datagram from non-peer src");
                goto retry_timer;
            }

            switch (kind) {
            case WG_DEMUX_HANDSHAKE_RESP:
                /* Accepted here = authenticated on the direct path; the
                 * handler stamps last_direct_rx_us itself. */
                if (handle_handshake_response(buf, (size_t)n, false)) {
                    if (!from_peer) {
                        roam_to(&src, "authenticated handshake response");
                    }
                    send_disco_advert();
                }
                break;
            case WG_DEMUX_TRANSPORT:
                if (handle_transport(buf, (size_t)n)) {
                    note_direct_rx(now, "transport");
                    if (!from_peer) {
                        roam_to(&src, "authenticated transport");
                    }
                }
                break;
            case WG_DEMUX_DISCO:
                handle_disco_direct(buf, (size_t)n, &src);
                break;
            case WG_DEMUX_STUN:
                /* Periodic STUN re-probe lives on the WG socket so
                 * the public AddrPort the server returns lines up
                 * with the WG NAT mapping. tinylink.c arms the cb at
                 * boot; if it's NULL we fall through to drop (which
                 * is the legacy behavior — used to be the only path). */
                if (g.stun_cb != NULL) {
                    g.stun_cb(buf, (size_t)n, g.stun_cb_user);
                }
                break;
            case WG_DEMUX_HANDSHAKE_INIT:
            case WG_DEMUX_HANDSHAKE_COOKIE:
                /* Initiator-only on INIT/COOKIE — drop. */
                break;
            case WG_DEMUX_DISCARD:
            default:
                break;
            }
        }
retry_timer:;

        /* The four handshake-state blocks below run under g.hs_lock
         * (see the struct field): the DERP-relayed response path mutates
         * the same state from another task. */
        xSemaphoreTake(g.hs_lock, portMAX_DELAY);

        /* Handshake retry timer. Fires regardless of whether recvfrom
         * timed out.
         *
         * On budget exhaustion (12 × 5 s = 60 s of no response from
         * peer), DO NOT transition to WG_NETIF_FAILED — that was
         * terminal and required ESP32 reboot to recover from a peer
         * outage longer than 60 s. Instead, sleep WG_HANDSHAKE_BACKOFF_MS
         * and start a fresh burst. The peer can be down for any
         * duration; the firmware recovers automatically on its next
         * burst after peer returns. We back-date last_handshake_us so
         * the next iteration of this block fires WG_HANDSHAKE_BACKOFF_MS
         * from now (rather than the 5 s that the unmodified
         * `now - last > REKEY_TIMEOUT` predicate would yield). */
        if (g.state == WG_NETIF_HANDSHAKE_PENDING &&
            wg_timer_due(now, g.last_handshake_us, handshake_retry_us())) {
            if (g.handshake_attempt >= WG_HANDSHAKE_MAX_RETRIES) {
                ESP_LOGW(TAG, "handshake budget exhausted (%d × %ds = %ds) — "
                              "backing off %ds before next burst (peer may be "
                              "rebooting)",
                         WG_HANDSHAKE_MAX_RETRIES,
                         WG_REKEY_TIMEOUT_MS / 1000,
                         (WG_HANDSHAKE_MAX_RETRIES * WG_REKEY_TIMEOUT_MS) / 1000,
                         WG_HANDSHAKE_BACKOFF_MS / 1000);
                g.handshake_attempt = 0;
                /* Schedule the NEXT retry attempt to fire WG_HANDSHAKE_BACKOFF_MS
                 * from now: pretend last_handshake_us is in the future, so the
                 * `now - last > WG_REKEY_TIMEOUT_MS` predicate above evaluates
                 * false until enough wall-clock time has elapsed. The +1 us
                 * avoids the corner where the math evaluates exactly equal. */
                g.last_handshake_us = now +
                    (WG_HANDSHAKE_BACKOFF_MS - WG_REKEY_TIMEOUT_MS) * 1000LL + 1;
            } else {
                ESP_LOGW(TAG, "handshake retry %d", g.handshake_attempt + 1);
                kick_off_handshake();
            }
        }

        /* Proactive rekey trigger. Only meaningful in steady state
         * (UP, no INIT in flight, completed at least one full
         * handshake). Fires once per rekey window — start_rekey sets
         * rekey_in_flight = true, which gates further entries here
         * until the response lands or the rekey-retry block below
         * gives up. */
        if (g.state == WG_NETIF_UP && !g.rekey_in_flight &&
            g.last_handshake_completed_us > 0 &&
            wg_timer_due(now, g.last_handshake_completed_us,
                         WG_REKEY_AFTER_MS * 1000LL)) {
            ESP_LOGI(TAG, "session age >%ds — triggering proactive rekey",
                     WG_REKEY_AFTER_MS / 1000);
            g.rekey_attempt = 0;
            start_rekey();
        }

        /* Active DISCO probe of alternate peer endpoints. Fires when
         * the WG transport has been silent for WG_RX_STALE_THRESHOLD_MS,
         * INDEPENDENTLY of which handshake state we're in (UP +
         * rekey-in-flight, HANDSHAKE_PENDING during cold retries — both
         * benefit). Throttled to WG_PATH_PROBE_COOLDOWN_MS so a long
         * outage doesn't burst-spam at every rx_task tick.
         *
         * The callback (registered by tinylink.c) sends DISCO pings to
         * every endpoint in the latest netmap's peers list. If the peer
         * responds from an AddrPort other than the one we're currently
         * targeting, handle_disco_direct's PONG branch swaps
         * g.peer.peer_endpoint to the live address — so the NEXT rekey
         * or cold-handshake INIT goes to a reachable place rather than
         * a stale NAT mapping. Without this the device hammers a dead
         * endpoint for the full handshake budget (60 s rekey + 60 s
         * cold + 30 s backoff = 2.5 min minimum), even when alternative
         * endpoints (LAN-direct, fresh STUN-learned port) are listed
         * in the netmap and immediately reachable.
         *
         * Modeled on upstream tailscale (endpoint.go:
         * setBestAddrLocked): the DISCO pong is the authoritative
         * liveness signal; we use it to pick a working path
         * before/instead of relying on WG handshake to surface a dead
         * one. */
        if ((g.state == WG_NETIF_UP || g.state == WG_NETIF_HANDSHAKE_PENDING) &&
            g.path_stale_cb != NULL &&
            g.last_transport_recv_us > 0 &&
            wg_timer_due(now, g.last_transport_recv_us,
                         WG_RX_STALE_THRESHOLD_MS * 1000LL) &&
            wg_timer_due(now, g.last_path_probe_us,
                         WG_PATH_PROBE_COOLDOWN_MS * 1000LL)) {
            g.last_path_probe_us = now;
            ESP_LOGI(TAG, "path stale (>%ds no transport decrypt) — "
                          "probing alternate peer endpoints via DISCO",
                     WG_RX_STALE_THRESHOLD_MS / 1000);
            g.path_stale_cb(g.path_stale_cb_user);
        }

        /* RX-stale watchdog. Detects "peer restarted" silent black-hole:
         * peer's tailscaled lost session keys (e.g. reboot,
         * `tailscale down && tailscale up`), our outbound transport
         * encrypts cleanly but the peer drops every datagram. Symptom:
         * we are sending (telemetry, ICMP replies) but receiving nothing
         * back — neither data nor zero-plaintext keepalives. Without
         * this watchdog, the firmware doesn't notice until the
         * age-based rekey above fires (worst case 110 s of silent loss
         * after a peer restart that lands right after a successful
         * rekey). 30 s threshold is well above WG persistent-keepalive
         * (25 s) and Tailscale's typical DISCO cadence, so genuine RX
         * silence on the WG transport for 30 s is abnormal. Same
         * make-before-break path as the proactive rekey — keys swap
         * only when the response lands, no observable downtime if the
         * peer is actually fine and just briefly silent. */
        if (g.state == WG_NETIF_UP && !g.rekey_in_flight &&
            g.last_transport_recv_us > 0 &&
            wg_timer_due(now, g.last_transport_recv_us,
                         WG_RX_STALE_THRESHOLD_MS * 1000LL)) {
            ESP_LOGW(TAG, "RX stale >%ds (no transport decrypt since) — "
                          "forcing rekey (suspected peer restart)",
                     WG_RX_STALE_THRESHOLD_MS / 1000);
            g.stat_rx_stale++;
            g.rekey_attempt = 0;
            /* Reset the watchdog clock so the rekey-in-flight has its
             * own grace window (the rekey-retry block below handles
             * rekey-itself-failed). Without this, if rekey INIT also
             * doesn't get a response, we'd keep tripping this branch on
             * every rx_task wake. Reset BEFORE the send: an ENETUNREACH
             * from it backdates the clock again (send_to_peer) so the
             * path probe still fires at the next wake. */
            g.last_transport_recv_us = now;
            start_rekey();
        }

        /* Rekey retry timer. Mirrors the cold-path retry but does NOT
         * tear down the live session on failure — if all attempts miss,
         * we fall back to a cold handshake (state = PENDING) which
         * pauses app traffic and uses the aggressive cold retry budget.
         * That fallback path matters because by then session age is
         * ~170 s and the responder is about to invalidate our keys
         * anyway; better a brief outage now than a silent black hole. */
        if (g.rekey_in_flight &&
            wg_timer_due(now, g.last_handshake_us, WG_REKEY_TIMEOUT_MS * 1000LL)) {
            if (g.rekey_attempt >= WG_HANDSHAKE_MAX_RETRIES) {
                ESP_LOGW(TAG, "proactive rekey exhausted after %d attempts — "
                              "falling back to cold handshake",
                         g.rekey_attempt);
                g.rekey_in_flight = false;
                g.rekey_attempt = 0;
                g.handshake_attempt = 0;
                g.state = WG_NETIF_HANDSHAKE_PENDING;
                kick_off_handshake();
            } else {
                ESP_LOGW(TAG, "rekey retry %d", g.rekey_attempt + 1);
                start_rekey();
            }
        }
        xSemaphoreGive(g.hs_lock);

        /* Persistent-keepalive trigger. WG NAT mappings on the
         * outbound path decay after ~30-60 s of idle (CGNAT being the
         * common offender). In normal operation telemetry tick at 5 s
         * keeps it warm; if telemetry pauses (sensor disabled, I²C
         * stall) the mapping silently expires and the next packet
         * lands at an unallocated port on the peer's NAT — dropped.
         * Send a zero-byte WG transport packet after
         * WG_PERSISTENT_KEEPALIVE_MS of outbound silence; the peer
         * accepts it (legitimate WG keepalive) and the sendto refreshes
         * the upstream NAT mapping. wg_netif_send_plaintext is mutex-
         * protected so this rx_task path does not race with TCPIP-side
         * encrypts on g.transport.send_counter. */
        if (g.state == WG_NETIF_UP && g.last_tx_us > 0 &&
            wg_timer_due(now, g.last_tx_us,
                         WG_PERSISTENT_KEEPALIVE_MS * 1000LL)) {
            esp_err_t err = wg_netif_send_plaintext(NULL, 0);
            if (err == ESP_OK) {
                ESP_LOGD(TAG, "persistent keepalive sent (0 B)");
            } else {
                ESP_LOGW(TAG,
                    "persistent keepalive failed: 0x%x", err);
                /* Try again in ~1 s (the old tick), not on every wake:
                 * the deadline-based wait would otherwise spin on a
                 * full TX ring. */
                g.last_tx_us = now -
                    (WG_PERSISTENT_KEEPALIVE_MS - 1000) * 1000LL;
            }
        }

        /* Sleep until the next timer deadline (B7). Until 1.3.1 the
         * wait was a fixed 1-s tick, so a REKEY_TIMEOUT retry fired 5–6 s
         * after its INIT. setsockopt only when the value changes. */
        const uint32_t want_ms = rx_plan_wait_ms();
        if (want_ms != rcv_ms) {
            rcv_ms = want_ms;
            tv.tv_sec  = rcv_ms / 1000;
            tv.tv_usec = (rcv_ms % 1000) * 1000;
            setsockopt(g.sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        }
    }

    ESP_LOGI(TAG, "rx task exiting");
    tl_wdt_unsubscribe();
    vTaskDelete(NULL);
}

/* Send one filled TX slot: DERP relay when the direct path is stale,
 * direct sendto otherwise (relay again on a sendto error); both while a
 * DERP-completed session has no confirmed direct path (B7). */
static void tx_send_item(const wg_tx_item_t *it, int64_t now)
{
    uint8_t dst_pub[WG_KEY_LEN];   /* filled only when relaying */
    if (it->relay_only) {
        /* DERP copy of a handshake INIT (B7). The direct copy already
         * went out from the task that built or re-sent it. A relay that
         * is not up yet (boot: INIT at netmap time, DERP login ~2 s
         * later) declines — dropped silently, the login kick re-sends. */
        if (g.relay_cb != NULL) {
            peer_static_snapshot(dst_pub);
            (void)g.relay_cb(dst_pub, it->buf, it->len, true, g.relay_cb_user);
        }
        return;
    }

    /* Preemptive DERP relay when the path-stale watchdog has fired
     * (RX has been silent past WG_RX_STALE_THRESHOLD_MS). Direct
     * UDP is almost certainly going to a black hole at this point
     * (peer NAT mapping aged out, peer changed WAN endpoint, etc.).
     * Skipping the direct sendto when the relay accepts the bytes
     * is the lossless-during-recovery property — without it, those
     * 30 s of telemetry packets between path-goes-stale and
     * peer-roam-handshake-completes are dropped silently. */
    bool path_stale =
        g.relay_cb != NULL &&
        g.state == WG_NETIF_UP &&
        g.last_transport_recv_us > 0 &&
        wg_timer_due(now, g.last_transport_recv_us,
                     (int64_t)WG_RX_STALE_THRESHOLD_MS * 1000LL);
    /* The session came up on a DERP-relayed response and nothing has
     * authenticated on the UDP socket since: the direct path is
     * unproven (at boot the peer may not have punched its side yet), so
     * send on both — magicsock's untrusted-bestAddr behaviour. The peer's
     * replay window drops whichever copy lands second. Ends at the
     * first direct transport / response / pong ("direct path
     * confirmed" log); a dead direct path falls to path_stale above. */
    const bool dual =
        !path_stale && g.relay_cb != NULL &&
        g.state == WG_NETIF_UP && g.session_via_relay &&
        g.last_direct_rx_us < g.last_handshake_completed_us;
    if (path_stale) {
        peer_static_snapshot(dst_pub);
        esp_err_t rerr = g.relay_cb(dst_pub, it->buf, it->len, false,
                                    g.relay_cb_user);
        if (rerr == ESP_OK) {
            g.relayed_stale++;
            return;  /* skip direct sendto: already shipped via relay */
        }
        /* relay declined (e.g. supervisor not connected) — fall
         * through to direct sendto. Errors logged once per worker
         * iteration cap below to avoid UART spam during sustained
         * relay-unavailable windows. */
        g.relay_errors++;
    }

    ssize_t n = sendto(g.sock, it->buf, it->len, 0,
                       (const struct sockaddr *)&it->dst, sizeof(it->dst));
    if (dual) {
        if (n < 0) ESP_LOGW(TAG, "tx sendto: errno=%d", errno);
        peer_static_snapshot(dst_pub);
        /* Best effort: a stalled DERP conn must not hold up the
         * direct path, which this item already used above. */
        if (g.relay_cb(dst_pub, it->buf, it->len, true,
                       g.relay_cb_user) != ESP_OK) {
            g.relay_errors++;
        }
        return;
    }
    if (n < 0) {
        ESP_LOGW(TAG, "tx sendto: errno=%d", errno);
        /* Direct UDP outright failed (ENETUNREACH, EHOSTUNREACH,
         * EAGAIN under load). Try the relay as a last resort. The
         * path_stale branch above already attempted it if relevant,
         * so we only re-try here when path wasn't yet marked stale
         * (i.e. errno arrived before the watchdog tripped). */
        if (!path_stale && g.relay_cb != NULL) {
            peer_static_snapshot(dst_pub);
            esp_err_t rerr = g.relay_cb(dst_pub, it->buf, it->len, false,
                                        g.relay_cb_user);
            if (rerr == ESP_OK) {
                g.relayed_errno++;
            } else {
                g.relay_errors++;
            }
        }
    }
}

/* TX worker: drains tx_ready_q + sendto outside the lwIP TCPIP task.
 * Gives tx_done_sem as the last thing before vTaskDelete(NULL) so
 * wg_netif_stop can wait for clean exit before destroying the queues. */
static void tx_task_fn(void *arg)
{
    (void)arg;
    tl_wdt_subscribe();
    int64_t last_feed_us = 0;
    while (!g.stop_requested) {
        /* Blocks until a frame (or wg_netif_stop's sentinel) arrives;
         * the timeout only paces the WDT feed. Only the slot index is
         * copied; the frame stays in its heap slot, off this stack
         * (sendto recurses into the WiFi TX callback chain). */
        uint8_t slot;
        const BaseType_t got = xQueueReceive(g.tx_ready_q, &slot,
                                             pdMS_TO_TICKS(WG_TX_IDLE_WAIT_MS));
        const int64_t now = now_us();
        wdt_feed_throttled(now, &last_feed_us);
        if (got != pdTRUE || slot >= WG_TX_SLOTS) {
            continue;   /* idle, or the stop sentinel (loop re-checks) */
        }
        tx_send_item(&g.tx_slots[slot], now);
        (void)xQueueSend(g.tx_free_q, &slot, 0);   /* never full */
    }
    if (g.tx_done_sem != NULL) {
        xSemaphoreGive(g.tx_done_sem);
    }
    tl_wdt_unsubscribe();
    vTaskDelete(NULL);
}

/* Allocate the TX slots (one heap block, like the old queue storage)
 * and the two index queues; every slot starts free. Boot-time only. */
static esp_err_t tx_ring_create(void)
{
    g.tx_slots   = calloc(WG_TX_SLOTS, sizeof(wg_tx_item_t));
    g.tx_free_q  = xQueueCreate(WG_TX_SLOTS, sizeof(uint8_t));
    g.tx_ready_q = xQueueCreate(WG_TX_SLOTS + 1, sizeof(uint8_t));
    if (g.tx_slots == NULL || g.tx_free_q == NULL || g.tx_ready_q == NULL) {
        return ESP_ERR_NO_MEM;   /* caller runs tx_ring_destroy() */
    }
    for (uint8_t i = 0; i < WG_TX_SLOTS; i++) {
        (void)xQueueSend(g.tx_free_q, &i, 0);
    }
    return ESP_OK;
}

static void tx_ring_destroy(void)
{
    if (g.tx_free_q != NULL)  { vQueueDelete(g.tx_free_q);  g.tx_free_q  = NULL; }
    if (g.tx_ready_q != NULL) { vQueueDelete(g.tx_ready_q); g.tx_ready_q = NULL; }
    if (g.tx_slots != NULL) {
        tl_secure_zero(g.tx_slots, WG_TX_SLOTS * sizeof(wg_tx_item_t));
        free(g.tx_slots);
        g.tx_slots = NULL;
    }
}

/* --- Public API ----------------------------------------------------- */

esp_err_t wg_netif_init(const struct wg_netif_local_config *local)
{
    if (g.initialized) return ESP_OK;
    if (local == NULL) return ESP_ERR_INVALID_ARG;

    memset(&g, 0, sizeof(g));
    memcpy(&g.local, local, sizeof(*local));

    /* Prepare the outbound-prober txid table. Both the supervisor task
     * (record outbound pings) and wg_rx (match inbound pongs) will use
     * it; idempotent so a second wg_netif_init / re-init is safe. */
    disco_prober_init();

    g.lock = xSemaphoreCreateMutex();
    if (g.lock == NULL) return ESP_ERR_NO_MEM;
    g.hs_lock = xSemaphoreCreateMutex();
    if (g.hs_lock == NULL) return ESP_ERR_NO_MEM;

    g.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g.sock < 0) {
        ESP_LOGE(TAG, "socket: errno=%d", errno);
        return ESP_FAIL;
    }
    struct sockaddr_in bind_addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(local->bind_port),  /* 0 = ephemeral */
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(g.sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        ESP_LOGE(TAG, "bind: errno=%d", errno);
        close(g.sock);
        return ESP_FAIL;
    }
    /* Read back the actual bound port (informational). */
    socklen_t alen = sizeof(bind_addr);
    if (getsockname(g.sock, (struct sockaddr *)&bind_addr, &alen) == 0) {
        g.bind_port_actual = ntohs(bind_addr.sin_port);
    }
    ESP_LOGI(TAG, "udp bound on port %u", (unsigned)g.bind_port_actual);

    if (tx_ring_create() != ESP_OK) {
        ESP_LOGE(TAG, "tx ring alloc failed");
        close(g.sock);
        return ESP_ERR_NO_MEM;
    }
    g.tx_done_sem = xSemaphoreCreateBinary();
    if (g.tx_done_sem == NULL) {
        ESP_LOGE(TAG, "tx_done_sem create failed");
        tx_ring_destroy();
        close(g.sock);
        return ESP_ERR_NO_MEM;
    }
    BaseType_t ok = xTaskCreate(tx_task_fn, "wg_tx",
                                WG_TX_TASK_STACK_BYTES, NULL,
                                WG_TX_TASK_PRIO, &g.tx_task);
    if (ok != pdPASS) {
        ESP_LOGE(TAG, "tx task spawn failed");
        vSemaphoreDelete(g.tx_done_sem);
        g.tx_done_sem = NULL;
        tx_ring_destroy();
        close(g.sock);
        return ESP_ERR_NO_MEM;
    }

    /* Best effort: without it a long Wi-Fi outage recovers at the next
     * handshake burst instead of at the next RX wake. */
    if (esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                   on_sta_got_ip, NULL) != ESP_OK) {
        ESP_LOGW(TAG, "GOT_IP handler not registered");
    }

    g.state       = WG_NETIF_IDLE;
    g.initialized = true;
    return ESP_OK;
}

esp_err_t wg_netif_start(const struct wg_netif_peer_config *peer)
{
    if (!g.initialized) return ESP_ERR_INVALID_STATE;
    if (peer == NULL) return ESP_ERR_INVALID_ARG;

    memcpy(&g.peer, peer, sizeof(*peer));
    rebuild_peer_sockaddr();

    /* Precompute the NaCl-box shared key for the direct DISCO RX hot
     * path. Done here (not at init time) because the peer DiscoKey is
     * peer config, not local config. If the X25519 yields zero (peer
     * pub is low-order) we mark the cache invalid and fall through to
     * the per-frame compute path — the same path also handles bringups
     * that don't pass a DiscoKey at all (has_peer_disco_pub == false). */
    g.peer_disco_shared_k_valid = false;
    if (g.peer.has_peer_disco_pub) {
        if (nacl_box_compute_shared(g.peer_disco_shared_k,
                                    g.peer.peer_disco_pub,
                                    g.local.disco_priv) == 0) {
            g.peer_disco_shared_k_valid = true;
        } else {
            ESP_LOGW(TAG,
                "peer_disco_pub low-order; shared-K cache disabled");
        }
    }

    g.handshake_attempt = 0;
    g.rekey_attempt = 0;
    g.rekey_in_flight = false;
    g.last_handshake_completed_us = 0;
    g.last_transport_recv_us = 0;  /* watchdog disarmed until session up */
    /* Under hs_lock like every other INIT build: when the first netmap
     * is late the DERP supervisor is already up, and its B7 kicks
     * (init_resend) read g.init_msg while this writes it. */
    xSemaphoreTake(g.hs_lock, portMAX_DELAY);
    const int kick_rc = kick_off_handshake();
    xSemaphoreGive(g.hs_lock);
    if (kick_rc != 0) return ESP_FAIL;

    BaseType_t ok = xTaskCreate(rx_task, "wg_rx",
                                WG_RX_TASK_STACK_BYTES, NULL,
                                WG_RX_TASK_PRIO, &g.rx_task);
    if (ok != pdPASS) {
        ESP_LOGE(TAG, "xTaskCreate(wg_rx) failed");
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

esp_err_t wg_netif_update_peer_endpoint(uint32_t v4_be, uint16_t port)
{
    if (!g.initialized) return ESP_ERR_INVALID_STATE;
    xSemaphoreTake(g.lock, portMAX_DELAY);
    g.peer.peer_endpoint_v4_be = v4_be;
    g.peer.peer_endpoint_port  = port;
    rebuild_peer_sockaddr();
    xSemaphoreGive(g.lock);
    /* Existing transport session keys remain valid — endpoint roaming
     * doesn't invalidate keys (per WG roaming spec). Subsequent
     * outgoing packets land at the new endpoint. */
    return ESP_OK;
}

esp_err_t wg_netif_update_peer_keys(const uint8_t static_pub[WG_KEY_LEN],
                                    const uint8_t *disco_pub)
{
    if (!g.initialized) return ESP_ERR_INVALID_STATE;
    if (static_pub == NULL) return ESP_ERR_INVALID_ARG;

    /* X25519 + HSalsa20 for the new DISCO shared key runs here, in the
     * caller's task (the long-poll task, 24 KiB stack) and outside both
     * locks, so neither the swap nor wg_rx waits ~20 ms on it
     * (X25519 also needs ~1 KiB of stack; 2.7 KiB before 1.3.3). */
    uint8_t k[WG_KEY_LEN];
    bool    k_ok = false;
    if (disco_pub != NULL) {
        k_ok = nacl_box_compute_shared(k, disco_pub, g.local.disco_priv) == 0;
    }

    xSemaphoreTake(g.hs_lock, portMAX_DELAY);
    const bool static_changed =
        memcmp(g.peer.peer_static_pub, static_pub, WG_KEY_LEN) != 0;
    xSemaphoreTake(g.lock, portMAX_DELAY);
    if (static_changed) {
        memcpy(g.peer.peer_static_pub, static_pub, WG_KEY_LEN);
    }
    if (disco_pub != NULL) {
        memcpy(g.peer.peer_disco_pub, disco_pub, WG_KEY_LEN);
        g.peer.has_peer_disco_pub = true;
        memcpy(g.peer_disco_shared_k, k, WG_KEY_LEN);
        g.peer_disco_shared_k_valid = k_ok;
    }
    xSemaphoreGive(g.lock);
    if (static_changed) {
        /* Peer re-login: the live session belongs to an identity that no
         * longer exists and the peer will not answer a rekey for it.
         * Start over with a cold handshake to the new static key (app
         * traffic pauses until it lands, as at boot). */
        g.rekey_in_flight = false;
        g.rekey_attempt = 0;
        g.handshake_attempt = 0;
        ESP_LOGI(TAG, "peer static key changed — cold handshake");
        (void)kick_off_handshake();
    }
    xSemaphoreGive(g.hs_lock);
    tl_secure_zero(k, sizeof(k));
    return ESP_OK;
}

esp_err_t wg_netif_inject_packet(const uint8_t *src_node_pub,
                                 const uint8_t *buf, size_t len)
{
    if (!g.initialized) return ESP_ERR_INVALID_STATE;
    if (src_node_pub == NULL || buf == NULL || len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    /* Constant-time-ish equality check is overkill here: the src_pub
     * comes from a DERP frame the relay authenticated against the
     * peer's NodeKey, so an adversary can't trivially spoof it. A
     * mismatch here means a different peer (CC'd PEER_PRESENT, etc.)
     * — drop. */
    uint8_t peer_pub[WG_KEY_LEN];
    peer_static_snapshot(peer_pub);
    if (memcmp(src_node_pub, peer_pub, WG_KEY_LEN) != 0) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    wg_demux_kind_t kind = wg_demux_classify(buf, len);
    switch (kind) {
    case WG_DEMUX_HANDSHAKE_RESP:
        if (handle_handshake_response(buf, len, true)) send_disco_advert();
        return ESP_OK;
    case WG_DEMUX_TRANSPORT:
        (void)handle_transport(buf, len);
        return ESP_OK;
    case WG_DEMUX_HANDSHAKE_INIT:
    case WG_DEMUX_HANDSHAKE_COOKIE:
    case WG_DEMUX_DISCO:
    case WG_DEMUX_STUN:
    case WG_DEMUX_DISCARD:
    default:
        /* Initiator-only and out-of-scope kinds match the UDP RX
         * task policy: silently drop. DISCO via DERP is already
         * processed by handle_disco_relayed before we get here. */
        return ESP_OK;
    }
}

void wg_netif_handshake_kick(wg_netif_kick_t why)
{
    if (!g.initialized || g.hs_lock == NULL) return;
    /* Lock order hs_lock → g.lock (peer_addr snapshot); the DERP copy is
     * queued for wg_tx, never written to TLS under a wg lock — callers
     * run in the DERP task. */
    xSemaphoreTake(g.hs_lock, portMAX_DELAY);
    switch (why) {
    case WG_NETIF_KICK_RELAY_UP:
        /* The INIT's own DERP copy (if any) was declined while the relay
         * was down: re-queue it now, past the per-path gate — or, if it
         * is older than WG_INIT_FRESH_AFTER_MS, replace it: the peer may
         * have consumed it and answered into the relay that was down. */
        init_refresh_or_resend(false, true, true, "DERP relay up");
        break;
    case WG_NETIF_KICK_CALL_ME_MAYBE:
        /* The peer is punching towards our endpoints right now: its NAT
         * has a mapping for us, so the direct copy can get through. */
        init_resend(true, !direct_path_confirmed(now_us()), false,
                    "call-me-maybe");
        break;
    }
    xSemaphoreGive(g.hs_lock);
}

esp_err_t wg_netif_send_plaintext(const uint8_t *pkt, size_t len)
{
    if (!g.initialized || g.state != WG_NETIF_UP) {
        return ESP_ERR_INVALID_STATE;
    }
    if (len + WG_TRANSPORT_OVERHEAD > WG_RX_BUF_LEN) {
        return ESP_ERR_INVALID_SIZE;
    }
    /* Encrypt inline. ChaCha20-Poly1305 is pure CPU + memory and is
     * safe to run on the lwIP TCPIP task. The actual sendto is what
     * re-enters lwIP — that's why the wire bytes are handed off to the
     * tx worker via the TX ring instead of called here directly.
     *
     * Claim a free slot first (B14): the frame is encrypted straight
     * into it (heap, off the TCPIP task's small stack) and only its
     * index is queued. No free slot = the old "queue full": drop this
     * frame; lwIP treats any non-OK return as a TX failure and discards
     * its pbuf. The worker is either starving (priority) or stuck in
     * sendto — log throttled so UART doesn't spam if backlog runs hot
     * for a sustained burst. */
    uint8_t slot;
    if (xQueueReceive(g.tx_free_q, &slot, 0) != pdTRUE) {
        uint64_t prev = g.tx_drops++;
        if ((prev % WG_TX_DROP_LOG_EVERY) == 0) {
            ESP_LOGW(TAG, "tx queue full — dropped frame (total=%lu)",
                     (unsigned long)g.tx_drops);
        }
        return ESP_FAIL;
    }
    wg_tx_item_t *it = &g.tx_slots[slot];

    /* Encrypt + enqueue under g.lock so a concurrent caller (lwIP
     * TCPIP for app traffic vs rx_task for the persistent-keepalive
     * path) cannot race on g.transport.send_counter —
     * `wg_transport_encrypt` reads-modifies-writes the 64-bit counter,
     * which is NOT atomic on ESP32-LX6 — and frames reach tx_ready_q in
     * counter order. */
    xSemaphoreTake(g.lock, portMAX_DELAY);
    int wlen = wg_transport_encrypt(&g.transport,
                                    it->buf, sizeof(it->buf), pkt, len);
    if (wlen < 0) {
        xSemaphoreGive(g.lock);
        (void)xQueueSend(g.tx_free_q, &slot, 0);
        return ESP_FAIL;
    }
    it->len = (size_t)wlen;
    it->relay_only = false;
    /* Snapshot the dest sockaddr at enqueue time so a concurrent
     * wg_netif_update_peer_endpoint after we release can't redirect a
     * frame whose counter is already committed. */
    it->dst = g.peer_addr;
    (void)xQueueSend(g.tx_ready_q, &slot, 0);   /* WG_TX_SLOTS + 1 deep: never full */
    xSemaphoreGive(g.lock);

    g.last_tx_us = now_us();
    return ESP_OK;
}

void wg_netif_set_rx_callback(wg_netif_rx_cb_t cb, void *user)
{
    g.rx_cb      = cb;
    g.rx_cb_user = user;
}

void wg_netif_set_stun_callback(wg_netif_stun_cb_t cb, void *user)
{
    g.stun_cb      = cb;
    g.stun_cb_user = user;
}

void wg_netif_set_path_stale_callback(wg_netif_path_stale_cb_t cb, void *user)
{
    g.path_stale_cb      = cb;
    g.path_stale_cb_user = user;
}

void wg_netif_set_relay_callback(wg_netif_relay_fn cb, void *user)
{
    g.relay_cb      = cb;
    g.relay_cb_user = user;
}

bool wg_netif_is_up(void)
{
    return g.initialized && g.state == WG_NETIF_UP;
}

void wg_netif_stop(void)
{
    if (!g.initialized) return;
    g.stop_requested = true;
    /* Wait for the TX worker to observe stop_requested and exit before
     * we tear down its queues; otherwise vQueueDelete can race against
     * an in-flight xQueueReceive. The sentinel wakes it at once (its idle
     * wait is WG_TX_IDLE_WAIT_MS); tx_ready_q has a spare entry for it.
     * 2 s is comfortable margin even under priority pressure. The RX
     * task observes stop_requested when close() below ends its recvfrom
     * (or at its next deadline wake) and self-deletes; we don't gate on
     * it here because nothing it touches gets freed below. */
    if (g.tx_ready_q != NULL) {
        const uint8_t stop = WG_TX_SLOT_STOP;
        (void)xQueueSend(g.tx_ready_q, &stop, 0);
    }
    (void)esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                       on_sta_got_ip);
    bool tx_exited = true;
    if (g.tx_done_sem != NULL) {
        if (xSemaphoreTake(g.tx_done_sem, pdMS_TO_TICKS(2000)) != pdTRUE) {
            ESP_LOGW(TAG, "tx task did not exit within 2s — forcing teardown");
            tx_exited = false;
        }
    }
    /* A worker still inside tx_send_item (e.g. a blocked DERP TLS write)
     * would touch a freed slot and deleted queues: leak the ring (~6 KB,
     * start-failure path only) rather than risk a use-after-free. */
    if (tx_exited) {
        tx_ring_destroy();
    }
    g.init_valid = false;
    if (g.tx_done_sem != NULL) {
        vSemaphoreDelete(g.tx_done_sem);
        g.tx_done_sem = NULL;
    }
    if (g.sock >= 0) {
        close(g.sock);
        g.sock = -1;
    }
    wg_handshake_scrub(&g.handshake);
    tl_secure_zero(&g.transport, sizeof(g.transport));
    /* Scrub the cached shared-K so a future wg_netif_start with a
     * different peer DiscoKey can't accidentally reuse stale K. */
    tl_secure_zero(g.peer_disco_shared_k, sizeof(g.peer_disco_shared_k));
    g.peer_disco_shared_k_valid = false;
    g.initialized = false;
}

uint64_t wg_netif_get_tx_drops(void)
{
    return g.tx_drops;
}

uint64_t wg_netif_get_relayed_stale(void)
{
    return g.relayed_stale;
}

uint64_t wg_netif_get_relayed_errno(void)
{
    return g.relayed_errno;
}

uint64_t wg_netif_get_relay_errors(void)
{
    return g.relay_errors;
}

int wg_netif_get_socket(void)
{
    return g.initialized ? g.sock : -1;
}

bool wg_netif_rx_running(void)
{
    return g.rx_task != NULL;
}

void wg_netif_get_stats(wg_netif_stats_t *out)
{
    if (out == NULL) return;
    memset(out, 0, sizeof(*out));
    out->state                 = (int)g.state;
    out->rekeys                = g.stat_rekeys;
    out->cold_handshakes       = g.stat_cold_handshakes;
    out->rx_stale_events       = g.stat_rx_stale;
    out->roams                 = g.stat_roams;
    out->disco_adverts         = g.stat_disco_adverts;
    out->tx_drops              = g.tx_drops;
    out->relayed_stale         = g.relayed_stale;
    out->relay_errors          = g.relay_errors;
    out->last_transport_recv_us = g.last_transport_recv_us;
    out->last_handshake_completed_us = g.last_handshake_completed_us;
}

bool wg_netif_get_peer_endpoint(uint32_t *v4_be, uint16_t *port)
{
    if (!g.initialized || v4_be == NULL || port == NULL) return false;
    xSemaphoreTake(g.lock, portMAX_DELAY);
    *v4_be = g.peer.peer_endpoint_v4_be;
    *port  = g.peer.peer_endpoint_port;
    xSemaphoreGive(g.lock);
    return *v4_be != 0;
}

bool wg_netif_path_alive(void)
{
    if (!g.initialized) return false;
    xSemaphoreTake(g.lock, portMAX_DELAY);
    const int64_t last = g.last_transport_recv_us;
    xSemaphoreGive(g.lock);
    return g.state == WG_NETIF_UP && last > 0 &&
           (now_us() - last) <= (int64_t)WG_RX_STALE_THRESHOLD_MS * 1000LL;
}

bool wg_netif_get_peer_disco_pub(uint8_t out[WG_KEY_LEN])
{
    if (!g.initialized) return false;
    xSemaphoreTake(g.lock, portMAX_DELAY);
    const bool have = g.peer.has_peer_disco_pub;
    if (have) memcpy(out, g.peer.peer_disco_pub, WG_KEY_LEN);
    xSemaphoreGive(g.lock);
    return have;
}

#endif /* ESP_PLATFORM */
