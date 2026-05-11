// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#ifdef ESP_PLATFORM

#include "wg_netif.h"

#include <errno.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"

#include "lwip/inet.h"
#include "lwip/sockets.h"

#include "disco_handler.h"
#include "disco_replay.h"
#include "wg_demux.h"
#include "wg_handshake.h"
#include "wg_transport.h"

static const char *TAG = "wg_netif";

/* Handshake retry policy: WG whitepaper §6.5 prescribes
 * REKEY_TIMEOUT = 5 s with a max of 18 retries (REJECT_AFTER_TIME =
 * 180 s). For first-version tinylink we use a slightly tighter budget
 * (5 s × 12 = 60 s) — long enough that a slow network completes,
 * short enough that the user notices a dead peer. */
#define WG_REKEY_TIMEOUT_MS  5000
#define WG_HANDSHAKE_MAX_RETRIES 12

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
 * crypto on the stack → disco_seal → sendto into WiFi TX). */
#define WG_RX_TASK_STACK_BYTES 8192
#define WG_RX_TASK_PRIO        (tskIDLE_PRIORITY + 3)

/* TX worker task: drains the outbound queue and runs sendto outside
 * the lwIP TCPIP context (calling sendto from there re-enters the
 * lwIP socket API and posts a tcpip_callback that the TCPIP task
 * itself would have to drain — guaranteed deadlock). One step below
 * the RX task so packet decode wins under load.
 *
 * Stack: 8 KiB. Earlier budget was 4 KiB (sendto recursing into the
 * WiFi driver TX callback chain measured >2 KiB; canary tripped at
 * 3 KiB on first sizing). That margin was marginal pre-PR-#65 and
 * insufficient post-#65 where the tinylink + main + mbedcrypto
 * components compile at -O2: aggressive inlining grows the effective
 * stack frame of the sendto path (lwIP linkoutput → wg_transport
 * encrypt → sendto → WiFi driver TX queue) past the 4 KiB ceiling.
 * Caught 2026-05-11 in /tmp/tinylink_capture_2026-05-11_validate_v2.log
 * at uptime 880578 ms: `wg_netif: session up` (a single legitimate
 * telemetry packet hitting the path after a 9-minute outage)
 * immediately followed by
 * `***ERROR*** A stack overflow in task wg_tx has been detected.`
 * + SW_CPU_RESET. The queue length (WG_TX_QUEUE_LEN=3) makes a real
 * flood impossible — drops happen at xQueueSend(..., 0) when full.
 * 8 KiB matches WG_RX_TASK_STACK_BYTES, gives ~5 KiB headroom over
 * the empirical 3 KiB peak, and absorbs the -O2 frame growth without
 * needing per-component tuning. The 1.5 KiB queue item still stays
 * OFF this stack (in g.tx_worker_scratch). */
#define WG_TX_TASK_STACK_BYTES 8192
#define WG_TX_TASK_PRIO        (tskIDLE_PRIORITY + 2)

/* Outbound TX queue depth. At 1.5 KiB per item, 3 items = 4.7 KiB
 * heap. Telemetry ticks every 5 s and ICMP responses are sporadic;
 * realistic burst depth is 1–2. Three gives margin without waste.
 * If this ever fills under steady-state operation it shows up in
 * wg_netif_get_tx_drops + the throttled drop log below. */
#define WG_TX_QUEUE_LEN        3

/* Drop-on-full log throttle. Print one warning per N drops so the
 * UART doesn't spam if the worker is stuck for an extended window. */
#define WG_TX_DROP_LOG_EVERY   64

/* Largest WG datagram we accept on the wire. WG transport packets are
 * usually MTU-bounded; with our 1.5 KiB upper bound we have plenty of
 * headroom for IPv4 over WG. */
#define WG_RX_BUF_LEN 1536

/* Item shipped from wg_netif_send_plaintext (lwIP TCPIP context) to
 * the TX worker task. Carries the already-encrypted wire bytes plus a
 * snapshot of the destination sockaddr — snapshotting avoids racing
 * wg_netif_update_peer_endpoint between encrypt and send (the WG spec
 * tolerates a short trailing window of packets to the old endpoint
 * during roaming, so the old snapshot landing is fine). */
typedef struct {
    size_t              len;
    struct sockaddr_in  dst;
    uint8_t             buf[WG_RX_BUF_LEN];
} wg_tx_item_t;

typedef enum {
    WG_NETIF_IDLE = 0,
    WG_NETIF_HANDSHAKE_PENDING,
    WG_NETIF_UP,
    WG_NETIF_FAILED,   /* unreachable in current code: handshake budget
                        * exhaustion now backs off and retries
                        * indefinitely (see WG_HANDSHAKE_BACKOFF_MS).
                        * Kept for forward compatibility / external API. */
} wg_netif_state_t;

static struct {
    bool                    initialized;
    wg_netif_state_t        state;

    int                     sock;
    uint16_t                bind_port_actual;

    struct wg_netif_local_config local;
    struct wg_netif_peer_config  peer;
    struct sockaddr_in            peer_addr;

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

    TaskHandle_t            rx_task;
    SemaphoreHandle_t       lock;

    /* Outbound TX queue + worker. The worker drains in non-TCPIP
     * context so sendto can re-enter lwIP safely. tx_done_sem is
     * given by the worker as the last thing it does before
     * vTaskDelete(NULL); wg_netif_stop takes it (with timeout) so
     * vQueueDelete cannot race against an in-flight xQueueReceive. */
    QueueHandle_t           tx_queue;
    TaskHandle_t            tx_task;
    SemaphoreHandle_t       tx_done_sem;
    uint64_t                tx_drops;

    /* Scratch slots that keep the 1.5 KiB tx items OFF the stacks of
     * the producer (lwIP TCPIP, 3 KiB) and the worker (4 KiB but
     * sendto's WiFi tx chain eats most of it). Each is single-owner:
     * only the TCPIP task ever writes to tx_scratch (input to
     * xQueueSend), only the wg_tx worker ever writes to
     * tx_worker_scratch (output of xQueueReceive). */
    wg_tx_item_t            tx_scratch;
    wg_tx_item_t            tx_worker_scratch;

    wg_netif_rx_cb_t        rx_cb;
    void                   *rx_cb_user;

    /* Periodic STUN re-probe dispatch. tinylink.c arms this with a
     * callback that parses the response, matches the in-flight txid,
     * and signals the reprobe task. NULL = drop (legacy behavior). */
    wg_netif_stun_cb_t      stun_cb;
    void                   *stun_cb_user;

    bool                    stop_requested;
} g;

/* --- Helpers --------------------------------------------------------- */

static int64_t now_us(void) { return esp_timer_get_time(); }

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

static int send_to_peer(const uint8_t *buf, size_t len)
{
    ssize_t n = sendto(g.sock, buf, len, 0,
                       (struct sockaddr *)&g.peer_addr, sizeof(g.peer_addr));
    if (n < 0) {
        ESP_LOGW(TAG, "sendto: errno=%d", errno);
        return -1;
    }
    return (int)n;
}

/* Build a fresh INIT and send it. Mutates g.handshake (overwrites the
 * Noise material with new ephemerals + chain key) and assigns a fresh
 * sender_index into g.local_index. Does NOT mutate g.state or the
 * existing g.transport session — callers decide what those mean for
 * the path they're on (cold start vs. proactive rekey). */
static int build_and_send_init(void)
{
    if (wg_handshake_init(&g.handshake,
                          g.local.static_priv,
                          g.local.static_pub,
                          g.peer.peer_static_pub,
                          g.peer.preshared_key) != 0) {
        ESP_LOGE(TAG, "handshake_init failed (low-order peer pub?)");
        return -1;
    }

    g.local_index = fresh_local_index();

    struct wg_msg_initiation msg;
    if (wg_handshake_create_initiation(&g.handshake, g.local_index, &msg) != 0) {
        ESP_LOGE(TAG, "create_initiation failed");
        return -1;
    }
    if (send_to_peer((const uint8_t *)&msg, sizeof(msg)) < 0) {
        return -1;
    }
    g.last_handshake_us = now_us();
    return 0;
}

/* Cold start: send INIT and transition to HANDSHAKE_PENDING. App
 * traffic is paused until the response lands. Used at boot and as the
 * fallback path when proactive rekey exhausts its budget. */
static int kick_off_handshake(void)
{
    if (build_and_send_init() != 0) return -1;
    g.handshake_attempt++;
    g.state = WG_NETIF_HANDSHAKE_PENDING;
    ESP_LOGI(TAG, "handshake init sent (attempt %d, idx=0x%08x)",
             g.handshake_attempt, (unsigned)g.local_index);
    return 0;
}

/* Proactive rekey: send a fresh INIT while keeping g.state == UP and
 * the existing g.transport session live. The new keys land only when
 * handle_handshake_response sees the matching reply and calls
 * wg_transport_session_init to swap them in atomically. Until then,
 * outbound app traffic continues to encrypt with the OLD keys (which
 * the responder still accepts up to its REJECT_AFTER_TIME = 180 s). */
static int start_rekey(void)
{
    if (build_and_send_init() != 0) return -1;
    g.rekey_attempt++;
    ESP_LOGI(TAG, "rekey init sent (attempt %d, idx=0x%08x, age=%llds)",
             g.rekey_attempt, (unsigned)g.local_index,
             (long long)((now_us() - g.last_handshake_completed_us) / 1000000LL));
    return 0;
}

/* Process a MessageResponse arriving on the socket. Two valid paths:
 *
 *  - Cold path: state == HANDSHAKE_PENDING. Boot or post-budget-exhaustion retry.
 *    App traffic was paused until now; transition to UP.
 *  - Rekey path: state == UP && rekey_in_flight. Old transport session
 *    is still serving traffic; we atomically install the new keys and
 *    drop the rekey-in-flight flag.
 *
 * In either case wg_transport_session_init overwrites g.transport with
 * the new keys, so any in-flight encrypt that just sampled the OLD
 * session pointer races into the swap; that's fine because both keys
 * are valid on the wire (responder accepts the previous session for
 * REJECT_AFTER_TIME after rotating). */
static void handle_handshake_response(const uint8_t *buf, size_t len)
{
    if (len != sizeof(struct wg_msg_response)) return;
    const bool cold_path  = (g.state == WG_NETIF_HANDSHAKE_PENDING);
    const bool rekey_path = (g.state == WG_NETIF_UP && g.rekey_in_flight);
    if (!cold_path && !rekey_path) {
        ESP_LOGD(TAG, "handshake response in state=%d rekey=%d ignored",
                 g.state, (int)g.rekey_in_flight);
        return;
    }
    const struct wg_msg_response *resp = (const struct wg_msg_response *)buf;

    uint8_t send_key[WG_KEY_LEN], recv_key[WG_KEY_LEN];
    uint32_t remote_index = 0;
    if (wg_handshake_process_response(&g.handshake, resp,
                                      send_key, recv_key, &remote_index) != 0) {
        ESP_LOGW(TAG, "handshake response rejected (path=%s)",
                 cold_path ? "cold" : "rekey");
        memset(send_key, 0, sizeof(send_key));
        memset(recv_key, 0, sizeof(recv_key));
        return;
    }

    wg_transport_session_init(&g.transport, g.local_index, remote_index,
                              send_key, recv_key);
    /* Scrub once the keys are copied into the session. */
    memset(send_key, 0, sizeof(send_key));
    memset(recv_key, 0, sizeof(recv_key));
    wg_handshake_scrub(&g.handshake);

    g.last_handshake_completed_us = now_us();
    /* Reset RX-stale watchdog clock on handshake (cold or rekey).
     * A fresh session starts with no transport packets seen yet —
     * setting last_transport_recv_us to now gives the watchdog a
     * 30 s grace before it can fire on this session. Without this
     * a peer-initiated rekey would immediately satisfy the stale
     * predicate (last_transport_recv_us would be 0 or stale from
     * the prior session). */
    g.last_transport_recv_us = now_us();
    if (cold_path) {
        g.state = WG_NETIF_UP;
        g.handshake_attempt = 0;
        ESP_LOGI(TAG, "session up: remote_idx=0x%08x", (unsigned)remote_index);
    } else {
        g.rekey_in_flight = false;
        g.rekey_attempt = 0;
        ESP_LOGI(TAG, "session rekeyed: remote_idx=0x%08x", (unsigned)remote_index);
    }
}

/* Process a MessageTransport from the peer. */
static void handle_transport(const uint8_t *buf, size_t len)
{
    if (g.state != WG_NETIF_UP) return;

    /* Decrypt straight into a stack buffer; max payload bounded by
     * WG_RX_BUF_LEN - WG_TRANSPORT_OVERHEAD. */
    uint8_t  plaintext[WG_RX_BUF_LEN];
    size_t   plen = 0;
    if (wg_transport_decrypt(&g.transport, buf, len,
                             plaintext, sizeof(plaintext), &plen) != 0) {
        return;  /* Replay / tamper / wrong index — silent drop. */
    }
    /* Successful decrypt = peer's session keys still match ours. Update
     * the RX-stale watchdog clock for both data packets AND zero-length
     * keepalives, since both prove the WG transport keys are mutually
     * valid. The watchdog cares about session liveness, not payload
     * direction. */
    g.last_transport_recv_us = now_us();
    if (plen == 0) {
        /* WG keepalive (zero plaintext) — peer is alive, nothing to
         * deliver upstream. */
        return;
    }
    if (g.rx_cb) {
        g.rx_cb(plaintext, plen, g.rx_cb_user);
    }
    /* Best-effort scrub — plaintext might be sensitive (passwords,
     * tokens) and the buffer is on the stack of a long-lived task. */
    memset(plaintext, 0, plen);
}

/* Handle a DISCO datagram that arrived on the shared UDP socket. The
 * source AddrPort is whatever the peer used to dial us — for direct UDP
 * this is the peer's reflexive endpoint behind their NAT. We sendto the
 * reply on g.sock back to that exact src so the response traverses the
 * same NAT mappings as the request (which is how peer A learns its own
 * public AddrPort works to reach us). */
static void handle_disco_direct(const uint8_t *buf, size_t len,
                                const struct sockaddr_in *src)
{
    uint8_t reply[DISCO_HANDLER_REPLY_MAX];
    disco_msg_type_t type = (disco_msg_type_t)0;
    uint8_t peer_disco_pub[WG_KEY_LEN] = {0};
    uint8_t txid[DISCO_TXID_LEN] = {0};
    /* peer_disco_pub used below as the roaming gate. */

    size_t reply_len = disco_handle_recv(reply, sizeof(reply),
                                         buf, len,
                                         g.local.disco_priv, g.local.disco_pub,
                                         &type, peer_disco_pub, txid);
    if (type == 0) {
        /* Decrypt failed: someone sealed against the wrong DiscoKey, or
         * the bytes weren't actually a DISCO frame. Silent drop — magic
         * prefix already matched so spam is bounded. */
        return;
    }

    /* Replay rejection. The wire layout is fixed (disco.c:113-115):
     *   [0..5]    DISCO_MAGIC
     *   [6..37]   sender_pub
     *   [38..61]  nonce
     *   [62..]    NaCl box (tag||ct)
     * The frame already passed disco_open's decrypt+auth so length checks
     * are satisfied and the bytes at buf[6+32..6+32+24] are the nonce. */
    const uint8_t *nonce = buf + DISCO_MAGIC_LEN + DISCO_KEY_LEN;
    if (disco_replay_check_and_record(nonce)) {
        ESP_LOGW(TAG, "disco replay dropped: nonce=%02x%02x%02x%02x.. type=%u",
                 nonce[0], nonce[1], nonce[2], nonce[3], (unsigned)type);
        return;
    }

    /* Roaming gate: only DISCO frames sealed by OUR WG peer's DiscoKey
     * may roam g.peer.peer_endpoint. The same UDP socket also receives
     * DISCO from other Tailscale peers in the netmap (e.g. a laptop
     * we're not WG-connected to but whose call-me-maybe punches still
     * reach us). Without this gate, those frames would flap our WG
     * transport target between unrelated peers. has_peer_disco_pub is
     * false on legacy bringups that didn't pass the DiscoKey through
     * — there we fall back to permissive (legacy) behavior. */
    const bool roam_allowed =
        !g.peer.has_peer_disco_pub ||
        memcmp(peer_disco_pub, g.peer.peer_disco_pub, WG_KEY_LEN) == 0;

    if (type == DISCO_TYPE_PING && reply_len > 0) {
        ssize_t n = sendto(g.sock, reply, reply_len, 0,
                           (const struct sockaddr *)src, sizeof(*src));
        if (n < 0) {
            ESP_LOGW(TAG, "disco pong sendto: errno=%d", errno);
        } else {
            char src_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &src->sin_addr, src_ip, sizeof(src_ip));
            ESP_LOGI(TAG, "disco ping→pong (direct): src=%s:%u txid=%02x%02x%02x%02x..",
                     src_ip, (unsigned)ntohs(src->sin_port),
                     txid[0], txid[1], txid[2], txid[3]);
            /* WG endpoint roaming via DISCO direct-path observation.
             * The peer demonstrated this AddrPort is reachable in BOTH
             * directions (we got a sealed ping FROM there, our pong
             * sendto succeeded), so future WG transport replies should
             * target it instead of g.peer.peer_endpoint_v4_be (the
             * netmap-picked address, often a stale public NAT mapping
             * or a value that only worked at handshake time). Without
             * this, peer-side ICMP echo requests come in via direct
             * UDP but our ICMP echo replies go to the netmap endpoint
             * — peer's NAT may have no reverse mapping at that port,
             * and the response gets DERP-routed or lost. */
            if (roam_allowed) {
                uint32_t src_v4_be = (uint32_t)src->sin_addr.s_addr;
                uint16_t src_port  = ntohs(src->sin_port);
                if (src_v4_be != g.peer.peer_endpoint_v4_be ||
                    src_port  != g.peer.peer_endpoint_port) {
                    ESP_LOGI(TAG, "WG endpoint roam → %s:%u (was %u.%u.%u.%u:%u)",
                             src_ip, (unsigned)src_port,
                             (unsigned)((g.peer.peer_endpoint_v4_be      ) & 0xFF),
                             (unsigned)((g.peer.peer_endpoint_v4_be >>  8) & 0xFF),
                             (unsigned)((g.peer.peer_endpoint_v4_be >> 16) & 0xFF),
                             (unsigned)((g.peer.peer_endpoint_v4_be >> 24) & 0xFF),
                             (unsigned)g.peer.peer_endpoint_port);
                    g.peer.peer_endpoint_v4_be = src_v4_be;
                    g.peer.peer_endpoint_port  = src_port;
                    rebuild_peer_sockaddr();
                }
            }
        }
        return;
    }
    if (type == DISCO_TYPE_PONG) {
        /* Peer responded to one of our (prepunch / DISCO outbound) pings.
         * The src is also a verified-working AddrPort — apply the same
         * roaming policy so the WG transport benefits. Same DiscoKey
         * gate as PING: don't migrate WG endpoint based on a non-WG
         * peer's pong. */
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src->sin_addr, src_ip, sizeof(src_ip));
        ESP_LOGI(TAG, "disco pong (direct): src=%s:%u txid=%02x%02x%02x%02x..",
                 src_ip, (unsigned)ntohs(src->sin_port),
                 txid[0], txid[1], txid[2], txid[3]);
        if (roam_allowed) {
            uint32_t src_v4_be = (uint32_t)src->sin_addr.s_addr;
            uint16_t src_port  = ntohs(src->sin_port);
            if (src_v4_be != g.peer.peer_endpoint_v4_be ||
                src_port  != g.peer.peer_endpoint_port) {
                ESP_LOGI(TAG, "WG endpoint roam (via pong) → %s:%u",
                         src_ip, (unsigned)src_port);
                g.peer.peer_endpoint_v4_be = src_v4_be;
                g.peer.peer_endpoint_port  = src_port;
                rebuild_peer_sockaddr();
            }
        }
        return;
    }
    if (type == DISCO_TYPE_CALLMEMAYBE) {
        ESP_LOGI(TAG, "disco call-me-maybe (direct path)");
        return;
    }
}

/* RX task: blocks on recvfrom, classifies, dispatches. */
static void rx_task(void *arg)
{
    (void)arg;
    uint8_t buf[WG_RX_BUF_LEN];
    /* Short receive timeout so we can periodically check
     * stop_requested and the handshake retry timer. */
    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    setsockopt(g.sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (!g.stop_requested) {
        struct sockaddr_in src;
        socklen_t srclen = sizeof(src);
        ssize_t n = recvfrom(g.sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&src, &srclen);
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
            if (is_wg_proto &&
                (src.sin_addr.s_addr != g.peer_addr.sin_addr.s_addr ||
                 src.sin_port        != g.peer_addr.sin_port)) {
                ESP_LOGD(TAG, "drop WG datagram from non-peer src");
                goto retry_timer;
            }

            switch (kind) {
            case WG_DEMUX_HANDSHAKE_RESP:
                handle_handshake_response(buf, (size_t)n);
                break;
            case WG_DEMUX_TRANSPORT:
                handle_transport(buf, (size_t)n);
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
            (now_us() - g.last_handshake_us) > WG_REKEY_TIMEOUT_MS * 1000LL) {
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
                g.last_handshake_us = now_us() +
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
            (now_us() - g.last_handshake_completed_us) >
                WG_REKEY_AFTER_MS * 1000LL) {
            ESP_LOGI(TAG, "session age >%ds — triggering proactive rekey",
                     WG_REKEY_AFTER_MS / 1000);
            g.rekey_attempt = 0;
            if (start_rekey() == 0) {
                g.rekey_in_flight = true;
            }
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
            (now_us() - g.last_transport_recv_us) >
                WG_RX_STALE_THRESHOLD_MS * 1000LL) {
            ESP_LOGW(TAG, "RX stale >%ds (no transport decrypt since) — "
                          "forcing rekey (suspected peer restart)",
                     WG_RX_STALE_THRESHOLD_MS / 1000);
            g.rekey_attempt = 0;
            if (start_rekey() == 0) {
                g.rekey_in_flight = true;
                /* Reset the watchdog clock so the rekey-in-flight has
                 * its own grace window (the rekey-retry block below
                 * handles rekey-itself-failed). Without this, if rekey
                 * INIT also doesn't get a response, we'd keep tripping
                 * this branch on every rx_task tick. */
                g.last_transport_recv_us = now_us();
            }
        }

        /* Rekey retry timer. Mirrors the cold-path retry but does NOT
         * tear down the live session on failure — if all attempts miss,
         * we fall back to a cold handshake (state = PENDING) which
         * pauses app traffic and uses the aggressive cold retry budget.
         * That fallback path matters because by then session age is
         * ~170 s and the responder is about to invalidate our keys
         * anyway; better a brief outage now than a silent black hole. */
        if (g.rekey_in_flight &&
            (now_us() - g.last_handshake_us) > WG_REKEY_TIMEOUT_MS * 1000LL) {
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
    }

    ESP_LOGI(TAG, "rx task exiting");
    vTaskDelete(NULL);
}

/* TX worker: drains tx_queue + sendto outside the lwIP TCPIP task.
 * Gives tx_done_sem as the last thing before vTaskDelete(NULL) so
 * wg_netif_stop can wait for clean exit before destroying the queue. */
static void tx_task_fn(void *arg)
{
    (void)arg;
    while (!g.stop_requested) {
        /* 500 ms wakeup so stop_requested is observed even when no
         * outbound traffic is flowing. xQueueReceive memcpys the
         * dequeued item directly into our BSS scratch — keeping it
         * off-stack matters here because sendto recurses into the
         * WiFi TX callback chain and chews into our budget. */
        if (xQueueReceive(g.tx_queue, &g.tx_worker_scratch,
                          pdMS_TO_TICKS(500)) != pdTRUE) {
            continue;
        }
        ssize_t n = sendto(g.sock,
                           g.tx_worker_scratch.buf, g.tx_worker_scratch.len, 0,
                           (struct sockaddr *)&g.tx_worker_scratch.dst,
                           sizeof(g.tx_worker_scratch.dst));
        if (n < 0) {
            ESP_LOGW(TAG, "tx sendto: errno=%d", errno);
        }
    }
    if (g.tx_done_sem != NULL) {
        xSemaphoreGive(g.tx_done_sem);
    }
    vTaskDelete(NULL);
}

/* --- Public API ----------------------------------------------------- */

esp_err_t wg_netif_init(const struct wg_netif_local_config *local)
{
    if (g.initialized) return ESP_OK;
    if (local == NULL) return ESP_ERR_INVALID_ARG;

    memset(&g, 0, sizeof(g));
    memcpy(&g.local, local, sizeof(*local));

    g.lock = xSemaphoreCreateMutex();
    if (g.lock == NULL) return ESP_ERR_NO_MEM;

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

    g.tx_queue = xQueueCreate(WG_TX_QUEUE_LEN, sizeof(wg_tx_item_t));
    if (g.tx_queue == NULL) {
        ESP_LOGE(TAG, "tx_queue create failed");
        close(g.sock);
        return ESP_ERR_NO_MEM;
    }
    g.tx_done_sem = xSemaphoreCreateBinary();
    if (g.tx_done_sem == NULL) {
        ESP_LOGE(TAG, "tx_done_sem create failed");
        vQueueDelete(g.tx_queue);
        g.tx_queue = NULL;
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
        vQueueDelete(g.tx_queue);
        g.tx_queue = NULL;
        close(g.sock);
        return ESP_ERR_NO_MEM;
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

    g.handshake_attempt = 0;
    g.rekey_attempt = 0;
    g.rekey_in_flight = false;
    g.last_handshake_completed_us = 0;
    g.last_transport_recv_us = 0;  /* watchdog disarmed until session up */
    if (kick_off_handshake() != 0) return ESP_FAIL;

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
    g.peer.peer_endpoint_v4_be = v4_be;
    g.peer.peer_endpoint_port  = port;
    rebuild_peer_sockaddr();
    /* Existing transport session keys remain valid — endpoint roaming
     * doesn't invalidate keys (per WG roaming spec). Subsequent
     * outgoing packets land at the new endpoint. */
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
    if (memcmp(src_node_pub, g.peer.peer_static_pub, WG_KEY_LEN) != 0) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    wg_demux_kind_t kind = wg_demux_classify(buf, len);
    switch (kind) {
    case WG_DEMUX_HANDSHAKE_RESP:
        handle_handshake_response(buf, len);
        return ESP_OK;
    case WG_DEMUX_TRANSPORT:
        handle_transport(buf, len);
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
     * tx worker via tx_queue instead of called here directly.
     *
     * Use g.tx_scratch (BSS) instead of a stack-local item so the
     * TCPIP task's small stack doesn't have to absorb the 1.5 KiB
     * wire buffer alongside its own frames. xQueueSend memcpys the
     * full sizeof(wg_tx_item_t) into the queue's internal storage,
     * so it's safe to reuse the scratch on the next call. */
    int wlen = wg_transport_encrypt(&g.transport,
                                    g.tx_scratch.buf, sizeof(g.tx_scratch.buf),
                                    pkt, len);
    if (wlen < 0) return ESP_FAIL;
    g.tx_scratch.len = (size_t)wlen;
    /* Snapshot the dest sockaddr at enqueue time so a concurrent
     * wg_netif_update_peer_endpoint after we release can't redirect a
     * frame whose counter is already committed. */
    g.tx_scratch.dst = g.peer_addr;

    if (xQueueSend(g.tx_queue, &g.tx_scratch, 0) != pdTRUE) {
        /* Queue full. Drop this frame; lwIP treats any non-OK return
         * as a TX failure and discards its pbuf. The worker is either
         * starving (priority) or stuck in sendto — log throttled so
         * UART doesn't spam if backlog runs hot for a sustained burst. */
        uint64_t prev = g.tx_drops++;
        if ((prev % WG_TX_DROP_LOG_EVERY) == 0) {
            ESP_LOGW(TAG, "tx queue full — dropped frame (total=%llu)",
                     (unsigned long long)g.tx_drops);
        }
        return ESP_FAIL;
    }
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

bool wg_netif_is_up(void)
{
    return g.initialized && g.state == WG_NETIF_UP;
}

void wg_netif_stop(void)
{
    if (!g.initialized) return;
    g.stop_requested = true;
    /* Wait for the TX worker to observe stop_requested and exit before
     * we tear down its queue; otherwise vQueueDelete can race against
     * an in-flight xQueueReceive. The worker wakes at most every 500
     * ms; 2 s is comfortable margin even under priority pressure. The
     * RX task observes stop_requested via its 1-s recvfrom timeout
     * and self-deletes; we don't gate on it here because nothing it
     * touches gets freed below. */
    if (g.tx_done_sem != NULL) {
        if (xSemaphoreTake(g.tx_done_sem, pdMS_TO_TICKS(2000)) != pdTRUE) {
            ESP_LOGW(TAG, "tx task did not exit within 2s — forcing teardown");
        }
    }
    if (g.tx_queue != NULL) {
        vQueueDelete(g.tx_queue);
        g.tx_queue = NULL;
    }
    if (g.tx_done_sem != NULL) {
        vSemaphoreDelete(g.tx_done_sem);
        g.tx_done_sem = NULL;
    }
    if (g.sock >= 0) {
        close(g.sock);
        g.sock = -1;
    }
    wg_handshake_scrub(&g.handshake);
    memset(&g.transport, 0, sizeof(g.transport));
    g.initialized = false;
}

uint64_t wg_netif_get_tx_drops(void)
{
    return g.tx_drops;
}

int wg_netif_get_socket(void)
{
    return g.initialized ? g.sock : -1;
}

bool wg_netif_rx_running(void)
{
    return g.rx_task != NULL;
}

#endif /* ESP_PLATFORM */
