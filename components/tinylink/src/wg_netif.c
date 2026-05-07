// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#ifdef ESP_PLATFORM

#include "wg_netif.h"

#include <errno.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"

#include "lwip/inet.h"
#include "lwip/sockets.h"

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

/* RX task stack: the dispatch path is shallow (recvfrom + decrypt +
 * callback). 4 KiB matches research §J's `app_task` budget. */
#define WG_RX_TASK_STACK_BYTES 4096
#define WG_RX_TASK_PRIO        (tskIDLE_PRIORITY + 3)

/* Largest WG datagram we accept on the wire. WG transport packets are
 * usually MTU-bounded; with our 1.5 KiB upper bound we have plenty of
 * headroom for IPv4 over WG. */
#define WG_RX_BUF_LEN 1536

typedef enum {
    WG_NETIF_IDLE = 0,
    WG_NETIF_HANDSHAKE_PENDING,
    WG_NETIF_UP,
    WG_NETIF_FAILED,
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

    TaskHandle_t            rx_task;
    SemaphoreHandle_t       lock;

    wg_netif_rx_cb_t        rx_cb;
    void                   *rx_cb_user;

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

/* Compose and send MessageInitiation, advance state to PENDING. */
static int kick_off_handshake(void)
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
    g.handshake_attempt++;
    g.state = WG_NETIF_HANDSHAKE_PENDING;
    ESP_LOGI(TAG, "handshake init sent (attempt %d, idx=0x%08x)",
             g.handshake_attempt, (unsigned)g.local_index);
    return 0;
}

/* Process a MessageResponse arriving on the socket. */
static void handle_handshake_response(const uint8_t *buf, size_t len)
{
    if (len != sizeof(struct wg_msg_response)) return;
    if (g.state != WG_NETIF_HANDSHAKE_PENDING) {
        ESP_LOGD(TAG, "handshake response in state=%d ignored", g.state);
        return;
    }
    const struct wg_msg_response *resp = (const struct wg_msg_response *)buf;

    uint8_t send_key[WG_KEY_LEN], recv_key[WG_KEY_LEN];
    uint32_t remote_index = 0;
    if (wg_handshake_process_response(&g.handshake, resp,
                                      send_key, recv_key, &remote_index) != 0) {
        ESP_LOGW(TAG, "handshake response rejected");
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

    g.state = WG_NETIF_UP;
    g.handshake_attempt = 0;
    ESP_LOGI(TAG, "session up: remote_idx=0x%08x", (unsigned)remote_index);
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
            /* Drop datagrams from anyone who isn't our peer. (We
             * could relax this for DISCO discovery once step 7
             * lands.) */
            if (src.sin_addr.s_addr != g.peer_addr.sin_addr.s_addr ||
                src.sin_port        != g.peer_addr.sin_port) {
                ESP_LOGD(TAG, "drop datagram from non-peer src");
                continue;
            }

            wg_demux_kind_t kind = wg_demux_classify(buf, (size_t)n);
            switch (kind) {
            case WG_DEMUX_HANDSHAKE_RESP:
                handle_handshake_response(buf, (size_t)n);
                break;
            case WG_DEMUX_TRANSPORT:
                handle_transport(buf, (size_t)n);
                break;
            case WG_DEMUX_HANDSHAKE_INIT:
            case WG_DEMUX_HANDSHAKE_COOKIE:
            case WG_DEMUX_DISCO:
            case WG_DEMUX_STUN:
                /* Initiator-only — we never accept inbound init. DISCO
                 * and STUN handlers land in step 7 and M4. */
                break;
            case WG_DEMUX_DISCARD:
            default:
                break;
            }
        }

        /* Handshake retry timer. Fires regardless of whether recvfrom
         * timed out. */
        if (g.state == WG_NETIF_HANDSHAKE_PENDING &&
            (now_us() - g.last_handshake_us) > WG_REKEY_TIMEOUT_MS * 1000LL) {
            if (g.handshake_attempt >= WG_HANDSHAKE_MAX_RETRIES) {
                ESP_LOGE(TAG, "handshake gave up after %d attempts",
                         g.handshake_attempt);
                g.state = WG_NETIF_FAILED;
            } else {
                ESP_LOGW(TAG, "handshake retry %d", g.handshake_attempt + 1);
                kick_off_handshake();
            }
        }
    }

    ESP_LOGI(TAG, "rx task exiting");
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
    /* Refuse calls from the lwIP TCPIP task. wg_lwip's wg_transmit hooks
     * us as the netif TX callback, so any IP packet routed to the WG
     * netif lands here on TCPIP context. send_to_peer below issues a
     * BSD sendto on g.sock, which goes back through lwIP's socket API
     * and posts a tcpip_callback that waits on a semaphore — but the
     * TCPIP task is the very one that would have to dequeue it, so it
     * deadlocks. Symptom is a silent freeze of the entire data plane
     * (telemetry, DERP recv, ICMP all stop) while the supervisor task's
     * SO_RCVTIMEO-driven socket reads keep producing WANT_READ logs.
     *
     * Dropping here mirrors the pre-WG_NETIF_UP behavior: lwIP sees a
     * TX failure and discards the buffer. Outbound WG transport over
     * the tunnel is therefore non-functional via this path; a queue
     * model (encrypted bytes posted to a worker task that does the
     * sendto outside TCPIP context) is the proper fix and intended for
     * a follow-up PR alongside the outbound DERP queue. */
    const char *task_name = pcTaskGetName(NULL);
    if (task_name != NULL && strcmp(task_name, "tiT") == 0) {
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t wire[WG_RX_BUF_LEN];
    int wlen = wg_transport_encrypt(&g.transport, wire, sizeof(wire), pkt, len);
    if (wlen < 0) return ESP_FAIL;
    if (send_to_peer(wire, (size_t)wlen) < 0) return ESP_FAIL;
    return ESP_OK;
}

void wg_netif_set_rx_callback(wg_netif_rx_cb_t cb, void *user)
{
    g.rx_cb      = cb;
    g.rx_cb_user = user;
}

bool wg_netif_is_up(void)
{
    return g.initialized && g.state == WG_NETIF_UP;
}

void wg_netif_stop(void)
{
    if (!g.initialized) return;
    g.stop_requested = true;
    /* The RX task notices stop_requested when its 1-s recvfrom
     * timeout fires and self-deletes. We don't join here to keep
     * stop() non-blocking; the OS will reclaim. */
    if (g.sock >= 0) {
        close(g.sock);
        g.sock = -1;
    }
    wg_handshake_scrub(&g.handshake);
    memset(&g.transport, 0, sizeof(g.transport));
    g.initialized = false;
}

#endif /* ESP_PLATFORM */
