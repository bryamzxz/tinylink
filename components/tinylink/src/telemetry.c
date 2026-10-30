// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#ifdef ESP_PLATFORM

#include "telemetry.h"
#include "tinylink.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "sdkconfig.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"

#include "stats_json.h"
#include "tlm_sched.h"
#include "tmp117.h"
#include "tl_wdt.h"
#include "tl_time.h"

static const char *TAG = "telemetry";

/* Longest single wait of the loop. While select() serves /stats nothing
 * can wake it early (lwIP loopback is compiled out), so 5 s — 6 s when a
 * sample due just past it takes its place (tlm_sched.h) — bounds how
 * late a GOT_IP-requested STUN re-probe starts, and adds no wake-ups at
 * the default 5-s telemetry period. The notification wait is woken by
 * telemetry_kick and only needs to keep the task WDT (60 s) fed — also
 * for telemetry periods past 60 s, which Kconfig allows (≤ 600 s) and
 * which tripped it before 1.3.2. */
#define TLM_SLICE_STATS_US  (5LL * 1000LL * 1000LL)
#define TLM_SLICE_IDLE_US   (30LL * 1000LL * 1000LL)
/* Stack diag + NVS time-floor poll (every 12th sample ≈ 60 s until 1.3.2;
 * its own deadline since, so builds without telemetry persist the floor;
 * since 1.3.7 it rides the last sample wake before it is due,
 * tlm_sched.h). */
#define TLM_HOUSEKEEP_US    (60LL * 1000LL * 1000LL)
#define TLM_SPAWN_RETRY_US  (30LL * 1000LL * 1000LL)

static TaskHandle_t  s_task;
static volatile bool s_tunnel_up;     /* telemetry_start(): WG netif up */
static void (*s_persist_hook)(void);  /* tinylink_set_persist_hook */

void tinylink_set_persist_hook(void (*fn)(void))
{
    __atomic_store_n(&s_persist_hook, fn, __ATOMIC_RELEASE);
}

#if CONFIG_TINYLINK_TELEMETRY_ENABLE

#define TX_BUF_SZ 160

static int parse_dest(const char *spec, char *host_out, size_t host_size,
                      uint16_t *port_out)
{
    const char *colon = strrchr(spec, ':');
    if (colon == NULL) return -1;
    size_t hlen = (size_t)(colon - spec);
    if (hlen + 1 > host_size) return -1;
    memcpy(host_out, spec, hlen);
    host_out[hlen] = '\0';
    int p = atoi(colon + 1);
    if (p <= 0 || p > 65535) return -1;
    *port_out = (uint16_t)p;
    return 0;
}

static int open_dest_socket(const char *host, uint16_t port,
                            struct sockaddr_in *out_addr)
{
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) {
        ESP_LOGE(TAG, "socket: errno=%d", errno);
        return -1;
    }
    memset(out_addr, 0, sizeof(*out_addr));
    out_addr->sin_family = AF_INET;
    out_addr->sin_port   = htons(port);
    if (inet_pton(AF_INET, host, &out_addr->sin_addr) != 1) {
        ESP_LOGE(TAG, "inet_pton(%s): errno=%d", host, errno);
        close(s);
        return -1;
    }
    return s;
}

static uint32_t s_stats_seq;

#if CONFIG_TINYLINK_STATS_PORT > 0
/* Answer /stats queries while waiting out one telemetry period (tlm_wait):
 * deadline-based, feeds the WDT, ignores non-tailnet sources. The reply
 * is one JSON line built into a BSS buffer (the task stack is 4.5 KiB). */
static bool is_tailnet_v4(uint32_t be_addr)
{
    /* 100.64.0.0/10 */
    return (ntohl(be_addr) & 0xFFC00000u) == 0x64400000u;
}

static int stats_json(char *out, size_t cap, uint32_t telemetry_seq)
{
    tinylink_stats_t st;
    tinylink_get_stats(&st);
    return tl_stats_json(out, cap, &st, CONFIG_TINYLINK_DEVICE_HOSTNAME,
                         tinylink_version_string(), telemetry_seq);
}

/* A truncated reply is not sent, so this is sized for the worst case
 * (stats_json.h; tools/test/test_stats.c checks it). */
static char     s_stats_buf[TL_STATS_JSON_CAP];
#endif

/* TMP117, destination socket, /stats bind. Returns the socket (-1: no
 * telemetry and no /stats); *sensor_ok says whether samples can be
 * taken. Since the task also runs the STUN re-probe, a failure here
 * switches only this part off instead of ending the task — and a dead
 * sensor no longer takes /stats down with it. noinline (with
 * tlm_sample): keeps their buffers out of telemetry_task's frame, which
 * every other path (/stats, STUN, stack diag) stands on. */
static __attribute__((noinline))
int tlm_open(struct sockaddr_in *dest, bool *sensor_ok)
{
    esp_err_t err = tmp117_init(CONFIG_TINYLINK_I2C_SDA_GPIO,
                                CONFIG_TINYLINK_I2C_SCL_GPIO,
                                CONFIG_TINYLINK_TMP117_I2C_ADDR);
    *sensor_ok = (err == ESP_OK);
    if (!*sensor_ok) {
        ESP_LOGE(TAG, "tmp117_init failed: %s — telemetry samples off",
                 esp_err_to_name(err));
    }

    char     host[40];
    uint16_t port = 0;
    if (parse_dest(CONFIG_TINYLINK_TELEMETRY_DEST,
                   host, sizeof(host), &port) != 0) {
        ESP_LOGE(TAG, "telemetry dest malformed: %s",
                 CONFIG_TINYLINK_TELEMETRY_DEST);
        return -1;
    }
    int sock = open_dest_socket(host, port, dest);
    if (sock < 0) return -1;
    ESP_LOGI(TAG, "telemetry → %s:%u every %d ms",
             host, port, CONFIG_TINYLINK_TELEMETRY_PERIOD_MS);

    /* /stats responder (M16): bind the same socket to a known port so a
     * tailnet peer can `echo | nc -u 100.x.y.z 27822` and get a JSON
     * snapshot back. Only 100.64.0.0/10 sources are answered — the port
     * is also reachable on the LAN but a LAN sender gets silence. */
#if CONFIG_TINYLINK_STATS_PORT > 0
    struct sockaddr_in bind_addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(CONFIG_TINYLINK_STATS_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) == 0) {
        ESP_LOGI(TAG, "/stats responder on udp/%d (tailnet sources only)",
                 CONFIG_TINYLINK_STATS_PORT);
    } else {
        ESP_LOGW(TAG, "/stats bind(udp/%d) failed: errno=%d — responder off",
                 CONFIG_TINYLINK_STATS_PORT, errno);
    }
#endif
    return sock;
}

/* One TMP117 sample → JSON datagram. Tick counter is enough as a
 * sequence number; the collector can convert to wall time using its own
 * ingest timestamp. */
static __attribute__((noinline))
void tlm_sample(int sock, const struct sockaddr_in *dest, uint32_t *seq)
{
    int32_t milli_c = 0;
    esp_err_t err = tmp117_read_milli_c(&milli_c);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "tmp117 read failed: %s",
                 esp_err_to_name(err));
        return;
    }
    char buf[TX_BUF_SZ];
    int sign = (milli_c < 0) ? -1 : 1;
    int32_t abs_milli = milli_c * sign;
    int n = snprintf(buf, sizeof(buf),
        "{\"host\":\"%s\",\"seq\":%u,\"temp_c\":%s%ld.%03ld}\n",
        CONFIG_TINYLINK_DEVICE_HOSTNAME,
        (unsigned)(*seq)++,
        sign < 0 ? "-" : "",
        (long)(abs_milli / 1000), (long)(abs_milli % 1000));
    if (n < 0 || (size_t)n >= sizeof(buf)) return;
    s_stats_seq = *seq;

    ssize_t sent = sendto(sock, buf, (size_t)n, 0,
                          (const struct sockaddr *)dest, sizeof(*dest));
    if (sent < 0) {
        ESP_LOGW(TAG, "sendto failed: errno=%d", errno);
        /* WG netif may be transiently down during peer endpoint
         * updates — back off for one period and try again. */
    } else {
        ESP_LOGI(TAG, "tx seq=%u temp=%s%ld.%03ld°C (%d B)",
                 (unsigned)(*seq - 1),
                 sign < 0 ? "-" : "",
                 (long)(abs_milli / 1000), (long)(abs_milli % 1000),
                 (int)sent);
    }
}

#endif /* CONFIG_TINYLINK_TELEMETRY_ENABLE */

/* /stats is answered (by select() in tlm_wait) once the tunnel is up:
 * only tailnet sources get a reply, and they arrive through it. */
static bool tlm_serves_stats(int sock)
{
#if CONFIG_TINYLINK_TELEMETRY_ENABLE && CONFIG_TINYLINK_STATS_PORT > 0
    return sock >= 0 && s_tunnel_up;
#else
    (void)sock;
    return false;
#endif
}

/* Sleep until `deadline_us`. Serving /stats, answer queries meanwhile
 * (select(), which telemetry_kick cannot cut short — the caller's 5-s
 * slice bounds that); otherwise block on the task notification, so the
 * first netmap or a GOT_IP wakes the loop at once. */
static void tlm_wait(int sock, int64_t deadline_us)
{
    for (;;) {
        const int64_t left = deadline_us - esp_timer_get_time();
        if (left <= 0) return;
#if CONFIG_TINYLINK_TELEMETRY_ENABLE && CONFIG_TINYLINK_STATS_PORT > 0
        if (tlm_serves_stats(sock)) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sock, &rfds);
            struct timeval tv = { .tv_sec = left / 1000000LL, .tv_usec = left % 1000000LL };
            int r = select(sock + 1, &rfds, NULL, NULL, &tv);
            if (r == 0) return;                  /* timeout: tick */
            uint8_t q[64];
            struct sockaddr_in from;
            socklen_t fl = sizeof(from);
            ssize_t n = (r > 0)
                ? recvfrom(sock, q, sizeof(q), 0, (struct sockaddr *)&from, &fl) : -1;
            if (n >= 0) {
                tl_wdt_feed();
                if (!is_tailnet_v4((uint32_t)from.sin_addr.s_addr)) continue;
                int len = stats_json(s_stats_buf, sizeof(s_stats_buf), s_stats_seq);
                if (len > 0 && (size_t)len < sizeof(s_stats_buf)) {
                    (void)sendto(sock, s_stats_buf, (size_t)len, 0,
                                 (const struct sockaddr *)&from, sizeof(from));
                }
                continue;
            }
            /* select/recvfrom error: sit out the rest of this wait below
             * rather than spin on it. */
        }
#endif
        const TickType_t t = pdMS_TO_TICKS((uint32_t)((left + 999) / 1000));
        (void)ulTaskNotifyTake(pdTRUE, t > 0 ? t : 1);
        return;
    }
}

static void telemetry_task(void *arg)
{
    (void)arg;
    int sock = -1;
#if CONFIG_TINYLINK_TELEMETRY_ENABLE
    struct sockaddr_in dest;
    bool     sensor_ok = false;
    uint32_t seq = 0;
    int64_t  next_sample = 0;            /* first one as soon as the tunnel is up */
    sock = tlm_open(&dest, &sensor_ok);
#endif
    /* First stack diag ~60 s after spawn (end of bringup), when all
     * bringup tasks have stabilized. */
    int64_t next_housekeep = esp_timer_get_time() + TLM_HOUSEKEEP_US;

    tl_wdt_subscribe();
    for (;;) {
        tl_wdt_feed();
        int64_t now = esp_timer_get_time();
        int64_t deadline = now + (tlm_serves_stats(sock) ? TLM_SLICE_STATS_US
                                                         : TLM_SLICE_IDLE_US);
        /* While sampling, the housekeeping and the STUN re-probe run at
         * the last sample wake before they are due (tlm_sched.h): `early`
         * is how far ahead, `anchor` the next sample. */
        int64_t early  = tlm_early_us(false, 0);
        int64_t anchor = INT64_MAX;
#if CONFIG_TINYLINK_TELEMETRY_ENABLE
        if (s_tunnel_up && sensor_ok && sock >= 0) {
            const int64_t period = (int64_t)CONFIG_TINYLINK_TELEMETRY_PERIOD_MS * 1000LL;
            /* Within the slack: this wake is the sample's, though the
             * tick-counted wait ended a little before its instant. */
            if (tlm_due(now, next_sample, tlm_slack_us(period))) {
                tlm_sample(sock, &dest, &seq);
                /* On a grid since 1.3.7 (was one period after the
                 * sample's end: 5.01–5.02 s apart on the sensor). */
                next_sample = tlm_next_on_grid(next_sample, period, now);
                now = esp_timer_get_time();
            }
            early  = tlm_early_us(true, period);
            anchor = next_sample;
            /* A sample due within the slack past the /stats slice takes
             * its place: a slice cut short by the drift would otherwise
             * end each wait earlier than the last, until one fell
             * outside the slack and cost a wake of its own. */
            if (next_sample < deadline + tlm_slack_us(period)) deadline = next_sample;
        }
#endif
        if (tlm_due(now, next_housekeep, early)) {
            /* Soak observability: tinylink_diag_dump_stacks() walks every
             * FreeRTOS task's stack high-water mark (data source for the
             * task-stack-trim audit item). */
            tinylink_diag_dump_stacks();
            tl_time_poll_persist();
            tinylink_addr_persist_poll();
            void (*persist_hook)(void) = __atomic_load_n(&s_persist_hook, __ATOMIC_ACQUIRE);
            if (persist_hook != NULL) persist_hook();
            now = esp_timer_get_time();
            next_housekeep = tlm_next_on_grid(next_housekeep, TLM_HOUSEKEEP_US, now);
        }
        const int64_t hk_at = tlm_wake_at(next_housekeep, anchor, early);
        if (hk_at < deadline) deadline = hk_at;
        /* STUN re-probe when due (CONFIG_TINYLINK_STUN_REPROBE_MS) or
         * requested by GOT_IP; may block for one probe (it feeds). */
        const int64_t stun_due = tinylink_stun_reprobe_poll(now, early);
        const int64_t stun_at  = tlm_wake_at(stun_due, anchor, early);
        if (stun_at < deadline) deadline = stun_at;
        tlm_wait(sock, deadline);
    }
}

static bool tlm_try_spawn(void)
{
    /* 4.5 KiB: research §J's 4 KiB `app_task` budget plus 512 B for Log
     * V2 (round 1.3.1). The task bottomed out at 452 B free in the M16
     * 6-h soak (/stats snprintf + sendto + log lines) under Log V1, and
     * V2's esp_log_va → esp_log_format → esp_log_printf chain costs
     * ≈ 150–200 B more per call; 1 084 B free on hardware at 1.3.1.
     * The STUN re-probe folded in at 1.3.2 is not the deepest path: it
     * peaked at ~1.8 KB on its own task, ≈ 1.9 KB here, against
     * ≈ 3.3 KB for the /stats and sample paths, each ≥ 176 B shallower
     * than at 1.3.1 (frame sums in docs/ARCHITECTURE.md "FreeRTOS task
     * layout"). */
    TaskHandle_t h = NULL;
    if (xTaskCreate(telemetry_task, "tinylink_tlm",
                    4608, NULL, tskIDLE_PRIORITY + 2, &h) != pdPASS) {
        return false;
    }
    s_task = h;
    return true;
}

/* Boot-time heap pressure (TLS handshake transient + supervisor connect
 * peak still settling) can fail the spawn with NO_MEM. Without a retry
 * the STUN re-probe never runs and a later NAT rebind leaves the
 * advertised endpoint stale for good ("direct connection not
 * established" on the peer side — the reason the old re-probe task got
 * this timer). Runs on the esp_timer task, so no worker is needed to
 * wait for heap. */
static esp_timer_handle_t s_retry_timer;

static void tlm_retry_cb(void *arg)
{
    (void)arg;
    if (tlm_try_spawn()) {
        ESP_LOGI(TAG, "task spawn OK on retry (heap_free=%u largest=%u)",
                 (unsigned)esp_get_free_heap_size(),
                 (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT));
        return;   /* one-shot timer: do not rearm */
    }
    ESP_LOGW(TAG, "task spawn retry still failing (heap_free=%u largest=%u) "
                  "— retry in %d s",
             (unsigned)esp_get_free_heap_size(),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT),
             (int)(TLM_SPAWN_RETRY_US / 1000000LL));
    esp_err_t err = esp_timer_start_once(s_retry_timer, TLM_SPAWN_RETRY_US);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_timer_start_once(retry) failed: 0x%x — giving up", err);
    }
}

static portMUX_TYPE s_spawn_mux = portMUX_INITIALIZER_UNLOCKED;
static bool         s_spawn_claimed;   /* task running or its retry armed */

esp_err_t telemetry_task_start(void)
{
    /* Two callers can race at boot (main's tinylink_stun_reprobe_start,
     * the long-poll's first netmap): only the first one spawns. */
    taskENTER_CRITICAL(&s_spawn_mux);
    const bool mine = !s_spawn_claimed;
    s_spawn_claimed = true;
    taskEXIT_CRITICAL(&s_spawn_mux);
    if (!mine) return ESP_OK;
    if (tlm_try_spawn()) return ESP_OK;

    ESP_LOGW(TAG, "xTaskCreate(tinylink_tlm) failed (heap_free=%u largest=%u) "
                  "— scheduling retry in %d s",
             (unsigned)esp_get_free_heap_size(),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_DEFAULT),
             (int)(TLM_SPAWN_RETRY_US / 1000000LL));
    const esp_timer_create_args_t targs = {
        .callback = tlm_retry_cb,
        .name     = "tlm_retry",
    };
    esp_err_t err = esp_timer_create(&targs, &s_retry_timer);
    if (err == ESP_OK) err = esp_timer_start_once(s_retry_timer, TLM_SPAWN_RETRY_US);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "spawn retry timer failed: 0x%x", err);
        if (s_retry_timer != NULL) {
            (void)esp_timer_delete(s_retry_timer);
            s_retry_timer = NULL;
        }
        taskENTER_CRITICAL(&s_spawn_mux);
        s_spawn_claimed = false;       /* let the next caller try again */
        taskEXIT_CRITICAL(&s_spawn_mux);
        return err;
    }
    return ESP_OK;
}

esp_err_t telemetry_start(void)
{
    s_tunnel_up = true;
    esp_err_t err = telemetry_task_start();
    telemetry_kick();                  /* first sample now, not after a wait */
    return err;
}

void telemetry_kick(void)
{
    TaskHandle_t t = s_task;
    if (t != NULL) (void)xTaskNotifyGive(t);
}

#endif /* ESP_PLATFORM */
