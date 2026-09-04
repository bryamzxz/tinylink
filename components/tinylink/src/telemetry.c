// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#ifdef ESP_PLATFORM

#include "telemetry.h"
#include "tinylink.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "sdkconfig.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"

#include "tmp117.h"
#include "tl_wdt.h"
#include "tl_time.h"
#include "esp_timer.h"

#if CONFIG_TINYLINK_TELEMETRY_ENABLE

static const char *TAG = "telemetry";

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

/* Answer /stats queries while waiting out one telemetry period. Keeps
 * the 5-s cadence (deadline-based), feeds the WDT, ignores non-tailnet
 * sources. The reply is one JSON line built into a BSS buffer (the task
 * stack is 4 KiB). */
static bool is_tailnet_v4(uint32_t be_addr)
{
    /* 100.64.0.0/10 */
    return (ntohl(be_addr) & 0xFFC00000u) == 0x64400000u;
}

static int stats_json(char *out, size_t cap, uint32_t telemetry_seq)
{
    tinylink_stats_t st;
    tinylink_get_stats(&st);
    return snprintf(out, cap,
        "{\"host\":\"%s\",\"version\":\"%s\",\"uptime_s\":%u,"
        "\"heap_free\":%u,\"heap_largest\":%u,\"ntp_synced\":%s,"
        "\"control\":{\"open\":%s,\"alive_age_s\":%u,\"reconnects\":%u,\"endpoint_pushes\":%u},"
        "\"derp\":{\"connected\":%s,\"host\":\"%s\"},"
        "\"endpoint\":\"%u.%u.%u.%u:%u\","
        "\"wg\":{\"state\":%d,\"rekeys\":%u,\"cold_handshakes\":%u,\"rx_stale\":%u,"
        "\"roams\":%u,\"tx_drops\":%u,\"relayed_stale\":%u,\"relay_errors\":%u,\"last_rx_age_s\":%u},"
        "\"telemetry_seq\":%u}\n",
        CONFIG_TINYLINK_DEVICE_HOSTNAME, tinylink_version_string(),
        (unsigned)st.uptime_s, (unsigned)st.heap_free, (unsigned)st.heap_largest,
        st.ntp_synced ? "true" : "false",
        st.control_open ? "true" : "false", (unsigned)st.control_alive_age_s,
        (unsigned)st.control_reconnects, (unsigned)st.endpoint_pushes,
        st.derp_connected ? "true" : "false", st.derp_host,
        st.public_v4[0], st.public_v4[1], st.public_v4[2], st.public_v4[3],
        (unsigned)st.public_port,
        st.wg_state, (unsigned)st.wg_rekeys, (unsigned)st.wg_cold_handshakes,
        (unsigned)st.wg_rx_stale_events, (unsigned)st.wg_roams,
        (unsigned)st.wg_tx_drops, (unsigned)st.wg_relayed_stale,
        (unsigned)st.wg_relay_errors, (unsigned)st.wg_last_rx_age_s,
        (unsigned)telemetry_seq);
}

static uint32_t s_stats_seq;
static char     s_stats_buf[640];

static void stats_wait(int sock, uint32_t period_ms)
{
    const int64_t deadline = esp_timer_get_time() + (int64_t)period_ms * 1000LL;
    for (;;) {
        const int64_t left = deadline - esp_timer_get_time();
        if (left <= 0) return;
#if CONFIG_TINYLINK_STATS_PORT > 0
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        struct timeval tv = { .tv_sec = left / 1000000LL, .tv_usec = left % 1000000LL };
        int r = select(sock + 1, &rfds, NULL, NULL, &tv);
        if (r <= 0) return;                      /* timeout (or error): tick */
        uint8_t q[64];
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(sock, q, sizeof(q), 0, (struct sockaddr *)&from, &fl);
        if (n < 0) return;
        tl_wdt_feed();
        if (!is_tailnet_v4((uint32_t)from.sin_addr.s_addr)) continue;
        int len = stats_json(s_stats_buf, sizeof(s_stats_buf), s_stats_seq);
        if (len > 0 && (size_t)len < sizeof(s_stats_buf)) {
            (void)sendto(sock, s_stats_buf, (size_t)len, 0,
                         (const struct sockaddr *)&from, sizeof(from));
        }
#else
        (void)sock;
        vTaskDelay(pdMS_TO_TICKS(left / 1000));
        return;
#endif
    }
}

static void telemetry_task(void *arg)
{
    (void)arg;

    esp_err_t err = tmp117_init(CONFIG_TINYLINK_I2C_SDA_GPIO,
                                CONFIG_TINYLINK_I2C_SCL_GPIO,
                                CONFIG_TINYLINK_TMP117_I2C_ADDR);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "tmp117_init failed: %s — telemetry disabled",
                 esp_err_to_name(err));
        vTaskDelete(NULL);
        return;
    }

    char     host[40];
    uint16_t port = 0;
    if (parse_dest(CONFIG_TINYLINK_TELEMETRY_DEST,
                   host, sizeof(host), &port) != 0) {
        ESP_LOGE(TAG, "telemetry dest malformed: %s",
                 CONFIG_TINYLINK_TELEMETRY_DEST);
        vTaskDelete(NULL);
        return;
    }
    struct sockaddr_in dest;
    int sock = open_dest_socket(host, port, &dest);
    if (sock < 0) {
        vTaskDelete(NULL);
        return;
    }
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

    /* Tick counter is enough as a sequence number; the collector can
     * convert to wall time using its own ingest timestamp. */
    uint32_t seq = 0;
    char buf[TX_BUF_SZ];

    /* Periodic diag dump for soak observability: every 12th telemetry
     * tx ≈ every 60 s at the default 5 s period. Drives the
     * tinylink_diag_dump_stacks() walk of all FreeRTOS task stack
     * high-water marks (data source for the deferred task-stack-trim
     * audit item). Skip seq==0 so the first dump happens at seq=12
     * (~65 s post-boot) when all bringup tasks have stabilized. */
    enum { TL_DIAG_TX_PERIOD = 12 };

    tl_wdt_subscribe();
    for (;;) {
        tl_wdt_feed();
        int32_t milli_c = 0;
        err = tmp117_read_milli_c(&milli_c);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "tmp117 read failed: %s",
                     esp_err_to_name(err));
            vTaskDelay(pdMS_TO_TICKS(CONFIG_TINYLINK_TELEMETRY_PERIOD_MS));
            continue;
        }
        int sign = (milli_c < 0) ? -1 : 1;
        int32_t abs_milli = milli_c * sign;
        int n = snprintf(buf, sizeof(buf),
            "{\"host\":\"%s\",\"seq\":%u,\"temp_c\":%s%ld.%03ld}\n",
            CONFIG_TINYLINK_DEVICE_HOSTNAME,
            (unsigned)seq++,
            sign < 0 ? "-" : "",
            (long)(abs_milli / 1000), (long)(abs_milli % 1000));
        if (n < 0 || (size_t)n >= sizeof(buf)) continue;
        s_stats_seq = seq;

        ssize_t sent = sendto(sock, buf, (size_t)n, 0,
                              (const struct sockaddr *)&dest, sizeof(dest));
        if (sent < 0) {
            ESP_LOGW(TAG, "sendto failed: errno=%d", errno);
            /* WG netif may be transiently down during peer endpoint
             * updates — back off for one period and try again. */
        } else {
            ESP_LOGI(TAG, "tx seq=%u temp=%s%ld.%03ld°C (%d B)",
                     (unsigned)(seq - 1),
                     sign < 0 ? "-" : "",
                     (long)(abs_milli / 1000), (long)(abs_milli % 1000),
                     (int)sent);
        }
        if (seq > 0 && (seq % TL_DIAG_TX_PERIOD) == 0) {
            tinylink_diag_dump_stacks();
            tl_time_poll_persist();
        }
        stats_wait(sock, CONFIG_TINYLINK_TELEMETRY_PERIOD_MS);
    }
}

esp_err_t telemetry_start(void)
{
    /* 4 KiB stack matches research §J's `app_task` budget — the TMP117
     * read + snprintf + sendto path is shallow. */
    BaseType_t ok = xTaskCreate(telemetry_task, "tinylink_tlm",
                                4096, NULL, tskIDLE_PRIORITY + 2, NULL);
    if (ok != pdPASS) return ESP_ERR_NO_MEM;
    return ESP_OK;
}

#else  /* !CONFIG_TINYLINK_TELEMETRY_ENABLE */

esp_err_t telemetry_start(void)
{
    /* Telemetry disabled at build time — caller can ignore the no-op. */
    return ESP_OK;
}

#endif /* CONFIG_TINYLINK_TELEMETRY_ENABLE */

#endif /* ESP_PLATFORM */
