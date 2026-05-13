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

    for (;;) {
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
        }
        vTaskDelay(pdMS_TO_TICKS(CONFIG_TINYLINK_TELEMETRY_PERIOD_MS));
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
