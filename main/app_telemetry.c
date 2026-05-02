// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "app_telemetry.h"

#include <string.h>
#include <sys/socket.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "lwip/inet.h"

#include "app_sensor.h"

static const char *TAG = "app_tel";

#define TASK_STACK 4096
#define TASK_PRIO  5

static char s_peer_ip[32];

static void telemetry_task(void *arg)
{
    (void)arg;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket() failed");
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(CONFIG_TINYLINK_TELEMETRY_UDP_PORT);
    if (inet_aton(s_peer_ip, &dest.sin_addr) == 0) {
        ESP_LOGE(TAG, "invalid peer ip '%s'", s_peer_ip);
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    char payload[128];
    const TickType_t period = pdMS_TO_TICKS(CONFIG_TINYLINK_TELEMETRY_INTERVAL_MS);

    for (;;) {
        float temp_c = 0.0f;
        esp_err_t err = app_sensor_read_temperature_c(&temp_c);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "sensor read failed: 0x%x", err);
            vTaskDelay(period);
            continue;
        }

        uint64_t ts_ms = esp_timer_get_time() / 1000ULL;
        int n = snprintf(payload, sizeof(payload),
                         "{\"device\":\"%s\",\"ts\":%llu,\"temp_c\":%.3f}",
                         CONFIG_TINYLINK_DEVICE_HOSTNAME,
                         (unsigned long long)ts_ms, temp_c);
        if (n <= 0 || n >= (int)sizeof(payload)) {
            ESP_LOGW(TAG, "payload format error (n=%d)", n);
            vTaskDelay(period);
            continue;
        }

        ssize_t sent = sendto(sock, payload, (size_t)n, 0,
                              (struct sockaddr *)&dest, sizeof(dest));
        if (sent != n) {
            ESP_LOGW(TAG, "sendto failed (sent=%d/%d errno=%d)",
                     (int)sent, n, errno);
        } else {
            ESP_LOGI(TAG, "tx %s:%d %s", s_peer_ip,
                     CONFIG_TINYLINK_TELEMETRY_UDP_PORT, payload);
        }
        vTaskDelay(period);
    }
}

esp_err_t app_telemetry_start(const char *peer_allowed_ip)
{
    if (peer_allowed_ip == NULL || peer_allowed_ip[0] == '\0') {
        return ESP_ERR_INVALID_ARG;
    }
    /* Strip optional "/N" suffix from "100.x.y.z/32". */
    size_t i = 0;
    while (peer_allowed_ip[i] != '\0' && peer_allowed_ip[i] != '/' &&
           i < sizeof(s_peer_ip) - 1) {
        s_peer_ip[i] = peer_allowed_ip[i];
        i++;
    }
    s_peer_ip[i] = '\0';

    BaseType_t ok = xTaskCreate(telemetry_task, "telemetry", TASK_STACK,
                                NULL, TASK_PRIO, NULL);
    return (ok == pdPASS) ? ESP_OK : ESP_ERR_NO_MEM;
}
