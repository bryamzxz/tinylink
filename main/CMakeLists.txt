# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Bryam (bryamzxz)

idf_component_register(
    SRCS
        "main.c"
        "app_nvs.c"
        "app_wifi.c"
        "app_wireguard.c"
        "app_sensor.c"
        "app_telemetry.c"
    INCLUDE_DIRS
        "."
    REQUIRES
        nvs_flash
        esp_netif
        esp_wifi
        esp_event
        driver
        lwip
        tinylink
)
