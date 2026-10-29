# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Bryam (bryamzxz)

idf_component_register(
    SRCS
        "main.c"
        "app_nvs.c"
        "app_wifi.c"
    INCLUDE_DIRS
        "."
    REQUIRES
        nvs_flash
        esp_netif
        esp_wifi
        esp_event
        esp_pm
        esp_timer
        tinylink
)

# -O2 for app_main / app_wifi / app_nvs. Tiny code surface but no reason
# to leave it at the global -Os when the rest of tinylink runs -O2.
target_compile_options(${COMPONENT_LIB} PRIVATE -O2)
