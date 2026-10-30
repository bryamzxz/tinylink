# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Bryam (bryamzxz)

set(srcs "main.c" "app_nvs.c" "app_wifi.c")
if(CONFIG_TINYLINK_WIFI_DIAG)
    list(APPEND srcs "wifi_diag.c")
endif()

idf_component_register(
    SRCS
        ${srcs}
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

# Wi-Fi association diagnostics (round 1.3.7, default n): the supplicant's
# EAPOL path goes through wifi_diag.c's __wrap_ functions. app_wifi.c
# calls into wifi_diag.c, so the object (and its wrappers) is always
# linked when the option is on.
if(CONFIG_TINYLINK_WIFI_DIAG)
    target_link_libraries(${COMPONENT_LIB} INTERFACE
        "-Wl,--wrap=wpa_sm_rx_eapol"
        "-Wl,--wrap=wpa_ether_send"
        "-Wl,--wrap=eapol_txcb"
        "-Wl,--wrap=esp_wifi_internal_issue_disconnect")
endif()
