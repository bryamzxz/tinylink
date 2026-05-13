# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Bryam (bryamzxz)

cmake_minimum_required(VERSION 3.16)

# Strip IDF components with zero callers in tinylink. EXCLUDE_COMPONENTS
# tells the build system to skip them entirely — they don't enter the
# component graph, their CMakeLists never runs, and the linker never sees
# their object files. This is stronger than relying on -Wl,--gc-sections
# alone because (a) some components install their .text via constructor
# tables the linker can't strip and (b) it saves compile time too.
#
# Verified 0 callers via grep across components/tinylink/src + main/:
#
#   No connectivity stacks we don't use:
#   bt, openthread, ieee802154, esp_hal_ieee802154, usb, esp_eth
#
#   No filesystem / storage drivers we don't use:
#   spiffs, fatfs, sdmmc, wear_levelling, nvs_sec_provider
#   (CONFIG_NVS_ENCRYPTION=y uses the default eFuse-derived provider,
#    not the HMAC- or flash-encryption-key providers in this component)
#
#   No HTTP/MQTT/OTA server-side or auxiliary stacks:
#   mqtt, esp_http_server, esp_https_server, esp_https_ota,
#   wifi_provisioning, protocomm, esp_local_ctrl, protobuf-c
#   (protobuf-c is only pulled by protocomm; safe to drop together)
#
#   No display / camera / imaging / audio peripherals:
#   esp_lcd, esp_driver_cam, esp_driver_isp, esp_driver_jpeg,
#   esp_driver_ppa, esp_driver_i2s, esp_driver_dac
#
#   No peripheral drivers tinylink doesn't reference (TMP117 uses
#   esp_driver_i2c which stays in; UART output uses the default
#   driver via esp_vfs_console / vfs which also stay in):
#   esp_driver_mcpwm, esp_driver_rmt, esp_driver_sdmmc, esp_driver_sdio,
#   esp_driver_sdspi, esp_driver_sdm, esp_driver_ana_cmpr,
#   esp_driver_bitscrambler, esp_driver_parlio, esp_driver_pcnt,
#   esp_driver_touch_sens, esp_driver_tsens, esp_driver_twai,
#   esp_driver_usb_serial_jtag
#
#   No HID / perf-monitor / ULP coprocessor / Touch peripherals:
#   esp_hid, perfmon, ulp
#
# Re-verify if you add a new dep to components/tinylink/CMakeLists.txt:
# the build will fail loudly with `component X not found` if a REQUIRES
# names something we excluded here.
set(EXCLUDE_COMPONENTS
    bt
    openthread
    ieee802154
    esp_hal_ieee802154
    usb
    esp_eth

    spiffs
    fatfs
    sdmmc
    wear_levelling
    nvs_sec_provider

    mqtt
    esp_http_server
    esp_https_server
    esp_https_ota
    wifi_provisioning
    protocomm
    esp_local_ctrl
    protobuf-c

    esp_lcd
    esp_driver_cam
    esp_driver_isp
    esp_driver_jpeg
    esp_driver_ppa
    esp_driver_i2s
    esp_driver_dac

    esp_driver_mcpwm
    esp_driver_rmt
    esp_driver_sdmmc
    esp_driver_sdio
    esp_driver_sdspi
    esp_driver_sdm
    esp_driver_ana_cmpr
    esp_driver_bitscrambler
    esp_driver_parlio
    esp_driver_pcnt
    esp_driver_touch_sens
    esp_driver_tsens
    esp_driver_twai
    esp_driver_usb_serial_jtag

    esp_hid
    perfmon
    ulp
)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(tinylink)

# -O2 for IDF's mbedcrypto library only. This is what mbedtls uses for
# its symmetric/asymmetric primitives — i.e. the SHA/AES/RSA building
# blocks behind every TLS handshake on the control plane and DERP
# uplink. HW SHA/AES paths are already enabled (HARDWARE_AES=y,
# HARDWARE_SHA=y, HARDWARE_MPI=y in sdkconfig.defaults), so the win
# is on the SW glue around them. mbedtls + mbedx509 are intentionally
# left at the default opt level — the bulk of their code is parsing/
# validation, not arithmetic, and we want to minimize binary growth
# on the cold paths.
target_compile_options(mbedcrypto PRIVATE -O2)
