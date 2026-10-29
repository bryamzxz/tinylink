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

# mbedTLS user config (round 1.3.2): mbedtls_user_config.h #undefs what
# esp_config.h enables without a Kconfig (ARIA, CFB/OFB, 3 paddings,
# PKCS#12; reasons in the header). A build-wide COMPILE_DEFINITION, set
# before project(): every component's directory scope picks it up
# (idf_component_register), including mbedTLS's own mbedtls / mbedx509 /
# mbedcrypto targets, so all translation units that include mbedTLS
# headers compile the same configuration — the same reach as IDF's own
# MBEDTLS_CONFIG_FILE. Path from this file's directory, so it follows
# moves and other checkouts. The bootloader is a separate project and
# does not see it (bootloader.bin is byte-identical).
idf_build_set_property(COMPILE_DEFINITIONS
    "MBEDTLS_USER_CONFIG_FILE=\"${CMAKE_CURRENT_LIST_DIR}/mbedtls_user_config.h\"" APPEND)

project(tinylink)

# An existing sdkconfig always wins over sdkconfig.defaults, so one
# generated before round 1.3.1 silently keeps the old choice selections
# (-Og, full cert bundle, Log V1, DHCP ARP probe, brown-out level 0) in
# a build that reports 1.3.1. Say so; deleting sdkconfig regenerates it.
if(NOT CONFIG_COMPILER_OPTIMIZATION_SIZE OR NOT CONFIG_LOG_VERSION_2
   OR NOT CONFIG_LWIP_DHCP_DOES_NOT_CHECK_OFFERED_IP)
    message(WARNING "sdkconfig does not carry the round-1.3.1 defaults "
                    "(COMPILER_OPTIMIZATION_SIZE / LOG_VERSION_2 / "
                    "LWIP_DHCP_DOES_NOT_CHECK_OFFERED_IP). If it predates "
                    "1.3.1, delete it and rebuild; ignore this for a "
                    "deliberate debug configuration.")
endif()

# -O2 islands inside mbedcrypto (round 1.3.2, B6); the rest of mbedTLS
# (mbedcrypto, mbedtls, mbedx509) runs at the global -Os. Measured on
# the host (IDF's mbedTLS 3.6.7, gcov line counts of a full TLS 1.2
# handshake + response against controlplane): bignum_core.c 44.5 %, the
# constant_time_impl.h inlines 25.7 %, bignum.c 16.2 %, ecp_curves.c
# 10.1 %, ecp.c 2.0 %, everything else < 0.5 % (SHA, AES, ASN.1,
# X.509, RSA glue). Every handshake does X25519 ECDHE (mbedTLS ECP),
# one P-256 and three P-384 ECDSA verifies and one RSA verify. On the
# ESP32 each field multiplication goes through the MPI accelerator, so
# its glue (esp_bignum.c, bignum_alt.c) is per-mul hot too, and since
# TLS records are AES-128-GCM (B4) the record path is esp_aes_gcm.c
# (software GHASH, GCM_ALT) + esp_aes.c (HW block) per 16 bytes.
# ecdh.c, pk.c, pk_wrap.c, cipher_wrap.c and esp_sha512.c come out
# smaller at -O2 than at -Os, so they keep it. Everything else at -Os:
# libmbedcrypto.a 4.2 KB smaller than all-at-O2.
idf_component_get_property(tl_mbedtls_dir mbedtls COMPONENT_DIR)
set_property(SOURCE
        "${tl_mbedtls_dir}/mbedtls/library/bignum.c"
        "${tl_mbedtls_dir}/mbedtls/library/bignum_core.c"
        "${tl_mbedtls_dir}/mbedtls/library/ecp.c"
        "${tl_mbedtls_dir}/mbedtls/library/ecp_curves.c"
        "${tl_mbedtls_dir}/port/bignum/esp_bignum.c"
        "${tl_mbedtls_dir}/port/bignum/bignum_alt.c"
        "${tl_mbedtls_dir}/port/aes/esp_aes_gcm.c"
        "${tl_mbedtls_dir}/port/aes/block/esp_aes.c"
        "${tl_mbedtls_dir}/mbedtls/library/ecdh.c"
        "${tl_mbedtls_dir}/mbedtls/library/pk.c"
        "${tl_mbedtls_dir}/mbedtls/library/pk_wrap.c"
        "${tl_mbedtls_dir}/mbedtls/library/cipher_wrap.c"
        "${tl_mbedtls_dir}/port/sha/parallel_engine/esp_sha512.c"
    TARGET_DIRECTORY mbedcrypto
    APPEND PROPERTY COMPILE_OPTIONS -O2)

# -O2 islands inside IDF components (round 1.3.1). The global level is
# -Os (CONFIG_COMPILER_OPTIMIZATION_SIZE); these files sit on every WG
# packet: lwIP's Internet checksum (21 → 9 µs per 1 500 B at -O2), pbuf
# alloc/copy, UDP and IPv4 in/out, and the FreeRTOS queue the wg_tx task
# and the socket layer block on. Source-level COMPILE_OPTIONS land after
# the component's own flags on the command line, so -O2 wins.
idf_component_get_property(tl_lwip_lib lwip COMPONENT_LIB)
idf_component_get_property(tl_lwip_dir lwip COMPONENT_DIR)
set_property(SOURCE
        "${tl_lwip_dir}/lwip/src/core/inet_chksum.c"
        "${tl_lwip_dir}/lwip/src/core/pbuf.c"
        "${tl_lwip_dir}/lwip/src/core/udp.c"
        "${tl_lwip_dir}/lwip/src/core/ipv4/ip4.c"
    TARGET_DIRECTORY ${tl_lwip_lib}
    APPEND PROPERTY COMPILE_OPTIONS -O2)
idf_component_get_property(tl_freertos_lib freertos COMPONENT_LIB)
idf_component_get_property(tl_freertos_dir freertos COMPONENT_DIR)
set_property(SOURCE "${tl_freertos_dir}/FreeRTOS-Kernel/queue.c"
    TARGET_DIRECTORY ${tl_freertos_lib}
    APPEND PROPERTY COMPILE_OPTIONS -O2)
