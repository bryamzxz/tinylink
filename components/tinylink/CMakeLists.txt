# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Bryam (bryamzxz)

idf_component_register(
    SRCS
        "src/tinylink.c"
        "src/keys.c"
        "src/control_key.c"
        "src/json_helpers.c"
        "src/noise_ik.c"
        "src/tls_io.c"
        "src/tls_resume.c"
        "src/tls_offer.c"
        "src/tls_x25519.c"
        "src/ts2021_client.c"
        "src/h2_client.c"
        "src/h2_core.c"
        "src/hpack.c"
        "src/register.c"
        "src/mapreq.c"
        "src/wg_dataplane.c"
        "src/wg_proto.c"
        "src/wg_handshake.c"
        "src/wg_transport.c"
        "src/wg_demux.c"
        "src/disco.c"
        "src/disco_handler.c"
        "src/disco_prober.c"
        "src/stun.c"
        "src/stun_probe.c"
        "src/derp.c"
        "src/derp_client.c"
        "src/wg_netif.c"
        "src/wg_lwip.c"
        "src/tmp117.c"
        "src/telemetry.c"
        "src/pwr_diag.c"
        "src/crypto/blake2s.c"
        "src/crypto/curve25519.c"
        "src/crypto/curve25519_fiat32.c"
        "src/crypto/hkdf_blake2s.c"
        "src/crypto/salsa20.c"
        "src/crypto/nacl_box.c"
        "src/crypto/chacha20.c"
        "src/crypto/poly1305_donna.c"
        "src/crypto/chacha20poly1305.c"
        "src/crypto/secure_zero.c"
        "src/tinylink_bench.c"
        "src/tl_time.c"
        "src/tl_libc_stubs.c"
    INCLUDE_DIRS
        "include"
    PRIV_INCLUDE_DIRS
        "src"
        "src/crypto"
    REQUIRES
        nvs_flash
        esp_event
        esp_netif
        esp-tls
        esp_driver_i2c
        lwip
        mbedtls
    PRIV_REQUIRES
        esp_timer
        esp_pm
)

# -O2 islands inside tinylink (round 1.3.2, B6). The global level is -Os
# (CONFIG_COMPILER_OPTIMIZATION_SIZE); a source-level COMPILE_OPTIONS
# lands after the target's flags, so -O2 wins for these files only:
#  - crypto/*: the IRAM AEAD (every WG packet and Noise record), X25519
#    (WG / DISCO / Noise handshakes, 2.4 M instructions each since 1.3.3,
#    20 ms under donna), BLAKE2s + HKDF, XSalsa20 + NaCl box (DISCO, DERP
#    login);
#  - the WireGuard data plane and handshake: wg_netif, wg_lwip,
#    wg_transport, wg_demux (per packet), wg_handshake, wg_proto;
#  - DISCO (disco, disco_handler, disco_prober — on wg_rx) and the DERP
#    relay codec / client (derp, derp_client — every relayed packet);
#  - keys.c: boot-only, but -Os makes it 5 B larger;
#  - tmp117.c: 1/min, but -Os outlines read_reg16 (+64 B on the I2C
#    read chain of tinylink_tlm, the task with the smallest soak margin)
#    to save 63 B.
# Everything else is control plane, per-netmap or once-per-minute code
# at -Os: ts2021_client / noise_ik (record glue; the AEAD itself is in
# IRAM), h2_client / h2_core / hpack (round 1.3.4, D1: per record and per
# response header block, not per packet), tls_io, tls_resume (once per
# TLS connect), register, control_key, json_helpers,
# mapreq (netmap parse, ~4 ms), wg_dataplane (peer selection per
# netmap), stun / stun_probe, tinylink (bring-up, supervisors, thin
# DERP dispatch), telemetry (1/min), tl_time, tinylink_bench: the
# component is 5.4 KB smaller than all-at-O2. Their frames shrink or
# merge through inlining; the few that grow do so by 16 B on the
# 24 KiB long-poll task (worst case below long_poll_task +32 B, still
# 192 B under 1.3.1). New sources default to -Os: add them here only
# with a reason.
set_property(SOURCE
        "src/crypto/blake2s.c"
        "src/crypto/curve25519.c"
        "src/crypto/curve25519_fiat32.c"
        "src/crypto/hkdf_blake2s.c"
        "src/crypto/salsa20.c"
        "src/crypto/nacl_box.c"
        "src/crypto/chacha20.c"
        "src/crypto/poly1305_donna.c"
        "src/crypto/chacha20poly1305.c"
        "src/crypto/secure_zero.c"
        "src/wg_netif.c"
        "src/wg_lwip.c"
        "src/wg_transport.c"
        "src/wg_demux.c"
        "src/wg_handshake.c"
        "src/wg_proto.c"
        "src/disco.c"
        "src/disco_handler.c"
        "src/disco_prober.c"
        "src/derp.c"
        "src/derp_client.c"
        "src/keys.c"
        "src/tmp117.c"
    APPEND PROPERTY COMPILE_OPTIONS -O2)

# newlib-nano float formatting stubs (round 1.3.2, B3; audit in
# src/tl_libc_stubs.c). `-u` makes both symbols undefined from the first
# input on, so this archive — searched before libc — supplies them and
# libc's float printf/scanf back ends (dtoa, mprec, strtod, gdtoa) never
# link. A duplicate-definition link error would mean something now pulls
# that libc object in for another symbol: re-audit before removing this.
target_link_libraries(${COMPONENT_LIB} INTERFACE "-u _printf_float" "-u _scanf_float")

# The TLS ECDHE's X25519 on the in-tree Curve25519 (round 1.3.8,
# src/tls_x25519.c): ecdh.c's calls into mbedtls_ecp_mul_restartable go to
# __wrap_mbedtls_ecp_mul_restartable (a --wrap only redirects references
# from other objects; ecp.c's own calls keep the original). `-u` pulls the
# wrapper's object out of this archive before mbedcrypto asks for it.
if(CONFIG_TINYLINK_TLS_X25519_INTREE)
    target_link_libraries(${COMPONENT_LIB} INTERFACE
        "-Wl,--wrap=mbedtls_ecp_mul_restartable" "-u __wrap_mbedtls_ecp_mul_restartable")
endif()

# Build epoch for tl_time.c's clock floor (see tl_time.h). Evaluated at
# configure time, so a reconfigure moves it; that is the intent — the
# floor only has to be <= real time and >= the newest cert's notBefore
# the firmware will meet before its first NTP sync.
string(TIMESTAMP TL_BUILD_EPOCH "%s" UTC)
target_compile_definitions(${COMPONENT_LIB} PRIVATE TL_BUILD_EPOCH=${TL_BUILD_EPOCH}ULL)

# The jsmn token table of mapreq.c is in IRAM (round 1.3.4, D6), where a
# byte or half-word access is a LoadStoreError. Re-prove after every build
# of this component that every access the compiled mapreq.c makes through
# a pointer into it is 32-bit (tools/iram_access_check.py, a data-flow
# check of the object code): an innocent-looking source change such as
# `(tok->type & 0xff) == JSMN_STRING` compiles to an l8ui, and fails the
# build here instead of crashing the device.
idf_build_get_property(tl_python PYTHON)
add_custom_command(TARGET ${COMPONENT_LIB} POST_BUILD
    COMMAND ${tl_python} ${CMAKE_CURRENT_LIST_DIR}/../../tools/iram_access_check.py
            --objdump ${CMAKE_OBJDUMP} --section .iram.bss
            ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/${COMPONENT_LIB}.dir/src/mapreq.c.obj
    VERBATIM)
