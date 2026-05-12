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
        "src/ts2021_client.c"
        "src/h2_client.c"
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
        "src/crypto/blake2s.c"
        "src/crypto/curve25519.c"
        "src/crypto/curve25519_donna.c"
        "src/crypto/hkdf_blake2s.c"
        "src/crypto/salsa20.c"
        "src/crypto/nacl_box.c"
        "src/crypto/chacha20.c"
        "src/crypto/poly1305_donna.c"
        "src/crypto/chacha20poly1305.c"
        "src/tinylink_bench.c"
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
        esp_http_client
        esp_driver_i2c
        lwip
        mbedtls
        json
    PRIV_REQUIRES
        espressif__nghttp
)

# -O2 for the entire tinylink component. This is the perf-critical
# code: WG transport, ChaCha20-Poly1305 AEAD, Curve25519, BLAKE2s,
# HKDF, the DISCO/STUN/DERP codecs, and the netif fast path. The
# global default is CONFIG_COMPILER_OPTIMIZATION_DEBUG=y (-Og); the
# override here scopes -O2 to our own code only, so the documented
# toolchain hangs on certain lwIP files at -O2 are not in scope.
target_compile_options(${COMPONENT_LIB} PRIVATE -O2)
