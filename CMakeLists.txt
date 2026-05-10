# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Bryam (bryamzxz)

cmake_minimum_required(VERSION 3.16)

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
