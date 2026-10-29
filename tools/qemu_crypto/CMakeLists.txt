# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Bryam (bryamzxz)
#
# The crypto host suites built for the ESP32 and run on Espressif's QEMU
# (`-machine esp32`), so the Xtensa paths — the inline asm in
# curve25519_fiat32.c, chacha20.c, blake2s.c, salsa20.c, poly1305 — run
# on an ISA implementation nobody on this project wrote. The host suites
# only ever see the C fallbacks. See run.sh.
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(MINIMAL_BUILD ON)
project(qemu_crypto)
