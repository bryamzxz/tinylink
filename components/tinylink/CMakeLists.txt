# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Bryam (bryamzxz)

idf_component_register(
    SRCS
        "src/tinylink.c"
    INCLUDE_DIRS
        "include"
    REQUIRES
        esp_common
)
