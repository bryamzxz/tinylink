/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host-only stand-in for mbedtls/constant_time.h (tls_resume.c); the test
 * that links it defines mbedtls_ct_memcmp. */
#pragma once

#include <stddef.h>

int mbedtls_ct_memcmp(const void *a, const void *b, size_t n);
