// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Same file, C fallback (the code the host tests run), also built for the LX6.
#include <stdint.h>
#include <string.h>
#include "curve25519.h"
#include "secure_zero.h"
#undef __XTENSA__
#define curve25519_fiat32 curve25519_fiat32_c
#include "curve25519_fiat32.c"
void C_mul(u32 o[10], const u32 a[10], const u32 b[10]) { fe_mul_impl(o, a, b); }
void C_sqr(u32 o[10], const u32 a[10]) { fe_sqr_impl(o, a); }
void C_121(u32 o[10], const u32 a[10]) { fe_mul121666_impl(o, a); }
