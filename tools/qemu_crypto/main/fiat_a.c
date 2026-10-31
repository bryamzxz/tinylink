// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// The firmware's curve25519_fiat32.c as built for the LX6: Xtensa asm path.
#include "curve25519_fiat32.c"
void A_mul(u32 o[10], const u32 a[10], const u32 b[10]) { fe_mul_impl(o, a, b); }
void A_sqr(u32 o[10], const u32 a[10]) { fe_sqr_impl(o, a); }
void A_121(u32 o[10], const u32 a[10]) { fe_mul121666_impl(o, a); }
