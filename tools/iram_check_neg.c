// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Planted violations for tools/iram_access_check.py (round 1.3.4, D6):
// compiled with mapreq.c's flags, the checker must flag all eight bad_* /
// helper / maybe_mask cases and pass ok_fields. Not part of any build;
// the command is in tools/README.md. maybe_mask is the realistic one:
// GCC turns `(type & 0xff) == 4` into a byte load (l8ui), which in IRAM
// is a LoadStoreError.

#include <string.h>

#include "jsmn.h"

static jsmntok_t t[64] __attribute__((section(".iram.bss"), aligned(4)));
jsmntok_t *g_escape;
jsmntok_t *g_alias = t;

int ok_fields(int i) { return t[i].start + t[i].end + t[i].size + (t[i].type == JSMN_STRING); }
int bad_byte(int i) { return ((const volatile unsigned char *)&t[i])[1]; }
void bad_half(int i) { ((volatile unsigned short *)&t[i].size)[0] = 7; }
void bad_memset(void) { memset(t, 0, sizeof(t)); }
void bad_escape(int i) { g_escape = &t[i]; }
static __attribute__((noinline)) int helper(const jsmntok_t *p)
{
    return ((const volatile unsigned char *)p)[0];
}
int bad_callee(int i) { return helper(&t[i]); }
void bad_loop(int n)
{
    for (jsmntok_t *p = t; p < t + n; p++) ((volatile char *)p)[3] = 0;
}
int maybe_mask(int i) { return (t[i].type & 0xff) == 4; }
int bad_alias(int i) { return ((volatile jsmntok_t *)g_alias)[i].start; }
