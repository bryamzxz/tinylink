// SPDX-License-Identifier: MIT
//
// tinylink note: X25519 scalar multiplication from Linux's
// lib/crypto/curve25519-fiat32.c (fiat-crypto's formally verified 32-bit
// Curve25519, dual-licensed "GPL-2.0 OR MIT"; used here under MIT, notice
// below). Replaces agl's curve25519-donna in round 1.3.3 (C6). The
// representation (radix 2^25.5, ten u32 limbs), the "tight" / "loose"
// limb bounds, fe_frombytes / fe_freeze / fe_tobytes, fe_add / fe_sub,
// fe_cswap, the inversion chain and the ladder are fiat32's: same
// arithmetic, with the kernel helpers replaced (get_unaligned_le32,
// memzero_explicit → tl_secure_zero), fe_add / fe_sub written one limb per
// statement, fe_cswap unrolled and the ladder temporaries scrubbed too.
//
// Rewritten for the Xtensa LX6 (finding S3 of the 2026-10 optimization
// list): fe_mul, fe_sqr and fe_mul121666. Every 64-bit addition GCC emits
// on a core without a carry flag is `add; add; bgeu; addi` — a branch on
// the carry, i.e. on secret data. Donna's int64 limb arithmetic compiled
// to 162 such `bgeu` sites, executed 342 266 times per scalarmult, and
// fiat32's u64 column sums would do the same. Here no 64-bit value is
// ever added:
//  - fe_mul / fe_sqr scan the product column by column (product
//    scanning) and split each 32×32→64 product P at bit 28 into two
//    32-bit accumulators, L += P mod 2^28 and H += P >> 28 (mull, muluh,
//    src with SAR = 28, and, add, add — 6 instructions, no carry), then
//    move the column's carry into the next (L, H) with 32-bit shifts;
//  - fe_mul121666 multiplies limb by limb and only ever adds 32-bit
//    halves.
// Measured on the compiled firmware (instruction-level simulation of the
// Xtensa code, round 1.3.3): 3.51 M → 2.43 M instructions per scalarmult
// (−31 %), and the same instruction sequence, memory addresses and branch
// outcomes for any scalar and point. RFC 7748 vectors, cross-checks
// against donna and the field operations at their bounds:
// tools/test/test_x25519.c.
//
// Bounds (fiat32's): a "tight" limb i is < 1.125·2^w_i, a "loose" one
// < 3.375·2^w_i, w = 26, 25, 26, 25, …; fe_mul / fe_sqr take loose
// inputs. A product (odd×odd doubled) is < 2^55.6 in fe_mul, and < 2^56.6
// in fe_sqr (2·f_i·f_j, i and j even), so P >> 28 < 2^28.6 and
// P mod 2^28 < 2^28. A column has at most 10 products in fe_mul, 5 in
// fe_sqr, plus the carry from the previous one (< 2^28 + 2^7 into L,
// < 2^7 into H): L < 11·2^28 < 2^31.5 and H < 2^30.9 in both. The
// column's low w bits are the limb; columns 10..18 fold ×19 into limbs
// 0..8 (2^255 ≡ 19), limb-sized so 19·t < 2^30.3; the carry out of
// column 18 (< 2^28.6) folds ×19 into limb 9 (its low 25 bits) and ×361
// into limb 0 (the rest, weight 2^510). The last carry pass leaves limb
// 1 ≤ 2^25 and every other limb below 2^w_i: tight.
//
// ----------------------------------------------------------------------
// Copyright (C) 2015-2016 The fiat-crypto Authors.
// Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
//
// This is a machine-generated formally verified implementation of Curve25519
// ECDH from: <https://github.com/mit-plv/fiat-crypto>. Though originally
// machine generated, it has been tweaked to be suitable for use in the kernel.
// It is optimized for 32-bit machines and machines that cannot work efficiently
// with 128-bit integer types.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

#include "curve25519.h"

#include <stdint.h>
#include <string.h>

#include "secure_zero.h"

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

#ifndef __always_inline   /* newlib / glibc <sys/cdefs.h> already have it */
#define __always_inline inline __attribute__((always_inline))
#endif
#define noinline        __attribute__((noinline))

static __always_inline u32 get_unaligned_le32(const u8 *p)
{
	return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

/* fe means field element. Here the field is \Z/(2^255-19). An element t,
 * entries t[0]...t[9], represents the integer t[0]+2^26 t[1]+2^51 t[2]+2^77
 * t[3]+2^102 t[4]+...+2^230 t[9].
 * fe limbs are bounded by 1.125*2^26,1.125*2^25,1.125*2^26,1.125*2^25,etc.
 * Multiplication and carrying produce fe from fe_loose.
 */
typedef struct fe { u32 v[10]; } fe;

/* fe_loose limbs are bounded by 3.375*2^26,3.375*2^25,3.375*2^26,3.375*2^25,etc
 * Addition and subtraction produce fe_loose from (fe, fe).
 */
typedef struct fe_loose { u32 v[10]; } fe_loose;

static __always_inline void fe_frombytes_impl(u32 h[10], const u8 *s)
{
	/* Ignores top bit of s. */
	u32 a0 = get_unaligned_le32(s);
	u32 a1 = get_unaligned_le32(s+4);
	u32 a2 = get_unaligned_le32(s+8);
	u32 a3 = get_unaligned_le32(s+12);
	u32 a4 = get_unaligned_le32(s+16);
	u32 a5 = get_unaligned_le32(s+20);
	u32 a6 = get_unaligned_le32(s+24);
	u32 a7 = get_unaligned_le32(s+28);
	h[0] = a0&((1<<26)-1);                    /* 26 used, 32-26 left.   26 */
	h[1] = (a0>>26) | ((a1&((1<<19)-1))<< 6); /* (32-26) + 19 =  6+19 = 25 */
	h[2] = (a1>>19) | ((a2&((1<<13)-1))<<13); /* (32-19) + 13 = 13+13 = 26 */
	h[3] = (a2>>13) | ((a3&((1<< 6)-1))<<19); /* (32-13) +  6 = 19+ 6 = 25 */
	h[4] = (a3>> 6);                          /* (32- 6)              = 26 */
	h[5] = a4&((1<<25)-1);                    /*                        25 */
	h[6] = (a4>>25) | ((a5&((1<<19)-1))<< 7); /* (32-25) + 19 =  7+19 = 26 */
	h[7] = (a5>>19) | ((a6&((1<<12)-1))<<13); /* (32-19) + 12 = 13+12 = 25 */
	h[8] = (a6>>12) | ((a7&((1<< 6)-1))<<20); /* (32-12) +  6 = 20+ 6 = 26 */
	h[9] = (a7>> 6)&((1<<25)-1); /*                                     25 */
}

static __always_inline void fe_frombytes(fe *h, const u8 *s)
{
	fe_frombytes_impl(h->v, s);
}

static __always_inline u8 /*bool*/
addcarryx_u25(u8 /*bool*/ c, u32 a, u32 b, u32 *low)
{
	/* This function extracts 25 bits of result and 1 bit of carry
	 * (26 total), so a 32-bit intermediate is sufficient.
	 */
	u32 x = a + b + c;
	*low = x & ((1 << 25) - 1);
	return (x >> 25) & 1;
}

static __always_inline u8 /*bool*/
addcarryx_u26(u8 /*bool*/ c, u32 a, u32 b, u32 *low)
{
	/* This function extracts 26 bits of result and 1 bit of carry
	 * (27 total), so a 32-bit intermediate is sufficient.
	 */
	u32 x = a + b + c;
	*low = x & ((1 << 26) - 1);
	return (x >> 26) & 1;
}

static __always_inline u8 /*bool*/
subborrow_u25(u8 /*bool*/ c, u32 a, u32 b, u32 *low)
{
	/* This function extracts 25 bits of result and 1 bit of borrow
	 * (26 total), so a 32-bit intermediate is sufficient.
	 */
	u32 x = a - b - c;
	*low = x & ((1 << 25) - 1);
	return x >> 31;
}

static __always_inline u8 /*bool*/
subborrow_u26(u8 /*bool*/ c, u32 a, u32 b, u32 *low)
{
	/* This function extracts 26 bits of result and 1 bit of borrow
	 *(27 total), so a 32-bit intermediate is sufficient.
	 */
	u32 x = a - b - c;
	*low = x & ((1 << 26) - 1);
	return x >> 31;
}

static __always_inline u32 cmovznz32(u32 t, u32 z, u32 nz)
{
	t = -!!t; /* all set if nonzero, 0 if 0 */
	return (t&nz) | ((~t)&z);
}

static __always_inline void fe_freeze(u32 out[10], const u32 in1[10])
{
	{ const u32 x17 = in1[9];
	{ const u32 x18 = in1[8];
	{ const u32 x16 = in1[7];
	{ const u32 x14 = in1[6];
	{ const u32 x12 = in1[5];
	{ const u32 x10 = in1[4];
	{ const u32 x8 = in1[3];
	{ const u32 x6 = in1[2];
	{ const u32 x4 = in1[1];
	{ const u32 x2 = in1[0];
	{ u32 x20; u8/*bool*/ x21 = subborrow_u26(0x0, x2, 0x3ffffed, &x20);
	{ u32 x23; u8/*bool*/ x24 = subborrow_u25(x21, x4, 0x1ffffff, &x23);
	{ u32 x26; u8/*bool*/ x27 = subborrow_u26(x24, x6, 0x3ffffff, &x26);
	{ u32 x29; u8/*bool*/ x30 = subborrow_u25(x27, x8, 0x1ffffff, &x29);
	{ u32 x32; u8/*bool*/ x33 = subborrow_u26(x30, x10, 0x3ffffff, &x32);
	{ u32 x35; u8/*bool*/ x36 = subborrow_u25(x33, x12, 0x1ffffff, &x35);
	{ u32 x38; u8/*bool*/ x39 = subborrow_u26(x36, x14, 0x3ffffff, &x38);
	{ u32 x41; u8/*bool*/ x42 = subborrow_u25(x39, x16, 0x1ffffff, &x41);
	{ u32 x44; u8/*bool*/ x45 = subborrow_u26(x42, x18, 0x3ffffff, &x44);
	{ u32 x47; u8/*bool*/ x48 = subborrow_u25(x45, x17, 0x1ffffff, &x47);
	{ u32 x49 = cmovznz32(x48, 0x0, 0xffffffff);
	{ u32 x50 = (x49 & 0x3ffffed);
	{ u32 x52; u8/*bool*/ x53 = addcarryx_u26(0x0, x20, x50, &x52);
	{ u32 x54 = (x49 & 0x1ffffff);
	{ u32 x56; u8/*bool*/ x57 = addcarryx_u25(x53, x23, x54, &x56);
	{ u32 x58 = (x49 & 0x3ffffff);
	{ u32 x60; u8/*bool*/ x61 = addcarryx_u26(x57, x26, x58, &x60);
	{ u32 x62 = (x49 & 0x1ffffff);
	{ u32 x64; u8/*bool*/ x65 = addcarryx_u25(x61, x29, x62, &x64);
	{ u32 x66 = (x49 & 0x3ffffff);
	{ u32 x68; u8/*bool*/ x69 = addcarryx_u26(x65, x32, x66, &x68);
	{ u32 x70 = (x49 & 0x1ffffff);
	{ u32 x72; u8/*bool*/ x73 = addcarryx_u25(x69, x35, x70, &x72);
	{ u32 x74 = (x49 & 0x3ffffff);
	{ u32 x76; u8/*bool*/ x77 = addcarryx_u26(x73, x38, x74, &x76);
	{ u32 x78 = (x49 & 0x1ffffff);
	{ u32 x80; u8/*bool*/ x81 = addcarryx_u25(x77, x41, x78, &x80);
	{ u32 x82 = (x49 & 0x3ffffff);
	{ u32 x84; u8/*bool*/ x85 = addcarryx_u26(x81, x44, x82, &x84);
	{ u32 x86 = (x49 & 0x1ffffff);
	{ u32 x88; addcarryx_u25(x85, x47, x86, &x88);
	out[0] = x52;
	out[1] = x56;
	out[2] = x60;
	out[3] = x64;
	out[4] = x68;
	out[5] = x72;
	out[6] = x76;
	out[7] = x80;
	out[8] = x84;
	out[9] = x88;
	}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
}

static __always_inline void fe_tobytes(u8 s[32], const fe *f)
{
	u32 h[10];
	fe_freeze(h, f->v);
	s[0] = h[0] >> 0;
	s[1] = h[0] >> 8;
	s[2] = h[0] >> 16;
	s[3] = (h[0] >> 24) | (h[1] << 2);
	s[4] = h[1] >> 6;
	s[5] = h[1] >> 14;
	s[6] = (h[1] >> 22) | (h[2] << 3);
	s[7] = h[2] >> 5;
	s[8] = h[2] >> 13;
	s[9] = (h[2] >> 21) | (h[3] << 5);
	s[10] = h[3] >> 3;
	s[11] = h[3] >> 11;
	s[12] = (h[3] >> 19) | (h[4] << 6);
	s[13] = h[4] >> 2;
	s[14] = h[4] >> 10;
	s[15] = h[4] >> 18;
	s[16] = h[5] >> 0;
	s[17] = h[5] >> 8;
	s[18] = h[5] >> 16;
	s[19] = (h[5] >> 24) | (h[6] << 1);
	s[20] = h[6] >> 7;
	s[21] = h[6] >> 15;
	s[22] = (h[6] >> 23) | (h[7] << 3);
	s[23] = h[7] >> 5;
	s[24] = h[7] >> 13;
	s[25] = (h[7] >> 21) | (h[8] << 4);
	s[26] = h[8] >> 4;
	s[27] = h[8] >> 12;
	s[28] = (h[8] >> 20) | (h[9] << 6);
	s[29] = h[9] >> 2;
	s[30] = h[9] >> 10;
	s[31] = h[9] >> 18;
	tl_secure_zero(h, sizeof(h));
}

/* h = f */
static __always_inline void fe_copy(fe *h, const fe *f)
{
	memmove(h, f, sizeof(u32) * 10);
}

/* h = 0 */
static __always_inline void fe_0(fe *h)
{
	memset(h, 0, sizeof(u32) * 10);
}

/* h = 1 */
static __always_inline void fe_1(fe *h)
{
	memset(h, 0, sizeof(u32) * 10);
	h->v[0] = 1;
}

static noinline void fe_add_impl(u32 out[10], const u32 in1[10], const u32 in2[10])
{
	/* tinylink: one statement per limb instead of fiat's load-everything-
	 * first nesting (same arithmetic): GCC kept the 20 inputs live at
	 * once and spilled them, 20 a1 loads/stores per call, 2 040 calls
	 * per scalarmult. Limb i only depends on limb i, so in-place calls
	 * stay correct. */
	out[0] = in1[0] + in2[0];
	out[1] = in1[1] + in2[1];
	out[2] = in1[2] + in2[2];
	out[3] = in1[3] + in2[3];
	out[4] = in1[4] + in2[4];
	out[5] = in1[5] + in2[5];
	out[6] = in1[6] + in2[6];
	out[7] = in1[7] + in2[7];
	out[8] = in1[8] + in2[8];
	out[9] = in1[9] + in2[9];
}

/* h = f + g
 * Can overlap h with f or g.
 */
static __always_inline void fe_add(fe_loose *h, const fe *f, const fe *g)
{
	fe_add_impl(h->v, f->v, g->v);
}

static noinline void fe_sub_impl(u32 out[10], const u32 in1[10], const u32 in2[10])
{
	/* tinylink: one statement per limb, see fe_add_impl. */
	out[0] = (0x7ffffda + in1[0]) - in2[0];
	out[1] = (0x3fffffe + in1[1]) - in2[1];
	out[2] = (0x7fffffe + in1[2]) - in2[2];
	out[3] = (0x3fffffe + in1[3]) - in2[3];
	out[4] = (0x7fffffe + in1[4]) - in2[4];
	out[5] = (0x3fffffe + in1[5]) - in2[5];
	out[6] = (0x7fffffe + in1[6]) - in2[6];
	out[7] = (0x3fffffe + in1[7]) - in2[7];
	out[8] = (0x7fffffe + in1[8]) - in2[8];
	out[9] = (0x3fffffe + in1[9]) - in2[9];
}

/* h = f - g
 * Can overlap h with f or g.
 */
static __always_inline void fe_sub(fe_loose *h, const fe *f, const fe *g)
{
	fe_sub_impl(h->v, f->v, g->v);
}

/* ---- tinylink: carry-free field multiplication (see the file header) ----
 *
 * P28(a, b) adds the 32×32→64 product a·b into the column accumulators
 * (L, H) as L += P mod 2^28, H += P >> 28. On Xtensa one asm statement
 * of 6 instructions, kept atomic so GCC cannot hoist the multiplies and
 * spill their halves: the same split in C (measured) makes fe_mul 2 111
 * instructions with 1 150 a1-relative loads/stores, against 1 051 / 167,
 * and a scalarmult 4.41 M instructions — slower than donna. `src` reads
 * SAR, which nothing but FE_SAR28() writes; both asm statements are
 * volatile, so their order holds, and the functions that use P28 are
 * noinline, so no SAR-using code of a caller (the ladder's variable
 * shift, GCC's 64-bit shifts) can be scheduled in between. Interrupts
 * and context switches save SAR with the rest of the task state.
 * Hosts: the same split in C. */
#if defined(__XTENSA__)
#define FE_SAR28(dep) __asm__ volatile ("ssai 28" : : "a"(dep))
#define P28(xa, xb) do { u32 _lo, _hi;                                        \
	__asm__ volatile ("mull  %[lo], %[x], %[y]\n\t"                       \
			  "muluh %[hi], %[x], %[y]\n\t"                       \
			  "src   %[hi], %[hi], %[lo]\n\t"                     \
			  "and   %[lo], %[lo], %[m]\n\t"                      \
			  "add   %[L], %[L], %[lo]\n\t"                       \
			  "add   %[H], %[H], %[hi]"                           \
			  : [L] "+a"(L), [H] "+a"(H), [lo] "=&a"(_lo), [hi] "=&a"(_hi) \
			  : [x] "a"(xa), [y] "a"(xb), [m] "a"(m28));          \
	} while (0)
#else
#define FE_SAR28(dep) do { (void)(dep); } while (0)
#define P28(xa, xb) do { const u64 _p = (u64)(xa) * (xb);                     \
	L += (u32)_p & m28; H += (u32)(_p >> 28); } while (0)
#endif

#define M26 0x3ffffffu
#define M25 0x1ffffffu

/* LOWSH(x, w, sh) = (x mod 2^w) << sh as `slli` + `srli` (no constant):
 * written out because `extui` only extracts up to 16 bits, so GCC turns
 * 25/26-bit masks into a mask register — reloaded with `l32r` 50 times
 * in fe_mul under register pressure (measured: fe_mul 1 048 → 1 026,
 * fe_sqr 680 → 663 instructions). Not volatile: plain data flow, GCC may
 * schedule it freely. x >> w (w >= 16) is one `extui` already. */
#if defined(__XTENSA__)
#define LOWSH(x, w, sh) ({ u32 _r;                                            \
	__asm__ ("slli %0, %1, %2\n\tsrli %0, %0, %3"                          \
		 : "=a"(_r) : "a"(x), "i"(32 - (w)), "i"(32 - (w) - (sh)));   \
	_r; })
#else
#define LOWSH(x, w, sh) (((x) & ((1u << (w)) - 1)) << (sh))
#endif

/* Finish a column of width w: its low w bits are the limb r, the rest
 * (L >> w) + (H << (28 - w)) is the carry into the next column, split
 * so that neither half overflows: the low w bits of H go into L, the
 * high bits stay in H. */
#define COL(r, w) do {                                                        \
	r = LOWSH(L, w, 0);                                                   \
	L = (L >> (w)) + LOWSH(H, w, 28 - (w));                               \
	H >>= (w);                                                            \
	} while (0)
/* Columns 10..18 have weight 2^255 · 2^(limb k−10): fold ×19 into it. */
#define FOLD(r, w) do { u32 _t; COL(_t, w); r += 19 * _t; } while (0)

/* Columns 0..18 folded into limbs 0..9, then carry out of column 18 and
 * one carry pass: shared tail of fe_mul_impl and fe_sqr_impl. */
#define FE_REDUCE_STORE(out) do {                                             \
	const u32 _t = L + (H << 28);   /* carry out of column 18, < 2^28.6 */ \
	r9 += 19 * LOWSH(_t, 25, 0);                                          \
	r0 += 361 * (_t >> 25);                                               \
	r1 += r0 >> 26; r0 = LOWSH(r0, 26, 0);  r2 += r1 >> 25; r1 = LOWSH(r1, 25, 0); \
	r3 += r2 >> 26; r2 = LOWSH(r2, 26, 0);  r4 += r3 >> 25; r3 = LOWSH(r3, 25, 0); \
	r5 += r4 >> 26; r4 = LOWSH(r4, 26, 0);  r6 += r5 >> 25; r5 = LOWSH(r5, 25, 0); \
	r7 += r6 >> 26; r6 = LOWSH(r6, 26, 0);  r8 += r7 >> 25; r7 = LOWSH(r7, 25, 0); \
	r9 += r8 >> 26; r8 = LOWSH(r8, 26, 0);  r0 += 19 * (r9 >> 25); r9 = LOWSH(r9, 25, 0); \
	r1 += r0 >> 26; r0 = LOWSH(r0, 26, 0);                                \
	(out)[0] = r0; (out)[1] = r1; (out)[2] = r2; (out)[3] = r3;           \
	(out)[4] = r4; (out)[5] = r5; (out)[6] = r6; (out)[7] = r7;           \
	(out)[8] = r8; (out)[9] = r9;                                         \
	} while (0)

/* out = in1 · in2 (loose × loose → tight). out may alias an input: all
 * of it is read before out is written. Column k holds f_i·g_j, i+j = k;
 * odd×odd terms are doubled (2^ceil(25.5 i) · 2^ceil(25.5 j) =
 * 2 · 2^ceil(25.5 (i+j)) when i and j are odd) through d = 2f. */
static noinline void fe_mul_impl(u32 out[10], const u32 in1[10], const u32 in2[10])
{
	const u32 m28 = 0x0fffffffu;
	const u32 *f = in1, *g = in2;
	const u32 d1 = 2 * f[1], d3 = 2 * f[3], d5 = 2 * f[5], d7 = 2 * f[7], d9 = 2 * f[9];
	u32 L = 0, H = 0, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9;

	FE_SAR28(d9);
#define F(i) f[i]
#define D(i) d##i
#define G(j) g[j]
	P28(F(0), G(0));  COL(r0, 26);
	P28(F(0), G(1)); P28(F(1), G(0));  COL(r1, 25);
	P28(F(0), G(2)); P28(D(1), G(1)); P28(F(2), G(0));  COL(r2, 26);
	P28(F(0), G(3)); P28(F(1), G(2)); P28(F(2), G(1)); P28(F(3), G(0));  COL(r3, 25);
	P28(F(0), G(4)); P28(D(1), G(3)); P28(F(2), G(2)); P28(D(3), G(1)); P28(F(4), G(0));  COL(r4, 26);
	P28(F(0), G(5)); P28(F(1), G(4)); P28(F(2), G(3)); P28(F(3), G(2)); P28(F(4), G(1));
	P28(F(5), G(0));  COL(r5, 25);
	P28(F(0), G(6)); P28(D(1), G(5)); P28(F(2), G(4)); P28(D(3), G(3)); P28(F(4), G(2));
	P28(D(5), G(1)); P28(F(6), G(0));  COL(r6, 26);
	P28(F(0), G(7)); P28(F(1), G(6)); P28(F(2), G(5)); P28(F(3), G(4)); P28(F(4), G(3));
	P28(F(5), G(2)); P28(F(6), G(1)); P28(F(7), G(0));  COL(r7, 25);
	P28(F(0), G(8)); P28(D(1), G(7)); P28(F(2), G(6)); P28(D(3), G(5)); P28(F(4), G(4));
	P28(D(5), G(3)); P28(F(6), G(2)); P28(D(7), G(1)); P28(F(8), G(0));  COL(r8, 26);
	P28(F(0), G(9)); P28(F(1), G(8)); P28(F(2), G(7)); P28(F(3), G(6)); P28(F(4), G(5));
	P28(F(5), G(4)); P28(F(6), G(3)); P28(F(7), G(2)); P28(F(8), G(1)); P28(F(9), G(0));  COL(r9, 25);
	P28(D(1), G(9)); P28(F(2), G(8)); P28(D(3), G(7)); P28(F(4), G(6)); P28(D(5), G(5));
	P28(F(6), G(4)); P28(D(7), G(3)); P28(F(8), G(2)); P28(D(9), G(1));  FOLD(r0, 26);
	P28(F(2), G(9)); P28(F(3), G(8)); P28(F(4), G(7)); P28(F(5), G(6)); P28(F(6), G(5));
	P28(F(7), G(4)); P28(F(8), G(3)); P28(F(9), G(2));  FOLD(r1, 25);
	P28(D(3), G(9)); P28(F(4), G(8)); P28(D(5), G(7)); P28(F(6), G(6)); P28(D(7), G(5));
	P28(F(8), G(4)); P28(D(9), G(3));  FOLD(r2, 26);
	P28(F(4), G(9)); P28(F(5), G(8)); P28(F(6), G(7)); P28(F(7), G(6)); P28(F(8), G(5));
	P28(F(9), G(4));  FOLD(r3, 25);
	P28(D(5), G(9)); P28(F(6), G(8)); P28(D(7), G(7)); P28(F(8), G(6)); P28(D(9), G(5));  FOLD(r4, 26);
	P28(F(6), G(9)); P28(F(7), G(8)); P28(F(8), G(7)); P28(F(9), G(6));  FOLD(r5, 25);
	P28(D(7), G(9)); P28(F(8), G(8)); P28(D(9), G(7));  FOLD(r6, 26);
	P28(F(8), G(9)); P28(F(9), G(8));  FOLD(r7, 25);
	P28(D(9), G(9));  FOLD(r8, 26);
#undef F
#undef D
#undef G
	FE_REDUCE_STORE(out);
}

static __always_inline void fe_mul_ttt(fe *h, const fe *f, const fe *g)
{
	fe_mul_impl(h->v, f->v, g->v);
}

static __always_inline void fe_mul_tlt(fe *h, const fe_loose *f, const fe *g)
{
	fe_mul_impl(h->v, f->v, g->v);
}

static __always_inline void
fe_mul_tll(fe *h, const fe_loose *f, const fe_loose *g)
{
	fe_mul_impl(h->v, f->v, g->v);
}

/* out = in1^2 (loose → tight), 55 products: cross terms 2·f_i·f_j via
 * e = 2f, odd×odd cross terms 4·f_i·f_j via q = 4f, odd squares 2·f_i^2
 * via e. */
static noinline void fe_sqr_impl(u32 out[10], const u32 in1[10])
{
	const u32 m28 = 0x0fffffffu;
	const u32 *f = in1;
	u32 e[10];
	for (int i = 0; i < 10; i++) e[i] = 2 * f[i];
	const u32 q1 = 4 * f[1], q3 = 4 * f[3], q5 = 4 * f[5], q7 = 4 * f[7];
	u32 L = 0, H = 0, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9;

	FE_SAR28(q7);
#define F(i) f[i]
#define E(i) e[i]
#define Q(i) q##i
	P28(F(0), F(0));  COL(r0, 26);
	P28(E(0), F(1));  COL(r1, 25);
	P28(E(0), F(2)); P28(E(1), F(1));  COL(r2, 26);
	P28(E(0), F(3)); P28(E(1), F(2));  COL(r3, 25);
	P28(E(0), F(4)); P28(Q(1), F(3)); P28(F(2), F(2));  COL(r4, 26);
	P28(E(0), F(5)); P28(E(1), F(4)); P28(E(2), F(3));  COL(r5, 25);
	P28(E(0), F(6)); P28(Q(1), F(5)); P28(E(2), F(4)); P28(E(3), F(3));  COL(r6, 26);
	P28(E(0), F(7)); P28(E(1), F(6)); P28(E(2), F(5)); P28(E(3), F(4));  COL(r7, 25);
	P28(E(0), F(8)); P28(Q(1), F(7)); P28(E(2), F(6)); P28(Q(3), F(5)); P28(F(4), F(4));  COL(r8, 26);
	P28(E(0), F(9)); P28(E(1), F(8)); P28(E(2), F(7)); P28(E(3), F(6)); P28(E(4), F(5));  COL(r9, 25);
	P28(Q(1), F(9)); P28(E(2), F(8)); P28(Q(3), F(7)); P28(E(4), F(6)); P28(E(5), F(5));  FOLD(r0, 26);
	P28(E(2), F(9)); P28(E(3), F(8)); P28(E(4), F(7)); P28(E(5), F(6));  FOLD(r1, 25);
	P28(Q(3), F(9)); P28(E(4), F(8)); P28(Q(5), F(7)); P28(F(6), F(6));  FOLD(r2, 26);
	P28(E(4), F(9)); P28(E(5), F(8)); P28(E(6), F(7));  FOLD(r3, 25);
	P28(Q(5), F(9)); P28(E(6), F(8)); P28(E(7), F(7));  FOLD(r4, 26);
	P28(E(6), F(9)); P28(E(7), F(8));  FOLD(r5, 25);
	P28(Q(7), F(9)); P28(F(8), F(8));  FOLD(r6, 26);
	P28(E(8), F(9));  FOLD(r7, 25);
	P28(E(9), F(9));  FOLD(r8, 26);
#undef F
#undef E
#undef Q
	FE_REDUCE_STORE(out);
}

static __always_inline void fe_sq_tl(fe *h, const fe_loose *f)
{
	fe_sqr_impl(h->v, f->v);
}

static __always_inline void fe_sq_tt(fe *h, const fe *f)
{
	fe_sqr_impl(h->v, f->v);
}

static __always_inline void fe_loose_invert(fe *out, const fe_loose *z)
{
	fe t0;
	fe t1;
	fe t2;
	fe t3;
	int i;

	fe_sq_tl(&t0, z);
	fe_sq_tt(&t1, &t0);
	for (i = 1; i < 2; ++i)
		fe_sq_tt(&t1, &t1);
	fe_mul_tlt(&t1, z, &t1);
	fe_mul_ttt(&t0, &t0, &t1);
	fe_sq_tt(&t2, &t0);
	fe_mul_ttt(&t1, &t1, &t2);
	fe_sq_tt(&t2, &t1);
	for (i = 1; i < 5; ++i)
		fe_sq_tt(&t2, &t2);
	fe_mul_ttt(&t1, &t2, &t1);
	fe_sq_tt(&t2, &t1);
	for (i = 1; i < 10; ++i)
		fe_sq_tt(&t2, &t2);
	fe_mul_ttt(&t2, &t2, &t1);
	fe_sq_tt(&t3, &t2);
	for (i = 1; i < 20; ++i)
		fe_sq_tt(&t3, &t3);
	fe_mul_ttt(&t2, &t3, &t2);
	fe_sq_tt(&t2, &t2);
	for (i = 1; i < 10; ++i)
		fe_sq_tt(&t2, &t2);
	fe_mul_ttt(&t1, &t2, &t1);
	fe_sq_tt(&t2, &t1);
	for (i = 1; i < 50; ++i)
		fe_sq_tt(&t2, &t2);
	fe_mul_ttt(&t2, &t2, &t1);
	fe_sq_tt(&t3, &t2);
	for (i = 1; i < 100; ++i)
		fe_sq_tt(&t3, &t3);
	fe_mul_ttt(&t2, &t3, &t2);
	fe_sq_tt(&t2, &t2);
	for (i = 1; i < 50; ++i)
		fe_sq_tt(&t2, &t2);
	fe_mul_ttt(&t1, &t2, &t1);
	fe_sq_tt(&t1, &t1);
	for (i = 1; i < 5; ++i)
		fe_sq_tt(&t1, &t1);
	fe_mul_ttt(out, &t1, &t0);
	tl_secure_zero(&t0, sizeof(t0));
	tl_secure_zero(&t1, sizeof(t1));
	tl_secure_zero(&t2, sizeof(t2));
	tl_secure_zero(&t3, sizeof(t3));
}

static __always_inline void fe_invert(fe *out, const fe *z)
{
	fe_loose l;
	memmove(&l, z, sizeof(l));
	fe_loose_invert(out, &l);
	tl_secure_zero(&l, sizeof(l));
}

/* Replace (f,g) with (g,f) if b == 1;
 * replace (f,g) with (f,g) if b == 0.
 *
 * Preconditions: b in {0,1}
 */
static noinline void fe_cswap(fe *f, fe *g, unsigned int b)
{
	unsigned i;
	b = 0 - b;
	/* tinylink: unrolled (12 → 8 instructions per limb, 512 calls) */
#pragma GCC unroll 10
	for (i = 0; i < 10; i++) {
		u32 x = f->v[i] ^ g->v[i];
		x &= b;
		f->v[i] ^= x;
		g->v[i] ^= x;
	}
}

/* h = 121666 · f (loose → tight). tinylink: fiat32 runs its full fe_mul
 * with in2 = {121666, 0, …}, whose u64 column sums are the carry
 * branches this file removes. Limb by limb instead: f_i < 3.375·2^w_i
 * and 121666 < 2^17, so P_i < 2^44.6; its low w_i bits stay in limb i,
 * P_i >> w_i (< 2^19) moves to limb i+1, and the top one ×19 to limb 0
 * (< 2^26 + 2^23.3). One more carry from limb 0 leaves all limbs
 * < 2^w_i + 2^19: tight. Only 32-bit halves are ever added; the u64 is
 * a mull/muluh pair and a funnel shift. */
static noinline void fe_mul121666_impl(u32 out[10], const u32 in1[10])
{
	u64 p;
	u32 c, h0;
#define MUL121666_LIMB(i, w) do {                                              \
	p = (u64)in1[i] * 121666u;                                            \
	out[i] = ((u32)p & ((1u << (w)) - 1)) + c;                            \
	c = (u32)(p >> (w));                                                  \
	} while (0)
	p = (u64)in1[0] * 121666u;
	h0 = (u32)p & M26;
	c = (u32)(p >> 26);
	MUL121666_LIMB(1, 25); MUL121666_LIMB(2, 26); MUL121666_LIMB(3, 25);
	MUL121666_LIMB(4, 26); MUL121666_LIMB(5, 25); MUL121666_LIMB(6, 26);
	MUL121666_LIMB(7, 25); MUL121666_LIMB(8, 26); MUL121666_LIMB(9, 25);
#undef MUL121666_LIMB
	h0 += 19 * c;
	out[1] += h0 >> 26;
	out[0] = h0 & M26;
}

static __always_inline void fe_mul121666(fe *h, const fe_loose *f)
{
	fe_mul121666_impl(h->v, f->v);
}

/* RFC 7748 X25519: out = scalar · point (u-coordinates). The scalar is
 * clamped here; the top bit of point is ignored. Constant time: the
 * ladder runs all 255 steps, the swap is fe_cswap's mask, and the field
 * arithmetic above has no data-dependent branch or address. */
void curve25519_fiat32(u8 out[CURVE25519_KEY_LEN],
		       const u8 scalar[CURVE25519_KEY_LEN],
		       const u8 point[CURVE25519_KEY_LEN])
{
	fe x1, x2, z2, x3, z3;
	fe_loose x2l, z2l, x3l;
	/* tinylink: out of the loop so they can be scrubbed at the end */
	fe tmp0, tmp1;
	fe_loose tmp0l, tmp1l;
	unsigned swap = 0;
	int pos;
	u8 e[32];

	memcpy(e, scalar, 32);
	e[0] &= 248;
	e[31] = (e[31] & 127) | 64;

	/* The following implementation was transcribed to Coq and proven to
	 * correspond to unary scalar multiplication in affine coordinates given
	 * that x1 != 0 is the x coordinate of some point on the curve. It was
	 * also checked in Coq that doing a ladderstep with x1 = x3 = 0 gives
	 * z2' = z3' = 0, and z2 = z3 = 0 gives z2' = z3' = 0. The statement was
	 * quantified over the underlying field, so it applies to Curve25519
	 * itself and the quadratic twist of Curve25519. It was not proven in
	 * Coq that prime-field arithmetic correctly simulates extension-field
	 * arithmetic on prime-field values. The decoding of the byte array
	 * representation of e was not considered.
	 *
	 * Specification of Montgomery curves in affine coordinates:
	 * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Spec/MontgomeryCurve.v#L27>
	 *
	 * Proof that these form a group that is isomorphic to a Weierstrass
	 * curve:
	 * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/AffineProofs.v#L35>
	 *
	 * Coq transcription and correctness proof of the loop
	 * (where scalarbits=255):
	 * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZ.v#L118>
	 * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZProofs.v#L278>
	 * preconditions: 0 <= e < 2^255 (not necessarily e < order),
	 * fe_invert(0) = 0
	 */
	fe_frombytes(&x1, point);
	fe_1(&x2);
	fe_0(&z2);
	fe_copy(&x3, &x1);
	fe_1(&z3);

	for (pos = 254; pos >= 0; --pos) {
		/* loop invariant as of right before the test, for the case
		 * where x1 != 0:
		 *   pos >= -1; if z2 = 0 then x2 is nonzero; if z3 = 0 then x3
		 *   is nonzero
		 *   let r := e >> (pos+1) in the following equalities of
		 *   projective points:
		 *   to_xz (r*P)     === if swap then (x3, z3) else (x2, z2)
		 *   to_xz ((r+1)*P) === if swap then (x2, z2) else (x3, z3)
		 *   x1 is the nonzero x coordinate of the nonzero
		 *   point (r*P-(r+1)*P)
		 */
		unsigned b = 1 & (e[pos / 8] >> (pos & 7));
		swap ^= b;
		fe_cswap(&x2, &x3, swap);
		fe_cswap(&z2, &z3, swap);
		swap = b;
		/* Coq transcription of ladderstep formula (called from
		 * transcribed loop):
		 * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZ.v#L89>
		 * <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZProofs.v#L131>
		 * x1 != 0 <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZProofs.v#L217>
		 * x1  = 0 <https://github.com/mit-plv/fiat-crypto/blob/2456d821825521f7e03e65882cc3521795b0320f/src/Curves/Montgomery/XZProofs.v#L147>
		 */
		fe_sub(&tmp0l, &x3, &z3);
		fe_sub(&tmp1l, &x2, &z2);
		fe_add(&x2l, &x2, &z2);
		fe_add(&z2l, &x3, &z3);
		fe_mul_tll(&z3, &tmp0l, &x2l);
		fe_mul_tll(&z2, &z2l, &tmp1l);
		fe_sq_tl(&tmp0, &tmp1l);
		fe_sq_tl(&tmp1, &x2l);
		fe_add(&x3l, &z3, &z2);
		fe_sub(&z2l, &z3, &z2);
		fe_mul_ttt(&x2, &tmp1, &tmp0);
		fe_sub(&tmp1l, &tmp1, &tmp0);
		fe_sq_tl(&z2, &z2l);
		fe_mul121666(&z3, &tmp1l);
		fe_sq_tl(&x3, &x3l);
		fe_add(&tmp0l, &tmp0, &z3);
		fe_mul_ttt(&z3, &x1, &z2);
		fe_mul_tll(&z2, &tmp1l, &tmp0l);
	}
	/* here pos=-1, so r=e, so to_xz (e*P) === if swap then (x3, z3)
	 * else (x2, z2)
	 */
	fe_cswap(&x2, &x3, swap);
	fe_cswap(&z2, &z3, swap);

	fe_invert(&z2, &z2);
	fe_mul_ttt(&x2, &x2, &z2);
	fe_tobytes(out, &x2);

	tl_secure_zero(&x1, sizeof(x1));
	tl_secure_zero(&x2, sizeof(x2));
	tl_secure_zero(&z2, sizeof(z2));
	tl_secure_zero(&x3, sizeof(x3));
	tl_secure_zero(&z3, sizeof(z3));
	tl_secure_zero(&x2l, sizeof(x2l));
	tl_secure_zero(&z2l, sizeof(z2l));
	tl_secure_zero(&x3l, sizeof(x3l));
	tl_secure_zero(&tmp0, sizeof(tmp0));
	tl_secure_zero(&tmp1, sizeof(tmp1));
	tl_secure_zero(&tmp0l, sizeof(tmp0l));
	tl_secure_zero(&tmp1l, sizeof(tmp1l));
	tl_secure_zero(e, sizeof(e));
}
