// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// newlib-nano float formatting stubs (round 1.3.2, B3).
//
// Under CONFIG_LIBC_NEWLIB_NANO_FORMAT, ESP-IDF's newlib_init.c stores
// &_printf_float / &_scanf_float in the ROM syscall table, and that
// strong reference links newlib's whole float formatting path (dtoa,
// mprec, strtod, gdtoa, the float vfprintf/vfscanf back ends) into every
// image, whether anything prints a float or not. These two definitions
// win the link instead (components/tinylink/CMakeLists.txt marks both
// symbols undefined from the start, so this archive supplies them before
// libc is searched).
//
// Audit of the 1.3.2 image (cross-reference table + every NUL-terminated
// string in the allocated data sections, attributed through the map):
//   * tinylink / main never format or scan a float (telemetry prints the
//     temperature as %ld.%03ld);
//   * exactly one linked string has a float conversion — the ESP-MESH
//     power-management debug line "(mesh)pm stop, … running:%.02f" in the
//     Wi-Fi blob libpp.a(pm.o); ESP-MESH is not used;
//   * nothing calls the scanf family: after B2 removed cJSON the only
//     reference to _scanf_float is the syscall-table slot itself, and the
//     ROM's own nano printf/scanf (the table's consumers) are not linked
//     on this target (ESP_ROM_HAS_NEWLIB_32BIT_TIME).
// So the stubs only have to fail soft. Float math elsewhere (PHY/RTC
// calibration in the blobs) is unaffected — that is libgcc soft-float,
// not formatting.

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

struct _reent;

/* nano _vfprintf_r / _svfprintf_r call this for %e %f %g %E %F %G, add
 * the return to the character count, and treat -1 as an output error.
 * Consume the double (long double is the same 8 bytes on Xtensa) so the
 * rest of the format stays aligned, and print "?" in its place. */
int _printf_float(struct _reent *data, void *pdata, FILE *fp,
                  int (*pfunc)(struct _reent *, FILE *, const char *, size_t),
                  va_list *ap)
{
    (void)pdata;
    (void)va_arg(*ap, double);
    return (pfunc(data, fp, "?", 1) == EOF) ? -1 : 1;
}

/* nano __ssvfscanf_r calls this for a float conversion; 1 is newlib's
 * MATCH_FAILURE (what the real one returns when no number is there), so
 * scanning stops and the caller sees one conversion fewer. */
int _scanf_float(struct _reent *rptr, void *pdata, FILE *fp, va_list *ap)
{
    (void)rptr; (void)pdata; (void)fp; (void)ap;
    return 1;
}
