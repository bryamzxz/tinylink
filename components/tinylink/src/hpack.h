// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// HPACK (RFC 7541) for the in-tree HTTP/2 client (round 1.3.4, D1).
//
// Encoder: what tinylink sends — literal header fields without indexing
// (static-table name index where the name is in the static table), raw
// strings (no Huffman), optionally preceded by a dynamic table size
// update to 0. It never touches a dynamic table.
//
// Decoder: streaming — header block bytes are fed as they arrive, split
// anywhere (frame, CONTINUATION or Noise-record boundaries), and every
// field is reported through a callback as soon as it is complete. No
// header-block buffer: each field's name and value are captured into
// small fixed buffers (HPACK_NAME_CAP / HPACK_VALUE_CAP); longer strings
// are still fully decoded and validated, only their capture is cut
// (the field says so). The HTTP/2 layer only acts on `:status`,
// `content-length` and `retry-after`, all far below the caps.
//
// Dynamic table: bounded by `max_size`, the SETTINGS_HEADER_TABLE_SIZE
// the client advertised. tinylink advertises 0, so on the device every
// insertion empties the table and any dynamic index is a decoding error;
// the storage is caller-provided and the device passes none. The host
// tests give it storage to run the RFC 7541 Appendix C vectors. An entry
// can only be stored when neither of its strings was cut by the capture
// (otherwise HPACK_ERR_UNSUPPORTED) — unreachable with max_size 0.
//
// Huffman: a canonical bit-serial decoder over 282 B of tables (counts
// per code length + symbols in code order), against the 16 KB state
// table nghttp2 carries.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HPACK_NAME_CAP   32u
#define HPACK_VALUE_CAP  64u
/* Longest string literal accepted (nghttp2's NGHTTP2_HD_MAX_NV). */
#define HPACK_MAX_STRING 65536u
#define HPACK_STATIC_LEN 61u

/* hpack_field_t.flags */
#define HPACK_F_NAME_CUT    0x01u  /* name longer than HPACK_NAME_CAP   */
#define HPACK_F_VALUE_CUT   0x02u  /* value longer than HPACK_VALUE_CAP */
#define HPACK_F_NAME_BAD    0x04u  /* not a valid HTTP/2 field name     */
#define HPACK_F_NAME_UPPER  0x08u  /* name has an uppercase letter      */
#define HPACK_F_VALUE_BAD   0x10u  /* NUL/CR/LF/CTL, or leading/trailing SP/HTAB */
#define HPACK_F_NEVER_INDEX 0x20u  /* sent as "never indexed"           */

typedef struct {
    const uint8_t *name;
    const uint8_t *value;
    uint32_t name_len;    /* bytes in name[]  (≤ HPACK_NAME_CAP)  */
    uint32_t value_len;   /* bytes in value[] (≤ HPACK_VALUE_CAP) */
    uint32_t name_total;  /* decoded length of the whole string   */
    uint32_t value_total;
    uint8_t  flags;
} hpack_field_t;

/* Return 0 to go on; non-zero aborts hpack_dec_feed with HPACK_ERR_CB. */
typedef int (*hpack_field_fn)(void *ctx, const hpack_field_t *f);

enum {
    HPACK_OK              = 0,
    HPACK_ERR             = -1,  /* COMPRESSION_ERROR                 */
    HPACK_ERR_UNSUPPORTED = -2,  /* entry to store but a string was cut */
    HPACK_ERR_CB          = -3,  /* the field callback said stop       */
};

typedef struct {
    /* Dynamic table: entries packed newest first in tab[0..used) as
     * BE16 name_len || BE16 value_len || name || value. */
    uint8_t  *tab;
    uint32_t  tab_cap;
    uint32_t  max_size;     /* protocol limit (what we advertised)    */
    uint32_t  size_limit;   /* current limit (last size update)       */
    uint32_t  size;         /* RFC 7541 §4.1 size of the entries      */
    uint32_t  used;         /* bytes of tab[] in use                   */
    uint16_t  count;

    /* streaming state */
    uint8_t   st;           /* parser state                            */
    uint8_t   rep;          /* representation of the field in progress */
    uint8_t   int_for;      /* what the pending integer is             */
    bool      block_start;  /* no field decoded yet in this block     */
    uint8_t   int_shift;
    uint8_t   str_which;    /* 0 = name, 1 = value                     */
    bool      str_huff;
    uint8_t   fflags;       /* HPACK_F_* of the field in progress      */
    uint8_t   last_vbyte;
    uint8_t   hlen;         /* canonical Huffman decoder: code length, */
    uint32_t  hcode;        /* the code's bits so far, the first code  */
    uint32_t  hfirst;       /* and symbol index of that length         */
    uint32_t  hindex;
    uint32_t  int_val;
    uint32_t  str_left;     /* encoded bytes left                      */
    uint32_t  str_total;    /* decoded bytes so far                    */
    uint32_t  name_total;
    uint32_t  name_len;
    uint32_t  value_len;
    uint8_t   name[HPACK_NAME_CAP];
    uint8_t   value[HPACK_VALUE_CAP];
} hpack_dec_t;

/* tab may be NULL with tab_cap 0 (the device). max_size is the
 * SETTINGS_HEADER_TABLE_SIZE we advertised; tab_cap must be ≥ max_size
 * when max_size > 0 (entry bytes ≤ RFC size − 28). */
void hpack_dec_init(hpack_dec_t *d, uint8_t *tab, uint32_t tab_cap,
                    uint32_t max_size);
/* Start a header block: a size update is allowed before its first field. */
void hpack_dec_begin(hpack_dec_t *d);
/* Feed the next bytes of the block. Fields are reported through fn. */
int hpack_dec_feed(hpack_dec_t *d, const uint8_t *in, size_t len,
                   hpack_field_fn fn, void *ctx);
/* End of the block (END_HEADERS): HPACK_ERR if it stopped mid-field. */
int hpack_dec_end(hpack_dec_t *d);

/* ---- encoder ---- */

/* Prefixed integer (RFC 7541 §5.1): `first` holds the representation's
 * high bits, `prefix` the bit count left for the value. Returns the
 * bytes written, 0 if cap is too small. */
size_t hpack_put_int(uint8_t *out, size_t cap, uint8_t first,
                     uint8_t prefix, uint32_t v);

/* One field as "literal header field without indexing" (§6.2.2): the
 * static-table index of the name when it has one (4-bit prefix), else a
 * literal name; raw (non-Huffman) strings. Returns the bytes written, 0
 * if it does not fit. */
size_t hpack_put_field(uint8_t *out, size_t cap,
                       const char *name, size_t name_len,
                       const char *value, size_t value_len);

/* 1-based index of the first static-table entry with this name, else 0. */
unsigned hpack_static_name_index(const char *name, size_t len);

#ifdef __cplusplus
}
#endif
