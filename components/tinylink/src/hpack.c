// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// HPACK encoder / streaming decoder for the in-tree HTTP/2 client
// (round 1.3.4, D1). Design notes in hpack.h.

#include "hpack.h"

#include <string.h>

/* RFC 7541 Appendix A as length-prefixed name / value pairs, walked
 * linearly (a response carries a handful of fields). */
static const char k_static[] =
    "\x0a" ":authority"                  "\x00"                    /*  1 */
    "\x07" ":method"                     "\x03" "GET"              /*  2 */
    "\x07" ":method"                     "\x04" "POST"             /*  3 */
    "\x05" ":path"                       "\x01" "/"                /*  4 */
    "\x05" ":path"                       "\x0b" "/index.html"      /*  5 */
    "\x07" ":scheme"                     "\x04" "http"             /*  6 */
    "\x07" ":scheme"                     "\x05" "https"            /*  7 */
    "\x07" ":status"                     "\x03" "200"              /*  8 */
    "\x07" ":status"                     "\x03" "204"              /*  9 */
    "\x07" ":status"                     "\x03" "206"              /* 10 */
    "\x07" ":status"                     "\x03" "304"              /* 11 */
    "\x07" ":status"                     "\x03" "400"              /* 12 */
    "\x07" ":status"                     "\x03" "404"              /* 13 */
    "\x07" ":status"                     "\x03" "500"              /* 14 */
    "\x0e" "accept-charset"              "\x00"                    /* 15 */
    "\x0f" "accept-encoding"             "\x0d" "gzip, deflate"    /* 16 */
    "\x0f" "accept-language"             "\x00"                    /* 17 */
    "\x0d" "accept-ranges"               "\x00"                    /* 18 */
    "\x06" "accept"                      "\x00"                    /* 19 */
    "\x1b" "access-control-allow-origin" "\x00"                    /* 20 */
    "\x03" "age"                         "\x00"                    /* 21 */
    "\x05" "allow"                       "\x00"                    /* 22 */
    "\x0d" "authorization"               "\x00"                    /* 23 */
    "\x0d" "cache-control"               "\x00"                    /* 24 */
    "\x13" "content-disposition"         "\x00"                    /* 25 */
    "\x10" "content-encoding"            "\x00"                    /* 26 */
    "\x10" "content-language"            "\x00"                    /* 27 */
    "\x0e" "content-length"              "\x00"                    /* 28 */
    "\x10" "content-location"            "\x00"                    /* 29 */
    "\x0d" "content-range"               "\x00"                    /* 30 */
    "\x0c" "content-type"                "\x00"                    /* 31 */
    "\x06" "cookie"                      "\x00"                    /* 32 */
    "\x04" "date"                        "\x00"                    /* 33 */
    "\x04" "etag"                        "\x00"                    /* 34 */
    "\x06" "expect"                      "\x00"                    /* 35 */
    "\x07" "expires"                     "\x00"                    /* 36 */
    "\x04" "from"                        "\x00"                    /* 37 */
    "\x04" "host"                        "\x00"                    /* 38 */
    "\x08" "if-match"                    "\x00"                    /* 39 */
    "\x11" "if-modified-since"           "\x00"                    /* 40 */
    "\x0d" "if-none-match"               "\x00"                    /* 41 */
    "\x08" "if-range"                    "\x00"                    /* 42 */
    "\x13" "if-unmodified-since"         "\x00"                    /* 43 */
    "\x0d" "last-modified"               "\x00"                    /* 44 */
    "\x04" "link"                        "\x00"                    /* 45 */
    "\x08" "location"                    "\x00"                    /* 46 */
    "\x0c" "max-forwards"                "\x00"                    /* 47 */
    "\x12" "proxy-authenticate"          "\x00"                    /* 48 */
    "\x13" "proxy-authorization"         "\x00"                    /* 49 */
    "\x05" "range"                       "\x00"                    /* 50 */
    "\x07" "referer"                     "\x00"                    /* 51 */
    "\x07" "refresh"                     "\x00"                    /* 52 */
    "\x0b" "retry-after"                 "\x00"                    /* 53 */
    "\x06" "server"                      "\x00"                    /* 54 */
    "\x0a" "set-cookie"                  "\x00"                    /* 55 */
    "\x19" "strict-transport-security"   "\x00"                    /* 56 */
    "\x11" "transfer-encoding"           "\x00"                    /* 57 */
    "\x0a" "user-agent"                  "\x00"                    /* 58 */
    "\x04" "vary"                        "\x00"                    /* 59 */
    "\x03" "via"                         "\x00"                    /* 60 */
    "\x10" "www-authenticate"            "\x00";                   /* 61 */

/* RFC 7541 Appendix B is a canonical code: within each length the codes
 * are consecutive in symbol order (checked against nghttp2's encoder
 * table when this was written, and by test_hpack against an
 * independent copy of Appendix B). So the counts per code length and
 * the symbols in code order decode it — 282 B instead of nghttp2's
 * 16 KB state table. EOS (256) is the last 30-bit code: index 256. */
static const uint8_t k_huff_count[26] = {   /* code lengths 5..30 */
    10, 26, 32, 6, 0, 5, 3, 2, 6, 2, 3, 0, 0, 0, 3, 8, 13, 26, 29, 12, 4,
    15, 19, 29, 0, 4 };
static const uint8_t k_huff_sym[256] = {
    0x30, 0x31, 0x32, 0x61, 0x63, 0x65, 0x69, 0x6f, 0x73, 0x74, 0x20, 0x25, 0x2d, 0x2e, 0x2f, 0x33,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3d, 0x41, 0x5f, 0x62, 0x64, 0x66, 0x67, 0x68, 0x6c, 0x6d,
    0x6e, 0x70, 0x72, 0x75, 0x3a, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c,
    0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x59, 0x6a, 0x6b, 0x71, 0x76,
    0x77, 0x78, 0x79, 0x7a, 0x26, 0x2a, 0x2c, 0x3b, 0x58, 0x5a, 0x21, 0x22, 0x28, 0x29, 0x3f, 0x27,
    0x2b, 0x7c, 0x23, 0x3e, 0x00, 0x24, 0x40, 0x5b, 0x5d, 0x7e, 0x5e, 0x7d, 0x3c, 0x60, 0x7b, 0x5c,
    0xc3, 0xd0, 0x80, 0x82, 0x83, 0xa2, 0xb8, 0xc2, 0xe0, 0xe2, 0x99, 0xa1, 0xa7, 0xac, 0xb0, 0xb1,
    0xb3, 0xd1, 0xd8, 0xd9, 0xe3, 0xe5, 0xe6, 0x81, 0x84, 0x85, 0x86, 0x88, 0x92, 0x9a, 0x9c, 0xa0,
    0xa3, 0xa4, 0xa9, 0xaa, 0xad, 0xb2, 0xb5, 0xb9, 0xba, 0xbb, 0xbd, 0xbe, 0xc4, 0xc6, 0xe4, 0xe8,
    0xe9, 0x01, 0x87, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8f, 0x93, 0x95, 0x96, 0x97, 0x98, 0x9b, 0x9d,
    0x9e, 0xa5, 0xa6, 0xa8, 0xae, 0xaf, 0xb4, 0xb6, 0xb7, 0xbc, 0xbf, 0xc5, 0xe7, 0xef, 0x09, 0x8e,
    0x90, 0x91, 0x94, 0x9f, 0xab, 0xce, 0xd7, 0xe1, 0xec, 0xed, 0xc7, 0xcf, 0xea, 0xeb, 0xc0, 0xc1,
    0xc8, 0xc9, 0xca, 0xcd, 0xd2, 0xd5, 0xda, 0xdb, 0xee, 0xf0, 0xf2, 0xf3, 0xff, 0xcb, 0xcc, 0xd3,
    0xd4, 0xd6, 0xdd, 0xde, 0xdf, 0xf1, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0b, 0x0c, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
    0x15, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x7f, 0xdc, 0xf9, 0x0a, 0x0d, 0x16,
};

#define HUFF_MIN_LEN 5u
#define HUFF_MAX_LEN 30u
#define HUFF_EOS_IDX 256u

enum { ST_FIRST, ST_INT, ST_STR_HDR, ST_STR };
/* What a pending integer is for. */
enum { INT_INDEXED, INT_NAME, INT_SIZE, INT_STRLEN };
/* hpack_dec_t.rep */
enum { REP_INDEXED, REP_INCR, REP_NOIDX, REP_NEVER };

/* ---- static / dynamic table ----------------------------------------- */

static const char *static_entry(unsigned idx)   /* 1-based */
{
    const char *p = k_static;
    for (unsigned i = 1; i < idx; i++) {
        p += 1 + (uint8_t)p[0];
        p += 1 + (uint8_t)p[0];
    }
    return p;
}

unsigned hpack_static_name_index(const char *name, size_t len)
{
    const char *p = k_static;
    for (unsigned i = 1; i <= HPACK_STATIC_LEN; i++) {
        const size_t nl = (uint8_t)p[0];
        if (nl == len && memcmp(p + 1, name, len) == 0) return i;
        p += 1 + nl;
        p += 1 + (uint8_t)p[0];
    }
    return 0;
}

static uint32_t be16(const uint8_t *p) { return ((uint32_t)p[0] << 8) | p[1]; }

/* Dynamic entry j, 0 = newest. */
static const uint8_t *dyn_entry(const hpack_dec_t *d, uint32_t j)
{
    const uint8_t *p = d->tab;
    while (j--) p += 4 + be16(p) + be16(p + 2);
    return p;
}

static void dyn_evict_to(hpack_dec_t *d, uint32_t limit)
{
    while (d->count > 0 && d->size > limit) {
        const uint8_t *e = dyn_entry(d, d->count - 1u);
        const uint32_t n = be16(e), v = be16(e + 2);
        d->size -= 32u + n + v;
        d->used -= 4u + n + v;
        d->count--;
    }
}

/* §4.4 insertion of the field just decoded (incremental indexing). */
static int dyn_insert(hpack_dec_t *d)
{
    const uint32_t n = d->name_total, v = d->str_total;
    const uint32_t esz = 32u + n + v;
    if (esz > d->size_limit) {            /* too big: empties the table */
        dyn_evict_to(d, 0);
        return HPACK_OK;
    }
    if (d->fflags & (HPACK_F_NAME_CUT | HPACK_F_VALUE_CUT)) return HPACK_ERR_UNSUPPORTED;
    dyn_evict_to(d, d->size_limit - esz);
    const uint32_t eb = 4u + n + v;
    if (d->used + eb > d->tab_cap) return HPACK_ERR_UNSUPPORTED;   /* tab_cap < max_size */
    memmove(d->tab + eb, d->tab, d->used);
    d->tab[0] = (uint8_t)(n >> 8);
    d->tab[1] = (uint8_t)n;
    d->tab[2] = (uint8_t)(v >> 8);
    d->tab[3] = (uint8_t)v;
    memcpy(d->tab + 4, d->name, n);
    memcpy(d->tab + 4 + n, d->value, v);
    d->used += eb;
    d->size += esz;
    d->count++;
    return HPACK_OK;
}

/* ---- field assembly -------------------------------------------------- */

/* nghttp2_check_header_name: a token character; uppercase letters are
 * reported on their own (HPACK_F_NAME_UPPER), as nghttp2 treats them. */
static bool name_char_ok(uint8_t c)
{
    if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) return true;
    return c != 0 && strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

/* nghttp2_check_header_value: HTAB, SP..'~' and obs-text 0x80..0xff. */
static bool value_char_ok(uint8_t c)
{
    return c == '\t' || (c >= 0x20 && c != 0x7f);
}

static void put_char(hpack_dec_t *d, uint8_t c)
{
    const uint32_t pos = d->str_total++;
    if (d->str_which == 0) {
        if (d->name_len < HPACK_NAME_CAP) d->name[d->name_len++] = c;
        else d->fflags |= HPACK_F_NAME_CUT;
        if (c >= 'A' && c <= 'Z') d->fflags |= HPACK_F_NAME_UPPER;
        else if (!(pos == 0 && c == ':') && !name_char_ok(c)) d->fflags |= HPACK_F_NAME_BAD;
    } else {
        if (d->value_len < HPACK_VALUE_CAP) d->value[d->value_len++] = c;
        else d->fflags |= HPACK_F_VALUE_CUT;
        if (!value_char_ok(c) || (pos == 0 && (c == ' ' || c == '\t')))
            d->fflags |= HPACK_F_VALUE_BAD;
        d->last_vbyte = c;
    }
}

static void begin_name(hpack_dec_t *d)
{
    d->str_which = 0;
    d->str_total = 0;
    d->name_len = 0;
}

static void begin_value(hpack_dec_t *d)
{
    d->name_total = d->str_total;
    /* An empty name or a lone ':' is no field name either. */
    if (d->name_total == 0 || (d->name_total == 1 && d->name[0] == ':'))
        d->fflags |= HPACK_F_NAME_BAD;
    d->str_which = 1;
    d->str_total = 0;
    d->value_len = 0;
    d->last_vbyte = 0;
}

static int emit(hpack_dec_t *d, hpack_field_fn fn, void *ctx)
{
    const uint32_t vt = d->str_total;
    if (vt > 0 && (d->last_vbyte == ' ' || d->last_vbyte == '\t'))
        d->fflags |= HPACK_F_VALUE_BAD;
    if (d->rep == REP_INCR) {
        int rc = dyn_insert(d);
        if (rc != HPACK_OK) return rc;
    }
    hpack_field_t f = {
        .name = d->name, .value = d->value,
        .name_len = d->name_len, .value_len = d->value_len,
        .name_total = d->name_total, .value_total = vt,
        .flags = d->fflags,
    };
    d->st = ST_FIRST;
    if (fn != NULL && fn(ctx, &f) != 0) return HPACK_ERR_CB;
    return HPACK_OK;
}

static void put_bytes(hpack_dec_t *d, const uint8_t *s, uint32_t n)
{
    for (uint32_t i = 0; i < n; i++) put_char(d, s[i]);
}

/* Table entry idx (1-based: static, then dynamic newest first) into the
 * field in progress — its name, and its value when with_value. Copied
 * through put_char: same capture and checks as a literal, and a copy, so
 * an insertion that evicts the entry it named is safe (§4.4). */
static int table_field(hpack_dec_t *d, uint32_t idx, bool with_value)
{
    const uint8_t *n, *v;
    uint32_t nl, vl;
    if (idx == 0) return HPACK_ERR;
    if (idx <= HPACK_STATIC_LEN) {
        const char *e = static_entry(idx);
        nl = (uint8_t)e[0];
        n  = (const uint8_t *)e + 1;
        vl = (uint8_t)e[1 + nl];
        v  = (const uint8_t *)e + 2 + nl;
    } else {
        const uint32_t j = idx - HPACK_STATIC_LEN - 1u;
        if (j >= d->count) return HPACK_ERR;
        const uint8_t *e = dyn_entry(d, j);
        nl = be16(e);
        vl = be16(e + 2);
        n  = e + 4;
        v  = e + 4 + nl;
    }
    begin_name(d);
    put_bytes(d, n, nl);
    begin_value(d);
    if (with_value) put_bytes(d, v, vl);
    return HPACK_OK;
}

/* ---- strings ----------------------------------------------------------- */

static void huff_reset(hpack_dec_t *d)
{
    d->hcode = 0;
    d->hfirst = 0;
    d->hindex = 0;
    d->hlen = 1;
}

static int str_done(hpack_dec_t *d, hpack_field_fn fn, void *ctx)
{
    if (d->str_huff) {
        /* §5.2: at most 7 bits of padding, all ones (the EOS prefix). */
        const uint32_t plen = d->hlen - 1u;
        if (plen > 7 || (d->hcode >> 1) != ((1u << plen) - 1u)) return HPACK_ERR;
    }
    if (d->str_which == 0) {
        begin_value(d);
        d->st = ST_STR_HDR;
        return HPACK_OK;
    }
    return emit(d, fn, ctx);
}

/* Canonical decode, one bit at a time (zlib's puff): hcode holds the
 * code's bits so far, hfirst / hindex the first code / symbol index of
 * length hlen. Codes are 5..30 bits and the code is complete, so every
 * bit sequence decodes. */
static int huff_byte(hpack_dec_t *d, uint8_t b)
{
    for (int i = 7; i >= 0; i--) {
        d->hcode |= (uint32_t)(b >> i) & 1u;
        const uint32_t cnt = d->hlen >= HUFF_MIN_LEN ? k_huff_count[d->hlen - HUFF_MIN_LEN] : 0u;
        if (d->hcode - d->hfirst < cnt) {
            const uint32_t si = d->hindex + (d->hcode - d->hfirst);
            if (si >= HUFF_EOS_IDX) return HPACK_ERR;    /* EOS inside a string */
            put_char(d, k_huff_sym[si]);
            huff_reset(d);
            continue;
        }
        if (d->hlen >= HUFF_MAX_LEN) return HPACK_ERR;   /* unreachable */
        d->hindex += cnt;
        d->hfirst = (d->hfirst + cnt) << 1;
        d->hcode <<= 1;
        d->hlen++;
    }
    return HPACK_OK;
}

/* ---- integers ----------------------------------------------------------- */

static int int_done(hpack_dec_t *d, uint32_t v, hpack_field_fn fn, void *ctx)
{
    d->st = ST_FIRST;
    switch (d->int_for) {
    case INT_INDEXED:
        if (table_field(d, v, true) != HPACK_OK) return HPACK_ERR;
        return emit(d, fn, ctx);
    case INT_SIZE:
        if (v > d->max_size) return HPACK_ERR;   /* §6.3: above our SETTINGS */
        d->size_limit = v;
        dyn_evict_to(d, v);
        return HPACK_OK;
    case INT_NAME:
        if (v == 0) begin_name(d);
        else if (table_field(d, v, false) != HPACK_OK) return HPACK_ERR;
        d->st = ST_STR_HDR;
        return HPACK_OK;
    default:                                      /* INT_STRLEN */
        if (v > HPACK_MAX_STRING) return HPACK_ERR;
        d->str_left = v;
        huff_reset(d);
        if (v == 0) return str_done(d, fn, ctx);
        d->st = ST_STR;
        return HPACK_OK;
    }
}

/* A prefixed integer (§5.1) whose prefix holds `v` of `mask`. */
static int int_start(hpack_dec_t *d, uint8_t what, uint32_t v, uint32_t mask,
                     hpack_field_fn fn, void *ctx)
{
    d->int_for = what;
    if (v < mask) return int_done(d, v, fn, ctx);
    d->int_val = mask;
    d->int_shift = 0;
    d->st = ST_INT;
    return HPACK_OK;
}

/* ---- public ------------------------------------------------------------- */

void hpack_dec_init(hpack_dec_t *d, uint8_t *tab, uint32_t tab_cap,
                    uint32_t max_size)
{
    memset(d, 0, sizeof(*d));
    d->tab = tab;
    d->tab_cap = tab != NULL ? tab_cap : 0;
    d->max_size = max_size;
    d->size_limit = max_size;
    d->st = ST_FIRST;
    d->block_start = true;
}

void hpack_dec_begin(hpack_dec_t *d)
{
    d->st = ST_FIRST;
    d->block_start = true;
}

int hpack_dec_end(hpack_dec_t *d)
{
    return d->st == ST_FIRST ? HPACK_OK : HPACK_ERR;
}

int hpack_dec_feed(hpack_dec_t *d, const uint8_t *in, size_t len,
                   hpack_field_fn fn, void *ctx)
{
    size_t i = 0;
    int rc = HPACK_OK;
    while (i < len && rc == HPACK_OK) {
        const uint8_t b = in[i];
        switch (d->st) {
        case ST_FIRST:
            i++;
            if ((b & 0xe0) == 0x20) {             /* 001xxxxx size update */
                /* §4.2: only before the block's first field. */
                if (!d->block_start) return HPACK_ERR;
                rc = int_start(d, INT_SIZE, b & 0x1fu, 0x1fu, fn, ctx);
                break;
            }
            d->block_start = false;
            d->fflags = 0;
            if (b & 0x80) {                       /* 1xxxxxxx indexed */
                d->rep = REP_INDEXED;
                rc = int_start(d, INT_INDEXED, b & 0x7fu, 0x7fu, fn, ctx);
            } else if (b & 0x40) {                /* 01xxxxxx incremental */
                d->rep = REP_INCR;
                rc = int_start(d, INT_NAME, b & 0x3fu, 0x3fu, fn, ctx);
            } else {                              /* 0000xxxx / 0001xxxx */
                d->rep = (b & 0x10) ? REP_NEVER : REP_NOIDX;
                if (b & 0x10) d->fflags |= HPACK_F_NEVER_INDEX;
                rc = int_start(d, INT_NAME, b & 0x0fu, 0x0fu, fn, ctx);
            }
            break;
        case ST_INT: {
            i++;
            const uint64_t v = d->int_val + ((uint64_t)(b & 0x7fu) << d->int_shift);
            if (v > 0x7fffffffu) return HPACK_ERR;
            d->int_val = (uint32_t)v;
            d->int_shift += 7;
            if (b & 0x80) {
                if (d->int_shift > 28) return HPACK_ERR;   /* > 5 bytes */
                break;
            }
            rc = int_done(d, d->int_val, fn, ctx);
            break;
        }
        case ST_STR_HDR:
            i++;
            d->str_huff = (b & 0x80) != 0;
            rc = int_start(d, INT_STRLEN, b & 0x7fu, 0x7fu, fn, ctx);
            break;
        case ST_STR: {
            size_t n = len - i;
            if (n > d->str_left) n = d->str_left;
            if (d->str_huff) {
                for (size_t k = 0; k < n && rc == HPACK_OK; k++) rc = huff_byte(d, in[i + k]);
            } else {
                for (size_t k = 0; k < n; k++) put_char(d, in[i + k]);
            }
            i += n;
            d->str_left -= (uint32_t)n;
            if (rc == HPACK_OK && d->str_left == 0) rc = str_done(d, fn, ctx);
            break;
        }
        default:
            return HPACK_ERR;
        }
    }
    return rc;
}

/* ---- encoder ------------------------------------------------------------ */

size_t hpack_put_int(uint8_t *out, size_t cap, uint8_t first,
                     uint8_t prefix, uint32_t v)
{
    const uint32_t max = (1u << prefix) - 1u;
    if (cap == 0) return 0;
    if (v < max) {
        out[0] = (uint8_t)(first | v);
        return 1;
    }
    out[0] = (uint8_t)(first | max);
    v -= max;
    size_t n = 1;
    while (v >= 0x80) {
        if (n >= cap) return 0;
        out[n++] = (uint8_t)(0x80 | (v & 0x7f));
        v >>= 7;
    }
    if (n >= cap) return 0;
    out[n++] = (uint8_t)v;
    return n;
}

static size_t put_string(uint8_t *out, size_t cap, const char *s, size_t n)
{
    const size_t h = hpack_put_int(out, cap, 0x00, 7, (uint32_t)n);
    if (h == 0 || h + n > cap) return 0;
    memcpy(out + h, s, n);
    return h + n;
}

size_t hpack_put_field(uint8_t *out, size_t cap,
                       const char *name, size_t name_len,
                       const char *value, size_t value_len)
{
    size_t n;
    const unsigned idx = hpack_static_name_index(name, name_len);
    if (idx != 0) {
        n = hpack_put_int(out, cap, 0x00, 4, idx);   /* 0000 + name index */
    } else {
        if (cap < 1) return 0;
        out[0] = 0x00;                               /* 0000 0000: new name */
        const size_t s = put_string(out + 1, cap - 1, name, name_len);
        n = s != 0 ? 1 + s : 0;
    }
    if (n == 0) return 0;
    const size_t v = put_string(out + n, cap - n, value, value_len);
    return v != 0 ? n + v : 0;
}
