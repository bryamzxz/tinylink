// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Shallow JSON splitter: iterates the members of one object (or the
// elements of one array) by byte range WITHOUT tokenizing their
// contents. Since 2026-09 the MapResponse is cut into its top-level
// values (Node, Peers[i], DERPMap.Regions[id], PeersChangedPatch[i]),
// each handed to jsmn separately, so the token table only has to hold
// ONE peer / ONE region / the self node at a time instead of the whole
// document: 2 500 tokens (40 KiB BSS, and a hard ceiling on the tailnet
// size) → 640 tokens (10 KiB) with no ceiling at all. Since 1.3.4 (D2)
// mapreq.c does that cut on the stream with tl_jsplit_scan_* below
// (the byte-at-a-time form of tl_jsplit_value) instead of on a whole
// buffered document; json_helpers.c reads register / key bodies with
// the iterators.
//
// Pure, header-only, host-tested (tools/test/test_jsmn_split.c). Not a
// validator: it understands strings (with escapes), nesting and scalar
// delimiters — enough to find where a value ends. The sub-document is
// then validated by jsmn as before. Nesting is depth-bounded like
// jsmn_skip.h so an adversarial netmap cannot make the scan spin.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TL_JSPLIT_MAX_DEPTH
#define TL_JSPLIT_MAX_DEPTH 64   /* < 255: tl_jsplit_scan_t counts it in a byte */
#endif

typedef struct {
    const char *key;      /* raw key bytes (between the quotes, escapes intact) */
    size_t      key_len;
    const char *val;      /* raw value text: object/array/string/number/literal */
    size_t      val_len;
} tl_jsplit_kv_t;

static inline size_t tl_jsplit_ws(const char *js, size_t len, size_t pos)
{
    while (pos < len && (js[pos] == ' ' || js[pos] == '\t' ||
                         js[pos] == '\n' || js[pos] == '\r')) {
        pos++;
    }
    return pos;
}

/* js[pos] must be the opening quote. Returns the index just past the
 * closing quote, 0 if unterminated. */
static inline size_t tl_jsplit_string(const char *js, size_t len, size_t pos)
{
    if (pos >= len || js[pos] != '"') return 0;
    pos++;
    while (pos < len) {
        const char c = js[pos];
        if (c == '\\') { pos += 2; continue; }
        if (c == '"')  return pos + 1;
        pos++;
    }
    return 0;
}

/* Returns the index just past the value that starts (after whitespace)
 * at pos, or 0 if it is unterminated / nested deeper than
 * TL_JSPLIT_MAX_DEPTH. Brace/bracket kinds are not cross-checked — jsmn
 * does that on the extracted text. */
static inline size_t tl_jsplit_value(const char *js, size_t len, size_t pos)
{
    pos = tl_jsplit_ws(js, len, pos);
    if (pos >= len) return 0;
    char c = js[pos];
    if (c == '"') return tl_jsplit_string(js, len, pos);
    if (c == '{' || c == '[') {
        int depth = 0;
        while (pos < len) {
            c = js[pos];
            if (c == '"') {
                pos = tl_jsplit_string(js, len, pos);
                if (pos == 0) return 0;
                continue;
            }
            if (c == '{' || c == '[') {
                if (++depth > TL_JSPLIT_MAX_DEPTH) return 0;
            } else if (c == '}' || c == ']') {
                if (--depth == 0) return pos + 1;
                if (depth < 0) return 0;
            }
            pos++;
        }
        return 0;
    }
    /* Scalar (number / true / false / null): runs to the next delimiter. */
    const size_t start = pos;
    while (pos < len) {
        c = js[pos];
        if (c == ',' || c == '}' || c == ']' ||
            c == ' ' || c == '\t' || c == '\n' || c == '\r') break;
        pos++;
    }
    return (pos > start) ? pos : 0;
}

/* Member iterator for the object whose text is js[0..len). Start with
 * *pos = 0. Returns 1 and fills *kv for each member, 0 at the closing
 * brace, -1 if the text is not a well-formed object at this level. */
static inline int tl_jsplit_obj_next(const char *js, size_t len, size_t *pos,
                                     tl_jsplit_kv_t *kv)
{
    size_t p = tl_jsplit_ws(js, len, *pos);
    if (p >= len) return -1;
    if (*pos == 0) {
        if (js[p] != '{') return -1;
        p = tl_jsplit_ws(js, len, p + 1);
        if (p >= len) return -1;
    } else if (js[p] == ',') {
        p = tl_jsplit_ws(js, len, p + 1);
        if (p >= len) return -1;
    }
    if (js[p] == '}') { *pos = p + 1; return 0; }

    const size_t kend = tl_jsplit_string(js, len, p);
    if (kend == 0) return -1;
    kv->key     = js + p + 1;
    kv->key_len = kend - p - 2;

    p = tl_jsplit_ws(js, len, kend);
    if (p >= len || js[p] != ':') return -1;
    const size_t vstart = tl_jsplit_ws(js, len, p + 1);
    const size_t vend   = tl_jsplit_value(js, len, vstart);
    if (vend == 0) return -1;
    kv->val     = js + vstart;
    kv->val_len = vend - vstart;
    *pos = vend;
    return 1;
}

/* Element iterator for the array whose text is js[0..len). Same contract
 * as tl_jsplit_obj_next. */
static inline int tl_jsplit_arr_next(const char *js, size_t len, size_t *pos,
                                     const char **val, size_t *val_len)
{
    size_t p = tl_jsplit_ws(js, len, *pos);
    if (p >= len) return -1;
    if (*pos == 0) {
        if (js[p] != '[') return -1;
        p = tl_jsplit_ws(js, len, p + 1);
        if (p >= len) return -1;
    } else if (js[p] == ',') {
        p = tl_jsplit_ws(js, len, p + 1);
        if (p >= len) return -1;
    }
    if (js[p] == ']') { *pos = p + 1; return 0; }

    const size_t vend = tl_jsplit_value(js, len, p);
    if (vend == 0) return -1;
    *val     = js + p;
    *val_len = vend - p;
    *pos = vend;
    return 1;
}

static inline bool tl_jsplit_key_is(const tl_jsplit_kv_t *kv, const char *name)
{
    const size_t n = strlen(name);
    return kv->key_len == n && memcmp(kv->key, name, n) == 0;
}

/* Raw bytes of a scalar value; true when it is the literal `true`. */
static inline bool tl_jsplit_val_is_true(const tl_jsplit_kv_t *kv)
{
    return kv->val_len == 4 && memcmp(kv->val, "true", 4) == 0;
}

/* ---- Byte-at-a-time form of tl_jsplit_value (round 1.3.4, D2) ----------
 *
 * For text that arrives in pieces (the MapResponse stream, mapreq.c): the
 * same rules as tl_jsplit_value — strings with escapes, brackets counted
 * without checking their kinds, TL_JSPLIT_MAX_DEPTH, a scalar runs to the
 * next delimiter — fed one byte at a time, with no buffer. A value is
 * complete exactly where tl_jsplit_value would end it (test_jsmn_split.c
 * checks the two against each other). */

typedef struct {
    unsigned char depth;   /* open brackets (0: a string or scalar at the root) */
    unsigned char mode;    /* TL_JSCAN_TEXT / _STR / _ESC / _SCALAR */
} tl_jsplit_scan_t;

enum { TL_JSCAN_TEXT, TL_JSCAN_STR, TL_JSCAN_ESC, TL_JSCAN_SCALAR };

/* Results: the value goes on / `c` was its last byte / it ended just
 * before `c` (a scalar's delimiter, which belongs to the container) /
 * not a value (too deep, or a zero-length scalar). */
enum { TL_JSCAN_MORE = 0, TL_JSCAN_END = 1, TL_JSCAN_END_BEFORE = 2, TL_JSCAN_ERR = -1 };

static inline bool tl_jsplit_is_ws(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

/* `c` = the value's first byte (callers skip whitespace before it). */
static inline int tl_jsplit_scan_begin(tl_jsplit_scan_t *s, char c)
{
    s->depth = 0;
    if (c == '"') { s->mode = TL_JSCAN_STR; return TL_JSCAN_MORE; }
    if (c == '{' || c == '[') { s->depth = 1; s->mode = TL_JSCAN_TEXT; return TL_JSCAN_MORE; }
    if (c == ',' || c == '}' || c == ']') return TL_JSCAN_ERR;   /* empty scalar */
    s->mode = TL_JSCAN_SCALAR;
    return TL_JSCAN_MORE;
}

/* Every following byte. A scalar still open when the text ends is
 * complete there (tl_jsplit_value returns the end of the text). */
static inline int tl_jsplit_scan_byte(tl_jsplit_scan_t *s, char c)
{
    switch (s->mode) {
    case TL_JSCAN_SCALAR:
        return (c == ',' || c == '}' || c == ']' || tl_jsplit_is_ws(c))
                   ? TL_JSCAN_END_BEFORE : TL_JSCAN_MORE;
    case TL_JSCAN_ESC:
        s->mode = TL_JSCAN_STR;
        return TL_JSCAN_MORE;
    case TL_JSCAN_STR:
        if (c == '\\') {
            s->mode = TL_JSCAN_ESC;
        } else if (c == '"') {
            if (s->depth == 0) return TL_JSCAN_END;
            s->mode = TL_JSCAN_TEXT;
        }
        return TL_JSCAN_MORE;
    default:   /* TL_JSCAN_TEXT, inside brackets */
        if (c == '"') {
            s->mode = TL_JSCAN_STR;
        } else if (c == '{' || c == '[') {
            if (++s->depth > TL_JSPLIT_MAX_DEPTH) return TL_JSCAN_ERR;
        } else if (c == '}' || c == ']') {
            if (--s->depth == 0) return TL_JSCAN_END;
        }
        return TL_JSCAN_MORE;
    }
}

#ifdef __cplusplus
}
#endif
