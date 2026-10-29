// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// JSON for the two small control-plane documents that are not
// MapResponses: the RegisterRequest/Response (register.c) and the /key
// answer (control_key.c). Round 1.3.2 (B2) replaced cJSON here — a heap
// tree of 40–60 allocations per register for a dozen scalar fields —
// with:
//
//   * a reader over jsmn_split.h that looks up TOP-LEVEL members of an
//     object in place (no tokens, no allocation), and
//   * an append-only writer whose string escaping is byte-for-byte
//     cJSON's (print_string_ptr): `"` `\` and the C0 controls escaped,
//     \b \f \n \r \t short forms, the rest as \u00xx (lowercase); bytes
//     >= 0x20 other than `"` / `\` — '/', DEL, UTF-8 — pass through.
//
// Pure C, no ESP-IDF dependency; host-tested by tools/test/test_ctrl_json.c.

#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef ESP_PLATFORM
#include "esp_err.h"
#else
/* Host KAT build: the esp_err subset used here, ESP-IDF values. */
typedef int esp_err_t;
#define ESP_OK                   0
#define ESP_FAIL                 -1
#define ESP_ERR_INVALID_ARG      0x102
#define ESP_ERR_INVALID_SIZE     0x104
#define ESP_ERR_NOT_FOUND        0x105
#define ESP_ERR_INVALID_RESPONSE 0x108
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ---- reading -------------------------------------------------------------
 *
 * `js[0..len)` must be ONE JSON object (surrounding whitespace allowed).
 * Every lookup walks the whole top level, so a document that is not a
 * well-formed object at that level (unterminated string, unbalanced
 * nesting, trailing bytes) is rejected with ESP_ERR_INVALID_RESPONSE
 * even when the key appears before the damage. Nested values are only
 * delimited (jsmn_split.h), not validated — the callers read top-level
 * scalars and check their content themselves. Keys compare byte-exact,
 * case-sensitive; with duplicate keys the first wins (as in cJSON). */

/* ESP_OK when js[0..len) is one object, well-formed at the top level;
 * ESP_ERR_INVALID_RESPONSE otherwise. */
esp_err_t json_check_object(const char *js, size_t len);

/* ESP_OK + the raw value text, ESP_ERR_NOT_FOUND, or
 * ESP_ERR_INVALID_RESPONSE (not an object / malformed). */
esp_err_t json_get_member(const char *js, size_t len, const char *key,
                          const char **val, size_t *val_len);

/* String member, copied NUL-terminated WITHOUT decoding escapes (callers
 * read ASCII keys and log messages). ESP_ERR_NOT_FOUND if missing,
 * ESP_ERR_INVALID_RESPONSE if not a string, ESP_ERR_INVALID_SIZE if it
 * does not fit in out_size. */
esp_err_t json_get_string(const char *js, size_t len, const char *key,
                          char *out, size_t out_size);

/* Boolean member: exactly `true` / `false`; anything else (null, a
 * string, a number) is ESP_ERR_INVALID_RESPONSE. */
esp_err_t json_get_bool(const char *js, size_t len, const char *key,
                        bool *out);

/* ---- writing -------------------------------------------------------------
 *
 * Append into a caller buffer. `len` keeps counting past `cap`, so one
 * check at the end (json_out_ok) catches truncation anywhere; the buffer
 * is always NUL-terminated within cap. */
typedef struct {
    char  *buf;
    size_t cap;
    size_t len;
} json_out_t;

void json_out_init(json_out_t *o, char *buf, size_t cap);
/* Raw bytes (structure, keys, numbers), not escaped. */
void json_out_raw(json_out_t *o, const char *s);
/* `s` as a quoted, escaped JSON string. */
void json_out_str(json_out_t *o, const char *s);
/* True when nothing was truncated. */
static inline bool json_out_ok(const json_out_t *o)
{
    return o->cap > 0 && o->len < o->cap;
}

#ifdef __cplusplus
}
#endif
