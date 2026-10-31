// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "json_helpers.h"

#include <string.h>

#include "jsmn_split.h"

/* Walk every top-level member — to the closing brace even after a hit,
 * so the whole level must be well-formed, as under cJSON's full parse —
 * remembering the first one named `key` (NULL: none). */
static esp_err_t walk_object(const char *js, size_t len, const char *key,
                             const char **val, size_t *val_len)
{
    if (js == NULL) return ESP_ERR_INVALID_ARG;
    size_t pos = 0;
    tl_jsplit_kv_t kv;
    bool found = false;
    int rc;
    while ((rc = tl_jsplit_obj_next(js, len, &pos, &kv)) == 1) {
        if (!found && key != NULL && tl_jsplit_key_is(&kv, key)) {
            *val     = kv.val;
            *val_len = kv.val_len;
            found    = true;
        }
    }
    if (rc < 0 || tl_jsplit_ws(js, len, pos) != len) {
        return ESP_ERR_INVALID_RESPONSE;
    }
    return found ? ESP_OK : ESP_ERR_NOT_FOUND;
}

esp_err_t json_check_object(const char *js, size_t len)
{
    esp_err_t err = walk_object(js, len, NULL, NULL, NULL);
    return (err == ESP_ERR_NOT_FOUND) ? ESP_OK : err;
}

esp_err_t json_get_member(const char *js, size_t len, const char *key,
                          const char **val, size_t *val_len)
{
    if (key == NULL || val == NULL || val_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    return walk_object(js, len, key, val, val_len);
}

esp_err_t json_get_string(const char *js, size_t len, const char *key,
                          char *out, size_t out_size)
{
    if (out == NULL || out_size == 0) return ESP_ERR_INVALID_ARG;
    const char *v;
    size_t vlen;
    esp_err_t err = json_get_member(js, len, key, &v, &vlen);
    if (err != ESP_OK) return err;
    /* tl_jsplit_value ends a string value at its closing quote. */
    if (vlen < 2 || v[0] != '"' || v[vlen - 1] != '"') {
        return ESP_ERR_INVALID_RESPONSE;
    }
    const size_t n = vlen - 2;
    if (n + 1 > out_size) return ESP_ERR_INVALID_SIZE;
    memcpy(out, v + 1, n);
    out[n] = '\0';
    return ESP_OK;
}

esp_err_t json_get_bool(const char *js, size_t len, const char *key,
                        bool *out)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    const char *v;
    size_t vlen;
    esp_err_t err = json_get_member(js, len, key, &v, &vlen);
    if (err != ESP_OK) return err;
    if (vlen == 4 && memcmp(v, "true", 4) == 0)  { *out = true;  return ESP_OK; }
    if (vlen == 5 && memcmp(v, "false", 5) == 0) { *out = false; return ESP_OK; }
    return ESP_ERR_INVALID_RESPONSE;
}

void json_out_init(json_out_t *o, char *buf, size_t cap)
{
    o->buf = buf;
    o->cap = cap;
    o->len = 0;
    if (buf != NULL && cap > 0) buf[0] = '\0';
}

static void out_bytes(json_out_t *o, const char *s, size_t n)
{
    if (o->buf != NULL && o->len < o->cap) {
        const size_t room = o->cap - 1 - o->len;   /* keep the NUL */
        const size_t take = (n < room) ? n : room;
        memcpy(o->buf + o->len, s, take);
        o->buf[o->len + take] = '\0';
    }
    o->len += n;   /* keeps counting: json_out_ok sees any overflow */
}

void json_out_raw(json_out_t *o, const char *s)
{
    out_bytes(o, s, strlen(s));
}

void json_out_str(json_out_t *o, const char *s)
{
    static const char hex[] = "0123456789abcdef";
    out_bytes(o, "\"", 1);
    const char *run = s;          /* start of the pending unescaped run */
    for (const char *p = s; *p != '\0'; p++) {
        const unsigned char c = (unsigned char)*p;
        char esc[6];
        size_t n = 2;
        esc[0] = '\\';
        switch (c) {
            case '"':  esc[1] = '"';  break;
            case '\\': esc[1] = '\\'; break;
            case '\b': esc[1] = 'b';  break;
            case '\f': esc[1] = 'f';  break;
            case '\n': esc[1] = 'n';  break;
            case '\r': esc[1] = 'r';  break;
            case '\t': esc[1] = 't';  break;
            default:
                if (c >= 0x20) continue;            /* plain byte */
                esc[1] = 'u'; esc[2] = '0'; esc[3] = '0';
                esc[4] = hex[c >> 4]; esc[5] = hex[c & 0x0F];
                n = 6;
                break;
        }
        out_bytes(o, run, (size_t)(p - run));
        out_bytes(o, esc, n);
        run = p + 1;
    }
    out_bytes(o, run, strlen(run));
    out_bytes(o, "\"", 1);
}
