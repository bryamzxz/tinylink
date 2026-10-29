// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// KATs for jsmn_split.h — the shallow object/array splitter mapreq.c
// uses to feed jsmn one MapResponse value at a time.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "jsmn_split.h"

static int g_fail;
#define CHECK(name, cond) do { \
    if (cond) printf("[%s] OK\n", name); \
    else { printf("[%s] FAIL\n", name); g_fail = 1; } } while (0)

static int count_members(const char *js, size_t len, int *last_rc)
{
    size_t pos = 0; tl_jsplit_kv_t kv; int n = 0, rc;
    while ((rc = tl_jsplit_obj_next(js, len, &pos, &kv)) == 1) n++;
    *last_rc = rc;
    return n;
}

/* Where tl_jsplit_scan_* ends the value starting at js[0] (non-ws): the
 * index just past it, or 0 if it fails / is unterminated. A scalar still
 * open at the end of the text ends there, like tl_jsplit_value. */
static size_t scan_end(const char *js, size_t len)
{
    tl_jsplit_scan_t s;
    if (len == 0 || tl_jsplit_scan_begin(&s, js[0]) != TL_JSCAN_MORE) return 0;
    for (size_t i = 1; i < len; i++) {
        int r = tl_jsplit_scan_byte(&s, js[i]);
        if (r == TL_JSCAN_ERR) return 0;
        if (r == TL_JSCAN_END) return i + 1;
        if (r == TL_JSCAN_END_BEFORE) return i;
    }
    return (s.mode == TL_JSCAN_SCALAR) ? len : 0;
}

static int scan_matches_value(const char *js, size_t len)
{
    size_t a = scan_end(js, len), b = tl_jsplit_value(js, len, 0);
    if (a != b) printf("  scan %zu vs value %zu on \"%.*s\"\n", a, b, (int)len, js);
    return a == b;
}

int main(void)
{
    /* --- objects ------------------------------------------------- */
    {
        const char *js = "{}";
        int rc; int n = count_members(js, strlen(js), &rc);
        CHECK("obj/empty", n == 0 && rc == 0);
    }
    {
        const char *js = " { \"a\" : 1 , \"b\":\"x\",\"c\":true,\"d\":null } ";
        size_t pos = 0; tl_jsplit_kv_t kv; int n = 0, rc;
        int ok = 1;
        while ((rc = tl_jsplit_obj_next(js, strlen(js), &pos, &kv)) == 1) {
            n++;
            if (n == 1) ok &= tl_jsplit_key_is(&kv, "a") && kv.val_len == 1 && kv.val[0] == '1';
            if (n == 2) ok &= tl_jsplit_key_is(&kv, "b") && kv.val_len == 3 && memcmp(kv.val, "\"x\"", 3) == 0;
            if (n == 3) ok &= tl_jsplit_key_is(&kv, "c") && tl_jsplit_val_is_true(&kv);
            if (n == 4) ok &= tl_jsplit_key_is(&kv, "d") && kv.val_len == 4 && memcmp(kv.val, "null", 4) == 0;
        }
        CHECK("obj/scalars", ok && n == 4 && rc == 0);
    }
    {
        /* Nested values are returned whole; braces/brackets/quotes inside
         * strings must not confuse the depth count. */
        const char *js = "{\"Node\":{\"Name\":\"a}b]c\\\"{\",\"Addresses\":[\"100.1.2.3/32\"]},"
                         "\"Peers\":[{\"ID\":1,\"Endpoints\":[\"1.2.3.4:5\"]},{\"ID\":2}],"
                         "\"KeepAlive\":true}";
        size_t pos = 0; tl_jsplit_kv_t kv; int n = 0, rc, ok = 1;
        while ((rc = tl_jsplit_obj_next(js, strlen(js), &pos, &kv)) == 1) {
            n++;
            if (n == 1) ok &= tl_jsplit_key_is(&kv, "Node") && kv.val[0] == '{' && kv.val[kv.val_len - 1] == '}'
                              && kv.val_len == strlen("{\"Name\":\"a}b]c\\\"{\",\"Addresses\":[\"100.1.2.3/32\"]}");
            if (n == 2) ok &= tl_jsplit_key_is(&kv, "Peers") && kv.val[0] == '[' && kv.val[kv.val_len - 1] == ']';
            if (n == 3) ok &= tl_jsplit_key_is(&kv, "KeepAlive") && tl_jsplit_val_is_true(&kv);
        }
        CHECK("obj/nested-and-tricky-strings", ok && n == 3 && rc == 0);
    }
    {
        const char *js = "{\"a\":{\"b\":[1,2";           /* unterminated */
        int rc; count_members(js, strlen(js), &rc);
        CHECK("obj/unterminated", rc == -1);
    }
    {
        const char *js = "[1,2]";                         /* not an object */
        int rc; count_members(js, strlen(js), &rc);
        CHECK("obj/not-object", rc == -1);
    }
    {
        const char *js = "{\"a\" 1}";                     /* missing colon */
        int rc; count_members(js, strlen(js), &rc);
        CHECK("obj/missing-colon", rc == -1);
    }
    {
        /* Depth bound: 70 nested arrays exceed TL_JSPLIT_MAX_DEPTH (64). */
        char deep[256]; size_t o = 0;
        deep[o++] = '{'; memcpy(deep + o, "\"a\":", 4); o += 4;
        for (int i = 0; i < 70; i++) deep[o++] = '[';
        for (int i = 0; i < 70; i++) deep[o++] = ']';
        deep[o++] = '}'; deep[o] = '\0';
        int rc; count_members(deep, o, &rc);
        CHECK("obj/depth-bounded", rc == -1);
        /* ...and 60 levels are fine. */
        o = 0; deep[o++] = '{'; memcpy(deep + o, "\"a\":", 4); o += 4;
        for (int i = 0; i < 60; i++) deep[o++] = '[';
        for (int i = 0; i < 60; i++) deep[o++] = ']';
        deep[o++] = '}'; deep[o] = '\0';
        int n = count_members(deep, o, &rc);
        CHECK("obj/depth-in-bounds", n == 1 && rc == 0);
    }

    /* --- arrays -------------------------------------------------- */
    {
        const char *js = "[]";
        size_t pos = 0; const char *v; size_t vl; int rc = tl_jsplit_arr_next(js, 2, &pos, &v, &vl);
        CHECK("arr/empty", rc == 0);
    }
    {
        const char *js = "[ {\"ID\":1}, {\"ID\":2,\"K\":\"]\"} , 3 ,\"s\" ]";
        size_t pos = 0; const char *v; size_t vl; int n = 0, rc, ok = 1;
        while ((rc = tl_jsplit_arr_next(js, strlen(js), &pos, &v, &vl)) == 1) {
            n++;
            if (n == 1) ok &= vl == 8 && memcmp(v, "{\"ID\":1}", 8) == 0;
            if (n == 2) ok &= v[0] == '{' && v[vl - 1] == '}' && vl == strlen("{\"ID\":2,\"K\":\"]\"}");
            if (n == 3) ok &= vl == 1 && v[0] == '3';
            if (n == 4) ok &= vl == 3 && memcmp(v, "\"s\"", 3) == 0;
        }
        CHECK("arr/mixed", ok && n == 4 && rc == 0);
    }
    {
        const char *js = "[1,2";
        size_t pos = 0; const char *v; size_t vl; int rc;
        while ((rc = tl_jsplit_arr_next(js, strlen(js), &pos, &v, &vl)) == 1) {}
        CHECK("arr/unterminated", rc == -1);
    }
    {
        /* Iterating an object as an array is rejected. */
        const char *js = "{\"a\":1}";
        size_t pos = 0; const char *v; size_t vl;
        CHECK("arr/not-array", tl_jsplit_arr_next(js, strlen(js), &pos, &v, &vl) == -1);
    }

    /* --- a MapResponse-shaped document, split then re-split ------ */
    {
        const char *js =
            "{\"Node\":{\"ID\":7,\"Addresses\":[\"100.67.60.92/32\"]},"
            "\"PeersChanged\":[{\"ID\":1,\"Key\":\"nodekey:00\",\"Endpoints\":[\"1.1.1.1:1\",\"2.2.2.2:2\"]},"
                              "{\"ID\":2,\"Key\":\"nodekey:11\"}],"
            "\"DERPMap\":{\"Regions\":{\"1\":{\"RegionID\":1,\"Nodes\":[{\"HostName\":\"derp1\"}]},"
                                      "\"16\":{\"RegionID\":16,\"Nodes\":[{\"HostName\":\"derp16b\"}]}}},"
            "\"PeersChangedPatch\":[{\"NodeID\":1,\"DiscoKey\":\"discokey:22\"}]}";
        size_t pos = 0; tl_jsplit_kv_t kv; int rc, ok = 1, peers = 0, regions = 0, patch_ident = 0;
        while ((rc = tl_jsplit_obj_next(js, strlen(js), &pos, &kv)) == 1) {
            if (tl_jsplit_key_is(&kv, "PeersChanged")) {
                size_t ap = 0; const char *v; size_t vl; int arc;
                while ((arc = tl_jsplit_arr_next(kv.val, kv.val_len, &ap, &v, &vl)) == 1) peers++;
                ok &= arc == 0;
            } else if (tl_jsplit_key_is(&kv, "DERPMap")) {
                size_t dp = 0; tl_jsplit_kv_t dkv; int drc;
                while ((drc = tl_jsplit_obj_next(kv.val, kv.val_len, &dp, &dkv)) == 1) {
                    if (tl_jsplit_key_is(&dkv, "Regions")) {
                        size_t rp = 0; tl_jsplit_kv_t rkv; int rrc;
                        while ((rrc = tl_jsplit_obj_next(dkv.val, dkv.val_len, &rp, &rkv)) == 1) {
                            regions++;
                            ok &= rkv.val[0] == '{';
                        }
                        ok &= rrc == 0;
                    }
                }
                ok &= drc == 0;
            } else if (tl_jsplit_key_is(&kv, "PeersChangedPatch")) {
                size_t ap = 0; const char *v; size_t vl; int arc;
                while ((arc = tl_jsplit_arr_next(kv.val, kv.val_len, &ap, &v, &vl)) == 1) {
                    size_t ep = 0; tl_jsplit_kv_t ekv; int erc;
                    while ((erc = tl_jsplit_obj_next(v, vl, &ep, &ekv)) == 1) {
                        if (tl_jsplit_key_is(&ekv, "Key") || tl_jsplit_key_is(&ekv, "DiscoKey")) patch_ident++;
                    }
                    ok &= erc == 0;
                }
                ok &= arc == 0;
            }
        }
        CHECK("mapresponse/shape", ok && rc == 0 && peers == 2 && regions == 2 && patch_ident == 1);
    }

    /* --- tl_jsplit_scan_* (round 1.3.4, D2) ---------------------------
     * The byte-at-a-time scanner must end every value exactly where
     * tl_jsplit_value does, and fail exactly where it fails. */
    {
        static const char *cases[] = {
            "\"abc\"", "\"a\\\"b\"", "\"a\\\\\"x", "\"unterminated", "\"esc at end\\",
            "123,", "true}", "null]", "-1.5e3 ", "1\"x\"]", "x{\"a\":1}", ":1}",
            "{}", "[]", "{\"a\":[1,2,{\"b\":\"]\"}]}", "{\"a\":1]", "[1}", "[[[", "{\"a\":",
            "{\"k\\\"}\":1}rest", "[\"]\",\"[\"]", ",", "}", "]", "{\"a\":1}}", "a",
        };
        int ok = 1;
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
            ok &= scan_matches_value(cases[i], strlen(cases[i]));
        }
        CHECK("scan/same-end-as-value", ok);
    }
    {
        /* Depth: 64 levels end, 65 fail — the same bound. */
        char deep[160]; size_t o = 0;
        for (int i = 0; i < 64; i++) deep[o++] = '[';
        for (int i = 0; i < 64; i++) deep[o++] = ']';
        int ok = scan_matches_value(deep, o) && tl_jsplit_value(deep, o, 0) == o;
        o = 0;
        for (int i = 0; i < 65; i++) deep[o++] = '[';
        for (int i = 0; i < 65; i++) deep[o++] = ']';
        ok &= scan_matches_value(deep, o) && tl_jsplit_value(deep, o, 0) == 0;
        CHECK("scan/depth-bound", ok);
    }
    {
        /* 200 000 random strings over the characters that matter. */
        static const char alpha[] = "{}[]\",:\\ \nab1";
        unsigned seed = 12345; int ok = 1; char buf[48];
        for (int t = 0; t < 200000 && ok; t++) {
            size_t n = 1 + (size_t)((seed = seed * 1103515245u + 12345u) >> 16) % (sizeof(buf) - 1);
            for (size_t i = 0; i < n; i++) {
                seed = seed * 1103515245u + 12345u;
                buf[i] = alpha[(seed >> 16) % (sizeof(alpha) - 1)];
            }
            if (tl_jsplit_is_ws(buf[0])) buf[0] = 'a';
            ok &= scan_matches_value(buf, n);
        }
        CHECK("scan/random-vs-value", ok);
    }

    if (g_fail) { printf("\nFAIL\n"); return 1; }
    printf("\n[PASS] all jsmn_split assertions passed\n");
    return 0;
}
