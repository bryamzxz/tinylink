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

    if (g_fail) { printf("\nFAIL\n"); return 1; }
    printf("\n[PASS] all jsmn_split assertions passed\n");
    return 0;
}
