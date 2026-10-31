// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// KATs for the cJSON replacement on the control plane (round 1.3.2, B2):
// json_helpers.c (top-level reader + escaping writer) and register_json.h
// (RegisterRequest body, RegisterResponse verdict). The golden request
// bodies below were produced by the old code path — cJSON_AddXxx +
// cJSON_PrintUnformatted from ESP-IDF v5.5.6's components/json — for the
// same inputs, so the new builder is pinned byte-for-byte to what the
// control plane used to receive, including the escaping of hostile
// hostname / auth-key bytes.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json_helpers.h"
#include "register_json.h"

static int g_fail;
#define CHECK(name, cond) do { \
    if (cond) printf("[%s] OK\n", name); \
    else { printf("[%s] FAIL\n", name); g_fail = 1; } } while (0)

/* cJSON_PrintUnformatted output of the pre-1.3.2 register.c tree. */
static const char *const k_golden[] = {
    "{\"Version\":148,\"NodeKey\":\"nodekey:01080f161d242b323940474e555c636"
    "a71787f868d949ba2a9b0b7bec5ccd3da\",\"OldNodeKey\":\"nodekey:000000000"
    "0000000000000000000000000000000000000000000000000000000\",\"NLKey\":\""
    "nlpub:0000000000000000000000000000000000000000000000000000000000000000"
    "\",\"Followup\":\"\",\"Expiry\":\"0001-01-01T00:00:00Z\",\"Hostinfo\":"
    "{\"OS\":\"esp32\",\"Hostname\":\"sensor-test\",\"IPNVersion\":\"1.3.2-"
    "tinylink\"},\"Auth\":{\"AuthKey\":\"tskey-auth-kAbCdEf1CNTRL-012345678"
    "9abcdefABCDEF\"}}",
    "{\"Version\":148,\"NodeKey\":\"nodekey:0000000000000000000000000000000"
    "000000000000000000000000000000000\",\"OldNodeKey\":\"nodekey:000000000"
    "0000000000000000000000000000000000000000000000000000000\",\"NLKey\":\""
    "nlpub:0000000000000000000000000000000000000000000000000000000000000000"
    "\",\"Followup\":\"\",\"Expiry\":\"0001-01-01T00:00:00Z\",\"Hostinfo\":"
    "{\"OS\":\"esp32\",\"Hostname\":\"a\\\"b\\\\c/d\\te\\nf\\rg\\bh\\fi\\u0"
    "001j\\u001fk\x7f" "\xc3" "\xa9" "\",\"IPNVersion\":\"1.3.2-tinylink\"},\""
    "Auth\":{\"AuthKey\":\"hskey-auth-0123456789ab-\\\"\\\\\\u0002\"}}",
    "{\"Version\":148,\"NodeKey\":\"nodekey:01080f161d242b323940474e555c636"
    "a71787f868d949ba2a9b0b7bec5ccd3da\",\"OldNodeKey\":\"nodekey:000000000"
    "0000000000000000000000000000000000000000000000000000000\",\"NLKey\":\""
    "nlpub:0000000000000000000000000000000000000000000000000000000000000000"
    "\",\"Followup\":\"\",\"Expiry\":\"0001-01-01T00:00:00Z\",\"Hostinfo\":"
    "{\"OS\":\"esp32\",\"Hostname\":\"\",\"IPNVersion\":\"\"},\"Auth\":{\"A"
    "uthKey\":\"\"}}"
};

static void str_of(const char *js, const char *key, char *out, size_t cap,
                   esp_err_t *err)
{
    *err = json_get_string(js, strlen(js), key, out, cap);
}

int main(void)
{
    /* --- RegisterRequest bytes == cJSON's ------------------------- */
    {
        uint8_t k[32], z[32] = {0};
        for (int i = 0; i < 32; i++) k[i] = (uint8_t)(i * 7 + 1);
        static char out[2048];
        size_t n = 0;
        esp_err_t e = register_build_body(148, k, "sensor-test", "1.3.2-tinylink",
                                          "tskey-auth-kAbCdEf1CNTRL-0123456789abcdefABCDEF",
                                          out, sizeof(out), &n);
        CHECK("register/golden-typical", e == ESP_OK && n == strlen(k_golden[0]) &&
                                         strcmp(out, k_golden[0]) == 0);
        e = register_build_body(148, z,
                                "a\"b\\c/d\te\nf\rg\bh\fi\x01j\x1fk\x7f\xc3\xa9",
                                "1.3.2-tinylink", "hskey-auth-0123456789ab-\"\\\x02",
                                out, sizeof(out), &n);
        CHECK("register/golden-escaping", e == ESP_OK && strcmp(out, k_golden[1]) == 0);
        e = register_build_body(148, k, "", "", "", out, sizeof(out), &n);
        CHECK("register/golden-empty-strings", e == ESP_OK && strcmp(out, k_golden[2]) == 0);

        /* The body is valid JSON for our own reader, too. */
        char host[64];
        e = json_get_string(k_golden[0], strlen(k_golden[0]), "Followup", host, sizeof(host));
        CHECK("register/self-parse", e == ESP_OK && host[0] == '\0' &&
                                     json_check_object(k_golden[1], strlen(k_golden[1])) == ESP_OK);

        /* Exact fit vs one byte short (the NUL counts). */
        const size_t len0 = strlen(k_golden[0]);
        e = register_build_body(148, k, "sensor-test", "1.3.2-tinylink",
                                "tskey-auth-kAbCdEf1CNTRL-0123456789abcdefABCDEF",
                                out, len0 + 1, &n);
        CHECK("register/exact-fit", e == ESP_OK && n == len0);
        memset(out, 'X', sizeof(out));
        e = register_build_body(148, k, "sensor-test", "1.3.2-tinylink",
                                "tskey-auth-kAbCdEf1CNTRL-0123456789abcdefABCDEF",
                                out, len0, &n);
        CHECK("register/one-short", e == ESP_ERR_INVALID_SIZE && out[len0 - 1] == '\0'
                                    && out[len0] == 'X');
        e = register_build_body(7, k, "h", "v", "a", out, sizeof(out), &n);
        CHECK("register/capver-digits", e == ESP_OK && strncmp(out, "{\"Version\":7,", 13) == 0);

        /* B22: no auth key → no "Auth" member at all (omitempty), every
         * other byte as in the typical golden. */
        char want[2048];
        const char *auth_at = strstr(k_golden[0], ",\"Auth\":");
        CHECK("register/golden-has-auth", auth_at != NULL);
        const size_t head = (size_t)(auth_at - k_golden[0]);
        memcpy(want, k_golden[0], head);
        memcpy(want + head, "}", 2);
        e = register_build_body(148, k, "sensor-test", "1.3.2-tinylink", NULL,
                                out, sizeof(out), &n);
        CHECK("register/no-auth-omits-member", e == ESP_OK && n == strlen(want) &&
                                               strcmp(out, want) == 0 &&
                                               strstr(out, "Auth") == NULL);
        CHECK("register/no-auth-is-object", json_check_object(out, n) == ESP_OK);
        e = register_build_body(148, k, "sensor-test", "1.3.2-tinylink", NULL,
                                out, n + 1, &n);
        CHECK("register/no-auth-exact-fit", e == ESP_OK && n == strlen(want));
        e = register_build_body(148, k, "sensor-test", "1.3.2-tinylink", NULL,
                                out, strlen(want), &n);
        CHECK("register/no-auth-one-short", e == ESP_ERR_INVALID_SIZE);
        /* "" is still a key: the member stays (empty-strings golden). */
        e = register_build_body(148, k, "", "", "", out, sizeof(out), &n);
        CHECK("register/empty-auth-keeps-member", e == ESP_OK &&
                                                  strstr(out, ",\"Auth\":{\"AuthKey\":\"\"}}") != NULL);
    }

    /* --- B22 fallback: retry with the auth key? ------------------- */
    {
        CHECK("retry-auth/ok-never",       !register_retry_with_auth(200, ESP_OK));
        CHECK("retry-auth/not-authorized",  register_retry_with_auth(200, ESP_ERR_NOT_FINISHED));
        CHECK("retry-auth/key-expired",     register_retry_with_auth(200, ESP_ERR_INVALID_STATE));
        CHECK("retry-auth/error-answer",    register_retry_with_auth(200, ESP_FAIL));
        CHECK("retry-auth/malformed",       register_retry_with_auth(200, ESP_ERR_INVALID_RESPONSE));
        CHECK("retry-auth/401",             register_retry_with_auth(401, ESP_FAIL));
        CHECK("retry-auth/404",             register_retry_with_auth(404, ESP_FAIL));
        CHECK("retry-auth/500",             register_retry_with_auth(500, ESP_FAIL));
        CHECK("retry-auth/429-throttle",   !register_retry_with_auth(429, ESP_FAIL));
        CHECK("retry-auth/503-throttle",   !register_retry_with_auth(503, ESP_FAIL));
        CHECK("retry-auth/no-answer",      !register_retry_with_auth(0, ESP_FAIL));
        CHECK("retry-auth/busy-buffer",    !register_retry_with_auth(0, ESP_ERR_INVALID_STATE));
    }

    /* --- writer -------------------------------------------------- */
    {
        char b[64];
        json_out_t o;
        json_out_init(&o, b, sizeof(b));
        json_out_str(&o, "\x01\x1f\x7f/\xe2\x82\xac");
        CHECK("out/controls-del-slash-utf8", json_out_ok(&o) &&
              strcmp(b, "\"\\u0001\\u001f\x7f/\xe2\x82\xac\"") == 0);
        json_out_init(&o, b, sizeof(b));
        json_out_str(&o, "\"\\\b\f\n\r\t");
        CHECK("out/short-escapes", strcmp(b, "\"\\\"\\\\\\b\\f\\n\\r\\t\"") == 0);
        json_out_init(&o, b, 4);
        json_out_raw(&o, "{\"abc\":1}");
        CHECK("out/overflow-flagged", !json_out_ok(&o) && strcmp(b, "{\"a") == 0 && o.len == 9);
        json_out_init(&o, b, 1);
        json_out_str(&o, "");
        CHECK("out/cap1", !json_out_ok(&o) && b[0] == '\0');
        /* Every C0 byte uses cJSON's spelling. */
        int ok = 1;
        for (int c = 1; c < 0x20; c++) {
            char in[2] = { (char)c, 0 }, want[16];
            switch (c) {
                case '\b': strcpy(want, "\"\\b\""); break;
                case '\f': strcpy(want, "\"\\f\""); break;
                case '\n': strcpy(want, "\"\\n\""); break;
                case '\r': strcpy(want, "\"\\r\""); break;
                case '\t': strcpy(want, "\"\\t\""); break;
                default: snprintf(want, sizeof(want), "\"\\u%04x\"", c); break;
            }
            json_out_init(&o, b, sizeof(b));
            json_out_str(&o, in);
            if (strcmp(b, want) != 0) ok = 0;
        }
        CHECK("out/all-c0", ok);
    }

    /* --- reader -------------------------------------------------- */
    {
        /* The real /key answer: "publicKey" must not match the
         * "legacyPublicKey" member before it. */
        const char *key =
            "{\"legacyPublicKey\":\"mkey:0000000000000000000000000000000000000000000000000000000000000000\","
            "\"publicKey\":\"mkey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}\n";
        char v[80];
        esp_err_t e;
        str_of(key, "publicKey", v, sizeof(v), &e);
        CHECK("get/key-response", e == ESP_OK &&
              strcmp(v, "mkey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") == 0);
        str_of(key, "publicKey", v, 69, &e);
        CHECK("get/string-too-big", e == ESP_ERR_INVALID_SIZE);
        str_of(key, "PublicKey", v, sizeof(v), &e);
        CHECK("get/case-sensitive", e == ESP_ERR_NOT_FOUND);
    }
    {
        const char *js = " {\"a\":{\"MachineAuthorized\":true},\"b\":[1,{\"x\":\"}\"}],"
                         "\"s\":\"q\\\"uo\",\"t\":true,\"f\":false,\"n\":null,\"d\":1,\"d\":2} ";
        const size_t L = strlen(js);
        bool b = false;
        char s[16];
        CHECK("get/nested-key-not-top-level",
              json_get_bool(js, L, "MachineAuthorized", &b) == ESP_ERR_NOT_FOUND);
        CHECK("get/bool-true", json_get_bool(js, L, "t", &b) == ESP_OK && b);
        CHECK("get/bool-false", json_get_bool(js, L, "f", &b) == ESP_OK && !b);
        CHECK("get/bool-null-rejected", json_get_bool(js, L, "n", &b) == ESP_ERR_INVALID_RESPONSE);
        CHECK("get/bool-string-rejected", json_get_bool(js, L, "s", &b) == ESP_ERR_INVALID_RESPONSE);
        CHECK("get/string-raw-escapes", json_get_string(js, L, "s", s, sizeof(s)) == ESP_OK &&
                                        strcmp(s, "q\\\"uo") == 0);
        CHECK("get/string-type-check", json_get_string(js, L, "d", s, sizeof(s)) ==
                                       ESP_ERR_INVALID_RESPONSE);
        const char *v; size_t vl;
        CHECK("get/duplicate-first-wins", json_get_member(js, L, "d", &v, &vl) == ESP_OK &&
                                          vl == 1 && v[0] == '1');
    }
    {
        static const char *bad[] = {
            "", "   ", "[]", "\"x\"", "true", "{", "{\"a\":1", "{\"a\":\"x}",
            "{\"a\":1}x", "{\"a\":1}{}", "{\"a\"1}", "{a:1}", "{\"a\":[1,2}",
        };
        int ok = 1;
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            bool b;
            if (json_check_object(bad[i], strlen(bad[i])) != ESP_ERR_INVALID_RESPONSE ||
                json_get_bool(bad[i], strlen(bad[i]), "a", &b) != ESP_ERR_INVALID_RESPONSE) {
                printf("  bad[%u] accepted\n", (unsigned)i);
                ok = 0;
            }
        }
        CHECK("get/malformed-rejected", ok);
        /* Damage AFTER the key still rejects the document. */
        const char *late = "{\"MachineAuthorized\":true,\"x\":\"unterminated}";
        bool b;
        CHECK("get/late-damage", json_get_bool(late, strlen(late), "MachineAuthorized", &b)
                                 == ESP_ERR_INVALID_RESPONSE);
        CHECK("get/length-bounded", json_check_object("{}garbage", 2) == ESP_OK);
    }

    /* --- RegisterResponse verdict -------------------------------- */
    {
        /* Shape of a real tailscale.com answer. */
        const char *ok_resp =
            "{\"User\":{\"ID\":123,\"LoginName\":\"x@example.com\",\"DisplayName\":\"X\","
            "\"ProfilePicURL\":\"\",\"Created\":\"2026-01-01T00:00:00Z\"},"
            "\"Login\":{\"ID\":456,\"Provider\":\"github\",\"LoginName\":\"x\"},"
            "\"NodeKeyExpired\":false,\"MachineAuthorized\":true,\"AuthURL\":\"\"}\n";
        char em[160];
        CHECK("verdict/authorized",
              register_parse_response(ok_resp, strlen(ok_resp), em, sizeof(em)) == ESP_OK);
        const char *pend = "{\"MachineAuthorized\":false,\"AuthURL\":\"https://login/x\"}";
        CHECK("verdict/pending-approval",
              register_parse_response(pend, strlen(pend), em, sizeof(em)) == ESP_ERR_NOT_FINISHED);
        const char *exp = "{\"MachineAuthorized\":true,\"NodeKeyExpired\":true}";
        CHECK("verdict/node-key-expired",
              register_parse_response(exp, strlen(exp), em, sizeof(em)) == ESP_ERR_INVALID_STATE);
        const char *err = "{\"Error\":\"invalid key: unable to validate API key\"}";
        CHECK("verdict/error-message",
              register_parse_response(err, strlen(err), em, sizeof(em)) == ESP_FAIL &&
              strcmp(em, "invalid key: unable to validate API key") == 0);
        const char *none = "{}";
        CHECK("verdict/empty-object",
              register_parse_response(none, 2, em, sizeof(em)) == ESP_FAIL && em[0] == '\0');
        const char *wt = "{\"MachineAuthorized\":\"true\",\"NodeKeyExpired\":true}";
        CHECK("verdict/authorized-not-bool",
              register_parse_response(wt, strlen(wt), em, sizeof(em)) == ESP_ERR_INVALID_RESPONSE);
        const char *ek = "{\"MachineAuthorized\":false,\"NodeKeyExpired\":\"yes\"}";
        CHECK("verdict/expired-not-bool-ignored",
              register_parse_response(ek, strlen(ek), em, sizeof(em)) == ESP_ERR_NOT_FINISHED);
        const char *trunc = "{\"MachineAuthorized\":true,\"User\":{\"ID\":1";
        CHECK("verdict/truncated-rejected",
              register_parse_response(trunc, strlen(trunc), em, sizeof(em)) == ESP_ERR_INVALID_RESPONSE);
        const char *errbig = "{\"Error\":\"0123456789012345678901234567890123456789\"}";
        CHECK("verdict/error-too-long-dropped",
              register_parse_response(errbig, strlen(errbig), em, 8) == ESP_FAIL && em[0] == '\0');
    }

    return g_fail ? 1 : 0;
}
