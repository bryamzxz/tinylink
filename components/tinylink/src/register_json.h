// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// RegisterRequest body + RegisterResponse verdict for register.c, kept
// pure (no ESP-IDF, no I/O) so tools/test/test_ctrl_json.c can pin them.
// Round 1.3.2 (B2) moved these off cJSON; the request bytes are the ones
// cJSON_PrintUnformatted produced for the same tree (KAT-checked).

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "json_helpers.h"

#ifndef ESP_PLATFORM
#define ESP_ERR_INVALID_STATE    0x103
#define ESP_ERR_NOT_FINISHED     0x10C
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* "<prefix><64 lowercase hex>" + NUL into out. */
static inline void register_keyed_hex(char *out, const char *prefix,
                                      const uint8_t key[32])
{
    static const char hex[] = "0123456789abcdef";
    const size_t plen = strlen(prefix);
    memcpy(out, prefix, plen);
    for (size_t i = 0; i < 32; i++) {
        out[plen + 2 * i]     = hex[key[i] >> 4];
        out[plen + 2 * i + 1] = hex[key[i] & 0x0F];
    }
    out[plen + 64] = '\0';
}

/* tailcfg.RegisterRequest, field order as upstream / as cJSON emitted:
 *   {"Version":<capver>,"NodeKey":"nodekey:<hex>",
 *    "OldNodeKey":"nodekey:<64 zeros>","NLKey":"nlpub:<64 zeros>",
 *    "Followup":"","Expiry":"0001-01-01T00:00:00Z",
 *    "Hostinfo":{"OS":"esp32","Hostname":…,"IPNVersion":…},
 *    "Auth":{"AuthKey":…}}
 * - Version is the CapabilityVersion (TINYLINK_CAPVER).
 * - OldNodeKey is all zeros on first registration.
 * - NLKey is required (no `omitempty` upstream); there is no TKA, so an
 *   all-zero Ed25519 public key is tolerated.
 * - Timestamp / SignatureType / Signature / DeviceCert are omitempty and
 *   only populated for SignatureV1; we use SignatureNone, so they are
 *   absent. Ephemeral (bool, omitempty) is false → absent.
 * Hostname, IPNVersion and the auth key are JSON-escaped, so a quote or
 * a control byte in any of them cannot break the document. Returns
 * ESP_ERR_INVALID_SIZE if the body (plus NUL) does not fit out_size. */
static inline esp_err_t register_build_body(unsigned capver,
                                            const uint8_t node_pub[32],
                                            const char *hostname,
                                            const char *ipn_version,
                                            const char *auth_key,
                                            char *out, size_t out_size,
                                            size_t *out_len)
{
    char key[9 + 64 + 1];
    char ver[12];
    size_t vn = sizeof(ver) - 1;
    ver[vn] = '\0';
    do { ver[--vn] = (char)('0' + capver % 10); capver /= 10; } while (capver && vn);

    json_out_t o;
    json_out_init(&o, out, out_size);
    json_out_raw(&o, "{\"Version\":");
    json_out_raw(&o, ver + vn);
    json_out_raw(&o, ",\"NodeKey\":");
    register_keyed_hex(key, "nodekey:", node_pub);
    json_out_str(&o, key);
    json_out_raw(&o, ",\"OldNodeKey\":\"nodekey:");
    for (int i = 0; i < 4; i++) json_out_raw(&o, "0000000000000000");
    json_out_raw(&o, "\",\"NLKey\":\"nlpub:");
    for (int i = 0; i < 4; i++) json_out_raw(&o, "0000000000000000");
    json_out_raw(&o, "\",\"Followup\":\"\",\"Expiry\":\"0001-01-01T00:00:00Z\""
                     ",\"Hostinfo\":{\"OS\":\"esp32\",\"Hostname\":");
    json_out_str(&o, hostname);
    json_out_raw(&o, ",\"IPNVersion\":");
    json_out_str(&o, ipn_version);
    json_out_raw(&o, "},\"Auth\":{\"AuthKey\":");
    json_out_str(&o, auth_key);
    json_out_raw(&o, "}}");
    if (!json_out_ok(&o)) return ESP_ERR_INVALID_SIZE;
    *out_len = o.len;
    return ESP_OK;
}

/* Verdict of a tailcfg.RegisterResponse (same rules as under cJSON):
 *   ESP_OK                   MachineAuthorized=true
 *   ESP_ERR_NOT_FINISHED     MachineAuthorized=false (operator approval)
 *   ESP_ERR_INVALID_STATE    NodeKeyExpired=true — control accepted the
 *                            machine but the NodeKey we re-send is
 *                            expired; checked before MachineAuthorized
 *   ESP_FAIL                 MachineAuthorized absent; err_msg gets the
 *                            response's "Error" string ("" if none)
 *   ESP_ERR_INVALID_RESPONSE not a well-formed object, or
 *                            MachineAuthorized not a bool
 * NodeKeyExpired that is absent or not a bool counts as false. */
static inline esp_err_t register_parse_response(const char *js, size_t len,
                                                char *err_msg, size_t err_cap)
{
    if (err_msg != NULL && err_cap > 0) err_msg[0] = '\0';
    bool authorized = false;
    esp_err_t err = json_get_bool(js, len, "MachineAuthorized", &authorized);
    if (err == ESP_ERR_NOT_FOUND) {
        if (err_msg != NULL && err_cap > 0 &&
            json_get_string(js, len, "Error", err_msg, err_cap) != ESP_OK) {
            err_msg[0] = '\0';
        }
        return ESP_FAIL;
    }
    if (err != ESP_OK) return ESP_ERR_INVALID_RESPONSE;
    bool key_expired = false;
    if (json_get_bool(js, len, "NodeKeyExpired", &key_expired) != ESP_OK) {
        key_expired = false;
    }
    if (key_expired) return ESP_ERR_INVALID_STATE;
    return authorized ? ESP_OK : ESP_ERR_NOT_FINISHED;
}

#ifdef __cplusplus
}
#endif
