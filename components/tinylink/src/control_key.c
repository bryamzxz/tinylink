// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "control_key.h"

#include <string.h>

#include "esp_crt_bundle.h"
#include "tl_time.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "nvs.h"
#include "sdkconfig.h"

#include "cJSON.h"

#include "json_helpers.h"
#include "tinylink.h"        /* TINYLINK_CAPVER / TINYLINK_STR */

static const char *TAG = "ctrl_key";

#define NS         "tl_pin"
#define KEY_PIN    "control_pub"
/* Tailscale's /key?v=<n> returns OverTLSPublicKeyResponse JSON whose
 * `publicKey` field is a key.MachinePublic — serialized as the prefix
 * "mkey:" followed by 64 hex chars (32 raw bytes). M1 originally had
 * "nlpub:" which is the Network Lock prefix, a different concept; on
 * the official control plane the actual prefix gives 69 total chars
 * (5+64), not 70 (6+64), so the parser rejected it. */
#define KEY_PREFIX "mkey:"
#define KEY_HEX_LEN 64
/* /key?v=<n> advertises our CapabilityVersion, exactly like the upstream
 * client (control/controlclient/direct.go: `/key?v=%d` with
 * CurrentCapabilityVersion). This used to be a fixed, deliberately lower
 * `v=100`; headscale 5b6e1e17 (2026-07) now gates /key on the same
 * capver.MinSupportedCapabilityVersion floor as the /ts2021 handshake
 * (115 as of 0.29.3/0.30-dev, and it climbs with every release), so a
 * fixed low value gets a 400 "unsupported client version" and the TOFU
 * bootstrap fails. Derive from TINYLINK_CAPVER so the three wire sites
 * (Noise prologue, register/map JSON, /key) can never diverge. */
#define KEY_PATH   "/key?v=" TINYLINK_STR(TINYLINK_CAPVER)

/* Production-profile guard: when the operator opted into the
 * "official" control-pub bootstrap profile (TOFU window closed at
 * compile time), refuse to build firmware that still has an empty
 * fallback hex — that would silently fall through to the network
 * fetch and defeat the whole point of the profile. The string
 * literal "" has sizeof == 1; a populated 64-hex value has
 * sizeof == 65. Anything else is also rejected via the runtime
 * length check below, but at runtime is too late for production
 * firmware. */
#if defined(CONFIG_TINYLINK_CONTROL_PROFILE_OFFICIAL)
_Static_assert(sizeof(CONFIG_TINYLINK_CONTROL_PUB_FALLBACK_HEX) == 65,
               "CONFIG_TINYLINK_CONTROL_PROFILE_OFFICIAL requires "
               "CONFIG_TINYLINK_CONTROL_PUB_FALLBACK_HEX to be exactly "
               "64 hex chars. See sdkconfig.defaults.prod.example for "
               "how to populate it from a curl of /key?v=<capver>.");
#endif
#define BODY_MAX   512

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static esp_err_t hex_decode_32(const char *hex, uint8_t out[CONTROL_KEY_LEN])
{
    for (int i = 0; i < CONTROL_KEY_LEN; i++) {
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return ESP_ERR_INVALID_ARG;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return ESP_OK;
}

typedef struct {
    char  *buf;
    size_t cap;
    size_t len;
} body_buf_t;

static esp_err_t http_event_collect(esp_http_client_event_t *evt)
{
    body_buf_t *b = (body_buf_t *)evt->user_data;
    if (evt->event_id == HTTP_EVENT_ON_DATA && evt->data_len > 0) {
        if (b->len + (size_t)evt->data_len >= b->cap) {
            return ESP_FAIL; /* response too large */
        }
        memcpy(b->buf + b->len, evt->data, evt->data_len);
        b->len += evt->data_len;
        b->buf[b->len] = '\0';
    }
    return ESP_OK;
}

static esp_err_t fetch_pubkey(uint8_t out[CONTROL_KEY_LEN])
{
    char url[160];
    int n = snprintf(url, sizeof(url), "https://%s:%d%s",
                     CONFIG_TINYLINK_CONTROL_HOST,
                     CONFIG_TINYLINK_CONTROL_PORT,
                     KEY_PATH);
    if (n <= 0 || n >= (int)sizeof(url)) return ESP_ERR_INVALID_SIZE;

    char body[BODY_MAX];
    body_buf_t bb = { .buf = body, .cap = BODY_MAX, .len = 0 };

    esp_http_client_config_t cfg = {
        .url = url,
        .crt_bundle_attach = tl_crt_bundle_attach,
        .event_handler = http_event_collect,
        .user_data = &bb,
        .timeout_ms = 15000,
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (client == NULL) return ESP_FAIL;

    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    if (err != ESP_OK) return err;
    if (status != 200) {
        ESP_LOGE(TAG, "GET %s returned %d", KEY_PATH, status);
        return ESP_FAIL;
    }

    cJSON *root = cJSON_ParseWithLength(body, bb.len);
    if (root == NULL) return ESP_ERR_INVALID_RESPONSE;

    char pub_b64_or_hex[80] = {0};
    err = json_get_string(root, "publicKey",
                          pub_b64_or_hex, sizeof(pub_b64_or_hex));
    cJSON_Delete(root);
    if (err != ESP_OK) return err;

    /* Tailscale's /key endpoint returns "nlpub:<64hex>". */
    const char *p = pub_b64_or_hex;
    if (strncmp(p, KEY_PREFIX, strlen(KEY_PREFIX)) == 0) {
        p += strlen(KEY_PREFIX);
    }
    if (strlen(p) != KEY_HEX_LEN) {
        ESP_LOGE(TAG, "publicKey wrong length: %u", (unsigned)strlen(p));
        return ESP_ERR_INVALID_SIZE;
    }
    return hex_decode_32(p, out);
}

static esp_err_t persist(const uint8_t pub[CONTROL_KEY_LEN])
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(h, KEY_PIN, pub, CONTROL_KEY_LEN);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

static esp_err_t load_pin(uint8_t out[CONTROL_KEY_LEN])
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READONLY, &h);
    if (err != ESP_OK) return err;
    size_t len = CONTROL_KEY_LEN;
    err = nvs_get_blob(h, KEY_PIN, out, &len);
    nvs_close(h);
    if (err == ESP_OK && len != CONTROL_KEY_LEN) return ESP_ERR_INVALID_SIZE;
    return err;
}

/* Decode the optional compile-in fallback pin from
 * CONFIG_TINYLINK_CONTROL_PUB_FALLBACK_HEX into 32 raw bytes.
 *
 * Return values:
 *   ESP_OK              — fallback is present and valid; out filled.
 *   ESP_ERR_NOT_FOUND   — fallback is empty (legacy TOFU mode).
 *   ESP_ERR_INVALID_SIZE — fallback present but wrong length / hex.
 *
 * Callers fail-loud on INVALID_SIZE because a non-empty malformed pin
 * almost certainly means the operator intended to ship a fallback and
 * fat-fingered it; silently falling back to TOFU would be a footgun. */
static esp_err_t parse_fallback(uint8_t out[CONTROL_KEY_LEN])
{
    const char *s = CONFIG_TINYLINK_CONTROL_PUB_FALLBACK_HEX;
    if (s == NULL || s[0] == '\0') return ESP_ERR_NOT_FOUND;
    if (strlen(s) != KEY_HEX_LEN) {
        ESP_LOGE(TAG,
            "CONFIG_TINYLINK_CONTROL_PUB_FALLBACK_HEX must be %d hex chars "
            "(got %u) — refusing to boot insecure",
            KEY_HEX_LEN, (unsigned)strlen(s));
        return ESP_ERR_INVALID_SIZE;
    }
    return hex_decode_32(s, out);
}

/* Three-tier trust resolution for the control plane pubkey:
 *
 *   1. NVS pin present  → use it. The operator already accepted this
 *      key (either via prior TOFU, prior fallback install, or manual
 *      provisioning). NVS wins regardless of fallback config.
 *   2. NVS empty + fallback set → install fallback as the pin without
 *      contacting the network. This eliminates the TOFU window where
 *      a MITM during the initial GET /key?v=<capver> could substitute the
 *      pin. Production deployments should always reach this branch on
 *      first boot.
 *   3. NVS empty + no fallback → legacy TOFU via GET /key. Logs a
 *      loud WARN so this path is visible in production logs (it
 *      should not happen in production firmware). */
esp_err_t control_key_get(uint8_t out_pub[CONTROL_KEY_LEN])
{
    if (out_pub == NULL) return ESP_ERR_INVALID_ARG;

    esp_err_t err = load_pin(out_pub);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "using pinned control pub from NVS");
        return ESP_OK;
    }
    if (err != ESP_ERR_NVS_NOT_FOUND && err != ESP_ERR_NVS_NOT_INITIALIZED) {
        ESP_LOGW(TAG, "load_pin returned 0x%x, will try fallback / fetch", err);
    }

    uint8_t fallback[CONTROL_KEY_LEN];
    err = parse_fallback(fallback);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "no NVS pin — installing compile-in fallback (no TOFU)");
        memcpy(out_pub, fallback, CONTROL_KEY_LEN);
        return persist(out_pub);
    }
    if (err != ESP_ERR_NOT_FOUND) {
        /* Malformed Kconfig — surface immediately. */
        return err;
    }

    ESP_LOGW(TAG,
        "no NVS pin and no compile-in fallback — falling back to TOFU "
        "via GET /key (vulnerable to first-boot MITM; set "
        "CONFIG_TINYLINK_CONTROL_PUB_FALLBACK_HEX for production)");
    err = fetch_pubkey(out_pub);
    if (err != ESP_OK) return err;
    err = persist(out_pub);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "control pub fetched and pinned (TOFU)");
    }
    return err;
}
