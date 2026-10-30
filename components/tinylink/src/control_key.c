// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "control_key.h"

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_tls.h"
#include "mbedtls/ssl.h"
#include "nvs.h"
#include "sdkconfig.h"

#include "ctrl_buf.h"
#include "json_helpers.h"
#include "tinylink.h"        /* TINYLINK_CAPVER / TINYLINK_STR / version */
#include "tl_http1.h"
#include "tl_time.h"
#include "tls_io.h"

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
/* The /key JSON is ~150 B ({"legacyPublicKey":"mkey:…","publicKey":"mkey:…"});
 * the body may be at most BODY_MAX - 1 bytes (the old collector's cap). */
#define BODY_MAX   512
/* Whole response — status line, headers and body. A Go net/http answer
 * carries ~150 B of headers; this leaves room for a proxy's. */
#define RESP_MAX   4096
/* Connect timeout and socket SO_RCVTIMEO / SO_SNDTIMEO, as the
 * esp_http_client config had it. A blocking esp_tls read or write only
 * returns WANT_* when that timeout expired, so one such poll = 15 s
 * without progress ends the fetch, as it did before. */
#define KEY_TIMEOUT_MS 15000
#define KEY_MAX_IDLE_POLLS 1

_Static_assert(RESP_MAX <= TL_CTRL_REQ_OFF, "key response must not reach the request");

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

static ssize_t key_tls_write(void *ctx, const uint8_t *buf, size_t len)
{
    return esp_tls_conn_write((esp_tls_t *)ctx, buf, len);
}

/* HTTPS GET KEY_PATH on esp_tls (round 1.3.2, B1: this was the only
 * user of esp_http_client, which dragged in tcp_transport and most of
 * http_parser as well). Sends `Connection: close`, reads until
 * tl_http1.h says the response is complete (Content-Length, chunked,
 * or EOF) and leaves it in buf[0..RESP_MAX).
 * Redirects are not followed: the TOFU pin comes from the configured
 * host or not at all. */
static esp_err_t https_get_key(uint8_t *buf, tl_http1_resp_t *resp)
{
    /* Host header as esp_http_client built it: no port for 443 / 80. */
    char *req = (char *)buf + TL_CTRL_REQ_OFF;
    const int port = CONFIG_TINYLINK_CONTROL_PORT;
    char port_sfx[8] = "";
    if (port != 443 && port != 80) {
        snprintf(port_sfx, sizeof(port_sfx), ":%d", port);
    }
    int n = snprintf(req, TL_CTRL_REQ_CAP,
        "GET " KEY_PATH " HTTP/1.1\r\n"
        "Host: %s%s\r\n"
        "User-Agent: tinylink/" TINYLINK_VERSION_STRING "\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n"
        "\r\n",
        CONFIG_TINYLINK_CONTROL_HOST, port_sfx);
    if (n <= 0 || n >= (int)TL_CTRL_REQ_CAP) return ESP_ERR_INVALID_SIZE;

    esp_tls_cfg_t cfg = {
        .crt_bundle_attach = tl_crt_bundle_attach,
        .timeout_ms        = KEY_TIMEOUT_MS,
    };
    esp_tls_t *tls = esp_tls_init();
    if (tls == NULL) return ESP_ERR_NO_MEM;
    esp_err_t err  = ESP_OK;
    int       rc   = 0;
    size_t    len  = 0;
    bool      eof  = false;
    uint32_t  idle = 0;
    if (esp_tls_conn_new_sync(CONFIG_TINYLINK_CONTROL_HOST,
                              (int)strlen(CONFIG_TINYLINK_CONTROL_HOST),
                              port, &cfg, tls) != 1) {
        ESP_LOGE(TAG, "TLS connect to %s:%d failed",
                 CONFIG_TINYLINK_CONTROL_HOST, port);
        err = ESP_FAIL;
        goto out;
    }
    rc = tls_io_write_full(key_tls_write, tls, (const uint8_t *)req,
                           (size_t)n, KEY_MAX_IDLE_POLLS);
    if (rc != 0) {
        ESP_LOGE(TAG, "GET %s: write failed: %d", KEY_PATH, rc);
        err = ESP_FAIL;
        goto out;
    }

    while ((rc = tl_http1_parse(buf, len, eof, BODY_MAX - 1, resp)) == TL_HTTP1_MORE) {
        if (len == RESP_MAX) { rc = TL_HTTP1_ERR_TOO_LARGE; break; }
        ssize_t r = esp_tls_conn_read(tls, buf + len, RESP_MAX - len);
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (++idle >= KEY_MAX_IDLE_POLLS) {
                ESP_LOGE(TAG, "GET %s: no response within %d ms",
                         KEY_PATH, KEY_TIMEOUT_MS);
                err = ESP_ERR_TIMEOUT;
                goto out;
            }
            continue;
        }
        /* 0 = close_notify; a bare FIN counts too — every framed body is
         * length-checked by the parser, a close-delimited one by the
         * strict publicKey validation in fetch_pubkey_in. */
        if (r == 0 || r == MBEDTLS_ERR_SSL_CONN_EOF) { eof = true; continue; }
        if (r < 0) {
            ESP_LOGE(TAG, "GET %s: read failed: -0x%x", KEY_PATH, (unsigned)-r);
            err = ESP_FAIL;
            goto out;
        }
        idle = 0;
        len += (size_t)r;
    }

    /* `status` is set once the whole head parsed, so a non-200 is
     * reported as such even when its body is too big or cut short. */
    if (resp->status != 0 && resp->status != 200) {
        ESP_LOGE(TAG, "GET %s returned %d", KEY_PATH, resp->status);
        err = ESP_FAIL;
    } else if (rc == TL_HTTP1_ERR_TOO_LARGE) {
        ESP_LOGE(TAG, "GET %s: response too large (body cap %d B)",
                 KEY_PATH, BODY_MAX - 1);
        err = ESP_ERR_INVALID_SIZE;
    } else if (rc != TL_HTTP1_OK) {
        ESP_LOGE(TAG, "GET %s: malformed HTTP response (%d)", KEY_PATH, rc);
        err = ESP_ERR_INVALID_RESPONSE;
    }
out:
    esp_tls_conn_destroy(tls);
    return err;
}

static esp_err_t fetch_pubkey_in(uint8_t *buf, uint8_t out[CONTROL_KEY_LEN])
{
    tl_http1_resp_t resp;
    esp_err_t err = https_get_key(buf, &resp);
    if (err != ESP_OK) return err;

    char pub_b64_or_hex[80] = {0};
    err = json_get_string((const char *)buf + resp.body_off, resp.body_len,
                          "publicKey", pub_b64_or_hex, sizeof(pub_b64_or_hex));
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "GET %s: no usable publicKey in the response (0x%x)",
                 KEY_PATH, err);
        return err;
    }

    /* Tailscale's /key endpoint returns "mkey:<64hex>". */
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

/* The request and the response live in the shared control buffer
 * (ctrl_buf.h): this runs from tinylink_init, before any ts2021 conn. */
static esp_err_t fetch_pubkey(uint8_t out[CONTROL_KEY_LEN])
{
    uint8_t *buf = tl_ctrl_buf_claim("key");
    if (buf == NULL) return ESP_ERR_INVALID_STATE;
    esp_err_t err = fetch_pubkey_in(buf, out);
    tl_ctrl_buf_release();
    return err;
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

esp_err_t control_key_peek(uint8_t out_pub[CONTROL_KEY_LEN])
{
    if (out_pub == NULL) return ESP_ERR_INVALID_ARG;
    return load_pin(out_pub);
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
static bool s_pinned;

bool control_key_pinned(void)
{
    return s_pinned;
}

esp_err_t control_key_get(uint8_t out_pub[CONTROL_KEY_LEN])
{
    if (out_pub == NULL) return ESP_ERR_INVALID_ARG;
    s_pinned = false;

    esp_err_t err = load_pin(out_pub);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "using pinned control pub from NVS");
        s_pinned = true;
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
        err = persist(out_pub);
        s_pinned = (err == ESP_OK);   /* compiled in: as good as a pin */
        return err;
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
