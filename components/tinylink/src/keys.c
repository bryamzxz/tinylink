// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "keys.h"

#include <string.h>

#include "esp_log.h"
#include "nvs.h"

#include "crypto/curve25519.h"
#include "keys_regen.h"

static const char *TAG = "tl_keys";

#define NS "tl_keys"

#define KEY_MACHINE "machine"
#define KEY_NODE    "node"
#define KEY_DISCO   "disco"

typedef enum { KL_OK, KL_ABSENT, KL_ERROR } key_load_t;

/* Read one key blob and derive its public half. Returns KL_OK on a clean
 * load, KL_ABSENT when the key is missing OR corrupt (wrong size / fails
 * pub derivation) — the caller treats absent==regenerate — and KL_ERROR
 * only on a hard NVS fault, which must NOT be papered over by regenerating
 * (that would destroy a recoverable identity over a transient error). */
static key_load_t load_one(nvs_handle_t h, const char *key,
                           uint8_t priv[TINYLINK_KEY_LEN],
                           uint8_t pub[TINYLINK_KEY_LEN])
{
    size_t len = TINYLINK_KEY_LEN;
    esp_err_t err = nvs_get_blob(h, key, priv, &len);
    if (err == ESP_ERR_NVS_NOT_FOUND) return KL_ABSENT;
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_get_blob(%s) failed: 0x%x", key, err);
        return KL_ERROR;
    }
    if (len != TINYLINK_KEY_LEN) {
        ESP_LOGW(TAG, "stored %s key size %u (expected %u) — regenerating",
                 key, (unsigned)len, TINYLINK_KEY_LEN);
        return KL_ABSENT;
    }
    if (curve25519_derive_pub(pub, priv) != 0) {
        ESP_LOGW(TAG, "%s key pub-derive failed — regenerating", key);
        return KL_ABSENT;
    }
    return KL_OK;
}

static esp_err_t gen_store(nvs_handle_t h, const char *key,
                           uint8_t priv[TINYLINK_KEY_LEN],
                           uint8_t pub[TINYLINK_KEY_LEN])
{
    if (curve25519_keypair(priv, pub) != 0) return ESP_FAIL;
    esp_err_t err = nvs_set_blob(h, key, priv, TINYLINK_KEY_LEN);
    if (err != ESP_OK) ESP_LOGE(TAG, "nvs_set_blob(%s) failed: 0x%x", key, err);
    return err;
}

esp_err_t keys_load_or_generate(tinylink_keys_t *out)
{
    if (out == NULL) return ESP_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    nvs_handle_t h;
    esp_err_t err = nvs_open(NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_open(%s) failed: 0x%x", NS, err);
        return err;
    }

    key_load_t km = load_one(h, KEY_MACHINE, out->machine_priv, out->machine_pub);
    key_load_t kn = load_one(h, KEY_NODE,    out->node_priv,    out->node_pub);
    key_load_t kd = load_one(h, KEY_DISCO,   out->disco_priv,   out->disco_pub);
    if (km == KL_ERROR || kn == KL_ERROR || kd == KL_ERROR) {
        err = ESP_FAIL;
        goto done;
    }

    /* Machine + node regenerate as one unit (headscale 1:1 binding); disco
     * is independent. See keys_regen.h for the rationale. */
    keys_regen_plan_t plan = keys_plan_regen(km == KL_OK, kn == KL_OK,
                                             kd == KL_OK);
    if (plan.machine || plan.node) {
        ESP_LOGW(TAG, "machine/node identity incomplete (machine=%s node=%s)"
                 " — regenerating both as a unit",
                 km == KL_OK ? "ok" : "missing", kn == KL_OK ? "ok" : "missing");
    }

    bool dirty = false;
    if (plan.machine) {
        if ((err = gen_store(h, KEY_MACHINE,
                             out->machine_priv, out->machine_pub)) != ESP_OK) goto done;
        dirty = true;
    }
    if (plan.node) {
        if ((err = gen_store(h, KEY_NODE,
                             out->node_priv, out->node_pub)) != ESP_OK) goto done;
        dirty = true;
    }
    if (plan.disco) {
        if ((err = gen_store(h, KEY_DISCO,
                             out->disco_priv, out->disco_pub)) != ESP_OK) goto done;
        dirty = true;
    }

    if (dirty) {
        err = nvs_commit(h);
        if (err == ESP_OK) ESP_LOGI(TAG, "persisted node identity");
    }
done:
    nvs_close(h);
    return err;
}
