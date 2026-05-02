// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "keys.h"

#include <string.h>

#include "esp_log.h"
#include "nvs.h"

#include "crypto/curve25519.h"

static const char *TAG = "tl_keys";

#define NS "tl_keys"

#define KEY_MACHINE "machine"
#define KEY_NODE    "node"
#define KEY_DISCO   "disco"

static esp_err_t load_or_generate_one(nvs_handle_t h, const char *key,
                                      uint8_t priv[TINYLINK_KEY_LEN],
                                      uint8_t pub[TINYLINK_KEY_LEN],
                                      bool *generated)
{
    size_t len = TINYLINK_KEY_LEN;
    esp_err_t err = nvs_get_blob(h, key, priv, &len);
    if (err == ESP_OK) {
        if (len != TINYLINK_KEY_LEN) {
            ESP_LOGE(TAG, "stored %s key has size %u, expected %u",
                     key, (unsigned)len, TINYLINK_KEY_LEN);
            return ESP_ERR_INVALID_SIZE;
        }
        if (curve25519_derive_pub(pub, priv) != 0) return ESP_FAIL;
        return ESP_OK;
    }
    if (err != ESP_ERR_NVS_NOT_FOUND) return err;

    /* Generate fresh keypair, persist private. */
    if (curve25519_keypair(priv, pub) != 0) return ESP_FAIL;
    err = nvs_set_blob(h, key, priv, TINYLINK_KEY_LEN);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nvs_set_blob(%s) failed: 0x%x", key, err);
        return err;
    }
    *generated = true;
    return ESP_OK;
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

    bool generated = false;
    err = load_or_generate_one(h, KEY_MACHINE,
                               out->machine_priv, out->machine_pub, &generated);
    if (err != ESP_OK) goto done;
    err = load_or_generate_one(h, KEY_NODE,
                               out->node_priv, out->node_pub, &generated);
    if (err != ESP_OK) goto done;
    err = load_or_generate_one(h, KEY_DISCO,
                               out->disco_priv, out->disco_pub, &generated);
    if (err != ESP_OK) goto done;

    if (generated) {
        err = nvs_commit(h);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "generated new node identity");
        }
    }
done:
    nvs_close(h);
    return err;
}
