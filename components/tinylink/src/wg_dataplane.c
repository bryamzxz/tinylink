// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#ifdef ESP_PLATFORM

#include "wg_dataplane.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"

#include "esp_wireguard.h"

static const char *TAG = "wg";

static bool              s_started;
static wireguard_config_t s_cfg;
static wireguard_ctx_t   s_ctx;

/* Static backing storage for the strings the trombik config points at —
 * the library copies them into its peer struct on init, but it's
 * cleaner to keep a stable copy than to rely on lifetime. */
static char s_priv_b64[64];
static char s_pub_b64[64];
static char s_allowed_ip[16];   /* "100.64.0.7" */
static char s_allowed_mask[16]; /* "255.255.255.255" */
static char s_endpoint_host[64];

static const char b64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_encode(const uint8_t *in, size_t in_len,
                      char *out, size_t out_size)
{
    size_t needed = ((in_len + 2) / 3) * 4 + 1;
    if (needed > out_size) return -1;

    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < in_len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < in_len) v |= (uint32_t)in[i + 2];
        out[o++] = b64_alphabet[(v >> 18) & 0x3F];
        out[o++] = b64_alphabet[(v >> 12) & 0x3F];
        out[o++] = (i + 1 < in_len) ? b64_alphabet[(v >> 6) & 0x3F] : '=';
        out[o++] = (i + 2 < in_len) ? b64_alphabet[v & 0x3F]        : '=';
    }
    out[o] = '\0';
    return (int)o;
}

/* Parse "1.2.3.4/32" → host out + numeric prefix length. Caller-side
 * Tailscale CIDRs are always /32 in the v4 case (each node is a /32
 * host route), but we still parse defensively. */
static int parse_cidr(const char *cidr, char *host_out, size_t host_size,
                      int *prefix_out)
{
    const char *slash = strchr(cidr, '/');
    if (slash == NULL) return -1;
    size_t hlen = (size_t)(slash - cidr);
    if (hlen + 1 > host_size) return -1;
    memcpy(host_out, cidr, hlen);
    host_out[hlen] = '\0';
    *prefix_out = atoi(slash + 1);
    if (*prefix_out < 0 || *prefix_out > 32) return -1;
    return 0;
}

/* "ip:port" → ip out + port out. v6 was already filtered upstream. */
static int parse_endpoint(const char *ep, char *host_out, size_t host_size,
                          int *port_out)
{
    const char *colon = strchr(ep, ':');
    if (colon == NULL) return -1;
    size_t hlen = (size_t)(colon - ep);
    if (hlen + 1 > host_size) return -1;
    memcpy(host_out, ep, hlen);
    host_out[hlen] = '\0';
    *port_out = atoi(colon + 1);
    if (*port_out <= 0 || *port_out > 65535) return -1;
    return 0;
}

static void prefix_to_mask(int prefix, char *out, size_t out_size)
{
    /* Always /32 for Tailscale v4, but keep the math honest. */
    uint32_t mask = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
    snprintf(out, out_size, "%u.%u.%u.%u",
             (unsigned)((mask >> 24) & 0xFF),
             (unsigned)((mask >> 16) & 0xFF),
             (unsigned)((mask >>  8) & 0xFF),
             (unsigned)( mask        & 0xFF));
}

esp_err_t wg_dataplane_start(const tinylink_keys_t *keys,
                             const tl_netmap_t *nm)
{
    if (keys == NULL || nm == NULL) return ESP_ERR_INVALID_ARG;
    if (s_started) return ESP_ERR_INVALID_STATE;
    if (nm->n_peers == 0) {
        ESP_LOGE(TAG, "no peers in netmap — nothing to bring up");
        return ESP_ERR_INVALID_STATE;
    }
    if (nm->n_self_addresses == 0) {
        ESP_LOGE(TAG, "self has no v4 address — control plane did not assign one?");
        return ESP_ERR_INVALID_STATE;
    }
    const tl_peer_t *peer = &nm->peers[0];
    if (peer->n_endpoints == 0) {
        ESP_LOGE(TAG, "peer has no v4 endpoint — DERP-only path is M5 work");
        return ESP_ERR_NOT_SUPPORTED;
    }

    /* Encode keys (raw 32 B → 44-char base64). */
    if (b64_encode(keys->node_priv, 32, s_priv_b64, sizeof(s_priv_b64)) < 0 ||
        b64_encode(peer->node_pub,  32, s_pub_b64,  sizeof(s_pub_b64))  < 0) {
        return ESP_ERR_INVALID_SIZE;
    }

    /* Local v4 + mask. */
    int prefix = 32;
    if (parse_cidr(nm->self_addresses[0].str,
                   s_allowed_ip, sizeof(s_allowed_ip), &prefix) != 0) {
        ESP_LOGE(TAG, "self CIDR malformed: %s", nm->self_addresses[0].str);
        return ESP_ERR_INVALID_ARG;
    }
    prefix_to_mask(prefix, s_allowed_mask, sizeof(s_allowed_mask));

    /* Peer endpoint. */
    int port = 41641;
    if (parse_endpoint(peer->endpoints[0].str,
                       s_endpoint_host, sizeof(s_endpoint_host), &port) != 0) {
        ESP_LOGE(TAG, "peer endpoint malformed: %s", peer->endpoints[0].str);
        return ESP_ERR_INVALID_ARG;
    }

    s_cfg = (wireguard_config_t)ESP_WIREGUARD_CONFIG_DEFAULT();
    s_cfg.private_key     = s_priv_b64;
    s_cfg.public_key      = s_pub_b64;
    s_cfg.allowed_ip      = s_allowed_ip;
    s_cfg.allowed_ip_mask = s_allowed_mask;
    s_cfg.endpoint        = s_endpoint_host;
    s_cfg.port            = port;
    /* Tailscale's keepalive is normally driven by DISCO. Until DISCO is
     * up in M3, ask the WG layer to send a 25 s keepalive so NAT
     * mappings stay open. */
    s_cfg.persistent_keepalive = 25;

    esp_err_t err = esp_wireguard_init(&s_cfg, &s_ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_init: %s", esp_err_to_name(err));
        return err;
    }
    err = esp_wireguard_connect(&s_ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_connect: %s", esp_err_to_name(err));
        return err;
    }
    s_started = true;
    ESP_LOGI(TAG, "WG bringup: self=%s/%d peer-endpoint=%s:%d",
             s_allowed_ip, prefix, s_endpoint_host, port);
    return ESP_OK;
}

esp_err_t wg_dataplane_peer_is_up(void)
{
    if (!s_started) return ESP_ERR_INVALID_STATE;
    return esp_wireguardif_peer_is_up(&s_ctx);
}

void wg_dataplane_stop(void)
{
    if (!s_started) return;
    esp_wireguard_disconnect(&s_ctx);
    s_started = false;
}

#endif /* ESP_PLATFORM */
