// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "derp.h"

#include <string.h>

#include "crypto/nacl_box.h"

const uint8_t DERP_MAGIC[DERP_MAGIC_LEN] = {
    0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91   /* "DERP🔑" */
};

/* Fixed ClientInfo JSON for a leaf node:
 *   - version: 2 (DERP_PROTOCOL_VERSION)
 *   - CanAckPings: true (we mirror Pings as Pongs)
 *   - MeshKey omitted (we are not a mesh peer)
 *   - IsProber omitted (regular client)
 *
 * Field name casing matches upstream Go marshaling (lowercase tags
 * for meshKey/version, default-cased CanAckPings/IsProber). 31 bytes. */
static const char k_client_info_json[] =
    "{\"version\":2,\"CanAckPings\":true}";
#define K_CLIENT_INFO_JSON_LEN  (sizeof(k_client_info_json) - 1)

static inline void put_u32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static inline uint32_t get_u32_be(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

/* ------------------------------------------------------------------ */
/* Frame header                                                       */
/* ------------------------------------------------------------------ */

size_t derp_write_frame_header(uint8_t out[DERP_FRAME_HDR_LEN],
                               derp_frame_type_t type, uint32_t len)
{
    if (out == NULL) return 0;
    out[0] = (uint8_t)type;
    put_u32_be(&out[1], len);
    return DERP_FRAME_HDR_LEN;
}

int derp_read_frame_header(const uint8_t *buf, size_t buflen,
                           derp_frame_type_t *out_type,
                           uint32_t *out_len)
{
    if (buf == NULL || out_type == NULL || out_len == NULL) return -1;
    if (buflen < DERP_FRAME_HDR_LEN) return -1;
    *out_type = (derp_frame_type_t)buf[0];
    *out_len  = get_u32_be(&buf[1]);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Login handshake                                                    */
/* ------------------------------------------------------------------ */

int derp_parse_server_key(const uint8_t *payload, size_t plen,
                          uint8_t out_server_pub[DERP_KEY_LEN])
{
    if (payload == NULL || out_server_pub == NULL) return -1;
    if (plen < DERP_MAGIC_LEN + DERP_KEY_LEN) return -1;
    if (memcmp(payload, DERP_MAGIC, DERP_MAGIC_LEN) != 0) return -1;
    memcpy(out_server_pub, payload + DERP_MAGIC_LEN, DERP_KEY_LEN);
    return 0;
}

size_t derp_build_client_info(uint8_t *out, size_t out_cap,
                              const uint8_t client_pub[DERP_KEY_LEN],
                              const uint8_t client_priv[DERP_KEY_LEN],
                              const uint8_t server_pub[DERP_KEY_LEN],
                              const uint8_t nonce[DERP_NONCE_LEN])
{
    if (out == NULL || client_pub == NULL || client_priv == NULL ||
        server_pub == NULL || nonce == NULL) return 0;
    const size_t need = DERP_KEY_LEN + DERP_NONCE_LEN +
                        DERP_TAG_LEN + K_CLIENT_INFO_JSON_LEN;
    if (out_cap < need) return 0;

    uint8_t *p = out;
    memcpy(p, client_pub, DERP_KEY_LEN); p += DERP_KEY_LEN;
    memcpy(p, nonce, DERP_NONCE_LEN);    p += DERP_NONCE_LEN;

    /* nacl_box writes [tag(16) || ct(plen)] which is exactly the
     * "boxed json" the wire format expects. */
    if (nacl_box(p, (const uint8_t *)k_client_info_json,
                 K_CLIENT_INFO_JSON_LEN, nonce, server_pub,
                 client_priv) != 0) {
        return 0;
    }
    return need;
}

/* Tiny scanner: find the integer following a key in JSON. Returns
 * the parsed int or 0 if the key isn't found. Tolerates
 * key:val | key: val | key :val | key : val. Stops at first
 * non-digit. */
static int json_scan_int(const char *js, size_t jslen, const char *key)
{
    size_t klen = strlen(key);
    if (jslen < klen + 3) return 0;
    for (size_t i = 0; i + klen + 2 <= jslen; i++) {
        if (js[i] != '"') continue;
        if (memcmp(js + i + 1, key, klen) != 0) continue;
        size_t k = i + 1 + klen;
        if (k >= jslen || js[k] != '"') continue;
        k++;
        while (k < jslen && (js[k] == ' ' || js[k] == ':' || js[k] == '\t')) k++;
        if (k >= jslen) return 0;
        bool neg = false;
        if (js[k] == '-') { neg = true; k++; }
        int n = 0;
        bool any = false;
        while (k < jslen && js[k] >= '0' && js[k] <= '9') {
            n = n * 10 + (js[k] - '0');
            k++; any = true;
        }
        if (!any) return 0;
        return neg ? -n : n;
    }
    return 0;
}

int derp_parse_server_info(const uint8_t *payload, size_t plen,
                           const uint8_t client_priv[DERP_KEY_LEN],
                           const uint8_t server_pub[DERP_KEY_LEN],
                           int *out_version)
{
    if (payload == NULL || client_priv == NULL || server_pub == NULL) {
        return -1;
    }
    if (plen < DERP_NONCE_LEN + DERP_TAG_LEN) return -1;

    const uint8_t *nonce = payload;
    const uint8_t *box   = payload + DERP_NONCE_LEN;
    const size_t  boxlen = plen - DERP_NONCE_LEN;
    const size_t  ptlen  = boxlen - DERP_TAG_LEN;

    /* Server info JSON observed at <= 100 bytes upstream. 256 leaves
     * headroom for added fields. Anything bigger gets truncated and
     * fails the AEAD verify. */
    uint8_t pt[256];
    if (ptlen > sizeof(pt)) return -1;

    if (nacl_box_open(pt, box, boxlen, nonce, server_pub,
                      client_priv) != 0) {
        return -1;
    }
    if (out_version != NULL) {
        *out_version = json_scan_int((const char *)pt, ptlen, "version");
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Packet relay                                                       */
/* ------------------------------------------------------------------ */

size_t derp_build_send_packet(uint8_t *out, size_t out_cap,
                              const uint8_t dst_pub[DERP_KEY_LEN],
                              const uint8_t *packet, size_t plen)
{
    if (out == NULL || dst_pub == NULL) return 0;
    if (plen > 0 && packet == NULL) return 0;
    if (plen > DERP_MAX_PACKET) return 0;
    const size_t need = DERP_KEY_LEN + plen;
    if (out_cap < need) return 0;

    memcpy(out, dst_pub, DERP_KEY_LEN);
    if (plen > 0) memcpy(out + DERP_KEY_LEN, packet, plen);
    return need;
}

int derp_parse_recv_packet(const uint8_t *payload, size_t plen,
                           uint8_t out_src_pub[DERP_KEY_LEN],
                           const uint8_t **out_packet, size_t *out_len)
{
    if (payload == NULL || out_src_pub == NULL ||
        out_packet == NULL || out_len == NULL) return -1;
    if (plen < DERP_KEY_LEN) return -1;

    memcpy(out_src_pub, payload, DERP_KEY_LEN);
    *out_packet = payload + DERP_KEY_LEN;
    *out_len    = plen - DERP_KEY_LEN;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Liveness & control                                                 */
/* ------------------------------------------------------------------ */

int derp_parse_ping_or_pong(const uint8_t *payload, size_t plen,
                            uint8_t out_data[DERP_PING_LEN])
{
    if (payload == NULL || out_data == NULL) return -1;
    if (plen < DERP_PING_LEN) return -1;
    memcpy(out_data, payload, DERP_PING_LEN);
    return 0;
}

size_t derp_build_note_preferred(uint8_t out[1], bool is_home)
{
    if (out == NULL) return 0;
    out[0] = is_home ? 0x01 : 0x00;
    return 1;
}

int derp_parse_peer_gone(const uint8_t *payload, size_t plen,
                         uint8_t out_peer_pub[DERP_KEY_LEN],
                         uint8_t *out_reason)
{
    if (payload == NULL || out_peer_pub == NULL || out_reason == NULL) {
        return -1;
    }
    if (plen < DERP_KEY_LEN) return -1;
    memcpy(out_peer_pub, payload, DERP_KEY_LEN);
    /* Older servers omit the reason byte. Default per upstream:
     * controlclient.PeerGoneReasonDisconnected = 0x00. */
    *out_reason = (plen > DERP_KEY_LEN)
                  ? payload[DERP_KEY_LEN]
                  : (uint8_t)DERP_PEER_GONE_DISCONNECTED;
    return 0;
}

int derp_parse_restarting(const uint8_t *payload, size_t plen,
                          uint32_t *out_reconnect_ms,
                          uint32_t *out_total_ms)
{
    if (payload == NULL || out_reconnect_ms == NULL || out_total_ms == NULL) {
        return -1;
    }
    if (plen < 8) return -1;
    *out_reconnect_ms = get_u32_be(payload);
    *out_total_ms     = get_u32_be(payload + 4);
    return 0;
}
