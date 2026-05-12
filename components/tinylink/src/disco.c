// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "disco.h"

#include <string.h>

#include "crypto/nacl_box.h"

const uint8_t DISCO_MAGIC[DISCO_MAGIC_LEN] = {
    0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac
};

/* ------------------------------------------------------------------ */
/* Encoders                                                           */
/* ------------------------------------------------------------------ */

static inline void put_u16_be(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}

static inline uint16_t get_u16_be(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | (uint16_t)p[1]);
}

size_t disco_encode_ping(uint8_t *out, size_t out_cap,
                         const disco_ping_t *m)
{
    if (out == NULL || m == NULL) return 0;

    size_t need = DISCO_INNER_HDR_LEN + DISCO_TXID_LEN +
                  (m->has_node_key ? DISCO_NODEKEY_LEN : 0) +
                  m->padding;
    if (out_cap < need) return 0;

    uint8_t *p = out;
    *p++ = (uint8_t)DISCO_TYPE_PING;
    *p++ = 0x00;                                     /* version */
    memcpy(p, m->txid, DISCO_TXID_LEN); p += DISCO_TXID_LEN;
    if (m->has_node_key) {
        memcpy(p, m->node_key, DISCO_NODEKEY_LEN);
        p += DISCO_NODEKEY_LEN;
    }
    if (m->padding > 0) {
        memset(p, 0, m->padding);
        p += m->padding;
    }
    return (size_t)(p - out);
}

size_t disco_encode_pong(uint8_t *out, size_t out_cap,
                         const disco_pong_t *m)
{
    if (out == NULL || m == NULL) return 0;
    const size_t need = DISCO_INNER_HDR_LEN + DISCO_TXID_LEN + 16 + 2;
    if (out_cap < need) return 0;

    uint8_t *p = out;
    *p++ = (uint8_t)DISCO_TYPE_PONG;
    *p++ = 0x00;
    memcpy(p, m->txid, DISCO_TXID_LEN); p += DISCO_TXID_LEN;
    memcpy(p, m->src_addr, 16); p += 16;
    put_u16_be(p, m->src_port); p += 2;
    return (size_t)(p - out);
}

size_t disco_encode_call_me_maybe(uint8_t *out, size_t out_cap,
                                  const disco_call_me_maybe_t *m)
{
    if (out == NULL || m == NULL) return 0;
    if (m->n > DISCO_CMM_MAX_ENDPOINTS) return 0;
    const size_t need = DISCO_INNER_HDR_LEN + DISCO_AP_LEN * m->n;
    if (out_cap < need) return 0;

    uint8_t *p = out;
    *p++ = (uint8_t)DISCO_TYPE_CALLMEMAYBE;
    *p++ = 0x00;
    for (size_t i = 0; i < m->n; i++) {
        memcpy(p, m->endpoints[i].addr, 16); p += 16;
        put_u16_be(p, m->endpoints[i].port); p += 2;
    }
    return (size_t)(p - out);
}

/* ------------------------------------------------------------------ */
/* Frame seal / open                                                  */
/* ------------------------------------------------------------------ */

bool disco_looks_like(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len < DISCO_MAGIC_LEN + DISCO_KEY_LEN + DISCO_NONCE_LEN) {
        return false;
    }
    return memcmp(buf, DISCO_MAGIC, DISCO_MAGIC_LEN) == 0;
}

size_t disco_seal(uint8_t *out, size_t out_cap,
                  const uint8_t *plaintext, size_t plen,
                  const uint8_t nonce[DISCO_NONCE_LEN],
                  const uint8_t sender_pub[DISCO_KEY_LEN],
                  const uint8_t recipient_pub[DISCO_KEY_LEN],
                  const uint8_t my_priv[DISCO_KEY_LEN])
{
    if (out == NULL || plaintext == NULL || nonce == NULL ||
        sender_pub == NULL || recipient_pub == NULL || my_priv == NULL) {
        return 0;
    }
    const size_t wire = DISCO_OVERHEAD + plen;
    if (out_cap < wire) return 0;

    uint8_t *p = out;
    memcpy(p, DISCO_MAGIC, DISCO_MAGIC_LEN);    p += DISCO_MAGIC_LEN;
    memcpy(p, sender_pub, DISCO_KEY_LEN);       p += DISCO_KEY_LEN;
    memcpy(p, nonce, DISCO_NONCE_LEN);          p += DISCO_NONCE_LEN;

    /* nacl_box writes [tag(16) || ciphertext(plen)] which is exactly
     * what the disco wire format expects after the cleartext header. */
    if (nacl_box(p, plaintext, plen, nonce, recipient_pub, my_priv) != 0) {
        return 0;
    }
    return wire;
}

size_t disco_open(uint8_t *pt, size_t pt_cap,
                  uint8_t out_sender_pub[DISCO_KEY_LEN],
                  const uint8_t *in, size_t ilen,
                  const uint8_t my_priv[DISCO_KEY_LEN])
{
    if (pt == NULL || out_sender_pub == NULL || in == NULL || my_priv == NULL) {
        return 0;
    }
    if (!disco_looks_like(in, ilen)) return 0;
    if (ilen < DISCO_OVERHEAD) return 0;
    const size_t plen = ilen - DISCO_OVERHEAD;
    if (pt_cap < plen) return 0;

    const uint8_t *sender = in + DISCO_MAGIC_LEN;
    const uint8_t *nonce  = sender + DISCO_KEY_LEN;
    const uint8_t *box    = nonce + DISCO_NONCE_LEN;   /* tag||ct, length 16+plen */
    const size_t  boxlen  = DISCO_TAG_LEN + plen;

    if (nacl_box_open(pt, box, boxlen, nonce, sender, my_priv) != 0) {
        return 0;
    }
    memcpy(out_sender_pub, sender, DISCO_KEY_LEN);
    return plen;
}

size_t disco_open_with_shared(uint8_t *pt, size_t pt_cap,
                              uint8_t out_sender_pub[DISCO_KEY_LEN],
                              const uint8_t *in, size_t ilen,
                              const uint8_t shared_k[DISCO_KEY_LEN])
{
    if (pt == NULL || out_sender_pub == NULL ||
        in == NULL || shared_k == NULL) {
        return 0;
    }
    if (!disco_looks_like(in, ilen)) return 0;
    if (ilen < DISCO_OVERHEAD) return 0;
    const size_t plen = ilen - DISCO_OVERHEAD;
    if (pt_cap < plen) return 0;

    const uint8_t *sender = in + DISCO_MAGIC_LEN;
    const uint8_t *nonce  = sender + DISCO_KEY_LEN;
    const uint8_t *box    = nonce + DISCO_NONCE_LEN;
    const size_t  boxlen  = DISCO_TAG_LEN + plen;

    if (nacl_box_open_after_shared(pt, box, boxlen, nonce, shared_k) != 0) {
        return 0;
    }
    memcpy(out_sender_pub, sender, DISCO_KEY_LEN);
    return plen;
}

/* ------------------------------------------------------------------ */
/* Parser                                                             */
/* ------------------------------------------------------------------ */

int disco_parse(const uint8_t *pt, size_t plen, disco_msg_t *out)
{
    if (pt == NULL || out == NULL) return -1;
    if (plen < DISCO_INNER_HDR_LEN) return -1;

    out->type    = (disco_msg_type_t)pt[0];
    out->version = pt[1];

    const uint8_t *p = pt + DISCO_INNER_HDR_LEN;
    size_t rem = plen - DISCO_INNER_HDR_LEN;

    switch (out->type) {
    case DISCO_TYPE_PING: {
        if (rem < DISCO_TXID_LEN) return -1;
        memset(&out->u.ping, 0, sizeof(out->u.ping));
        memcpy(out->u.ping.txid, p, DISCO_TXID_LEN);
        p += DISCO_TXID_LEN; rem -= DISCO_TXID_LEN;

        /* Upstream: "Deliberately lax on longer-than-expected messages".
         * If at least 32 bytes follow, treat them as the optional
         * NodeKey; remaining bytes count as PMTU padding. */
        if (rem >= DISCO_NODEKEY_LEN) {
            memcpy(out->u.ping.node_key, p, DISCO_NODEKEY_LEN);
            out->u.ping.has_node_key = true;
            p += DISCO_NODEKEY_LEN; rem -= DISCO_NODEKEY_LEN;
        }
        out->u.ping.padding = rem;
        return 0;
    }
    case DISCO_TYPE_PONG: {
        const size_t pong_len = DISCO_TXID_LEN + 16 + 2;
        if (rem < pong_len) return -1;
        memcpy(out->u.pong.txid, p, DISCO_TXID_LEN); p += DISCO_TXID_LEN;
        memcpy(out->u.pong.src_addr, p, 16); p += 16;
        out->u.pong.src_port = get_u16_be(p);
        return 0;
    }
    case DISCO_TYPE_CALLMEMAYBE: {
        memset(&out->u.cmm, 0, sizeof(out->u.cmm));
        /* Upstream tolerates ver != 0 by returning an empty list; we
         * mirror that behavior. */
        if (out->version != 0 || rem == 0) return 0;
        if (rem % DISCO_AP_LEN != 0) return -1;
        size_t n = rem / DISCO_AP_LEN;
        if (n > DISCO_CMM_MAX_ENDPOINTS) n = DISCO_CMM_MAX_ENDPOINTS;
        for (size_t i = 0; i < n; i++) {
            memcpy(out->u.cmm.endpoints[i].addr, p, 16); p += 16;
            out->u.cmm.endpoints[i].port = get_u16_be(p); p += 2;
        }
        out->u.cmm.n = n;
        return 0;
    }
    default:
        return -1;
    }
}
