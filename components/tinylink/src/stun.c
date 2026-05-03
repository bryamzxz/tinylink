// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "stun.h"

#include <string.h>

const uint8_t STUN_MAGIC_COOKIE[4] = { 0x21, 0x12, 0xa4, 0x42 };

static const uint8_t k_software[] = "tailnode";   /* 8 bytes, no padding */
#define STUN_SOFTWARE_LEN          8
#define STUN_SOFTWARE_ATTR_LEN     (4 + STUN_SOFTWARE_LEN)   /* 12 */
#define STUN_FINGERPRINT_ATTR_LEN  (4 + 4)                   /*  8 */

#define ATTR_MAPPED_ADDRESS         0x0001
#define ATTR_XOR_MAPPED_ADDRESS     0x0020
#define ATTR_XOR_MAPPED_ADDRESS_ALT 0x8020
#define ATTR_SOFTWARE               0x8022
#define ATTR_FINGERPRINT            0x8028

#define FAMILY_IPV4                 0x01
#define FAMILY_IPV6                 0x02

#define BINDING_REQUEST_HI          0x00
#define BINDING_REQUEST_LO          0x01
#define BINDING_SUCCESS_HI          0x01
#define BINDING_SUCCESS_LO          0x01

static inline void put_u16_be(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}

static inline uint16_t get_u16_be(const uint8_t *p) {
    return (uint16_t)((uint16_t)p[0] << 8 | (uint16_t)p[1]);
}

static inline void put_u32_be(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

/* Bit-by-bit IEEE CRC32 (poly 0xEDB88320). One STUN request per
 * discovery, ~36 bytes — table-driven would be wasted RAM here. */
static uint32_t crc32_ieee(const uint8_t *p, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++) {
            uint32_t mask = (uint32_t)0u - (c & 1u);
            c = (c >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~c;
}

/* RFC 5389 §15.5 fingerprint: CRC32 of all preceding bytes XOR'd
 * with the magic constant 0x5354554E ("STUN"). */
static inline uint32_t stun_fingerprint(const uint8_t *p, size_t n) {
    return crc32_ieee(p, n) ^ 0x5354554Eu;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

bool stun_is(const uint8_t *buf, size_t len)
{
    if (buf == NULL || len < STUN_HEADER_LEN) return false;
    if ((buf[0] & 0xC0u) != 0) return false;        /* top 2 bits must be zero */
    return memcmp(buf + 4, STUN_MAGIC_COOKIE, 4) == 0;
}

size_t stun_build_request(uint8_t out[STUN_REQUEST_LEN],
                          const uint8_t txid[STUN_TXID_LEN])
{
    if (out == NULL || txid == NULL) return 0;

    /* Header */
    out[0] = BINDING_REQUEST_HI;
    out[1] = BINDING_REQUEST_LO;
    put_u16_be(&out[2], STUN_SOFTWARE_ATTR_LEN + STUN_FINGERPRINT_ATTR_LEN);
    memcpy(&out[4], STUN_MAGIC_COOKIE, 4);
    memcpy(&out[8], txid, STUN_TXID_LEN);

    /* SOFTWARE attribute (RFC 5389 §15.10) */
    put_u16_be(&out[20], ATTR_SOFTWARE);
    put_u16_be(&out[22], STUN_SOFTWARE_LEN);
    memcpy(&out[24], k_software, STUN_SOFTWARE_LEN);

    /* FINGERPRINT attribute (RFC 5389 §15.5) — must be last. */
    uint32_t fp = stun_fingerprint(out, 32);
    put_u16_be(&out[32], ATTR_FINGERPRINT);
    put_u16_be(&out[34], 4);
    put_u32_be(&out[36], fp);

    return STUN_REQUEST_LEN;
}

/* Decode an XOR-MAPPED-ADDRESS attribute body. Returns 0 on success,
 * negative on malformation. addr_out is always written as 16 bytes
 * (v4-mapped form for IPv4). */
static int decode_xor_mapped(const uint8_t *attr, size_t alen,
                             const uint8_t txid[STUN_TXID_LEN],
                             stun_addr_t *out)
{
    if (alen < 4) return STUN_ERR_MALFORMED_ATTRS;

    uint8_t family = attr[1];
    uint16_t xor_port = get_u16_be(&attr[2]);
    uint16_t port = xor_port ^ 0x2112u;

    size_t addr_len;
    bool is_v6;
    if (family == FAMILY_IPV4) {
        addr_len = 4;
        is_v6 = false;
    } else if (family == FAMILY_IPV6) {
        addr_len = 16;
        is_v6 = true;
    } else {
        return STUN_ERR_MALFORMED_ATTRS;
    }
    if (alen < 4 + addr_len) return STUN_ERR_MALFORMED_ATTRS;

    uint8_t raw[16];
    for (size_t i = 0; i < addr_len; i++) {
        if (i < 4) {
            raw[i] = attr[4 + i] ^ STUN_MAGIC_COOKIE[i];
        } else {
            raw[i] = attr[4 + i] ^ txid[i - 4];
        }
    }

    memset(out->addr, 0, sizeof(out->addr));
    if (is_v6) {
        memcpy(out->addr, raw, 16);
    } else {
        /* IPv4-mapped IPv6: ::ffff:a.b.c.d */
        out->addr[10] = 0xff;
        out->addr[11] = 0xff;
        memcpy(&out->addr[12], raw, 4);
    }
    out->port  = port;
    out->is_v6 = is_v6;
    return 0;
}

/* Decode a legacy MAPPED-ADDRESS attribute body. Returns 0 on success,
 * negative on malformation. */
static int decode_mapped(const uint8_t *attr, size_t alen, stun_addr_t *out)
{
    if (alen < 4) return STUN_ERR_MALFORMED_ATTRS;

    uint8_t family = attr[1];
    uint16_t port = get_u16_be(&attr[2]);

    size_t addr_len;
    bool is_v6;
    if (family == FAMILY_IPV4) {
        addr_len = 4;
        is_v6 = false;
    } else if (family == FAMILY_IPV6) {
        addr_len = 16;
        is_v6 = true;
    } else {
        return STUN_ERR_MALFORMED_ATTRS;
    }
    if (alen < 4 + addr_len) return STUN_ERR_MALFORMED_ATTRS;

    memset(out->addr, 0, sizeof(out->addr));
    if (is_v6) {
        memcpy(out->addr, &attr[4], 16);
    } else {
        out->addr[10] = 0xff;
        out->addr[11] = 0xff;
        memcpy(&out->addr[12], &attr[4], 4);
    }
    out->port  = port;
    out->is_v6 = is_v6;
    return 0;
}

int stun_parse_response(const uint8_t *buf, size_t len,
                        uint8_t out_txid[STUN_TXID_LEN],
                        stun_addr_t *out_addr)
{
    if (buf == NULL || out_txid == NULL || out_addr == NULL) {
        return STUN_ERR_BAD_ARG;
    }
    if (!stun_is(buf, len)) return STUN_ERR_NOT_STUN;

    memcpy(out_txid, &buf[8], STUN_TXID_LEN);

    if (buf[0] != BINDING_SUCCESS_HI || buf[1] != BINDING_SUCCESS_LO) {
        return STUN_ERR_NOT_SUCCESS;
    }

    size_t attrs_len = get_u16_be(&buf[2]);
    const uint8_t *p = buf + STUN_HEADER_LEN;
    size_t rem = len - STUN_HEADER_LEN;
    if (attrs_len > rem) return STUN_ERR_MALFORMED_ATTRS;
    rem = attrs_len;   /* trim any tail bytes the same way upstream does */

    bool got_xor = false;
    bool got_mapped = false;
    stun_addr_t xor_addr = {0};
    stun_addr_t fallback = {0};

    while (rem > 0) {
        if (rem < 4) return STUN_ERR_MALFORMED_ATTRS;
        uint16_t atype = get_u16_be(p);
        uint16_t alen  = get_u16_be(p + 2);
        size_t alen_pad = ((size_t)alen + 3u) & ~(size_t)3u;
        p += 4; rem -= 4;
        if (alen_pad > rem) return STUN_ERR_MALFORMED_ATTRS;

        switch (atype) {
        case ATTR_XOR_MAPPED_ADDRESS:
        case ATTR_XOR_MAPPED_ADDRESS_ALT: {
            int rc = decode_xor_mapped(p, alen, out_txid, &xor_addr);
            if (rc == 0) got_xor = true;
            /* else: ignore malformed attr — preserves upstream behavior */
            break;
        }
        case ATTR_MAPPED_ADDRESS: {
            int rc = decode_mapped(p, alen, &fallback);
            if (rc == 0) got_mapped = true;
            break;
        }
        default:
            /* SOFTWARE, FINGERPRINT, etc. — ignored on responses. */
            break;
        }
        p += alen_pad; rem -= alen_pad;
    }

    if (got_xor) {
        *out_addr = xor_addr;
        return 0;
    }
    if (got_mapped) {
        *out_addr = fallback;
        return 0;
    }
    return STUN_ERR_NO_MAPPED_ADDR;
}
