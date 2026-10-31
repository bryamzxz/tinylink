// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// TSMP (Tailscale Message Protocol, IPv4 proto 99) — the in-tunnel side
// channel tailscaled speaks inside WireGuard. tinylink only ever builds
// one message: the disco-key advertisement capver 144 promises. Header-
// only so the host test target can KAT it without lwIP.

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define TSMP_IP_PROTO            99
#define TSMP_TYPE_DISCO_ADVERT   'a'
#define TSMP_DISCO_KEY_LEN       32
/* 20-byte IPv4 header + 'a' + 32-byte disco key. */
#define TSMP_DISCO_ADVERT_LEN    (20 + 1 + TSMP_DISCO_KEY_LEN)

/* RFC 1071 one's-complement checksum over an IPv4 header whose checksum
 * field is zero. */
static inline uint16_t tsmp_ip4_checksum(const uint8_t *hdr, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += ((uint32_t)hdr[i] << 8) | hdr[i + 1];
    }
    while (sum >> 16) sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

/* Build a TSMPDiscoKeyAdvertisement (tailscale net/packet/tsmp.go
 * TSMPDiscoKeyAdvertisement.Marshal + ip4.go IP4Header.Marshal):
 * IHL 5, no DSCP, total length exact, IPID 0, no fragmentation, TTL 64,
 * proto 99, then 'a' + the raw 32-byte disco public key. Addresses are
 * in network byte order (as `inet_pton` returns them). The receiver
 * requires IHL 5, total length == bytes present, an inner src inside
 * the sender's AllowedIPs and a non-zero key; dst and checksum are not
 * checked, but we fill both like upstream does.
 *
 * Returns TSMP_DISCO_ADVERT_LEN, or 0 if `out_len` is too small. */
static inline size_t tsmp_build_disco_advert(uint8_t *out, size_t out_len,
                                             uint32_t src_v4_be,
                                             uint32_t dst_v4_be,
                                             const uint8_t disco_pub[TSMP_DISCO_KEY_LEN])
{
    if (out == NULL || out_len < TSMP_DISCO_ADVERT_LEN) return 0;
    memset(out, 0, 20);
    out[0] = 0x45;                               /* IPv4, IHL 5 */
    out[2] = 0;                                  /* total length (BE) */
    out[3] = TSMP_DISCO_ADVERT_LEN;
    out[8] = 64;                                 /* TTL */
    out[9] = TSMP_IP_PROTO;
    memcpy(out + 12, &src_v4_be, 4);
    memcpy(out + 16, &dst_v4_be, 4);
    const uint16_t csum = tsmp_ip4_checksum(out, 20);
    out[10] = (uint8_t)(csum >> 8);
    out[11] = (uint8_t)csum;
    out[20] = TSMP_TYPE_DISCO_ADVERT;
    memcpy(out + 21, disco_pub, TSMP_DISCO_KEY_LEN);
    return TSMP_DISCO_ADVERT_LEN;
}
