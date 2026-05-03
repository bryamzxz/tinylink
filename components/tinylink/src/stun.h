// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// STUN (RFC 5389) binding client — used by magicsock to discover its
// own public-side AddrPort so it can advertise it to peers (HostInfo
// endpoints + DISCO CallMeMaybe).
//
// Wire format mirrors /home/bryam/dev/tailscale/net/stun/stun.go:
//   - Request: header(20) + SOFTWARE("tailnode", 12) + FINGERPRINT(8) = 40
//   - Response parsing prefers XOR-MAPPED-ADDRESS (RFC 5389) and falls
//     back to MAPPED-ADDRESS (RFC 3489) for legacy servers.
//
// This module is host-testable: no I/O, no platform deps. The caller
// supplies the 12-byte transaction ID (and is responsible for sourcing
// it from a CSPRNG on-target).

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STUN_TXID_LEN       12
#define STUN_HEADER_LEN     20
#define STUN_ADDR_LEN       16   /* v4-mapped if IPv4, native otherwise */

/* Header(20) + SOFTWARE attr(4 + 8 "tailnode") + FINGERPRINT(4 + 4) */
#define STUN_REQUEST_LEN    40

extern const uint8_t STUN_MAGIC_COOKIE[4];   /* {0x21, 0x12, 0xa4, 0x42} */

typedef struct {
    uint8_t  addr[STUN_ADDR_LEN]; /* v4-mapped (::ffff:a.b.c.d) when !is_v6 */
    uint16_t port;
    bool     is_v6;               /* true if the server reported native v6 */
} stun_addr_t;

/* True if buf carries the STUN magic cookie at offset 4 and the top
 * two bits of byte 0 are clear. Mirror of upstream stun.Is — does NOT
 * verify it's a success response or a binding response specifically. */
bool stun_is(const uint8_t *buf, size_t len);

/* Build a binding request into out. out must hold STUN_REQUEST_LEN
 * bytes. txid is the caller-supplied 12-byte transaction ID. Returns
 * STUN_REQUEST_LEN on success, 0 on bad arguments. */
size_t stun_build_request(uint8_t out[STUN_REQUEST_LEN],
                          const uint8_t txid[STUN_TXID_LEN]);

/* Parse a STUN binding success response. On success, copies the 12-byte
 * transaction ID into out_txid and the mapped address into *out_addr.
 * Returns 0, or a negative error code (see STUN_ERR_*). */
int stun_parse_response(const uint8_t *buf, size_t len,
                        uint8_t out_txid[STUN_TXID_LEN],
                        stun_addr_t *out_addr);

#define STUN_ERR_NOT_STUN          (-1)
#define STUN_ERR_NOT_SUCCESS       (-2)
#define STUN_ERR_MALFORMED_ATTRS   (-3)
#define STUN_ERR_NO_MAPPED_ADDR    (-4)
#define STUN_ERR_BAD_ARG           (-5)

#ifdef __cplusplus
}
#endif
