// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Tailscale DISCO v1 message codec — used for NAT-traversal endpoint
// discovery between magicsock peers (Ping/Pong) and DERP-mediated
// path-up requests (CallMeMaybe).
//
// Wire format per /home/bryam/dev/tailscale/disco/disco.go:
//
//   cleartext header:
//     magic[6]              "TS💬" = 54 53 f0 9f 92 ac
//     senderDiscoPub[32]    Curve25519 public key of the sender
//     nonce[24]             NaCl box nonce (random per message)
//
//   nacl_box-sealed payload (seal key = X25519(my_priv, peer_pub)):
//     msgType[1]            disco_msg_type_t
//     msgVersion[1]         currently always 0x00
//     ...type-specific payload...
//
// This module is host-testable: it does no I/O, owns no keys, and uses
// only the in-tree NaCl crypto wrappers (crypto/nacl_box.{c,h}).

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DISCO_MAGIC_LEN     6
#define DISCO_KEY_LEN       32
#define DISCO_NONCE_LEN     24
#define DISCO_TAG_LEN       16
#define DISCO_INNER_HDR_LEN 2   /* msgType + msgVersion */

/* Wire bytes consumed before any inner payload starts:
 * magic + senderPub + nonce + AEAD tag = 78. */
#define DISCO_OVERHEAD      (DISCO_MAGIC_LEN + DISCO_KEY_LEN + \
                             DISCO_NONCE_LEN + DISCO_TAG_LEN)

/* Smallest possible disco datagram: overhead + inner header.
 * Matches the cutoff used by wg_demux_classify. */
#define DISCO_MIN_WIRE_LEN  (DISCO_OVERHEAD + DISCO_INNER_HDR_LEN)

#define DISCO_TXID_LEN      12
#define DISCO_NODEKEY_LEN   32
#define DISCO_AP_LEN        18  /* 16-byte addr (v4-mapped if IPv4) + 2-byte port */

#define DISCO_CMM_MAX_ENDPOINTS 8

extern const uint8_t DISCO_MAGIC[DISCO_MAGIC_LEN];

typedef enum {
    DISCO_TYPE_PING        = 0x01,
    DISCO_TYPE_PONG        = 0x02,
    DISCO_TYPE_CALLMEMAYBE = 0x03,
} disco_msg_type_t;

typedef struct {
    uint8_t txid[DISCO_TXID_LEN];
    uint8_t node_key[DISCO_NODEKEY_LEN];
    bool    has_node_key;
    size_t  padding;   /* bytes of zero padding appended for PMTU probing */
} disco_ping_t;

typedef struct {
    uint8_t  txid[DISCO_TXID_LEN];
    uint8_t  src_addr[16]; /* IPv4-mapped IPv6 form if IPv4 */
    uint16_t src_port;
} disco_pong_t;

typedef struct {
    uint8_t  addr[16];
    uint16_t port;
} disco_addrport_t;

typedef struct {
    disco_addrport_t endpoints[DISCO_CMM_MAX_ENDPOINTS];
    size_t n;
} disco_call_me_maybe_t;

typedef struct {
    disco_msg_type_t type;
    uint8_t          version;
    union {
        disco_ping_t          ping;
        disco_pong_t          pong;
        disco_call_me_maybe_t cmm;
    } u;
} disco_msg_t;

/* ------------------------------------------------------------------ */
/* Inner-payload encoders. Write [msgType][msgVer][payload] into out and
 * return the byte count written, or 0 if out_cap is too small.
 * out_cap must accommodate the worst case for the message type. */
size_t disco_encode_ping(uint8_t *out, size_t out_cap,
                         const disco_ping_t *m);
size_t disco_encode_pong(uint8_t *out, size_t out_cap,
                         const disco_pong_t *m);
size_t disco_encode_call_me_maybe(uint8_t *out, size_t out_cap,
                                  const disco_call_me_maybe_t *m);

/* True if buf carries the disco magic prefix. Mirror of upstream
 * disco.LooksLikeDiscoWrapper — does NOT verify decryption. */
bool disco_looks_like(const uint8_t *buf, size_t len);

/* Seal a fully-formed inner plaintext into a wire-format disco frame.
 * out_cap must be >= DISCO_OVERHEAD + plen (= 78 + plen).
 * Returns wire length on success, 0 on failure. */
size_t disco_seal(uint8_t *out, size_t out_cap,
                  const uint8_t *plaintext, size_t plen,
                  const uint8_t nonce[DISCO_NONCE_LEN],
                  const uint8_t sender_pub[DISCO_KEY_LEN],
                  const uint8_t recipient_pub[DISCO_KEY_LEN],
                  const uint8_t my_priv[DISCO_KEY_LEN]);

/* Open a wire-format disco frame using my_priv. On success, copies the
 * sender's disco pubkey into out_sender_pub, writes the inner plaintext
 * into pt (which must hold at least ilen - DISCO_OVERHEAD bytes), and
 * returns the plaintext length. Returns 0 on bad magic, short input,
 * or AEAD auth failure. */
size_t disco_open(uint8_t *pt, size_t pt_cap,
                  uint8_t out_sender_pub[DISCO_KEY_LEN],
                  const uint8_t *in, size_t ilen,
                  const uint8_t my_priv[DISCO_KEY_LEN]);

/* Parse an already-decrypted inner payload. Returns 0 on success,
 * -1 on unknown type / short / malformed. */
int disco_parse(const uint8_t *pt, size_t plen, disco_msg_t *out);

#ifdef __cplusplus
}
#endif
