// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "disco_handler.h"

#include <string.h>

#ifdef ESP_PLATFORM
#include "esp_random.h"
#else
/* Host build (test_disco_handler.c provides its own deterministic
 * esp_fill_random for KAT reproducibility — same pattern as the
 * existing test_disco.c. Declare here so disco.c's transitive uses
 * also link. */
extern void esp_fill_random(void *buf, size_t len);
#endif

/* Maximum sealed-Pong inner plaintext size: 1 (type) + 1 (ver) + 12
 * (txid) + 16 (addr) + 2 (port) = 32 bytes. */
#define DISCO_PONG_PLAINTEXT_MAX 32

/* Maximum decrypted plaintext we accept from a peer. The biggest
 * legitimate inner is a CallMeMaybe with DISCO_CMM_MAX_ENDPOINTS
 * (8) entries: 1 + 1 + 8 * 18 = 146. Round up to 256 for slack. */
#define DISCO_OPEN_PLAINTEXT_MAX 256

size_t disco_handle_recv(uint8_t *out_reply, size_t out_cap,
                         const uint8_t *frame, size_t frame_len,
                         const uint8_t my_disco_priv[DISCO_KEY_LEN],
                         const uint8_t my_disco_pub[DISCO_KEY_LEN],
                         disco_msg_type_t *out_type,
                         uint8_t out_peer_disco_pub[DISCO_KEY_LEN],
                         uint8_t out_txid[DISCO_TXID_LEN])
{
    if (out_reply == NULL || frame == NULL ||
        my_disco_priv == NULL || my_disco_pub == NULL) {
        return 0;
    }
    if (out_cap < DISCO_HANDLER_REPLY_MAX) return 0;

    /* Step 1: cheap magic check — gates the AEAD work behind a 6-byte
     * memcmp so non-DISCO traffic (raw WG packets relayed via DERP)
     * doesn't burn CPU on a guaranteed-failed nacl_box_open. */
    if (!disco_looks_like(frame, frame_len)) return 0;

    /* Step 2: decrypt. The peer's DiscoKey lives in the cleartext
     * header, so disco_open extracts it for us. */
    uint8_t pt[DISCO_OPEN_PLAINTEXT_MAX];
    uint8_t peer_disco_pub[DISCO_KEY_LEN];
    size_t  pt_len = disco_open(pt, sizeof(pt), peer_disco_pub,
                                frame, frame_len, my_disco_priv);
    if (pt_len == 0) return 0;

    if (out_peer_disco_pub != NULL) {
        memcpy(out_peer_disco_pub, peer_disco_pub, DISCO_KEY_LEN);
    }

    /* Step 3: parse the inner. */
    disco_msg_t msg;
    if (disco_parse(pt, pt_len, &msg) != 0) return 0;

    if (out_type != NULL) *out_type = msg.type;

    /* Step 4: only Pings produce a reply right now. Pong matching for
     * our outbound probes lands when M3 step 3 wires up the prober;
     * CallMeMaybe handling lands with M5 step 3 magicsock fallback. */
    if (msg.type != DISCO_TYPE_PING) {
        return 0;
    }

    if (out_txid != NULL) {
        memcpy(out_txid, msg.u.ping.txid, DISCO_TXID_LEN);
    }

    /* Build the Pong inner. src_addr / src_port left zero — see
     * note in the header. The originator still accepts by TxID match. */
    disco_pong_t pong = {0};
    memcpy(pong.txid, msg.u.ping.txid, DISCO_TXID_LEN);
    /* pong.src_addr and pong.src_port stay zero. */

    uint8_t inner[DISCO_PONG_PLAINTEXT_MAX];
    size_t  inner_len = disco_encode_pong(inner, sizeof(inner), &pong);
    if (inner_len == 0) return 0;

    /* Fresh random nonce — NaCl box requires uniqueness per (sender,
     * recipient) pair; reusing one would compromise authentication. */
    uint8_t nonce[DISCO_NONCE_LEN];
    esp_fill_random(nonce, sizeof(nonce));

    /* Seal back to the same DiscoKey we just decrypted from. */
    size_t wire_len = disco_seal(out_reply, out_cap,
                                 inner, inner_len,
                                 nonce, my_disco_pub,
                                 peer_disco_pub, my_disco_priv);
    return wire_len;   /* 0 on failure, > 0 on success */
}
