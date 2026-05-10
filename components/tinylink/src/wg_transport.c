// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "wg_transport.h"

#include <stdint.h>
#include <string.h>

#include "crypto/chacha20poly1305.h"

/* --- Anti-replay window (RFC 6479) ---------------------------------- */

/* Reserved sentinel: WG never accepts UINT64_MAX as a counter (would
 * imply a counter wrap on next increment). Refuse it explicitly. */
#define WG_COUNTER_REJECT_AT  (UINT64_MAX)

int wg_replay_check_and_update(struct wg_replay_window *w, uint64_t counter)
{
    if (counter == WG_COUNTER_REJECT_AT) return -1;

    if (counter > w->highest) {
        uint64_t diff = counter - w->highest;
        if (diff >= WG_REPLAY_WINDOW_BITS) {
            /* Window jumps past its size — every position is now
             * stale, so wipe and start fresh. */
            memset(w->bitmap, 0, sizeof(w->bitmap));
        } else {
            /* Clear bits for counters (highest, counter] — these slots
             * may have been set by some old counter c - n*W and would
             * otherwise look like replays. The c == counter slot is
             * cleared here too, then set below. */
            for (uint64_t c = w->highest + 1; c <= counter; c++) {
                size_t pos = (size_t)(c & (WG_REPLAY_WINDOW_BITS - 1));
                w->bitmap[pos / 8] &= (uint8_t)~(1u << (pos % 8));
            }
        }
        size_t pos = (size_t)(counter & (WG_REPLAY_WINDOW_BITS - 1));
        w->bitmap[pos / 8] |= (uint8_t)(1u << (pos % 8));
        w->highest = counter;
        return 0;
    }

    /* counter <= highest. Reject if it fell out of the window. */
    if (counter + WG_REPLAY_WINDOW_BITS <= w->highest) {
        return -1;
    }

    size_t pos = (size_t)(counter & (WG_REPLAY_WINDOW_BITS - 1));
    if (w->bitmap[pos / 8] & (1u << (pos % 8))) {
        return -1;  /* replay */
    }
    w->bitmap[pos / 8] |= (uint8_t)(1u << (pos % 8));
    return 0;
}

/* --- Session ---------------------------------------------------------- */

void wg_transport_session_init(struct wg_transport_session *s,
                               uint32_t local_index,
                               uint32_t remote_index,
                               const uint8_t send_key[WG_KEY_LEN],
                               const uint8_t recv_key[WG_KEY_LEN])
{
    memcpy(s->send_key, send_key, WG_KEY_LEN);
    memcpy(s->recv_key, recv_key, WG_KEY_LEN);
    s->local_index   = local_index;
    s->remote_index  = remote_index;
    s->send_counter  = 0;
    memset(&s->replay, 0, sizeof(s->replay));
}

/* Build the 12-byte AEAD nonce from a 64-bit counter: 4 zero bytes
 * followed by the 8-byte LE counter (per WG whitepaper §5.4.6).
 * Xtensa LX6 + every supported host build is little-endian, so the
 * __builtin_memcpy of `counter` is byte-identical to a manual LE
 * pack — same correctness rationale as chacha20.c. */
static void counter_to_nonce(uint64_t counter,
                             uint8_t nonce[CHACHA20POLY1305_NONCE_LEN])
{
    memset(nonce, 0, 4);
    __builtin_memcpy(nonce + 4, &counter, sizeof(counter));
}

/* Wire-format header layout:
 *   off  0: u8  message_type = 4
 *   off  1: u8  reserved[3]  = 0
 *   off  4: u32 receiver_index (LE)
 *   off  8: u64 counter (LE)
 *   off 16: encrypted payload + 16-byte tag
 */
#define HDR_TYPE_OFF    0
#define HDR_RX_IDX_OFF  4
#define HDR_COUNTER_OFF 8
#define HDR_PAYLOAD_OFF 16

/* LE pack/unpack helpers. Xtensa LX6 + host builds are all little-endian,
 * so __builtin_memcpy is byte-identical to a manual LE loop and folds to
 * 1× l32i/s32i (aligned) or 4× l8ui/s8i (unaligned) — same rationale as
 * chacha20.c's U8TO32_LITTLE / U32TO8_LITTLE. */
static void store_u32_le(uint8_t out[4], uint32_t v)
{
    __builtin_memcpy(out, &v, sizeof(v));
}
static void store_u64_le(uint8_t out[8], uint64_t v)
{
    __builtin_memcpy(out, &v, sizeof(v));
}
static uint32_t load_u32_le(const uint8_t in[4])
{
    uint32_t v;
    __builtin_memcpy(&v, in, sizeof(v));
    return v;
}
static uint64_t load_u64_le(const uint8_t in[8])
{
    uint64_t v;
    __builtin_memcpy(&v, in, sizeof(v));
    return v;
}

int wg_transport_encrypt(struct wg_transport_session *s,
                         uint8_t *out, size_t out_size,
                         const uint8_t *plaintext, size_t plen)
{
    const size_t wire_len = WG_TRANSPORT_HEADER_LEN + plen + WG_TAG_LEN;
    if (out_size < wire_len) return -1;
    if (s->send_counter == WG_COUNTER_REJECT_AT) return -1;

    uint64_t counter = s->send_counter;
    s->send_counter++;

    out[HDR_TYPE_OFF]     = WG_MSG_TRANSPORT;
    out[HDR_TYPE_OFF + 1] = 0;
    out[HDR_TYPE_OFF + 2] = 0;
    out[HDR_TYPE_OFF + 3] = 0;
    store_u32_le(out + HDR_RX_IDX_OFF,  s->remote_index);
    store_u64_le(out + HDR_COUNTER_OFF, counter);

    uint8_t nonce[CHACHA20POLY1305_NONCE_LEN];
    counter_to_nonce(counter, nonce);
    chacha20poly1305_encrypt(out + HDR_PAYLOAD_OFF,
                             plaintext, plen,
                             NULL, 0,
                             s->send_key, nonce);

    memset(nonce, 0, sizeof(nonce));
    return (int)wire_len;
}

int wg_transport_decrypt(struct wg_transport_session *s,
                         const uint8_t *wire, size_t wire_len,
                         uint8_t *out, size_t out_size,
                         size_t *out_len)
{
    if (wire_len < (size_t)WG_TRANSPORT_OVERHEAD) return -1;
    if (wire[HDR_TYPE_OFF]     != WG_MSG_TRANSPORT) return -1;
    if (wire[HDR_TYPE_OFF + 1] != 0 ||
        wire[HDR_TYPE_OFF + 2] != 0 ||
        wire[HDR_TYPE_OFF + 3] != 0) return -1;
    if (load_u32_le(wire + HDR_RX_IDX_OFF) != s->local_index) return -1;

    const uint64_t counter = load_u64_le(wire + HDR_COUNTER_OFF);
    /* Replay-window check is cheap; do it before the AEAD decrypt to
     * shed obvious garbage early. The window is *tentatively* updated
     * here; on AEAD failure we don't roll it back, which means a
     * forged packet with a valid counter-not-yet-seen DOES burn that
     * slot. That matches RFC 6479's "validate replay first, drop
     * forgeries silently" model — at worst, an attacker who can spoof
     * source IP can cause us to drop one legitimate counter slot,
     * which is a 1/(window) probability of a missed real packet. */
    if (wg_replay_check_and_update(&s->replay, counter) != 0) return -1;

    const size_t cipher_len = wire_len - WG_TRANSPORT_HEADER_LEN;
    const size_t plen       = cipher_len - WG_TAG_LEN;
    if (out_size < plen) return -1;

    uint8_t nonce[CHACHA20POLY1305_NONCE_LEN];
    counter_to_nonce(counter, nonce);
    int rc = chacha20poly1305_decrypt(out,
                                      wire + HDR_PAYLOAD_OFF, cipher_len,
                                      NULL, 0,
                                      s->recv_key, nonce);
    memset(nonce, 0, sizeof(nonce));
    if (rc != 0) return -1;

    *out_len = plen;
    return 0;
}
