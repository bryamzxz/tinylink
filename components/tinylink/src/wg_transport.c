// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "wg_transport.h"

#include <stdint.h>
#include <string.h>

#include "crypto/chacha20poly1305.h"
#include "crypto/secure_zero.h"

/* --- Anti-replay window (RFC 6479) ---------------------------------- */

/* Reserved sentinel: WG never accepts UINT64_MAX as a counter (would
 * imply a counter wrap on next increment). Refuse it explicitly. */
#define WG_COUNTER_REJECT_AT  (UINT64_MAX)

int wg_replay_check(const struct wg_replay_window *w, uint64_t counter)
{
    if (counter == WG_COUNTER_REJECT_AT) return -1;
    if (counter > w->highest) return 0;
    /* counter <= highest. Reject if it fell out of the window. */
    if (counter + WG_REPLAY_WINDOW_BITS <= w->highest) return -1;
    size_t pos = (size_t)(counter & (WG_REPLAY_WINDOW_BITS - 1));
    return (w->bitmap[pos / 8] & (1u << (pos % 8))) ? -1 : 0;   /* replay */
}

/* Clear the `n` (< WG_REPLAY_WINDOW_BITS) window slots starting at the
 * slot of counter `first`, wrapping around the ring. Whole bytes are
 * zeroed at once: since round 1.3.3 (C2) this runs inside the short
 * commit section under the caller's lock, and a jump of up to 8 191
 * counters used to be 8 191 single-bit clears on a 64-bit loop counter
 * (~120 k instructions, est. 0.5 ms — longer than the AEAD the split
 * takes out of the lock); now ≤ 14 bit clears + ≤ 1 023 byte stores.
 * Same result bit for bit (test_wg_transport fuzzes it against the old
 * loop). */
static void replay_clear_slots(uint8_t *bm, uint64_t first, uint32_t n)
{
    size_t pos = (size_t)(first & (WG_REPLAY_WINDOW_BITS - 1));
    while (n > 0 && (pos & 7u) != 0) {
        bm[pos / 8] &= (uint8_t)~(1u << (pos % 8));
        pos = (pos + 1) & (WG_REPLAY_WINDOW_BITS - 1);
        n--;
    }
    while (n >= 8) {
        bm[pos / 8] = 0;
        pos = (pos + 8) & (WG_REPLAY_WINDOW_BITS - 1);
        n -= 8;
    }
    while (n > 0) {
        bm[pos / 8] &= (uint8_t)~(1u << (pos % 8));
        pos = (pos + 1) & (WG_REPLAY_WINDOW_BITS - 1);
        n--;
    }
}

void wg_replay_update(struct wg_replay_window *w, uint64_t counter)
{
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
            replay_clear_slots(w->bitmap, w->highest + 1, (uint32_t)diff);
        }
        w->highest = counter;
    }
    size_t pos = (size_t)(counter & (WG_REPLAY_WINDOW_BITS - 1));
    w->bitmap[pos / 8] |= (uint8_t)(1u << (pos % 8));
}

int wg_replay_check_and_update(struct wg_replay_window *w, uint64_t counter)
{
    if (wg_replay_check(w, counter) != 0) return -1;
    wg_replay_update(w, counter);
    return 0;
}

/* --- Session ---------------------------------------------------------- */

/* Keypair generations come from one process-wide counter rather than
 * from s->gen + 1, so a session need not be zeroed before its first init
 * and a scrub followed by an init can never hand an old ticket's number
 * back (ABA). Atomic because sessions with different owners (locks) may
 * be initialized concurrently. 2^32 keypairs at one rekey per 110 s is
 * ~15 000 years. */
static uint32_t s_next_gen;

static uint32_t new_gen(void)
{
    return __atomic_add_fetch(&s_next_gen, 1u, __ATOMIC_RELAXED);
}

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
    s->gen           = new_gen();
    s->valid         = true;
    memset(&s->replay, 0, sizeof(s->replay));
}

void wg_transport_session_scrub(struct wg_transport_session *s)
{
    tl_secure_zero(s, sizeof(*s));   /* valid = false, local_index = 0 */
    s->gen = new_gen();
}

void wg_transport_ticket_scrub(void *ticket, size_t len)
{
    tl_secure_zero(ticket, len);
}

/* The 12-byte AEAD nonce: 4 zero bytes followed by the 8-byte LE
 * counter (per WG whitepaper §5.4.6). Word-typed, so building it is
 * three aligned word stores; Xtensa LX6 + every supported host build is
 * little-endian, so w[1]/w[2] are the LE counter bytes — same
 * correctness rationale as chacha20.c. It IS the counter in the packet
 * header, i.e. public: since round 1.3.2 (B21) it is no longer memset
 * after use like the key material. */
typedef union {
    uint8_t  b[CHACHA20POLY1305_NONCE_LEN];
    uint32_t w[CHACHA20POLY1305_NONCE_LEN / 4];
} wg_nonce_t;

static void counter_to_nonce(uint64_t counter, wg_nonce_t *n)
{
    n->w[0] = 0;
    n->w[1] = (uint32_t)counter;
    n->w[2] = (uint32_t)(counter >> 32);
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

/* --- TX: reserve under the lock, seal outside it (C2) ---------------- */

int wg_transport_tx_reserve(struct wg_transport_session *s,
                            struct wg_tx_ticket *t)
{
    if (!s->valid) return -1;
    if (s->send_counter == WG_COUNTER_REJECT_AT) return -1;
    t->counter      = s->send_counter++;
    t->remote_index = s->remote_index;
    memcpy(t->key, s->send_key, WG_KEY_LEN);
    return 0;
}

int wg_transport_tx_seal(struct wg_tx_ticket *t,
                         uint8_t *out, size_t out_size,
                         const uint8_t *plaintext, size_t plen)
{
    const size_t wire_len = WG_TRANSPORT_HEADER_LEN + plen + WG_TAG_LEN;
    int rc = -1;
    if (out_size >= wire_len) {
        out[HDR_TYPE_OFF]     = WG_MSG_TRANSPORT;
        out[HDR_TYPE_OFF + 1] = 0;
        out[HDR_TYPE_OFF + 2] = 0;
        out[HDR_TYPE_OFF + 3] = 0;
        store_u32_le(out + HDR_RX_IDX_OFF,  t->remote_index);
        store_u64_le(out + HDR_COUNTER_OFF, t->counter);

        wg_nonce_t nonce;
        counter_to_nonce(t->counter, &nonce);
        chacha20poly1305_encrypt(out + HDR_PAYLOAD_OFF,
                                 plaintext, plen,
                                 NULL, 0,
                                 t->key, nonce.b);
        rc = (int)wire_len;
    }
    tl_secure_zero(t->key, sizeof(t->key));
    return rc;
}

/* --- RX: begin + commit under the lock, open outside it (C2) ---------- */

int wg_transport_rx_begin(const struct wg_transport_session *s,
                          const uint8_t *wire, size_t wire_len,
                          size_t max_plen, struct wg_rx_ticket *t)
{
    if (!s->valid) return -1;
    if (wire_len < (size_t)WG_TRANSPORT_OVERHEAD) return -1;
    if (wire[HDR_TYPE_OFF]     != WG_MSG_TRANSPORT) return -1;
    if (wire[HDR_TYPE_OFF + 1] != 0 ||
        wire[HDR_TYPE_OFF + 2] != 0 ||
        wire[HDR_TYPE_OFF + 3] != 0) return -1;
    if (load_u32_le(wire + HDR_RX_IDX_OFF) != s->local_index) return -1;

    const uint64_t counter = load_u64_le(wire + HDR_COUNTER_OFF);
    /* Replay check first (cheap, sheds replays before the AEAD), but the
     * window is only UPDATED after the tag verifies — WireGuard
     * whitepaper §5.4.6 / RFC 6479 §3. Updating it before
     * authentication (as this did until round 1.3.0) let one forged
     * packet with a huge counter move `highest` past every legitimate
     * counter: all inbound transport was dropped until the next rekey,
     * repeatable at will by anyone who saw our receiver index. Since
     * 1.3.3 (C2) the AEAD runs between two lock sections, so
     * rx_commit checks again before it records the counter. */
    if (wg_replay_check(&s->replay, counter) != 0) return -1;

    const size_t plen = wire_len - WG_TRANSPORT_OVERHEAD;
    if (plen > max_plen) return -1;

    memcpy(t->key, s->recv_key, WG_KEY_LEN);
    t->counter = counter;
    t->gen     = s->gen;
    t->plen    = plen;
    return 0;
}

int wg_transport_rx_open(struct wg_rx_ticket *t,
                         const uint8_t *wire, size_t wire_len,
                         uint8_t *out)
{
    int rc = -1;
    if (wire_len == t->plen + WG_TRANSPORT_OVERHEAD) {
        /* The nonce is built from the counter rx_begin read, so a tag
         * that verifies authenticates exactly the counter rx_commit
         * records. */
        wg_nonce_t nonce;
        counter_to_nonce(t->counter, &nonce);
        rc = chacha20poly1305_decrypt(out,
                                      wire + HDR_PAYLOAD_OFF,
                                      t->plen + WG_TAG_LEN,
                                      NULL, 0,
                                      t->key, nonce.b);
    }
    tl_secure_zero(t->key, sizeof(t->key));
    return rc == 0 ? 0 : -1;
}

int wg_transport_rx_commit(struct wg_transport_session *s,
                           const struct wg_rx_ticket *t)
{
    /* Keypair first: after a rekey the window belongs to the NEW keys;
     * recording an old-key counter there would be wrong both ways. The
     * packet is dropped — the same fate as every later packet of the
     * old keypair, which rx_begin rejects on the receiver index. */
    if (!s->valid || s->gen != t->gen) return WG_TRANSPORT_RX_STALE;
    if (wg_replay_check(&s->replay, t->counter) != 0) {
        return WG_TRANSPORT_RX_REPLAY;
    }
    wg_replay_update(&s->replay, t->counter);
    return 0;
}

/* --- Single-owner wrappers ------------------------------------------- */

int wg_transport_encrypt(struct wg_transport_session *s,
                         uint8_t *out, size_t out_size,
                         const uint8_t *plaintext, size_t plen)
{
    /* Size first, so a short buffer does not burn a counter. */
    if (out_size < WG_TRANSPORT_HEADER_LEN + plen + WG_TAG_LEN) return -1;
    struct wg_tx_ticket t;
    if (wg_transport_tx_reserve(s, &t) != 0) return -1;
    return wg_transport_tx_seal(&t, out, out_size, plaintext, plen);
}

int wg_transport_decrypt(struct wg_transport_session *s,
                         const uint8_t *wire, size_t wire_len,
                         uint8_t *out, size_t out_size,
                         size_t *out_len)
{
    struct wg_rx_ticket t;
    if (wg_transport_rx_begin(s, wire, wire_len, out_size, &t) != 0) return -1;
    if (wg_transport_rx_open(&t, wire, wire_len, out) != 0) return -1;
    if (wg_transport_rx_commit(s, &t) != 0) return -1;
    *out_len = t.plen;
    return 0;
}
