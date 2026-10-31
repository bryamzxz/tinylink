/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for WG transport (data-plane) encrypt / decrypt and the
 * RFC 6479 anti-replay window. Both halves of session keys are
 * exercised in roundtrip; the replay window is poked directly.
 *
 * Round 1.3.3 (C2): the split API wg_netif runs with its lock held only
 * around tx_reserve / rx_begin / rx_commit. The interleavings that
 * matter on the dual-core target are replayed here step by step (two
 * copies of one packet in flight, a rekey or a scrub between begin and
 * commit, a window that moved past the packet), plus a pthread stress
 * of the exact lock protocol: two RX threads on the same packets (the
 * DERP + direct copies) and two TX producers, each against a rekeying
 * thread, with the races forced at rendezvous points so they happen on
 * any number of CPUs (and under TSan). The byte-wise window update is
 * fuzzed against the old bit-by-bit loop.
 */

#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "wg_proto.h"
#include "wg_transport.h"

#include "crypto/chacha20poly1305.h"

static int fails = 0;

static int check_eq_int(const char *name, int got, int want) {
    if (got == want) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL: %d != %d\n", name, got, want);
    return 1;
}


/* --- Replay window ---------------------------------------------------- */

static void test_replay_window(void) {
    struct wg_replay_window w;
    memset(&w, 0, sizeof(w));

    /* Initial state: counter 0 accepted. */
    fails += check_eq_int("replay/c=0-first", wg_replay_check_and_update(&w, 0), 0);
    /* Replay of 0: rejected. */
    fails += check_eq_int("replay/c=0-replay", wg_replay_check_and_update(&w, 0), -1);

    /* Counters 1..5 in order. */
    for (int i = 1; i <= 5; i++) {
        char nm[32]; snprintf(nm, sizeof(nm), "replay/c=%d-fwd", i);
        fails += check_eq_int(nm, wg_replay_check_and_update(&w, i), 0);
    }
    /* Replay of 3. */
    fails += check_eq_int("replay/c=3-replay", wg_replay_check_and_update(&w, 3), -1);

    /* Out-of-order delivery within window: jump to 100, then accept 50. */
    fails += check_eq_int("replay/c=100-jump", wg_replay_check_and_update(&w, 100), 0);
    fails += check_eq_int("replay/c=50-late",  wg_replay_check_and_update(&w, 50), 0);
    fails += check_eq_int("replay/c=50-replay", wg_replay_check_and_update(&w, 50), -1);

    /* Big jump that wipes the window. */
    fails += check_eq_int("replay/c=20000-jump", wg_replay_check_and_update(&w, 20000), 0);
    /* Counter 100 is now far older than the window — rejected as too old. */
    fails += check_eq_int("replay/c=100-too-old",
                          wg_replay_check_and_update(&w, 100), -1);
    /* But counter 19999 (one back from highest) is in window and unseen. */
    fails += check_eq_int("replay/c=19999-in-window",
                          wg_replay_check_and_update(&w, 19999), 0);

    /* Counter UINT64_MAX always rejected. */
    fails += check_eq_int("replay/c=uint64max",
                          wg_replay_check_and_update(&w, UINT64_MAX), -1);

    /* After replay-window jump from 19999 to 20000, both should be set;
     * a fresh slot in window is still acceptable. */
    fails += check_eq_int("replay/c=20001-fwd",
                          wg_replay_check_and_update(&w, 20001), 0);
}

/* --- Roundtrip ------------------------------------------------------- */

static void test_roundtrip(void) {
    /* Two separate sessions wired together by hand; in real use the
     * keys come from the handshake's transport-key split (init.send ==
     * resp.recv crossed). */
    uint8_t send_key[32], recv_key[32];
    for (int i = 0; i < 32; i++) {
        send_key[i] = (uint8_t)(i * 7 + 1);
        recv_key[i] = (uint8_t)(i * 11 + 3);
    }
    /* Initiator-side session: sends with send_key, expects recv_key. */
    struct wg_transport_session ist;
    wg_transport_session_init(&ist, /*local*/0xAA000001, /*remote*/0xBB000002,
                              send_key, recv_key);
    /* Responder-side session: keys crossed. */
    struct wg_transport_session rst;
    wg_transport_session_init(&rst, /*local*/0xBB000002, /*remote*/0xAA000001,
                              recv_key, send_key);

    /* Encrypt 100 packets initiator → responder, decrypt on the other side. */
    for (int i = 0; i < 100; i++) {
        uint8_t plaintext[64];
        for (int j = 0; j < 64; j++) plaintext[j] = (uint8_t)(i * 31 + j);

        uint8_t wire[64 + WG_TRANSPORT_OVERHEAD];
        int wlen = wg_transport_encrypt(&ist, wire, sizeof(wire), plaintext, 64);
        if (wlen != (int)(64 + WG_TRANSPORT_OVERHEAD)) {
            printf("[rt/encrypt-len-i=%d] FAIL: %d\n", i, wlen); fails++; return;
        }

        uint8_t out_pt[64];
        size_t  out_len = 0;
        int rc = wg_transport_decrypt(&rst, wire, (size_t)wlen,
                                      out_pt, sizeof(out_pt), &out_len);
        if (rc != 0 || out_len != 64) {
            printf("[rt/decrypt-i=%d] FAIL: rc=%d out_len=%zu\n", i, rc, out_len);
            fails++; return;
        }
        if (memcmp(out_pt, plaintext, 64) != 0) {
            printf("[rt/plaintext-i=%d] FAIL\n", i); fails++; return;
        }
    }
    printf("[rt/100-packets-init-to-resp] OK\n");

    /* Counter is monotonic: ist.send_counter advanced by 100. */
    fails += check_eq_int("rt/send-counter-after-100",
                          (int)ist.send_counter, 100);

    /* Send a reply responder → initiator using rst.send_key (which is
     * recv_key from initiator's POV). */
    uint8_t reply_pt[8] = {1,2,3,4,5,6,7,8};
    uint8_t reply_wire[8 + WG_TRANSPORT_OVERHEAD];
    int wlen = wg_transport_encrypt(&rst, reply_wire, sizeof(reply_wire),
                                    reply_pt, 8);
    if (wlen <= 0) { printf("[rt/reply-encrypt] FAIL\n"); fails++; return; }

    uint8_t recovered[8];
    size_t rlen;
    int rc = wg_transport_decrypt(&ist, reply_wire, (size_t)wlen,
                                  recovered, sizeof(recovered), &rlen);
    if (rc != 0 || rlen != 8 ||
        memcmp(recovered, reply_pt, 8) != 0) {
        printf("[rt/reply-decrypt] FAIL\n"); fails++; return;
    }
    printf("[rt/reply-roundtrip] OK\n");

    /* Replay of the very first packet (already consumed by rst) → rejected. */
    /* We need to re-encrypt at counter=0, but our send_counter has
     * advanced. Instead, build a fresh session pair and replay. */
    struct wg_transport_session ist2;
    wg_transport_session_init(&ist2, 0xAA000001, 0xBB000002, send_key, recv_key);
    struct wg_transport_session rst2;
    wg_transport_session_init(&rst2, 0xBB000002, 0xAA000001, recv_key, send_key);

    uint8_t pt[16] = {0xAB};
    uint8_t w1[16 + WG_TRANSPORT_OVERHEAD];
    wlen = wg_transport_encrypt(&ist2, w1, sizeof(w1), pt, 16);
    uint8_t out1[16]; size_t l1 = 0;
    rc = wg_transport_decrypt(&rst2, w1, (size_t)wlen, out1, sizeof(out1), &l1);
    fails += check_eq_int("rt/replay-first-accepted", rc, 0);
    /* Same wire bytes, second time: replay. */
    rc = wg_transport_decrypt(&rst2, w1, (size_t)wlen, out1, sizeof(out1), &l1);
    fails += check_eq_int("rt/replay-rejected", rc, -1);
}

/* --- Tamper / mismatch checks --------------------------------------- */

static void test_negative_paths(void) {
    uint8_t send_key[32], recv_key[32];
    for (int i = 0; i < 32; i++) {
        send_key[i] = (uint8_t)(i * 5 + 7);
        recv_key[i] = (uint8_t)(i * 13 + 2);
    }
    struct wg_transport_session ist, rst;
    wg_transport_session_init(&ist, 0x11111111, 0x22222222, send_key, recv_key);
    wg_transport_session_init(&rst, 0x22222222, 0x11111111, recv_key, send_key);

    uint8_t pt[32]; for (int i = 0; i < 32; i++) pt[i] = (uint8_t)i;
    uint8_t wire[32 + WG_TRANSPORT_OVERHEAD];
    int wlen = wg_transport_encrypt(&ist, wire, sizeof(wire), pt, 32);
    if (wlen <= 0) { printf("[neg/encrypt] FAIL\n"); fails++; return; }

    /* Tamper: flip a bit in the AEAD ciphertext. */
    {
        uint8_t bad[sizeof(wire)];
        memcpy(bad, wire, (size_t)wlen);
        bad[WG_TRANSPORT_HEADER_LEN] ^= 0x01;

        struct wg_transport_session rst_tmp;
        wg_transport_session_init(&rst_tmp, 0x22222222, 0x11111111,
                                  recv_key, send_key);
        uint8_t out[32]; size_t ol = 0;
        int rc = wg_transport_decrypt(&rst_tmp, bad, (size_t)wlen,
                                      out, sizeof(out), &ol);
        fails += check_eq_int("neg/tamper-ct", rc, -1);
    }

    /* Tamper: flip a bit in the tag. */
    {
        uint8_t bad[sizeof(wire)];
        memcpy(bad, wire, (size_t)wlen);
        bad[wlen - 1] ^= 0x01;

        struct wg_transport_session rst_tmp;
        wg_transport_session_init(&rst_tmp, 0x22222222, 0x11111111,
                                  recv_key, send_key);
        uint8_t out[32]; size_t ol = 0;
        int rc = wg_transport_decrypt(&rst_tmp, bad, (size_t)wlen,
                                      out, sizeof(out), &ol);
        fails += check_eq_int("neg/tamper-tag", rc, -1);
    }

    /* Forged packet with a huge counter (bad tag) must NOT move the
     * replay window: the next legitimate packet still decrypts. Until
     * round 1.3.0 the window was updated before the AEAD and this
     * forgery blocked all inbound traffic until the next rekey. */
    {
        struct wg_transport_session rst_tmp;
        wg_transport_session_init(&rst_tmp, 0x22222222, 0x11111111,
                                  recv_key, send_key);
        uint8_t forged[sizeof(wire)];
        memcpy(forged, wire, (size_t)wlen);
        const uint64_t big = 1000000;      /* far past the 8192-bit window */
        memcpy(forged + 8, &big, sizeof(big));
        uint8_t out[32]; size_t ol = 0;
        int rc = wg_transport_decrypt(&rst_tmp, forged, (size_t)wlen,
                                      out, sizeof(out), &ol);
        fails += check_eq_int("neg/forged-high-counter-rejected", rc, -1);
        fails += check_eq_int("neg/forged-window-untouched",
                              (int)(rst_tmp.replay.highest == 0), 1);
        rc = wg_transport_decrypt(&rst_tmp, wire, (size_t)wlen,
                                  out, sizeof(out), &ol);
        fails += check_eq_int("neg/legit-after-forgery-accepted", rc, 0);
        rc = wg_transport_decrypt(&rst_tmp, wire, (size_t)wlen,
                                  out, sizeof(out), &ol);
        fails += check_eq_int("neg/legit-replay-still-rejected", rc, -1);
    }

    /* Wrong receiver_index → reject before crypto. */
    {
        uint8_t bad[sizeof(wire)];
        memcpy(bad, wire, (size_t)wlen);
        bad[4] ^= 0xFF;  /* clobber receiver_index byte */
        struct wg_transport_session rst_tmp;
        wg_transport_session_init(&rst_tmp, 0x22222222, 0x11111111,
                                  recv_key, send_key);
        uint8_t out[32]; size_t ol = 0;
        int rc = wg_transport_decrypt(&rst_tmp, bad, (size_t)wlen,
                                      out, sizeof(out), &ol);
        fails += check_eq_int("neg/wrong-receiver-idx", rc, -1);
    }

    /* Wrong message_type. */
    {
        uint8_t bad[sizeof(wire)];
        memcpy(bad, wire, (size_t)wlen);
        bad[0] = WG_MSG_INITIATION;
        struct wg_transport_session rst_tmp;
        wg_transport_session_init(&rst_tmp, 0x22222222, 0x11111111,
                                  recv_key, send_key);
        uint8_t out[32]; size_t ol = 0;
        int rc = wg_transport_decrypt(&rst_tmp, bad, (size_t)wlen,
                                      out, sizeof(out), &ol);
        fails += check_eq_int("neg/wrong-msg-type", rc, -1);
    }

    /* Reserved bytes nonzero. */
    {
        uint8_t bad[sizeof(wire)];
        memcpy(bad, wire, (size_t)wlen);
        bad[1] = 0xFF;
        struct wg_transport_session rst_tmp;
        wg_transport_session_init(&rst_tmp, 0x22222222, 0x11111111,
                                  recv_key, send_key);
        uint8_t out[32]; size_t ol = 0;
        int rc = wg_transport_decrypt(&rst_tmp, bad, (size_t)wlen,
                                      out, sizeof(out), &ol);
        fails += check_eq_int("neg/reserved-nonzero", rc, -1);
    }

    /* Truncated wire (less than overhead). */
    {
        uint8_t out[32]; size_t ol = 0;
        struct wg_transport_session rst_tmp;
        wg_transport_session_init(&rst_tmp, 0x22222222, 0x11111111,
                                  recv_key, send_key);
        int rc = wg_transport_decrypt(&rst_tmp, wire, 4,
                                      out, sizeof(out), &ol);
        fails += check_eq_int("neg/truncated", rc, -1);
    }
}

/* Wire layout against the AEAD called directly with the whitepaper's
 * nonce (§5.4.6: 4 zero bytes || LE64 counter), for counters on both
 * sides of 2^32 — pins the word-built nonce of round 1.3.2 (B21), which
 * a self-roundtrip could not tell from a wrong but symmetric one. */
static void test_nonce_layout(void) {
    static const uint64_t counters[] = { 0, 1, 0xFFFFFFFFull, 0x123456789ull,
                                         0xFFFFFFFFFFFFFFFEull };
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0xA0 + i);
    uint8_t pt[64];
    for (int i = 0; i < 64; i++) pt[i] = (uint8_t)(i * 7);
    for (unsigned c = 0; c < sizeof(counters) / sizeof(counters[0]); c++) {
        struct wg_transport_session s;
        wg_transport_session_init(&s, 0x11111111u, 0x22222222u, key, key);
        s.send_counter = counters[c];
        uint8_t wire[16 + 64 + 16];
        int n = wg_transport_encrypt(&s, wire, sizeof(wire), pt, sizeof(pt));
        uint8_t nonce[CHACHA20POLY1305_NONCE_LEN] = {0};
        for (int b = 0; b < 8; b++) nonce[4 + b] = (uint8_t)(counters[c] >> (8 * b));
        uint8_t want[64 + 16];
        chacha20poly1305_encrypt(want, pt, sizeof(pt), NULL, 0, key, nonce);
        char name[64];
        snprintf(name, sizeof(name), "nonce/layout-%u", c);
        const int same = n == (int)sizeof(wire) &&
                         memcmp(wire + 16, want, sizeof(want)) == 0;
        fails += check_eq_int(name, same, 1);
        /* And the receive side takes it back. */
        uint8_t out[64];
        size_t olen = 0;
        struct wg_transport_session r;
        wg_transport_session_init(&r, 0x22222222u, 0x11111111u, key, key);
        snprintf(name, sizeof(name), "nonce/decrypt-%u", c);
        fails += check_eq_int(name, wg_transport_decrypt(&r, wire, sizeof(wire),
                                                         out, sizeof(out), &olen) == 0 &&
                                    olen == sizeof(pt) && memcmp(out, pt, olen) == 0, 1);
    }
}

/* --- C2: byte-wise window update vs the pre-1.3.3 loop -------------- */

/* The window update exactly as it was until 1.3.2 (bit-by-bit clear). */
static void ref_replay_update(struct wg_replay_window *w, uint64_t counter) {
    if (counter > w->highest) {
        uint64_t diff = counter - w->highest;
        if (diff >= WG_REPLAY_WINDOW_BITS) {
            memset(w->bitmap, 0, sizeof(w->bitmap));
        } else {
            for (uint64_t c = w->highest + 1; c <= counter; c++) {
                size_t pos = (size_t)(c & (WG_REPLAY_WINDOW_BITS - 1));
                w->bitmap[pos / 8] &= (uint8_t)~(1u << (pos % 8));
            }
        }
        w->highest = counter;
    }
    size_t pos = (size_t)(counter & (WG_REPLAY_WINDOW_BITS - 1));
    w->bitmap[pos / 8] |= (uint8_t)(1u << (pos % 8));
}

static uint64_t rng_state = 0x9E3779B97F4A7C15ull;
static uint64_t rng(void) {   /* xorshift64*: deterministic, no libc rand */
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 0x2545F4914F6CDD1Dull;
}

static void test_replay_update_fuzz(void) {
    static struct wg_replay_window a, b;
    int same_verdict = 1, same_state = 1;
    for (int run = 0; run < 40; run++) {
        memset(&a, 0, sizeof(a));
        memset(&b, 0, sizeof(b));
        uint64_t base = (run & 1) ? 0 : (rng() >> 8);   /* also far from 0 */
        a.highest = b.highest = base;
        for (int op = 0; op < 4000; op++) {
            /* Mostly small steps (the normal case), some jumps of every
             * size up to past the window, some late / replayed ones. */
            const uint64_t r = rng();
            uint64_t c;
            switch (r & 7) {
            case 0: case 1: case 2: c = a.highest + 1 + (r >> 60); break;
            case 3: c = a.highest + 1 + ((r >> 16) % 9000); break;
            case 4: c = a.highest + ((r >> 16) % 64); break;
            case 5: c = a.highest - ((r >> 16) % 8300); break;
            case 6: c = a.highest - ((r >> 16) % 16); break;
            default: c = a.highest + 8185 + ((r >> 16) % 16); break;
            }
            const int va = wg_replay_check(&a, c);
            const int vb = wg_replay_check(&b, c);
            if (va != vb) same_verdict = 0;
            if (va == 0) {
                wg_replay_update(&a, c);
                ref_replay_update(&b, c);
                if (a.highest != b.highest ||
                    memcmp(a.bitmap, b.bitmap, sizeof(a.bitmap)) != 0) {
                    same_state = 0;
                }
            }
        }
    }
    fails += check_eq_int("c2/replay-update-fuzz-verdicts", same_verdict, 1);
    fails += check_eq_int("c2/replay-update-fuzz-window", same_state, 1);

    /* Every jump length 1..8192 from every bit offset of a byte, on a
     * fully set window: exactly the slots (h, c] end up clear but c. */
    int exact = 1;
    for (uint64_t off = 0; off < 8 && exact; off++) {
        for (uint64_t d = 1; d <= WG_REPLAY_WINDOW_BITS && exact; d += (d < 64 ? 1 : 61)) {
            memset(&a, 0xFF, sizeof(a.bitmap));
            memset(&b, 0xFF, sizeof(b.bitmap));
            a.highest = b.highest = 100000 + off;
            wg_replay_update(&a, a.highest + d);
            ref_replay_update(&b, b.highest + d);
            exact = memcmp(a.bitmap, b.bitmap, sizeof(a.bitmap)) == 0 &&
                    a.highest == b.highest;
        }
    }
    fails += check_eq_int("c2/replay-update-every-jump", exact, 1);
}

/* --- C2: split RX / TX, interleavings replayed step by step ------------ */

static void c2_keys(int e, uint8_t k[32]) {
    for (int i = 0; i < 32; i++) k[i] = (uint8_t)(e * 37 + i * 3 + 1);
}

/* Sender + receiver session pair for "epoch" e (receiver = our side). */
static void c2_pair(int e, struct wg_transport_session *tx,
                    struct wg_transport_session *rx) {
    uint8_t k[32];
    c2_keys(e, k);
    const uint32_t idx = 0x5100A000u + (uint32_t)e;
    if (tx) wg_transport_session_init(tx, 0x77000000u, idx, k, k);
    if (rx) wg_transport_session_init(rx, idx, 0x77000000u, k, k);
}

static int all_zero(const uint8_t *p, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

static void test_split_rx(void) {
    struct wg_transport_session tx, rx;
    c2_pair(1, &tx, &rx);
    uint8_t pt[40], wire[40 + WG_TRANSPORT_OVERHEAD], out[40];
    for (int i = 0; i < 40; i++) pt[i] = (uint8_t)(i ^ 0x5A);
    int n = wg_transport_encrypt(&tx, wire, sizeof(wire), pt, sizeof(pt));
    fails += check_eq_int("c2/rx-encrypt", n, (int)sizeof(wire));

    /* Two copies of one packet in flight at once (direct + DERP during
     * the dual send): both pass begin, both open, only one commits. */
    struct wg_rx_ticket t1, t2;
    fails += check_eq_int("c2/dup-begin-1", wg_transport_rx_begin(&rx, wire, n, sizeof(out), &t1), 0);
    fails += check_eq_int("c2/dup-begin-2", wg_transport_rx_begin(&rx, wire, n, sizeof(out), &t2), 0);
    fails += check_eq_int("c2/dup-open-1", wg_transport_rx_open(&t1, wire, n, out), 0);
    fails += check_eq_int("c2/dup-open-2", wg_transport_rx_open(&t2, wire, n, out), 0);
    fails += check_eq_int("c2/dup-plaintext", memcmp(out, pt, sizeof(pt)), 0);
    fails += check_eq_int("c2/dup-commit-1", wg_transport_rx_commit(&rx, &t1), 0);
    fails += check_eq_int("c2/dup-commit-2-replay", wg_transport_rx_commit(&rx, &t2),
                          WG_TRANSPORT_RX_REPLAY);
    /* ...and a third copy that arrives later is shed before the AEAD. */
    fails += check_eq_int("c2/dup-late-begin-rejected",
                          wg_transport_rx_begin(&rx, wire, n, sizeof(out), &t1), -1);
    fails += check_eq_int("c2/ticket-key-scrubbed-after-open",
                          all_zero(t2.key, sizeof(t2.key)), 1);

    /* A failed open scrubs too, and leaves out untouched. */
    n = wg_transport_encrypt(&tx, wire, sizeof(wire), pt, sizeof(pt));
    fails += check_eq_int("c2/badtag-begin", wg_transport_rx_begin(&rx, wire, n, sizeof(out), &t1), 0);
    wire[n - 1] ^= 1;
    memset(out, 0xEE, sizeof(out));
    fails += check_eq_int("c2/badtag-open", wg_transport_rx_open(&t1, wire, n, out), -1);
    fails += check_eq_int("c2/badtag-key-scrubbed", all_zero(t1.key, sizeof(t1.key)), 1);
    int untouched = 1;
    for (size_t i = 0; i < sizeof(out); i++) untouched &= out[i] == 0xEE;
    fails += check_eq_int("c2/badtag-out-untouched", untouched, 1);
    wire[n - 1] ^= 1;
    /* The forgery moved nothing: the genuine packet still goes through. */
    size_t ol = 0;
    fails += check_eq_int("c2/badtag-then-genuine",
                          wg_transport_decrypt(&rx, wire, n, out, sizeof(out), &ol), 0);

    /* open() needs the wire length begin saw. */
    n = wg_transport_encrypt(&tx, wire, sizeof(wire), pt, sizeof(pt));
    fails += check_eq_int("c2/len-begin", wg_transport_rx_begin(&rx, wire, n, sizeof(out), &t1), 0);
    fails += check_eq_int("c2/len-mismatch-open", wg_transport_rx_open(&t1, wire, n - 1, out), -1);
    fails += check_eq_int("c2/len-mismatch-scrubbed", all_zero(t1.key, sizeof(t1.key)), 1);

    /* max_plen bounds the allocation before any crypto. */
    fails += check_eq_int("c2/max-plen-short", wg_transport_rx_begin(&rx, wire, n, sizeof(pt) - 1, &t1), -1);
    fails += check_eq_int("c2/max-plen-exact", wg_transport_rx_begin(&rx, wire, n, sizeof(pt), &t1), 0);
    wg_transport_ticket_scrub(&t1, sizeof(t1));
    fails += check_eq_int("c2/ticket-scrub", all_zero(t1.key, sizeof(t1.key)), 1);

    /* The window moved past the packet while it was being opened. */
    n = wg_transport_encrypt(&tx, wire, sizeof(wire), pt, sizeof(pt));
    fails += check_eq_int("c2/old-begin", wg_transport_rx_begin(&rx, wire, n, sizeof(out), &t1), 0);
    tx.send_counter += WG_REPLAY_WINDOW_BITS + 5;
    uint8_t wire2[sizeof(wire)];
    int n2 = wg_transport_encrypt(&tx, wire2, sizeof(wire2), pt, sizeof(pt));
    fails += check_eq_int("c2/old-newer-accepted",
                          wg_transport_decrypt(&rx, wire2, n2, out, sizeof(out), &ol), 0);
    fails += check_eq_int("c2/old-open", wg_transport_rx_open(&t1, wire, n, out), 0);
    fails += check_eq_int("c2/old-commit-too-old", wg_transport_rx_commit(&rx, &t1),
                          WG_TRANSPORT_RX_REPLAY);

    /* Zero-length keepalive: out may be NULL. */
    n = wg_transport_encrypt(&tx, wire, sizeof(wire), NULL, 0);
    fails += check_eq_int("c2/keepalive-begin", wg_transport_rx_begin(&rx, wire, n, 0, &t1), 0);
    fails += check_eq_int("c2/keepalive-plen", (int)t1.plen, 0);
    fails += check_eq_int("c2/keepalive-open-null", wg_transport_rx_open(&t1, wire, n, NULL), 0);
    fails += check_eq_int("c2/keepalive-commit", wg_transport_rx_commit(&rx, &t1), 0);
}

static void test_split_rekey_scrub(void) {
    struct wg_transport_session tx, rx;
    uint8_t pt[24] = {1, 2, 3}, wire[24 + WG_TRANSPORT_OVERHEAD], out[24];
    struct wg_rx_ticket t;

    /* Rekey between begin and commit. The open still works — it runs on
     * the ticket's key copy, not on the session bytes the rekey just
     * overwrote — but the commit refuses the old keypair. The new
     * session is installed with the SAME receiver index and keys, so
     * only the generation can tell the two apart. */
    c2_pair(2, &tx, &rx);
    int n = wg_transport_encrypt(&tx, wire, sizeof(wire), pt, sizeof(pt));
    fails += check_eq_int("c2/rekey-begin", wg_transport_rx_begin(&rx, wire, n, sizeof(out), &t), 0);
    const uint32_t gen_before = rx.gen;
    c2_pair(2, NULL, &rx);
    fails += check_eq_int("c2/rekey-new-gen", rx.gen != gen_before, 1);
    fails += check_eq_int("c2/rekey-open", wg_transport_rx_open(&t, wire, n, out), 0);
    fails += check_eq_int("c2/rekey-commit-stale", wg_transport_rx_commit(&rx, &t),
                          WG_TRANSPORT_RX_STALE);
    fails += check_eq_int("c2/rekey-new-window-untouched", (int)(rx.replay.highest == 0 &&
                          all_zero(rx.replay.bitmap, sizeof(rx.replay.bitmap))), 1);

    /* Scrub (wg_netif_stop) between begin and commit: the open reads no
     * session byte (a zeroed key would fail the tag here), the commit
     * is stale, and nothing begins any more. */
    c2_pair(3, &tx, &rx);
    n = wg_transport_encrypt(&tx, wire, sizeof(wire), pt, sizeof(pt));
    fails += check_eq_int("c2/scrub-begin", wg_transport_rx_begin(&rx, wire, n, sizeof(out), &t), 0);
    wg_transport_session_scrub(&rx);
    fails += check_eq_int("c2/scrub-keys-zero", all_zero(rx.recv_key, 32) && all_zero(rx.send_key, 32), 1);
    fails += check_eq_int("c2/scrub-open-uses-copy", wg_transport_rx_open(&t, wire, n, out), 0);
    fails += check_eq_int("c2/scrub-plaintext", memcmp(out, pt, sizeof(pt)), 0);
    fails += check_eq_int("c2/scrub-commit-stale", wg_transport_rx_commit(&rx, &t),
                          WG_TRANSPORT_RX_STALE);
    fails += check_eq_int("c2/scrub-begin-refused", wg_transport_rx_begin(&rx, wire, n, sizeof(out), &t), -1);

    /* A scrubbed session (local index 0, all-zero keys) must not accept
     * a packet forged for index 0 under the all-zero key. */
    {
        struct wg_transport_session forger;
        uint8_t zero[32] = {0};
        wg_transport_session_init(&forger, 0, 0, zero, zero);
        n = wg_transport_encrypt(&forger, wire, sizeof(wire), pt, sizeof(pt));
        size_t ol = 0;
        fails += check_eq_int("c2/scrubbed-zero-key-forgery",
                              wg_transport_decrypt(&rx, wire, n, out, sizeof(out), &ol), -1);
        struct wg_tx_ticket tt;
        fails += check_eq_int("c2/scrubbed-no-reserve", wg_transport_tx_reserve(&rx, &tt), -1);
    }

    /* Generations never repeat across init / scrub, and init needs no
     * zeroed session (stack garbage). */
    {
        struct wg_transport_session g1;
        memset(&g1, 0xA5, sizeof(g1));
        uint8_t k[32];
        c2_keys(9, k);
        wg_transport_session_init(&g1, 1, 2, k, k);
        const uint32_t a = g1.gen;
        wg_transport_session_scrub(&g1);
        const uint32_t b = g1.gen;
        wg_transport_session_init(&g1, 1, 2, k, k);
        const uint32_t c = g1.gen;
        fails += check_eq_int("c2/gen-unique", a != b && b != c && a != c, 1);
        fails += check_eq_int("c2/init-on-garbage", g1.valid && g1.send_counter == 0 &&
                              g1.replay.highest == 0, 1);
    }
}

static void test_split_tx(void) {
    struct wg_transport_session tx, rx;
    c2_pair(4, &tx, &rx);
    uint8_t pt[16] = {9, 8, 7}, out[16];
    uint8_t w1[16 + WG_TRANSPORT_OVERHEAD], w2[sizeof(w1)], w3[sizeof(w1)];

    /* Two producers reserve, then seal in the opposite order: distinct
     * counters, both frames valid, accepted in either arrival order. */
    struct wg_tx_ticket a, b;
    fails += check_eq_int("c2/tx-reserve-a", wg_transport_tx_reserve(&tx, &a), 0);
    fails += check_eq_int("c2/tx-reserve-b", wg_transport_tx_reserve(&tx, &b), 0);
    fails += check_eq_int("c2/tx-distinct-counters", (int)(a.counter == 0 && b.counter == 1), 1);
    fails += check_eq_int("c2/tx-seal-b", wg_transport_tx_seal(&b, w2, sizeof(w2), pt, sizeof(pt)),
                          (int)sizeof(w2));
    fails += check_eq_int("c2/tx-seal-a", wg_transport_tx_seal(&a, w1, sizeof(w1), pt, sizeof(pt)),
                          (int)sizeof(w1));
    fails += check_eq_int("c2/tx-ticket-scrubbed", all_zero(a.key, 32) && all_zero(b.key, 32), 1);
    size_t ol = 0;
    fails += check_eq_int("c2/tx-rx-b-first", wg_transport_decrypt(&rx, w2, sizeof(w2), out, sizeof(out), &ol), 0);
    fails += check_eq_int("c2/tx-rx-a-late", wg_transport_decrypt(&rx, w1, sizeof(w1), out, sizeof(out), &ol), 0);

    /* Reserve under the old keypair, rekey, reserve again: the old
     * ticket keeps (old key, old counter), the new one starts at 0 with
     * the new key — never a new key with an old counter (nonce reuse
     * once the new session climbs back to that counter). */
    for (int i = 0; i < 5; i++) {
        struct wg_tx_ticket x;
        wg_transport_tx_reserve(&tx, &x);
        wg_transport_ticket_scrub(&x, sizeof(x));
    }
    fails += check_eq_int("c2/tx-old-reserve", wg_transport_tx_reserve(&tx, &a), 0);
    struct wg_transport_session rx_new;
    c2_pair(5, &tx, &rx_new);
    fails += check_eq_int("c2/tx-new-reserve", wg_transport_tx_reserve(&tx, &b), 0);
    fails += check_eq_int("c2/tx-old-counter-kept", (int)(a.counter == 7 && b.counter == 0), 1);
    wg_transport_tx_seal(&a, w1, sizeof(w1), pt, sizeof(pt));
    wg_transport_tx_seal(&b, w3, sizeof(w3), pt, sizeof(pt));
    fails += check_eq_int("c2/tx-old-frame-old-keys",
                          wg_transport_decrypt(&rx, w1, sizeof(w1), out, sizeof(out), &ol), 0);
    fails += check_eq_int("c2/tx-new-frame-new-keys",
                          wg_transport_decrypt(&rx_new, w3, sizeof(w3), out, sizeof(out), &ol), 0);
    fails += check_eq_int("c2/tx-old-frame-not-new-keys",
                          wg_transport_decrypt(&rx_new, w1, sizeof(w1), out, sizeof(out), &ol), -1);

    /* Short buffer: -1 and a scrubbed ticket (the counter is skipped). */
    fails += check_eq_int("c2/tx-short-reserve", wg_transport_tx_reserve(&tx, &a), 0);
    fails += check_eq_int("c2/tx-short-seal", wg_transport_tx_seal(&a, w1, sizeof(w1) - 1, pt, sizeof(pt)), -1);
    fails += check_eq_int("c2/tx-short-scrubbed", all_zero(a.key, 32), 1);

    /* Exhaustion: the reserved sentinel is never handed out. */
    tx.send_counter = UINT64_MAX - 1;
    fails += check_eq_int("c2/tx-last-counter", wg_transport_tx_reserve(&tx, &a), 0);
    fails += check_eq_int("c2/tx-last-counter-value", (int)(a.counter == UINT64_MAX - 1), 1);
    fails += check_eq_int("c2/tx-exhausted", wg_transport_tx_reserve(&tx, &b), -1);
    wg_transport_ticket_scrub(&a, sizeof(a));
}

/* --- C2: the lock protocol under real threads -------------------------- */

/* Two RX threads walk the same packets (the direct and DERP copies) and
 * a third thread rekeys / scrubs the session they decrypt against, every
 * step under mt_lock exactly as wg_netif does under g.lock. The two
 * races C2 must survive are forced, not left to the scheduler, so they
 * happen on any number of CPUs: on every MT_RV_EVERY-th packet a thread
 * that holds a ticket waits until the other thread holds one for the
 * same packet too (both copies in flight: one commit must be refused as
 * a duplicate), and thread 0 asks for a rekey between rx_begin and
 * rx_commit of packet MT_REKEY_AT of every epoch (the commit must be
 * refused as stale). Waits are bounded by MT_SPIN_CAP. */
#define MT_EPOCHS    16
#define MT_PKTS      64
#define MT_PT        48
#define MT_WIRE      (MT_PT + WG_TRANSPORT_OVERHEAD)
#define MT_RV_EVERY  8
#define MT_REKEY_AT  21
#define MT_SPIN_CAP  1000000

static pthread_mutex_t mt_lock = PTHREAD_MUTEX_INITIALIZER;
/* Everything below is guarded by mt_lock, like g.transport by g.lock. */
static struct wg_transport_session mt_rx;
static int      mt_epoch;          /* epoch whose keys mt_rx holds, -1 = scrubbed */
static int      mt_req;            /* epoch thread 0 asked the rekeyer for, 0 = none */
static int      mt_rekey_done;
static unsigned mt_delivered[MT_EPOCHS][MT_PKTS];
static unsigned char mt_rv[MT_EPOCHS][MT_PKTS];   /* tickets held for this packet */
static int      mt_bad;            /* open failed on a begun ticket, or commit on a wrong epoch */
static int      mt_stale, mt_dup;  /* commit refusals: keypair gone / copy accepted first */
static int      mt_capped;         /* a wait hit MT_SPIN_CAP */
static uint8_t  mt_wire[MT_EPOCHS][MT_PKTS][MT_WIRE];

static int mt_get(const int *v) {
    pthread_mutex_lock(&mt_lock);
    const int x = *v;
    pthread_mutex_unlock(&mt_lock);
    return x;
}

/* Wait until the epoch is no longer `e` (thread 0's rekey request). */
static void mt_wait_epoch_moves(int e) {
    for (int n = 0; n < MT_SPIN_CAP; n++) {
        if (mt_get(&mt_epoch) != e) return;
        sched_yield();
    }
    pthread_mutex_lock(&mt_lock);
    mt_capped++;
    pthread_mutex_unlock(&mt_lock);
}

static void mt_rx_pass(int e, int id) {
    for (int i = 0; i < MT_PKTS; i++) {
        /* Thread 1 leaves the rekey packet to thread 0, so thread 0
         * always holds a ticket for it when it asks for the rekey. */
        if (id == 1 && i == MT_REKEY_AT) continue;
        const uint8_t *w = mt_wire[e][i];
        const int rv = (i % MT_RV_EVERY) == 3;
        struct wg_rx_ticket t;
        pthread_mutex_lock(&mt_lock);
        int rc = wg_transport_rx_begin(&mt_rx, w, MT_WIRE, MT_PT, &t);
        if (rc == 0 && rv) mt_rv[e][i]++;
        pthread_mutex_unlock(&mt_lock);
        if (rc != 0) continue;
        if (rv) {
            int n = 0;
            for (; n < MT_SPIN_CAP; n++) {
                pthread_mutex_lock(&mt_lock);
                const int both = mt_rv[e][i] >= 2, moved = mt_epoch != e;
                pthread_mutex_unlock(&mt_lock);
                if (both || moved) break;
                sched_yield();
            }
            if (n == MT_SPIN_CAP) { pthread_mutex_lock(&mt_lock); mt_capped++; pthread_mutex_unlock(&mt_lock); }
        }
        if (id == 0 && i == MT_REKEY_AT && e + 1 < MT_EPOCHS) {
            pthread_mutex_lock(&mt_lock);
            if (mt_epoch == e && mt_req == 0) mt_req = e + 1;
            pthread_mutex_unlock(&mt_lock);
            mt_wait_epoch_moves(e);
        }
        if ((i & 3) == 0) sched_yield();
        uint8_t pt[MT_PT];
        const int orc = wg_transport_rx_open(&t, w, MT_WIRE, pt);
        pthread_mutex_lock(&mt_lock);
        if (orc != 0) {
            mt_bad++;      /* a genuine packet that began must open */
        } else {
            const int crc = wg_transport_rx_commit(&mt_rx, &t);
            if (crc == 0) {
                if (mt_epoch != e || pt[0] != (uint8_t)e || pt[1] != (uint8_t)i) mt_bad++;
                mt_delivered[e][i]++;
            } else if (crc == WG_TRANSPORT_RX_STALE) {
                mt_stale++;
            } else {
                mt_dup++;
            }
        }
        pthread_mutex_unlock(&mt_lock);
    }
}

static void *mt_rx_thread(void *arg) {
    const int id = (int)(intptr_t)arg;
    for (;;) {
        pthread_mutex_lock(&mt_lock);
        const int e = mt_epoch, done = mt_rekey_done;
        pthread_mutex_unlock(&mt_lock);
        if (e >= 0) mt_rx_pass(e, id); else sched_yield();
        if (done) break;   /* this pass started after the last rekey */
        if (id == 0 && e >= 0 && e + 1 < MT_EPOCHS) {
            /* Progress even if this pass could not ask (epoch moved). */
            pthread_mutex_lock(&mt_lock);
            if (mt_epoch == e && mt_req == 0) mt_req = e + 1;
            pthread_mutex_unlock(&mt_lock);
            mt_wait_epoch_moves(e);
        }
    }
    return NULL;
}

/* Serves thread 0's requests; every 5th epoch is a stop-style scrub
 * followed by a new session. */
static void *mt_rekey_thread(void *arg) {
    (void)arg;
    for (int n = 0; n < 50 * MT_SPIN_CAP; n++) {
        pthread_mutex_lock(&mt_lock);
        const int req = mt_req;
        if (req != 0) {
            if (req % 5 == 0) {
                wg_transport_session_scrub(&mt_rx);
                mt_epoch = -1;
                pthread_mutex_unlock(&mt_lock);
                sched_yield();
                pthread_mutex_lock(&mt_lock);
            }
            c2_pair(req, NULL, &mt_rx);
            mt_epoch = req;
            mt_req = 0;
            if (req == MT_EPOCHS - 1) mt_rekey_done = 1;
        }
        const int done = mt_rekey_done;
        pthread_mutex_unlock(&mt_lock);
        if (done) return NULL;
        if (req == 0) sched_yield();
    }
    pthread_mutex_lock(&mt_lock);
    mt_capped++;
    mt_rekey_done = 1;     /* let the RX threads finish */
    pthread_mutex_unlock(&mt_lock);
    return NULL;
}

static void test_mt_rx(void) {
    for (int e = 0; e < MT_EPOCHS; e++) {
        struct wg_transport_session tx;
        c2_pair(e, &tx, NULL);
        for (int i = 0; i < MT_PKTS; i++) {
            uint8_t pt[MT_PT];
            memset(pt, 0xC3, sizeof(pt));
            pt[0] = (uint8_t)e;
            pt[1] = (uint8_t)i;
            wg_transport_encrypt(&tx, mt_wire[e][i], MT_WIRE, pt, sizeof(pt));
        }
    }
    c2_pair(0, NULL, &mt_rx);
    mt_epoch = 0;
    pthread_t a, b, r;
    pthread_create(&a, NULL, mt_rx_thread, (void *)(intptr_t)0);
    pthread_create(&b, NULL, mt_rx_thread, (void *)(intptr_t)1);
    pthread_create(&r, NULL, mt_rekey_thread, NULL);
    pthread_join(r, NULL);
    pthread_join(a, NULL);
    pthread_join(b, NULL);

    int at_most_once = 1, last_complete = 1;
    for (int e = 0; e < MT_EPOCHS; e++) {
        for (int i = 0; i < MT_PKTS; i++) at_most_once &= mt_delivered[e][i] <= 1;
    }
    for (int i = 0; i < MT_PKTS; i++) last_complete &= mt_delivered[MT_EPOCHS - 1][i] == 1;
    fails += check_eq_int("c2/mt-rx-no-key-confusion", mt_bad, 0);
    fails += check_eq_int("c2/mt-rx-each-packet-at-most-once", at_most_once, 1);
    fails += check_eq_int("c2/mt-rx-last-epoch-all-delivered", last_complete, 1);
    fails += check_eq_int("c2/mt-rx-no-wait-capped", mt_capped, 0);
    /* One forced keypair race per rekey (scrubs included). */
    fails += check_eq_int("c2/mt-rx-keypair-race-refused", mt_stale >= MT_EPOCHS - 1, 1);
    fails += check_eq_int("c2/mt-rx-dup-in-flight-refused", mt_dup > 0, 1);
    wg_transport_session_scrub(&mt_rx);
}

/* Two TX producers reserve + seal against a session a third thread
 * rekeys; producer 0 forces a rekey between the reserve and the seal of
 * every MT_TX_FORCE-th frame (the (old key, old counter) case). */
#define MT_TX_FRAMES 600
#define MT_TX_FORCE  50

static struct wg_transport_session mt_tx;   /* guarded by mt_lock */
static int mt_tx_epoch;                     /* guarded */
static int mt_tx_req;                       /* guarded: rekey requested */
static int mt_tx_stop;                      /* guarded */
static int mt_tx_raced;    /* guarded: a rekey landed between a reserve and its seal */

struct mt_frame { int epoch; uint64_t counter; uint8_t wire[MT_WIRE]; };
static struct mt_frame mt_frames[2][MT_TX_FRAMES];

static void *mt_tx_thread(void *arg) {
    const int id = (int)(intptr_t)arg;
    for (int i = 0; i < MT_TX_FRAMES; i++) {
        struct mt_frame *f = &mt_frames[id][i];
        struct wg_tx_ticket t;
        pthread_mutex_lock(&mt_lock);
        const int rc = wg_transport_tx_reserve(&mt_tx, &t);
        f->epoch = mt_tx_epoch;        /* the keypair the ticket came from */
        pthread_mutex_unlock(&mt_lock);
        if (rc != 0) { f->epoch = -1; continue; }
        f->counter = t.counter;
        if (id == 0 && i % MT_TX_FORCE == MT_TX_FORCE / 2) {
            pthread_mutex_lock(&mt_lock);
            mt_tx_req = 1;
            pthread_mutex_unlock(&mt_lock);
            int n = 0;
            while (mt_get(&mt_tx_req) != 0 && n++ < MT_SPIN_CAP) sched_yield();
        }
        if ((i & 7) == 0) sched_yield();
        uint8_t pt[MT_PT];
        memset(pt, id, sizeof(pt));
        if (wg_transport_tx_seal(&t, f->wire, MT_WIRE, pt, sizeof(pt)) != MT_WIRE) f->epoch = -2;
        pthread_mutex_lock(&mt_lock);
        if (mt_tx_epoch != f->epoch) mt_tx_raced++;
        pthread_mutex_unlock(&mt_lock);
    }
    return NULL;
}

static void *mt_tx_rekey_thread(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&mt_lock);
        const int stop = mt_tx_stop, req = mt_tx_req;
        if (req && mt_tx_epoch + 1 < MT_EPOCHS) {
            c2_pair(mt_tx_epoch + 1, &mt_tx, NULL);
            mt_tx_epoch++;
        }
        mt_tx_req = 0;
        pthread_mutex_unlock(&mt_lock);
        if (stop) return NULL;
        if (!req) sched_yield();
    }
}

static void test_mt_tx(void) {
    c2_pair(0, &mt_tx, NULL);
    mt_tx_epoch = 0;
    pthread_t a, b, r;
    pthread_create(&r, NULL, mt_tx_rekey_thread, NULL);
    pthread_create(&a, NULL, mt_tx_thread, (void *)(intptr_t)0);
    pthread_create(&b, NULL, mt_tx_thread, (void *)(intptr_t)1);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    pthread_mutex_lock(&mt_lock);
    mt_tx_stop = 1;
    pthread_mutex_unlock(&mt_lock);
    pthread_join(r, NULL);

    /* Every frame opens under exactly the keypair its counter was
     * reserved from, with that counter in its header, and no (keypair,
     * counter) pair — i.e. no AEAD nonce under one key — occurs twice. */
    static unsigned char used[MT_EPOCHS][2 * MT_TX_FRAMES];
    memset(used, 0, sizeof(used));
    int ok_open = 1, unique = 1, sealed = 0;
    for (int id = 0; id < 2; id++) {
        for (int i = 0; i < MT_TX_FRAMES; i++) {
            const struct mt_frame *f = &mt_frames[id][i];
            if (f->epoch < 0) { ok_open = 0; continue; }
            sealed++;
            uint64_t hdr_ctr;
            memcpy(&hdr_ctr, f->wire + 8, 8);
            struct wg_transport_session rx;
            c2_pair(f->epoch, NULL, &rx);
            uint8_t out[MT_PT];
            size_t ol = 0;
            ok_open &= hdr_ctr == f->counter &&
                       wg_transport_decrypt(&rx, f->wire, MT_WIRE, out, sizeof(out), &ol) == 0 &&
                       out[0] == (uint8_t)id;
            if (f->counter >= 2 * MT_TX_FRAMES || used[f->epoch][f->counter]++) unique = 0;
        }
    }
    fails += check_eq_int("c2/mt-tx-frames-open-under-their-keypair", ok_open, 1);
    fails += check_eq_int("c2/mt-tx-no-nonce-reuse", unique, 1);
    fails += check_eq_int("c2/mt-tx-all-sealed", sealed, 2 * MT_TX_FRAMES);
    /* At least the forced ones (12 rekeys) landed between a reserve and its seal. */
    fails += check_eq_int("c2/mt-tx-rekey-between-reserve-and-seal",
                          mt_tx_raced >= MT_TX_FRAMES / MT_TX_FORCE, 1);
    wg_transport_session_scrub(&mt_tx);
}

int main(void) {
    test_replay_window();
    test_roundtrip();
    test_negative_paths();
    test_nonce_layout();
    test_replay_update_fuzz();
    test_split_rx();
    test_split_rekey_scrub();
    test_split_tx();
    test_mt_rx();
    test_mt_tx();
    if (fails == 0) printf("\nALL OK\n");
    return fails ? 1 : 0;
}
