/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for WG transport (data-plane) encrypt / decrypt and the
 * RFC 6479 anti-replay window. Both halves of session keys are
 * exercised in roundtrip; the replay window is poked directly.
 */

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

int main(void) {
    test_replay_window();
    test_roundtrip();
    test_negative_paths();
    if (fails == 0) printf("\nALL OK\n");
    return fails ? 1 : 0;
}
