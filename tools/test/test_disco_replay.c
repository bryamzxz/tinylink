/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for disco_replay.c — the nonce-window that defeats DISCO
 * datagram replay. Without this layer, an attacker who passively
 * captures a single sealed DISCO PING/PONG can replay the bytes from a
 * spoofed/owned source AddrPort and trigger handle_disco_direct's roam
 * path to redirect g.peer_addr (WireGuard transport endpoint) to the
 * attacker. NaCl box (XSalsa20-Poly1305) is stateless and deterministic,
 * so the AEAD itself accepts the replay; we reject above the AEAD by
 * tracking nonces.
 *
 * Coverage:
 *   - First arrival of a fresh nonce → not seen, recorded.
 *   - Immediate replay of the same nonce → reported as seen.
 *   - Distinct nonces don't false-positive each other.
 *   - Window eviction: after WINDOW_SIZE distinct fresh nonces, the
 *     oldest is evicted and reusing it (improbable in practice, but
 *     spec'd) is no longer reported as seen.
 *   - reset() empties the window.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "disco.h"
#include "disco_replay.h"

static int fails = 0;

static int ok(const char *name, int condition) {
    if (condition) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL\n", name);
    return 1;
}

/* Build a deterministic 24-byte nonce from a single seed byte. */
static void nonce_from_seed(uint8_t out[DISCO_NONCE_LEN], uint8_t seed)
{
    for (int i = 0; i < DISCO_NONCE_LEN; i++) out[i] = (uint8_t)(seed + i);
}

static void test_first_then_replay(void)
{
    disco_replay_reset();
    uint8_t n[DISCO_NONCE_LEN];
    nonce_from_seed(n, 0x10);

    fails += ok("first/not-seen", disco_replay_check_and_record(n) == false);
    fails += ok("replay/seen",    disco_replay_check_and_record(n) == true);
    fails += ok("replay/seen-2",  disco_replay_check_and_record(n) == true);
}

static void test_distinct_no_collide(void)
{
    disco_replay_reset();
    uint8_t a[DISCO_NONCE_LEN], b[DISCO_NONCE_LEN], c[DISCO_NONCE_LEN];
    nonce_from_seed(a, 0x20);
    nonce_from_seed(b, 0x21);
    nonce_from_seed(c, 0x22);

    fails += ok("a/first",  disco_replay_check_and_record(a) == false);
    fails += ok("b/first",  disco_replay_check_and_record(b) == false);
    fails += ok("c/first",  disco_replay_check_and_record(c) == false);
    fails += ok("a/replay", disco_replay_check_and_record(a) == true);
    fails += ok("b/replay", disco_replay_check_and_record(b) == true);
    fails += ok("c/replay", disco_replay_check_and_record(c) == true);
}

static void test_window_eviction(void)
{
    disco_replay_reset();
    /* Pin: this assumes DISCO_REPLAY_WINDOW_SIZE matches the production
     * setting. If the size changes, this test must be updated alongside
     * the BSS-cost trade-off doc. */
    const int W = DISCO_REPLAY_WINDOW_SIZE;

    uint8_t first[DISCO_NONCE_LEN];
    nonce_from_seed(first, 0x30);
    fails += ok("evict/first-not-seen",
                disco_replay_check_and_record(first) == false);

    /* Fill the window with W more distinct nonces, evicting `first`. */
    for (int i = 1; i <= W; i++) {
        uint8_t n[DISCO_NONCE_LEN];
        /* Use a 16-bit-spread seed so the W generated nonces are pairwise
         * distinct from each other and from `first`. */
        for (int k = 0; k < DISCO_NONCE_LEN; k++) {
            n[k] = (uint8_t)((0x80 + i + k) & 0xff);
        }
        (void)disco_replay_check_and_record(n);
    }

    /* `first` was evicted by the ring-buffer overwrite — re-arrival is
     * NOT reported as seen. (Replay window has finite memory; this is
     * the trade-off documented in disco_replay.h.) */
    fails += ok("evict/first-after-window-full-not-seen",
                disco_replay_check_and_record(first) == false);
}

static void test_reset(void)
{
    disco_replay_reset();
    uint8_t n[DISCO_NONCE_LEN];
    nonce_from_seed(n, 0x40);

    fails += ok("reset/before-first",  disco_replay_check_and_record(n) == false);
    fails += ok("reset/before-replay", disco_replay_check_and_record(n) == true);

    disco_replay_reset();
    fails += ok("reset/after",         disco_replay_check_and_record(n) == false);
}

int main(void)
{
    test_first_then_replay();
    test_distinct_no_collide();
    test_window_eviction();
    test_reset();

    if (fails) {
        printf("\n[FAIL] %d disco_replay assertion(s) failed\n", fails);
        return 1;
    }
    printf("\n[PASS] all disco_replay assertions passed\n");
    return 0;
}
