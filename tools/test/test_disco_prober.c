/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for disco_prober.c — outbound DISCO Ping tx-id table that
 * binds inbound Pongs to outbound Pings (M3 step 3). Covers:
 *   - record + match-and-remove roundtrip (matches once, then not).
 *   - multiple in-flight txids resolve to the correct one.
 *   - timeout: a Pong arriving after DISCO_PROBER_TIMEOUT_MS does not
 *     match, even if the txid was originally recorded.
 *   - LRU eviction when the table fills: the oldest fresh entry yields
 *     to a newer record(), and its Pong then no longer matches.
 *   - match without prior record returns false.
 *   - source binding: a Pong with a valid txid but from a source other
 *     than the probed destination does NOT match, and does NOT consume
 *     the slot (closes the replay-from-spoofed-AddrPort gap, ROAM-3).
 *   - basic NULL-arg safety.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "disco.h"
#include "disco_prober.h"

static int fails = 0;

static int ok(const char *name, int condition) {
    if (condition) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL\n", name);
    return 1;
}

static void make_txid(uint8_t out[DISCO_TXID_LEN], uint8_t seed) {
    for (int i = 0; i < DISCO_TXID_LEN; i++) out[i] = (uint8_t)(seed + i);
}

static void test_basic_roundtrip(void) {
    disco_prober_reset();
    uint8_t txid[DISCO_TXID_LEN];
    make_txid(txid, 0x10);

    disco_prober_record(txid, 0x01020304, 41641, 1000);
    fails += ok("basic/match-once",
                disco_prober_match_and_remove(txid, 0x01020304, 41641, 2000));
    fails += ok("basic/match-twice-fails",
                !disco_prober_match_and_remove(txid, 0x01020304, 41641, 2000));
}

static void test_multiple_txids(void) {
    disco_prober_reset();
    uint8_t a[DISCO_TXID_LEN], b[DISCO_TXID_LEN], c[DISCO_TXID_LEN];
    make_txid(a, 0x20);
    make_txid(b, 0x40);
    make_txid(c, 0x60);

    disco_prober_record(a, 1, 1001, 1000);
    disco_prober_record(b, 2, 1002, 1001);
    disco_prober_record(c, 3, 1003, 1002);

    /* Out-of-order matches all work (each from its own probed dst). */
    fails += ok("multi/match-b", disco_prober_match_and_remove(b, 2, 1002, 1500));
    fails += ok("multi/match-c", disco_prober_match_and_remove(c, 3, 1003, 1500));
    fails += ok("multi/match-a", disco_prober_match_and_remove(a, 1, 1001, 1500));
    /* All consumed. */
    fails += ok("multi/a-gone", !disco_prober_match_and_remove(a, 1, 1001, 1500));
}

static void test_timeout(void) {
    disco_prober_reset();
    uint8_t txid[DISCO_TXID_LEN];
    make_txid(txid, 0x30);

    /* Record at t=0 µs. Match at t = timeout_ms + 1 ms → expired. The
     * source matches the recorded dst, so it is the expiry — not the
     * source binding — that drives the false result. */
    int64_t now0 = 0;
    int64_t now1 = (int64_t)(DISCO_PROBER_TIMEOUT_MS + 1) * 1000LL;
    disco_prober_record(txid, 1, 41641, now0);
    fails += ok("timeout/stale-match-fails",
                !disco_prober_match_and_remove(txid, 1, 41641, now1));

    /* And the slot was cleared, so a fresh record reuses it cleanly. */
    disco_prober_record(txid, 2, 41642, now1 + 1);
    fails += ok("timeout/refresh-then-match",
                disco_prober_match_and_remove(txid, 2, 41642, now1 + 100));
}

static void test_lru_eviction(void) {
    disco_prober_reset();
    /* Fill the table with fresh (un-expired) entries. */
    uint8_t txids[DISCO_PROBER_TABLE_SIZE][DISCO_TXID_LEN];
    int64_t base = 1000;
    for (int i = 0; i < DISCO_PROBER_TABLE_SIZE; i++) {
        make_txid(txids[i], (uint8_t)(0x80 + i));
        /* Each entry recorded 100 µs apart so the FIRST is oldest. */
        disco_prober_record(txids[i], (uint32_t)i, (uint16_t)(40000 + i),
                            base + i * 100);
    }
    fails += ok("lru/table-full-all-match-before-eviction",
                disco_prober_match_and_remove(txids[0], 0, 40000,
                    base + DISCO_PROBER_TABLE_SIZE * 100));
    /* Recover by re-recording the freshness-spread for the eviction test. */
    disco_prober_reset();
    for (int i = 0; i < DISCO_PROBER_TABLE_SIZE; i++) {
        disco_prober_record(txids[i], (uint32_t)i, (uint16_t)(40000 + i),
                            base + i * 100);
    }
    /* Now record one more — should evict the oldest (txids[0]). */
    uint8_t newer[DISCO_TXID_LEN];
    make_txid(newer, 0xfe);
    disco_prober_record(newer, 0xff, 65000,
                        base + DISCO_PROBER_TABLE_SIZE * 100);
    /* The newer one matches. */
    fails += ok("lru/newer-matches",
                disco_prober_match_and_remove(newer, 0xff, 65000,
                    base + DISCO_PROBER_TABLE_SIZE * 100 + 1));
    /* The oldest (txids[0]) was evicted, so it no longer matches. */
    fails += ok("lru/oldest-evicted",
                !disco_prober_match_and_remove(txids[0], 0, 40000,
                    base + DISCO_PROBER_TABLE_SIZE * 100 + 1));
    /* The second-oldest still matches. */
    fails += ok("lru/second-oldest-survives",
                disco_prober_match_and_remove(txids[1], 1, 40001,
                    base + DISCO_PROBER_TABLE_SIZE * 100 + 1));
}

static void test_unknown_txid(void) {
    disco_prober_reset();
    uint8_t known[DISCO_TXID_LEN], unknown[DISCO_TXID_LEN];
    make_txid(known,   0x50);
    make_txid(unknown, 0xaa);
    disco_prober_record(known, 1, 41641, 1000);
    fails += ok("unknown/no-match",
                !disco_prober_match_and_remove(unknown, 1, 41641, 1500));
    /* Known still matches afterwards. */
    fails += ok("unknown/known-still-matches",
                disco_prober_match_and_remove(known, 1, 41641, 1500));
}

static void test_source_binding(void) {
    disco_prober_reset();
    uint8_t txid[DISCO_TXID_LEN];
    make_txid(txid, 0x70);

    /* Probe sent TO 0x01020304:41641. */
    disco_prober_record(txid, 0x01020304, 41641, 1000);

    /* A Pong with the right txid but from a DIFFERENT (spoofed) source
     * must NOT match — this is the spoofed-AddrPort replay the prober
     * exists to defeat. */
    fails += ok("srcbind/wrong-src-no-match",
                !disco_prober_match_and_remove(txid, 0x05060708, 41641, 2000));
    /* Same address, wrong port is also a mismatch. */
    fails += ok("srcbind/wrong-port-no-match",
                !disco_prober_match_and_remove(txid, 0x01020304, 9999, 2000));
    /* CRITICAL: the rejected attempts did NOT consume the slot, so the
     * genuine Pong from the probed address still matches. (Otherwise a
     * spoofed Pong could burn the slot and lock out the real one.) */
    fails += ok("srcbind/genuine-still-matches-after-spoof",
                disco_prober_match_and_remove(txid, 0x01020304, 41641, 2000));
    /* And now it is consumed. */
    fails += ok("srcbind/consumed-after-genuine",
                !disco_prober_match_and_remove(txid, 0x01020304, 41641, 2000));
}

static void test_null_safety(void) {
    disco_prober_reset();
    fails += ok("null/record-no-crash",
                (disco_prober_record(NULL, 1, 1, 0), 1));
    fails += ok("null/match-returns-false",
                !disco_prober_match_and_remove(NULL, 0, 0, 1000));
}

int main(void) {
    disco_prober_init();
    test_basic_roundtrip();
    test_multiple_txids();
    test_timeout();
    test_lru_eviction();
    test_unknown_txid();
    test_source_binding();
    test_null_safety();

    if (fails == 0) {
        printf("\n[PASS] all disco_prober assertions passed\n");
        return 0;
    }
    printf("\n[FAIL] %d disco_prober assertion(s) failed\n", fails);
    return 1;
}
