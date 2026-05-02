/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for the UDP datagram classifier. Validates each routing
 * key, edge cases on size, and the DISCO-vs-Initiation collision
 * (both start with 0x01).
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "wg_demux.h"

static int fails = 0;

static int check(const char *name, wg_demux_kind_t got, wg_demux_kind_t want) {
    if (got == want) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL: got %d want %d\n", name, (int)got, (int)want);
    return 1;
}

int main(void) {
    /* MessageInitiation (148 bytes, first byte = 0x01). */
    {
        uint8_t buf[148] = {0};
        buf[0] = 0x01;
        fails += check("init/exact-148", wg_demux_classify(buf, 148),
                       WG_DEMUX_HANDSHAKE_INIT);
        fails += check("init/too-short-147", wg_demux_classify(buf, 147),
                       WG_DEMUX_DISCARD);
        fails += check("init/too-long-149", wg_demux_classify(buf, 149),
                       WG_DEMUX_DISCARD);
    }

    /* MessageResponse (92 bytes, 0x02). */
    {
        uint8_t buf[92] = {0};
        buf[0] = 0x02;
        fails += check("resp/exact-92", wg_demux_classify(buf, 92),
                       WG_DEMUX_HANDSHAKE_RESP);
        fails += check("resp/91", wg_demux_classify(buf, 91),
                       WG_DEMUX_DISCARD);
    }

    /* MessageCookieReply (64 bytes, 0x03). */
    {
        uint8_t buf[64] = {0};
        buf[0] = 0x03;
        fails += check("cookie/exact-64", wg_demux_classify(buf, 64),
                       WG_DEMUX_HANDSHAKE_COOKIE);
    }

    /* MessageTransport (≥32 bytes, 0x04). */
    {
        uint8_t buf[256] = {0};
        buf[0] = 0x04;
        fails += check("xport/min-32", wg_demux_classify(buf, 32),
                       WG_DEMUX_TRANSPORT);
        fails += check("xport/big-256", wg_demux_classify(buf, 256),
                       WG_DEMUX_TRANSPORT);
        fails += check("xport/short-31", wg_demux_classify(buf, 31),
                       WG_DEMUX_DISCARD);
    }

    /* STUN binding request (first 2 bytes 0x00 0x01). */
    {
        uint8_t buf[20] = {0};
        buf[0] = 0x00; buf[1] = 0x01;
        fails += check("stun/binding-req", wg_demux_classify(buf, 20),
                       WG_DEMUX_STUN);
        /* 0x00 0x02 is not a binding request — discard. */
        buf[1] = 0x02;
        fails += check("stun/wrong-method", wg_demux_classify(buf, 20),
                       WG_DEMUX_DISCARD);
    }

    /* DISCO v1: magic = "TS💬" = 54 53 f0 9f 92 ac, plus
     * senderPub(32) + nonce(24) + tag(16) + type+ver(2) = 80 bytes
     * minimum for a packet that could possibly parse. */
    {
        const uint8_t magic[6] = {0x54,0x53,0xf0,0x9f,0x92,0xac};
        uint8_t buf[80] = {0};
        memcpy(buf, magic, 6);
        fails += check("disco/min-80", wg_demux_classify(buf, 80),
                       WG_DEMUX_DISCO);
        /* 79 bytes — one byte short of the parseable minimum. */
        fails += check("disco/short-79", wg_demux_classify(buf, 79),
                       WG_DEMUX_DISCARD);
        /* Just the magic alone is way too short. */
        fails += check("disco/magic-only", wg_demux_classify(buf, 6),
                       WG_DEMUX_DISCARD);
    }

    /* Anti-spoof: a 148-byte buffer whose first byte is 0x54 (the
     * DISCO magic's first byte) but whose magic doesn't fully match
     * is NOT DISCO — and isn't a WG type either, so it's discard.
     * Confirms we don't latch onto partial magic. */
    {
        uint8_t buf[148] = {0};
        buf[0] = 0x54;  /* matches DISCO byte 0 */
        buf[1] = 0xFF;  /* differs from DISCO byte 1 = 0x53 */
        fails += check("disco/partial-magic-discard",
                       wg_demux_classify(buf, 148),
                       WG_DEMUX_DISCARD);
    }

    /* Empty / NULL input. */
    fails += check("edge/empty", wg_demux_classify(NULL, 0), WG_DEMUX_DISCARD);
    fails += check("edge/zerolen", wg_demux_classify((const uint8_t *)"x", 0),
                   WG_DEMUX_DISCARD);

    /* Unknown first byte. */
    {
        uint8_t buf[64] = {0};
        buf[0] = 0xFF;
        fails += check("unknown/first-byte", wg_demux_classify(buf, 64),
                       WG_DEMUX_DISCARD);
    }

    if (fails == 0) printf("\nALL OK\n");
    return fails ? 1 : 0;
}
