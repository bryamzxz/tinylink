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

    /* DISCO v1: magic = 01 05 fe 16 76 46 90 80, plus 32+24+16 = at
     * least 80 bytes total before payload. */
    {
        const uint8_t magic[8] = {0x01,0x05,0xfe,0x16,0x76,0x46,0x90,0x80};
        uint8_t buf[80] = {0};
        memcpy(buf, magic, 8);
        fails += check("disco/min-80", wg_demux_classify(buf, 80),
                       WG_DEMUX_DISCO);
        /* Just the magic alone is too short. */
        fails += check("disco/magic-only", wg_demux_classify(buf, 8),
                       WG_DEMUX_DISCARD);
    }

    /* Critical collision: DISCO and MessageInitiation both start with
     * 0x01. A 148-byte buffer starting with the DISCO magic must
     * classify as DISCO, not as init. */
    {
        const uint8_t magic[8] = {0x01,0x05,0xfe,0x16,0x76,0x46,0x90,0x80};
        uint8_t buf[148] = {0};
        memcpy(buf, magic, 8);
        fails += check("collision/disco-148", wg_demux_classify(buf, 148),
                       WG_DEMUX_DISCO);
    }
    {
        /* And conversely: 148-byte buffer starting with 0x01 but NOT
         * the DISCO magic is init. */
        uint8_t buf[148] = {0};
        buf[0] = 0x01;
        buf[1] = 0xFF;  /* differs from DISCO byte 1 = 0x05 */
        fails += check("collision/init-148", wg_demux_classify(buf, 148),
                       WG_DEMUX_HANDSHAKE_INIT);
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
