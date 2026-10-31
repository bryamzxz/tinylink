/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host test for tsmp_build_disco_advert — the capver-144 disco-key
 * advertisement tinylink sends after every WireGuard handshake. The
 * golden packet was computed from tailscale net/packet ip4.go +
 * tsmp.go (IP4Header.Marshal, TSMPDiscoKeyAdvertisement.Marshal) for
 * src 100.64.0.1, dst 100.64.0.2, key 0x01..0x20.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "tsmp.h"

static int check(const char *name, int ok)
{
    printf("[%s] %s\n", name, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}

static uint32_t v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    const uint8_t bytes[4] = { a, b, c, d };
    uint32_t be;
    memcpy(&be, bytes, sizeof(be));   /* network order, like inet_pton */
    return be;
}

int main(void)
{
    static const uint8_t golden[TSMP_DISCO_ADVERT_LEN] = {
        0x45, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x63, 0xb1, 0xe3, 0x64, 0x40, 0x00, 0x01,
        0x64, 0x40, 0x00, 0x02, 0x61,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };
    uint8_t key[TSMP_DISCO_KEY_LEN];
    for (int i = 0; i < TSMP_DISCO_KEY_LEN; i++) key[i] = (uint8_t)(i + 1);

    int fails = 0;
    uint8_t pkt[64];
    memset(pkt, 0xa5, sizeof(pkt));
    size_t n = tsmp_build_disco_advert(pkt, sizeof(pkt),
                                       v4(100, 64, 0, 1), v4(100, 64, 0, 2), key);

    fails += check("advert/length-53", n == TSMP_DISCO_ADVERT_LEN && n == 53);
    fails += check("advert/golden-bytes", memcmp(pkt, golden, sizeof(golden)) == 0);
    fails += check("advert/no-overrun", pkt[53] == 0xa5);
    fails += check("advert/total-length-field", ((pkt[2] << 8) | pkt[3]) == (int)n);
    /* A header with its checksum in place sums to 0xffff → ~ == 0. */
    fails += check("advert/checksum-verifies", tsmp_ip4_checksum(pkt, 20) == 0);
    fails += check("advert/proto-99", pkt[9] == TSMP_IP_PROTO);
    fails += check("advert/short-buffer", tsmp_build_disco_advert(pkt, 52,
                       v4(100, 64, 0, 1), v4(100, 64, 0, 2), key) == 0);

    /* Different addresses: checksum must still verify and the
     * addresses land at offsets 12 / 16 in network order. */
    n = tsmp_build_disco_advert(pkt, sizeof(pkt),
                                v4(100, 101, 102, 103), v4(100, 127, 255, 254), key);
    fails += check("advert/other-addrs-checksum", n == 53 && tsmp_ip4_checksum(pkt, 20) == 0);
    fails += check("advert/src-dst-offsets",
                   pkt[12] == 100 && pkt[13] == 101 && pkt[14] == 102 && pkt[15] == 103 &&
                   pkt[16] == 100 && pkt[17] == 127 && pkt[18] == 255 && pkt[19] == 254);

    if (fails == 0) {
        printf("\n[PASS] all tsmp assertions passed\n");
        return 0;
    }
    printf("\n[FAIL] %d tsmp assertion(s) failed\n", fails);
    return 1;
}
