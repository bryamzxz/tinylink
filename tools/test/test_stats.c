/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host tests for the /stats additions of 1.3.2:
 *   - tl_bootstat.h: the RTC no-init boot-counter record — garbage /
 *     wrong magic / torn update restart it from zero, each counted
 *     reset reason lands in its own counter, `boots` counts every boot.
 *   - stats_json.h: the /stats line at its worst case (every counter at
 *     its type's widest value, a 63-char hostname and DERP host) fits
 *     the 768-B reply buffer, and is valid JSON with the new keys.
 */

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tinylink.h"
#include "stats_json.h"
#include "tl_bootstat.h"

#define JSMN_STATIC
#include "jsmn.h"

static int fails = 0;

static int ok(const char *name, int condition)
{
    if (condition) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL\n", name);
    return 1;
}

static void test_bootstat(void)
{
    tl_bootstat_t b;

    /* Power-on: RTC memory holds whatever it powered up with. */
    memset(&b, 0x5A, sizeof(b));
    int was_valid = tl_bootstat_count(&b, 1 /* ESP_RST_POWERON */);
    fails += ok("bootstat/garbage-restarts",
                !was_valid && b.boots == 1 && b.brownout == 0 && b.panic == 0 &&
                b.task_wdt == 0 && b.int_wdt == 0 && tl_bootstat_valid(&b));

    memset(&b, 0, sizeof(b));
    fails += ok("bootstat/zeroes-invalid", !tl_bootstat_valid(&b));
    (void)tl_bootstat_count(&b, 1);

    /* One boot per reason; only the four tracked ones have a counter. */
    fails += ok("bootstat/brownout",
                tl_bootstat_count(&b, TL_RST_BROWNOUT) && b.boots == 2 && b.brownout == 1);
    fails += ok("bootstat/panic",
                tl_bootstat_count(&b, TL_RST_PANIC) && b.boots == 3 && b.panic == 1);
    fails += ok("bootstat/task-wdt",
                tl_bootstat_count(&b, TL_RST_TASK_WDT) && b.boots == 4 && b.task_wdt == 1);
    fails += ok("bootstat/int-wdt",
                tl_bootstat_count(&b, TL_RST_INT_WDT) && b.boots == 5 && b.int_wdt == 1);
    (void)tl_bootstat_count(&b, 3 /* ESP_RST_SW */);
    (void)tl_bootstat_count(&b, 7 /* ESP_RST_WDT (RTC / other) */);
    (void)tl_bootstat_count(&b, TL_RST_BROWNOUT);
    fails += ok("bootstat/other-reasons-only-total",
                b.boots == 8 && b.brownout == 2 && b.panic == 1 &&
                b.task_wdt == 1 && b.int_wdt == 1);

    /* A flipped bit (brown-out while RTC memory sagged, torn update)
     * fails the checksum: start over rather than report it. */
    tl_bootstat_t c = b;
    c.panic ^= 0x100;
    fails += ok("bootstat/bitflip-detected", !tl_bootstat_valid(&c));
    fails += ok("bootstat/bitflip-restarts",
                !tl_bootstat_count(&c, TL_RST_PANIC) && c.boots == 1 && c.panic == 1);

    /* Another layout version's record (same bytes, other magic). */
    c = b;
    c.magic ^= 0xFFu;
    c.check = tl_bootstat_check(&c);
    fails += ok("bootstat/other-magic-restarts",
                !tl_bootstat_count(&c, 3) && c.boots == 1);

    /* Random power-on contents never validate. */
    srand(1);
    int false_valid = 0;
    for (int i = 0; i < 100000; i++) {
        uint8_t *p = (uint8_t *)&c;
        for (size_t k = 0; k < sizeof(c); k++) p[k] = (uint8_t)rand();
        if (i % 2) c.magic = TL_BOOTSTAT_MAGIC;   /* half with the magic right */
        false_valid += tl_bootstat_valid(&c);
    }
    fails += ok("bootstat/random-never-valid", false_valid == 0);
}

static void fill_str(char *dst, size_t len, char ch)
{
    memset(dst, ch, len);
    dst[len] = '\0';
}

static int key_present(const char *js, const jsmntok_t *t, int n, const char *key)
{
    const size_t kl = strlen(key);
    for (int i = 1; i < n; i++) {
        if (t[i].type == JSMN_STRING && (size_t)(t[i].end - t[i].start) == kl &&
            memcmp(js + t[i].start, key, kl) == 0) {
            return 1;
        }
    }
    return 0;
}

static void test_stats_json(void)
{
    static char out[TL_STATS_JSON_CAP];
    char host[64];
    fill_str(host, 63, 'h');                 /* DNS label maximum */

    tinylink_stats_t st;
    memset(&st, 0, sizeof(st));
    st.uptime_s = UINT32_MAX;
    st.reset_reason = INT_MIN;               /* %d at its widest */
    st.boots = st.boots_brownout = st.boots_panic = UINT32_MAX;
    st.boots_task_wdt = st.boots_int_wdt = UINT32_MAX;
    st.heap_free = st.heap_min = st.heap_largest = UINT32_MAX;
    st.ntp_synced = false;                   /* "false" is the longer one */
    st.control_open = false;
    st.control_alive_age_s = st.control_reconnects = st.endpoint_pushes = UINT32_MAX;
    st.derp_connected = false;
    fill_str(st.derp_host, sizeof(st.derp_host) - 1, 'd');
    memset(st.public_v4, 255, sizeof(st.public_v4));
    st.public_port = UINT16_MAX;
    st.wg_state = INT_MIN;
    st.wg_rekeys = st.wg_cold_handshakes = st.wg_rx_stale_events = UINT32_MAX;
    st.wg_roams = st.wg_disco_adverts = st.wg_tx_drops = UINT32_MAX;
    st.wg_relayed_stale = st.wg_relay_errors = st.wg_last_rx_age_s = UINT32_MAX;
    st.wg_path = UINT8_MAX;
    st.wg_path_lapses = UINT32_MAX;

    /* Version at its widest plausible form, "255.255.255". */
    int len = tl_stats_json(out, sizeof(out), &st, host, "255.255.255", UINT32_MAX);
    printf("stats worst case: %d B of %d (version \"" TINYLINK_VERSION_STRING "\" "
           "is %zu B shorter)\n", len, TL_STATS_JSON_CAP,
           strlen("255.255.255") - strlen(TINYLINK_VERSION_STRING));
    fails += ok("stats/worst-case-fits", len > 0 && len < TL_STATS_JSON_CAP);

    jsmn_parser p;
    jsmntok_t tok[160];
    jsmn_init(&p);
    int n = jsmn_parse(&p, out, (size_t)len, tok, 160);
    fails += ok("stats/valid-json", n > 0 && tok[0].type == JSMN_OBJECT);
    fails += ok("stats/new-keys",
                n > 0 && key_present(out, tok, n, "heap_min") &&
                key_present(out, tok, n, "heap_largest") &&
                key_present(out, tok, n, "reset_reason") &&
                key_present(out, tok, n, "boots") &&
                key_present(out, tok, n, "brownout") &&
                key_present(out, tok, n, "task_wdt") &&
                key_present(out, tok, n, "int_wdt"));
    fails += ok("stats/path-keys",
                n > 0 && key_present(out, tok, n, "path") &&
                key_present(out, tok, n, "lapses"));

    /* A typical sensor reply for comparison. */
    memset(&st, 0, sizeof(st));
    st.uptime_s = 21600; st.reset_reason = 1; st.boots = 3;
    st.heap_free = 62700; st.heap_min = 31000; st.heap_largest = 31000;
    st.ntp_synced = true; st.control_open = true;
    snprintf(st.derp_host, sizeof(st.derp_host), "derp16b.tailscale.com");
    int typ = tl_stats_json(out, sizeof(out), &st, "sensor-test",
                            TINYLINK_VERSION_STRING, 4320);
    printf("stats typical: %d B\n", typ);
    fails += ok("stats/typical-fits", typ > 0 && typ < len);
}

int main(void)
{
    test_bootstat();
    test_stats_json();
    if (fails) return 1;
    printf("ALL OK\n");
    return 0;
}
