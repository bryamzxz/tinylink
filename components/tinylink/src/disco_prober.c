// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "disco_prober.h"

#include <string.h>

#ifdef ESP_PLATFORM
#include "freertos/FreeRTOS.h"
/* portMUX_TYPE / taskENTER_CRITICAL: cheapest available cross-task
 * mutual exclusion on ESP32-LX6 (~16 cycles per acquire/release). */
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;
#define PROBER_LOCK()   taskENTER_CRITICAL(&s_lock)
#define PROBER_UNLOCK() taskEXIT_CRITICAL(&s_lock)
#else
/* Host build: tests are single-threaded, no locking needed. */
#define PROBER_LOCK()   ((void)0)
#define PROBER_UNLOCK() ((void)0)
#endif

struct prober_slot {
    uint8_t  txid[DISCO_TXID_LEN];
    uint32_t dst_v4_be;     /* network order */
    uint16_t dst_port;      /* host order */
    int64_t  sent_us;       /* monotonic μs of the originating sendto */
    bool     valid;
};

static struct prober_slot s_table[DISCO_PROBER_TABLE_SIZE];

void disco_prober_init(void)
{
    PROBER_LOCK();
    memset(s_table, 0, sizeof(s_table));
    PROBER_UNLOCK();
}

void disco_prober_reset(void)
{
    disco_prober_init();
}

void disco_prober_record(const uint8_t txid[DISCO_TXID_LEN],
                         uint32_t dst_v4_be, uint16_t dst_port,
                         int64_t now_us)
{
    if (txid == NULL) return;

    PROBER_LOCK();

    /* Find a slot: first invalid, else first expired, else oldest. */
    int target = -1;
    int oldest = 0;
    const int64_t expiry_threshold_us =
        now_us - (int64_t)DISCO_PROBER_TIMEOUT_MS * 1000LL;

    for (int i = 0; i < DISCO_PROBER_TABLE_SIZE; i++) {
        if (!s_table[i].valid) {
            target = i;
            break;
        }
        if (s_table[i].sent_us < expiry_threshold_us) {
            target = i;
            break;
        }
        if (s_table[i].sent_us < s_table[oldest].sent_us) {
            oldest = i;
        }
    }
    if (target < 0) {
        /* Table full of fresh in-flight entries. Evict the oldest
         * (LRU) — that probe's Pong, if it still arrives, will fail
         * the match and be dropped silently. Bounded fallout: the
         * peer can always retry on the next prepunch cycle. */
        target = oldest;
    }

    memcpy(s_table[target].txid, txid, DISCO_TXID_LEN);
    s_table[target].dst_v4_be = dst_v4_be;
    s_table[target].dst_port  = dst_port;
    s_table[target].sent_us   = now_us;
    s_table[target].valid     = true;

    PROBER_UNLOCK();
}

bool disco_prober_match_and_remove(const uint8_t txid[DISCO_TXID_LEN],
                                   uint32_t src_v4_be, uint16_t src_port,
                                   int64_t now_us)
{
    if (txid == NULL) return false;

    bool matched = false;
    const int64_t expiry_threshold_us =
        now_us - (int64_t)DISCO_PROBER_TIMEOUT_MS * 1000LL;

    PROBER_LOCK();
    for (int i = 0; i < DISCO_PROBER_TABLE_SIZE; i++) {
        if (!s_table[i].valid) continue;
        if (memcmp(s_table[i].txid, txid, DISCO_TXID_LEN) != 0) continue;
        /* txid match. Bind the result to the probed destination: a Pong
         * from any source other than the AddrPort we pinged is a spoofed
         * replay and is rejected WITHOUT consuming the slot, so it cannot
         * lock out the genuine Pong that is still in flight. */
        if (s_table[i].dst_v4_be != src_v4_be ||
            s_table[i].dst_port  != src_port) {
            break;
        }
        /* Source matches. Check freshness. */
        if (s_table[i].sent_us >= expiry_threshold_us) {
            matched = true;
        }
        /* Whether stale or fresh, remove the slot — the same probe
         * cannot legitimately match twice (the responder MUST generate
         * a fresh txid for each ping; a duplicate matching pong is a
         * replay attempt). */
        memset(&s_table[i], 0, sizeof(s_table[i]));
        break;
    }
    PROBER_UNLOCK();

    return matched;
}
