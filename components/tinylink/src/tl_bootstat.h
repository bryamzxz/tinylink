// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Boot counters for /stats (1.3.2): how many boots, and how many of them
// followed a brown-out, a panic, a task-WDT or an interrupt-WDT reset.
// The record lives in RTC no-init memory (tinylink.c, RTC_NOINIT_ATTR):
// RTC slow memory keeps its contents across every reset except a power
// loss, and the startup code never clears .rtc_noinit. After a power-on
// (or a brown-out deep enough to lose RTC memory, or a new firmware that
// moved the variable) the bytes are garbage, so the record carries a
// magic and a checksum and restarts from zero when either fails.
//
// Counted once per boot from esp_reset_reason(), which on the ESP32
// reports a panic / WDT / brown-out reset through the RTC reset-reason
// hint the panic and brown-out handlers leave behind (IDF
// reset_reason.c). Pure logic, header-only so the host tests cover it.

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* esp_reset_reason_t values (esp_system.h), restated so the header
 * builds on the host; tinylink.c static-asserts they still match. */
#define TL_RST_PANIC     4
#define TL_RST_INT_WDT   5
#define TL_RST_TASK_WDT  6
#define TL_RST_BROWNOUT  9

/* "TLB" + layout version: a changed struct must not validate old bytes. */
#define TL_BOOTSTAT_MAGIC 0x544C4201u

typedef struct {
    uint32_t magic;
    uint32_t boots;          /* every boot, this one included */
    uint32_t brownout;
    uint32_t panic;
    uint32_t task_wdt;
    uint32_t int_wdt;
    uint32_t check;          /* tl_bootstat_check() of the words above */
} tl_bootstat_t;

/* FNV-1a over the counted words. Not cryptographic — it only has to
 * reject random power-on contents and a torn update. */
static inline uint32_t tl_bootstat_check(const tl_bootstat_t *b)
{
    const uint32_t w[6] = { b->magic, b->boots, b->brownout,
                            b->panic, b->task_wdt, b->int_wdt };
    uint32_t h = 2166136261u;
    for (unsigned i = 0; i < 6; i++) {
        for (unsigned k = 0; k < 4; k++) {
            h ^= (w[i] >> (8 * k)) & 0xFFu;
            h *= 16777619u;
        }
    }
    return h;
}

static inline bool tl_bootstat_valid(const tl_bootstat_t *b)
{
    return b->magic == TL_BOOTSTAT_MAGIC && b->check == tl_bootstat_check(b);
}

/* Count one boot whose reset reason is `reason` (esp_reset_reason_t).
 * An invalid record is zeroed first. Returns whether the record was
 * valid, i.e. whether the counters span earlier boots. */
static inline bool tl_bootstat_count(tl_bootstat_t *b, int reason)
{
    const bool valid = tl_bootstat_valid(b);
    if (!valid) {
        memset(b, 0, sizeof(*b));
        b->magic = TL_BOOTSTAT_MAGIC;
    }
    b->boots++;
    switch (reason) {
    case TL_RST_BROWNOUT: b->brownout++; break;
    case TL_RST_PANIC:    b->panic++;    break;
    case TL_RST_TASK_WDT: b->task_wdt++; break;
    case TL_RST_INT_WDT:  b->int_wdt++;  break;
    default: break;
    }
    b->check = tl_bootstat_check(b);
    return valid;
}
