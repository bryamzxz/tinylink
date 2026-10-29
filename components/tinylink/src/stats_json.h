// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// The /stats reply: one JSON line built from tinylink_get_stats()
// (telemetry.c answers CONFIG_TINYLINK_STATS_PORT with it). Header-only
// so the host test can format the worst case — every counter at its
// type's widest value, a 63-char hostname and DERP host — and check it
// fits TL_STATS_JSON_CAP, since a truncated reply is not sent at all.
// Keys are only ever added (soak tooling reads them by name).

#pragma once

#include <stdint.h>
#include <stdio.h>

#include "tinylink.h"

/* Reply buffer (BSS). Worst case 862 B (test_stats prints it): 1.3.1's
 * line peaked at 721 B in a 768-B buffer; the boot counters (+113 B)
 * and heap_min (+22 B) do not fit that, hence 896 (+128 B BSS).
 * ~600 B on the sensor. */
#define TL_STATS_JSON_CAP 896

static inline int tl_stats_json(char *out, size_t cap,
                                const tinylink_stats_t *st,
                                const char *host, const char *version,
                                uint32_t telemetry_seq)
{
    return snprintf(out, cap,
        "{\"host\":\"%s\",\"version\":\"%s\",\"uptime_s\":%u,\"reset_reason\":%d,"
        "\"boots\":{\"total\":%u,\"brownout\":%u,\"panic\":%u,\"task_wdt\":%u,\"int_wdt\":%u},"
        "\"heap_free\":%u,\"heap_min\":%u,\"heap_largest\":%u,\"ntp_synced\":%s,"
        "\"control\":{\"open\":%s,\"alive_age_s\":%u,\"reconnects\":%u,\"endpoint_pushes\":%u},"
        "\"derp\":{\"connected\":%s,\"host\":\"%s\"},"
        "\"endpoint\":\"%u.%u.%u.%u:%u\","
        "\"wg\":{\"state\":%d,\"rekeys\":%u,\"cold_handshakes\":%u,\"rx_stale\":%u,"
        "\"roams\":%u,\"disco_adverts\":%u,\"tx_drops\":%u,\"relayed_stale\":%u,\"relay_errors\":%u,\"last_rx_age_s\":%u},"
        "\"telemetry_seq\":%u}\n",
        host, version,
        (unsigned)st->uptime_s, st->reset_reason,
        (unsigned)st->boots, (unsigned)st->boots_brownout, (unsigned)st->boots_panic,
        (unsigned)st->boots_task_wdt, (unsigned)st->boots_int_wdt,
        (unsigned)st->heap_free, (unsigned)st->heap_min, (unsigned)st->heap_largest,
        st->ntp_synced ? "true" : "false",
        st->control_open ? "true" : "false", (unsigned)st->control_alive_age_s,
        (unsigned)st->control_reconnects, (unsigned)st->endpoint_pushes,
        st->derp_connected ? "true" : "false", st->derp_host,
        st->public_v4[0], st->public_v4[1], st->public_v4[2], st->public_v4[3],
        (unsigned)st->public_port,
        st->wg_state, (unsigned)st->wg_rekeys, (unsigned)st->wg_cold_handshakes,
        (unsigned)st->wg_rx_stale_events, (unsigned)st->wg_roams,
        (unsigned)st->wg_disco_adverts,
        (unsigned)st->wg_tx_drops, (unsigned)st->wg_relayed_stale,
        (unsigned)st->wg_relay_errors, (unsigned)st->wg_last_rx_age_s,
        (unsigned)telemetry_seq);
}
