// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Wi-Fi association diagnostics (round 1.3.7, CONFIG_TINYLINK_WIFI_DIAG,
// default n): the EAPOL timeline of each association attempt, recorded
// from the Wi-Fi task without logging there and printed from the event
// handler. See wifi_diag.c and the Kconfig help.

#pragma once

#include <stdint.h>

#include "sdkconfig.h"

#if CONFIG_TINYLINK_WIFI_DIAG

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WIFI_DIAG_CONNECTED = 1,   /* a = channel */
    WIFI_DIAG_DISCONNECTED,    /* a = reason, b = RSSI */
    WIFI_DIAG_GOT_IP,
    WIFI_DIAG_RETRY,           /* a = channel of the next attempt, b = delay ms (≤ 32 767) */
} wifi_diag_event_t;

/* At STA start, before the first esp_wifi_connect: arms the sniffer
 * (CONFIG_TINYLINK_WIFI_DIAG_SNIFF). */
void wifi_diag_start(void);

/* An application-side event, timestamped now. */
void wifi_diag_note(wifi_diag_event_t ev, uint16_t a, int16_t b);

/* Print what was recorded since the last flush (event-handler context).
 * The first flush after got-ip also stops the sniffer. */
void wifi_diag_flush(void);

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_TINYLINK_WIFI_DIAG */
