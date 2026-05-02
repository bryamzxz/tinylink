// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// esp_netif glue for tinylink_wg. Creates a custom esp_netif of
// PPP-flagged type (so DHCP callbacks don't trigger on it the way
// they do for ETH/STA netifs — that was the IDF v5.5 panic that
// killed the trombik-based dataplane on first HW boot 2026-05-02),
// attaches a transmit callback that encrypts via wg_netif, and
// registers an RX callback in wg_netif that injects the decrypted
// plaintext IP back into lwIP via esp_netif_receive.

#pragma once

#ifdef ESP_PLATFORM

#include <stdint.h>

#include "esp_err.h"
#include "esp_netif.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Bring up the WG tunnel netif:
 *   - local_ip_be: tunnel-side v4 in network byte order (e.g. 100.x.y.z)
 *   - mtu:         WG MTU (typical 1280, max 1420 for IPv4 over IPv4)
 * Must be called AFTER wg_netif_init/start so the protocol engine is
 * ready to consume plaintext IP packets via wg_netif_send_plaintext. */
esp_err_t wg_lwip_attach(uint32_t local_ip_be, uint16_t mtu);

/* Tear down — releases the esp_netif and its driver. */
void wg_lwip_detach(void);

#ifdef __cplusplus
}
#endif

#endif /* ESP_PLATFORM */
