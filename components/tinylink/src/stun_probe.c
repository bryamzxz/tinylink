// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#ifdef ESP_PLATFORM

#include "stun_probe.h"

#include <stdio.h>
#include <string.h>

#include "esp_log.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"

static const char *TAG = "stun_probe";

esp_err_t stun_probe_resolve(const char *host, uint16_t port,
                             struct sockaddr_in *out)
{
    if (host == NULL || out == NULL || port == 0) return ESP_ERR_INVALID_ARG;
    struct addrinfo hints = {
        .ai_family   = AF_INET,
        .ai_socktype = SOCK_DGRAM,
    };
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo *res = NULL;
    int gai = getaddrinfo(host, port_str, &hints, &res);
    if (gai != 0 || res == NULL) {
        ESP_LOGW(TAG, "getaddrinfo(%s:%u) failed: %d", host,
                 (unsigned)port, gai);
        if (res != NULL) freeaddrinfo(res);
        return ESP_FAIL;
    }
    /* getaddrinfo with AF_INET hint always returns a sockaddr_in. */
    memcpy(out, res->ai_addr, sizeof(*out));
    freeaddrinfo(res);
    return ESP_OK;
}

#endif /* ESP_PLATFORM */
