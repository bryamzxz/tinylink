// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#ifdef ESP_PLATFORM

#include "stun_probe.h"
#include "stun.h"

#include <string.h>
#include <errno.h>

#include "esp_log.h"
#include "esp_random.h"

#include "lwip/sockets.h"
#include "lwip/netdb.h"

static const char *TAG = "stun_probe";

/* Shared probe core. Sends one request on `sock`, polls up to 4
 * recvfroms for a matching response, populates *out on success. The
 * caller owns `sock` (open/close + bind). */
static esp_err_t do_probe(int sock,
                          const struct sockaddr *server_addr,
                          socklen_t server_addrlen,
                          uint32_t timeout_ms,
                          stun_probe_result_t *out)
{
    /* Bound recv timeout so a black-holed server doesn't park the boot
     * sequence forever. */
    struct timeval tv = {
        .tv_sec  = (time_t)(timeout_ms / 1000u),
        .tv_usec = (suseconds_t)((timeout_ms % 1000u) * 1000u),
    };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Build the request with a fresh random txid. The probe handler
     * verifies the response carries this same txid (basic anti-spoof:
     * a forged response would need to know our txid before we sent it). */
    uint8_t txid[STUN_TXID_LEN];
    esp_fill_random(txid, sizeof(txid));

    uint8_t req[STUN_REQUEST_LEN];
    if (stun_build_request(req, txid) != STUN_REQUEST_LEN) {
        ESP_LOGE(TAG, "stun_build_request failed");
        return ESP_FAIL;
    }

    ssize_t sent = sendto(sock, req, sizeof(req), 0,
                          server_addr, server_addrlen);
    if (sent != (ssize_t)sizeof(req)) {
        ESP_LOGW(TAG, "sendto failed: ret=%d errno=%d", (int)sent, errno);
        return ESP_FAIL;
    }

    /* Recv loop: discard any response that doesn't match our txid.
     * Bounded to 4 attempts so a chatty NAT doesn't keep us spinning. */
    uint8_t resp[256];
    for (int attempt = 0; attempt < 4; attempt++) {
        ssize_t got = recvfrom(sock, resp, sizeof(resp), 0, NULL, NULL);
        if (got < 0) {
            ESP_LOGW(TAG, "recvfrom timeout/error: errno=%d", errno);
            return ESP_FAIL;
        }
        uint8_t got_txid[STUN_TXID_LEN];
        stun_addr_t addr;
        int rc = stun_parse_response(resp, (size_t)got, got_txid, &addr);
        if (rc != 0) {
            ESP_LOGD(TAG, "parse_response: rc=%d (skip, retry)", rc);
            continue;
        }
        if (memcmp(got_txid, txid, STUN_TXID_LEN) != 0) {
            ESP_LOGD(TAG, "txid mismatch (skip)");
            continue;
        }
        if (addr.is_v6) {
            /* Unexpected: we asked for AF_INET; v6 response means the
             * server sent us its own v6 address. Drop and retry. */
            ESP_LOGD(TAG, "got v6 mapped addr, expected v4 (skip)");
            continue;
        }
        /* addr is v4-mapped (::ffff:a.b.c.d). The 4 v4 octets are at
         * the tail. */
        out->addr_v4[0] = addr.addr[12];
        out->addr_v4[1] = addr.addr[13];
        out->addr_v4[2] = addr.addr[14];
        out->addr_v4[3] = addr.addr[15];
        out->port  = addr.port;
        out->valid = true;
        ESP_LOGI(TAG, "public endpoint: %u.%u.%u.%u:%u",
                 out->addr_v4[0], out->addr_v4[1], out->addr_v4[2], out->addr_v4[3],
                 (unsigned)out->port);
        return ESP_OK;
    }

    ESP_LOGW(TAG, "no matching STUN response in 4 attempts");
    return ESP_FAIL;
}

static esp_err_t resolve_server(const char *host, uint16_t port,
                                struct sockaddr_in *out)
{
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
        return ESP_FAIL;
    }
    /* getaddrinfo with AF_INET hint always returns a sockaddr_in. */
    memcpy(out, res->ai_addr, sizeof(*out));
    freeaddrinfo(res);
    return ESP_OK;
}

esp_err_t stun_probe_run(const char *server_host, uint16_t server_port,
                         uint32_t timeout_ms, stun_probe_result_t *out)
{
    if (server_host == NULL || out == NULL || server_port == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    out->valid = false;

    struct sockaddr_in server;
    if (resolve_server(server_host, server_port, &server) != ESP_OK) {
        return ESP_FAIL;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket() failed: errno=%d", errno);
        return ESP_FAIL;
    }

    esp_err_t err = do_probe(sock,
                             (struct sockaddr *)&server, sizeof(server),
                             timeout_ms, out);
    close(sock);
    return err;
}

esp_err_t stun_probe_run_on_socket(int sock,
                                   const char *server_host,
                                   uint16_t server_port,
                                   uint32_t timeout_ms,
                                   stun_probe_result_t *out)
{
    if (sock < 0 || server_host == NULL || out == NULL || server_port == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    out->valid = false;

    struct sockaddr_in server;
    if (resolve_server(server_host, server_port, &server) != ESP_OK) {
        return ESP_FAIL;
    }
    return do_probe(sock,
                    (struct sockaddr *)&server, sizeof(server),
                    timeout_ms, out);
}

#endif /* ESP_PLATFORM */
