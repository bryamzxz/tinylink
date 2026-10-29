// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// The servers' last-known IPv4 addresses (round 1.3.5): DNS off the boot
// path. Two records in NVS `tl_state`, each written only when its bytes
// change:
//
//   derp_node  the home DERP node as the netmap last named it — HostName,
//              DERPPort, IPv4 and STUNPort of the first node of region
//              CONFIG_TINYLINK_PREFERRED_DERP. The supervisor dials its
//              IPv4 (SNI and the certificate check stay on HostName) and
//              the STUN probes ask its STUN service (UDP 3478).
//   ctl_addr   the address of the last control conn that came up; every
//              ts2021 connect dials it before resolving the control host.
//
// Why. DNS on the sensor's network loses queries: over 30 boot captures
// (1.3.3 / 1.3.4) got-ip → STUN "public endpoint" took 0.08–0.64 s in 18
// and 1.11–7.15 s in the other 12, exactly lwIP's resend schedule (dns.c:
// 1, 2, 4, 7 s). In 1.3.5 the STUN, DERP and control lookups all start
// within ~50 ms of got-ip: the DERP TLS connect took 1.79–6.36 s (1.6–
// 2.2 s on its own in 1.3.4), and a STUN lookup that needed a resend
// missed the endpoint push (stun_boot.h). Upstream needs no DNS here
// either: tailcfg.DERPNode.IPv4 "forces an IPv4 address to use, instead
// of using DNS" (derphttp dialNode, netcheck nodeAddrPort), and
// controlclient keeps the last good control address (dnscache
// UseLastGood) on top of net/dnsfallback's baked-in ones.
//
// Trust. An address only says where the SYN goes. The server is
// authenticated exactly as before — Noise IK against the pinned control
// key on :80, the certificate chain against the host NAME on :443 and on
// DERP — and the DNS answers these records stand in for were never
// authenticated either. A stale or forged address can only make a
// connect fail, and every caller then resolves the name in the same
// attempt (ts2021_client.c, derp_client.c).
//
// Everything here is pure and host-tested (tools/test/test_addr.c); the
// NVS calls and the locking are in tinylink.c.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "netmap.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TL_ADDR_HOST_MAX     TL_DERP_HOSTNAME_LEN   /* NUL included */
#define TL_IPV4_STRLEN       16                     /* "255.255.255.255" */
#define TL_STUN_DEFAULT_PORT 3478                   /* tailcfg STUNPort 0 */

/* NVS keys (namespace tl_state). */
#define TL_ADDR_KEY_DERP     "derp_node"
#define TL_ADDR_KEY_CTL      "ctl_addr"

/* ---- IPv4 literals --------------------------------------------------- */

/* A dotted-quad IPv4 literal of exactly n bytes, as Go's netip.ParseAddr
 * takes it (the DERP map is Go-encoded): four decimal fields 0..255, no
 * sign, no leading zero, nothing around them. tailcfg's "none" (IPv4
 * disabled), an IPv6 literal or a host name are not. */
static inline bool tl_ipv4_parse(const char *s, size_t n, uint8_t out[4])
{
    uint8_t ip[4];
    size_t  i = 0;
    for (int f = 0; f < 4; f++) {
        if (f > 0) {
            if (i >= n || s[i] != '.') return false;
            i++;
        }
        const size_t d0 = i;
        unsigned v = 0;
        while (i < n && i - d0 < 3 && s[i] >= '0' && s[i] <= '9') {
            v = v * 10u + (unsigned)(s[i] - '0');
            i++;
        }
        if (i == d0 || v > 255u || (i - d0 > 1 && s[d0] == '0')) return false;
        if (i < n && s[i] >= '0' && s[i] <= '9') return false;   /* 4+ digits */
        ip[f] = (uint8_t)v;
    }
    if (i != n) return false;
    memcpy(out, ip, 4);
    return true;
}

/* Worth a connect: unicast outside 0.0.0.0/8 (0.0.0.0 is also "none" in
 * the records), 127.0.0.0/8 and 224.0.0.0/3 (multicast, reserved,
 * broadcast). Private ranges stay: a self-hosted DERP or headscale on
 * the LAN is legitimate. */
static inline bool tl_ipv4_usable(const uint8_t ip[4])
{
    return ip != NULL && ip[0] != 0 && ip[0] != 127 && ip[0] < 224;
}

static inline void tl_ipv4_str(const uint8_t ip[4], char out[TL_IPV4_STRLEN])
{
    snprintf(out, TL_IPV4_STRLEN, "%u.%u.%u.%u",
             (unsigned)ip[0], (unsigned)ip[1], (unsigned)ip[2], (unsigned)ip[3]);
}

/* tailcfg.DERPNode.STUNPort (a JSON number) as the port to send STUN to:
 * 0 → 3478, 1..65535 as given; -1 (STUN off on the node) and anything
 * that is not a port → 0, i.e. not probed (netcheck nodeAddrPort: port
 * < 0 or > 65535 → no STUN). */
static inline uint16_t tl_stun_port_parse(const char *s, size_t n)
{
    if (n == 0 || n > 6) return 0;
    long v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return 0;   /* "-1", "1e3", "3478.0" */
        v = v * 10 + (s[i] - '0');
    }
    if (v == 0) return TL_STUN_DEFAULT_PORT;
    return v <= 65535 ? (uint16_t)v : 0;
}

/* Host-name bytes only (letters, digits, '-', '.'), 1..63 of them: a
 * record's host goes into the SNI, the certificate check and the HTTP
 * Host header, so a corrupted NVS blob must not put a CR / LF there. */
static inline bool tl_host_ok(const char *h, size_t n)
{
    if (h == NULL || n == 0 || n >= TL_ADDR_HOST_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        const char c = h[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '.')) {
            return false;
        }
    }
    return true;
}

/* ---- The home DERP node ---------------------------------------------- */

typedef struct {
    uint16_t region;                   /* DERPRegion ID */
    uint16_t port;                     /* DERPPort; 0 = 443 */
    uint16_t stun_port;                /* 0 = no STUN on the node */
    uint8_t  ipv4[4];                  /* 0.0.0.0 = none: resolve host */
    char     host[TL_ADDR_HOST_MAX];
} tl_derp_addr_t;

/* Blob layout: version ‖ region ‖ port ‖ stun_port (LE16 each) ‖ ipv4 ‖
 * host (no NUL) — 12..74 B. The control record: version ‖ ipv4 ‖ the
 * control host it belongs to, so a firmware built for another control
 * host ignores it. */
#define TL_ADDR_REC_V1    1
#define TL_DERP_ADDR_HDR  11
#define TL_CTL_ADDR_HDR   5
#define TL_ADDR_BLOB_MAX  (TL_DERP_ADDR_HDR + TL_ADDR_HOST_MAX - 1)

static inline size_t tl_derp_addr_encode(const tl_derp_addr_t *a,
                                         uint8_t *b, size_t cap)
{
    const size_t hn = strnlen(a->host, sizeof(a->host));
    if (!tl_host_ok(a->host, hn) || cap < TL_DERP_ADDR_HDR + hn) return 0;
    b[0] = TL_ADDR_REC_V1;
    b[1] = (uint8_t)a->region;    b[2] = (uint8_t)(a->region >> 8);
    b[3] = (uint8_t)a->port;      b[4] = (uint8_t)(a->port >> 8);
    b[5] = (uint8_t)a->stun_port; b[6] = (uint8_t)(a->stun_port >> 8);
    memcpy(b + 7, a->ipv4, 4);
    memcpy(b + TL_DERP_ADDR_HDR, a->host, hn);
    return TL_DERP_ADDR_HDR + hn;
}

static inline bool tl_derp_addr_decode(const uint8_t *b, size_t n,
                                       tl_derp_addr_t *out)
{
    if (b == NULL || n <= TL_DERP_ADDR_HDR || n > TL_ADDR_BLOB_MAX ||
        b[0] != TL_ADDR_REC_V1) {
        return false;
    }
    const char  *h  = (const char *)b + TL_DERP_ADDR_HDR;
    const size_t hn = n - TL_DERP_ADDR_HDR;
    if (!tl_host_ok(h, hn)) return false;
    tl_derp_addr_t a;
    memset(&a, 0, sizeof(a));
    a.region    = (uint16_t)(b[1] | (b[2] << 8));
    a.port      = (uint16_t)(b[3] | (b[4] << 8));
    a.stun_port = (uint16_t)(b[5] | (b[6] << 8));
    if (tl_ipv4_usable(b + 7)) memcpy(a.ipv4, b + 7, 4);
    memcpy(a.host, h, hn);
    *out = a;
    return true;
}

/* The record the netmap names for `region`: its first node — the node
 * the supervisor dials (tinylink.c) — or false when the map has none
 * there. An address tl_ipv4_usable rejects is kept as none. */
static inline bool tl_derp_addr_from_netmap(const tl_netmap_t *nm, int region,
                                            tl_derp_addr_t *out)
{
    _Static_assert(sizeof(((tl_derp_addr_t *)0)->host) ==
                   sizeof(((tl_derp_node_t *)0)->hostname), "host sizes");
    if (nm == NULL || region <= 0 || region > 0xffff) return false;
    for (size_t i = 0; i < nm->n_derp_regions; i++) {
        const tl_derp_region_t *r = &nm->derp_regions[i];
        if (r->region_id != region || r->n_nodes == 0) continue;
        const tl_derp_node_t *dn = &r->nodes[0];
        if (dn->hostname[0] == '\0') continue;
        tl_derp_addr_t a;
        memset(&a, 0, sizeof(a));
        a.region    = (uint16_t)region;
        a.port      = dn->port;
        a.stun_port = dn->stun_port;
        if (tl_ipv4_usable(dn->ipv4)) memcpy(a.ipv4, dn->ipv4, 4);
        memcpy(a.host, dn->hostname, sizeof(a.host));
        a.host[sizeof(a.host) - 1] = '\0';
        *out = a;
        return true;
    }
    return false;
}

/* The record to boot with: the stored one when it is for this
 * firmware's home region (a new CONFIG_TINYLINK_PREFERRED_DERP makes it
 * stale), else the Kconfig host without an address. */
static inline void tl_derp_addr_boot(const uint8_t *b, size_t n, int region,
                                     const char *kconfig_host, tl_derp_addr_t *out)
{
    tl_derp_addr_t a;
    if (region > 0 && tl_derp_addr_decode(b, n, &a) && a.region == region) {
        *out = a;
        return;
    }
    memset(out, 0, sizeof(*out));
    out->region = (uint16_t)(region > 0 ? region : 0);
    snprintf(out->host, sizeof(out->host), "%s", kconfig_host ? kconfig_host : "");
}

/* What a netmap's record changes against the current one. MOVED (host or
 * DERP port): the supervisor leaves its stream for the new node. ADDR
 * (address or STUN port only): taken at the next connect / probe — the
 * live stream to that host is fine. */
#define TL_DERP_MOVED 1u
#define TL_DERP_ADDR  2u

static inline unsigned tl_derp_addr_diff(const tl_derp_addr_t *cur,
                                         const tl_derp_addr_t *next)
{
    unsigned d = 0;
    if (strcmp(cur->host, next->host) != 0 || cur->port != next->port ||
        cur->region != next->region) {
        d |= TL_DERP_MOVED;
    }
    if (memcmp(cur->ipv4, next->ipv4, 4) != 0 || cur->stun_port != next->stun_port) {
        d |= TL_DERP_ADDR;
    }
    return d;
}

/* The home DERP node's STUN service, when the record has its address:
 * the probes then need no DNS (netcheck asks the same service). */
static inline bool tl_derp_addr_stun(const tl_derp_addr_t *a, uint8_t ip[4],
                                     uint16_t *port)
{
    if (a == NULL || !tl_ipv4_usable(a->ipv4) || a->stun_port == 0) return false;
    memcpy(ip, a->ipv4, 4);
    *port = a->stun_port;
    return true;
}

/* ---- The control plane's last good address --------------------------- */

static inline size_t tl_ctl_addr_encode(const uint8_t ip[4], const char *host,
                                        uint8_t *b, size_t cap)
{
    const size_t hn = host != NULL ? strlen(host) : 0;
    if (!tl_ipv4_usable(ip) || !tl_host_ok(host, hn) || cap < TL_CTL_ADDR_HDR + hn) {
        return 0;
    }
    b[0] = TL_ADDR_REC_V1;
    memcpy(b + 1, ip, 4);
    memcpy(b + TL_CTL_ADDR_HDR, host, hn);
    return TL_CTL_ADDR_HDR + hn;
}

static inline bool tl_ctl_addr_decode(const uint8_t *b, size_t n, const char *host,
                                      uint8_t ip[4])
{
    const size_t hn = host != NULL ? strlen(host) : 0;
    if (b == NULL || hn == 0 || n != TL_CTL_ADDR_HDR + hn || b[0] != TL_ADDR_REC_V1 ||
        memcmp(b + TL_CTL_ADDR_HDR, host, hn) != 0 || !tl_ipv4_usable(b + 1)) {
        return false;
    }
    memcpy(ip, b + 1, 4);
    return true;
}

/* ---- Written only on change ------------------------------------------ */

/* What one NVS blob holds, mirrored in RAM: loaded at boot and compared
 * before every write, so a record costs a flash write only when its bytes
 * change (an NVS write may erase a 4-KB sector, which stalls both CPUs —
 * tl_time.c). len 0 = nothing stored. */
typedef struct {
    uint8_t len;
    uint8_t b[TL_ADDR_BLOB_MAX];
} tl_addr_blob_t;

/* 0 = written, else failed. */
typedef int (*tl_addr_write_fn)(const uint8_t *b, size_t n, const void *ctx);

/* 0 = unchanged (nothing written), 1 = written, -1 = the write failed or
 * the record is empty / too long. Like reg_hint_store, the mirror takes
 * the new bytes even when the write fails: a broken NVS costs the next
 * boot a cache miss (DNS, as before), never a write attempt per call. */
static inline int tl_addr_store(tl_addr_blob_t *m, const uint8_t *b, size_t n,
                                tl_addr_write_fn write, const void *ctx)
{
    if (n == 0 || n > sizeof(m->b)) return -1;
    if (m->len == n && memcmp(m->b, b, n) == 0) return 0;
    memcpy(m->b, b, n);
    m->len = (uint8_t)n;
    return write(b, n, ctx) == 0 ? 1 : -1;
}

#ifdef __cplusplus
}
#endif
