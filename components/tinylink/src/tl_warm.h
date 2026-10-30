// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Warm start (round 1.3.9, CONFIG_TINYLINK_WARM_START): WireGuard up from
// the previous boot's netmap instead of after this boot's.
//
// Why. On the 1.3.8 sensor the WireGuard bring-up waits for the whole
// control path: got-ip 1.62 s, register 2.23 s, endpoint push 2.43 s,
// map stream headers 2.62 s, and the first netmap complete 3.6–7.7 s
// (its ~26 KB body alone took 0.7–6.2 s), then wg_dataplane_start and the
// session ~0.1–0.2 s later. What wg_dataplane_start consumes from that
// netmap is small and changes rarely: our tailnet address(es) and the
// one peer the session runs against (select_target_peer) — its NodeID,
// NodeKey, DiscoKey, endpoints and tailnet addresses. Our keys are in
// NVS already (keys.c).
//
// The record, NVS `tl_state` / "warm_rec", binary, 109..141 B:
//
//   0   version (TL_WARM_REC_V1: another layout is ignored, not parsed)
//   1   written, LE32 Unix seconds (0: the clock was not synced)
//   5   our NodeKey's first 8 bytes, 13 the control key's: a record
//       written under other keys or for another control plane is ignored
//   21  n_self (1..2), n_addr (0..2), n_ep (1..4), flags (bit 0: DiscoKey)
//   25  the peer's NodeID, LE64
//   33  its NodeKey, 65 its DiscoKey (zero without one)
//   97  n_self × (IPv4, prefix), n_addr × (IPv4, prefix),
//       n_ep × (IPv4, LE16 port)
//
// Everything is IPv4 like the rest of the data plane (netmap.h). The
// strings wg_dataplane_start parses are re-made from it in Go's canonical
// form ("100.64.0.1/32", "198.51.100.7:41641") — the netmap's own form,
// so the warm start passes it byte for byte what the cold start would
// have from the same netmap (test_warm.c checks the round trip).
//
// Written only from the telemetry task's 60-s housekeeping, only when the
// content differs from what NVS holds (the timestamp aside): a change of
// peer, NodeKey or a tailnet address at the next housekeeping, a change
// of endpoints or DiscoKey alone at most once an hour after the boot's
// first write (tl_warm_store_due) — those the netmap update absorbs in
// place at the next boot anyway (endpoint roam, key update), and an
// endpoint list that churns must not erase a flash sector every minute.
//
// Everything here is pure and host-tested (tools/test/test_warm.c); the
// NVS calls, the locking and the bring-up are in tinylink.c.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "netmap.h"
#include "tl_addr.h"   /* tl_ipv4_parse, tl_ipv4_usable */

#ifdef __cplusplus
extern "C" {
#endif

#define TL_WARM_KEY       "warm_rec"   /* NVS key, namespace tl_state */
#define TL_WARM_REC_V1    1
#define TL_WARM_TAG_LEN   8
#define TL_WARM_HDR       97
#define TL_WARM_CIDR_LEN  5
#define TL_WARM_EP_LEN    6
#define TL_WARM_BLOB_MIN  (TL_WARM_HDR + TL_WARM_CIDR_LEN + TL_WARM_EP_LEN)
#define TL_WARM_BLOB_MAX  (TL_WARM_HDR + TL_WARM_CIDR_LEN * 2 * TL_MAX_PEER_ADDRESSES + \
                           TL_WARM_EP_LEN * TL_MAX_PEER_ENDPOINTS)

/* Soft-only changes (endpoints, DiscoKey) are written at most this often
 * once the boot has written the record. */
#define TL_WARM_SOFT_MIN_US (3600LL * 1000000LL)

typedef struct {
    uint8_t ip[4];
    uint8_t prefix;
} tl_warm_cidr_t;

typedef struct {
    uint8_t  ip[4];
    uint16_t port;
} tl_warm_ep_t;

typedef struct {
    uint64_t       id;                             /* NodeID */
    uint8_t        node_pub[TINYLINK_KEY_LEN];
    uint8_t        disco_pub[TINYLINK_KEY_LEN];    /* zero when !has_disco */
    uint8_t        has_disco;
    uint8_t        n_addr;
    uint8_t        n_ep;
    tl_warm_cidr_t addr[TL_MAX_PEER_ADDRESSES];
    tl_warm_ep_t   ep[TL_MAX_PEER_ENDPOINTS];
} tl_warm_peer_t;

typedef struct {
    uint32_t       written;                        /* Unix s at the write, 0 = unknown */
    uint8_t        self_tag[TL_WARM_TAG_LEN];      /* our NodeKey's first bytes */
    uint8_t        ctl_tag[TL_WARM_TAG_LEN];       /* the control key's */
    uint8_t        n_self;                         /* 0: self[0] unusable */
    tl_warm_cidr_t self[TL_MAX_PEER_ADDRESSES];
    tl_warm_peer_t peer;
} tl_warm_rec_t;

/* ---- Text forms --------------------------------------------------------- */

/* 1..5 decimal digits, no sign, no leading zero, ≤ max. */
static inline bool tl_warm_dec(const char *s, size_t n, unsigned max, unsigned *out)
{
    if (n == 0 || n > 5 || (n > 1 && s[0] == '0')) return false;
    unsigned v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return false;
        v = v * 10u + (unsigned)(s[i] - '0');
    }
    if (v > max) return false;
    *out = v;
    return true;
}

/* "a.b.c.d/p" as Go's netip.Prefix prints it: a dotted quad, a prefix
 * 0..32, nothing else — and an address tl_ipv4_usable takes, as the
 * decode below does (what could not be read back is not written). */
static inline bool tl_warm_cidr_parse(const char *s, tl_warm_cidr_t *out)
{
    const size_t n = strnlen(s, TL_CIDR_STRLEN);
    const char *slash = (const char *)memchr(s, '/', n);
    if (n == TL_CIDR_STRLEN || slash == NULL) return false;
    tl_warm_cidr_t c;
    unsigned p = 0;
    if (!tl_ipv4_parse(s, (size_t)(slash - s), c.ip) || !tl_ipv4_usable(c.ip) ||
        !tl_warm_dec(slash + 1, n - (size_t)(slash - s) - 1, 32, &p)) {
        return false;
    }
    c.prefix = (uint8_t)p;
    *out = c;
    return true;
}

/* "a.b.c.d:port" as Go's netip.AddrPort prints an IPv4 one, port 1..65535
 * (wg_dataplane.c parse_endpoint refuses 0 too), a usable address. */
static inline bool tl_warm_ep_parse(const char *s, tl_warm_ep_t *out)
{
    const size_t n = strnlen(s, TL_ENDPOINT_STRLEN);
    const char *colon = (const char *)memchr(s, ':', n);
    if (n == TL_ENDPOINT_STRLEN || colon == NULL) return false;
    tl_warm_ep_t e;
    unsigned p = 0;
    if (!tl_ipv4_parse(s, (size_t)(colon - s), e.ip) || !tl_ipv4_usable(e.ip) ||
        !tl_warm_dec(colon + 1, n - (size_t)(colon - s) - 1, 65535, &p) || p == 0) {
        return false;
    }
    e.port = (uint16_t)p;
    *out = e;
    return true;
}

static inline void tl_warm_cidr_str(const tl_warm_cidr_t *c, tl_cidr_t *out)
{
    snprintf(out->str, sizeof(out->str), "%u.%u.%u.%u/%u", (unsigned)c->ip[0],
             (unsigned)c->ip[1], (unsigned)c->ip[2], (unsigned)c->ip[3], (unsigned)c->prefix);
}

static inline void tl_warm_ep_str(const tl_warm_ep_t *e, tl_endpoint_t *out)
{
    snprintf(out->str, sizeof(out->str), "%u.%u.%u.%u:%u", (unsigned)e->ip[0],
             (unsigned)e->ip[1], (unsigned)e->ip[2], (unsigned)e->ip[3], (unsigned)e->port);
}

/* ---- From / to the netmap's types --------------------------------------- */

/* The peer as the record keeps it. An address or endpoint that does not
 * parse is left out, the others keep their order — wg_dataplane skips
 * such entries as well (parse_endpoint, first_host_v4), and the endpoint
 * pick and the TSMP address go by order. */
static inline void tl_warm_peer_from(const tl_peer_t *p, tl_warm_peer_t *out)
{
    memset(out, 0, sizeof(*out));
    out->id = p->id;
    memcpy(out->node_pub, p->node_pub, TINYLINK_KEY_LEN);
    if (p->has_disco_pub) {
        out->has_disco = 1;
        memcpy(out->disco_pub, p->disco_pub, TINYLINK_KEY_LEN);
    }
    for (size_t i = 0; i < p->n_addresses && i < TL_MAX_PEER_ADDRESSES; i++) {
        if (tl_warm_cidr_parse(p->addresses[i].str, &out->addr[out->n_addr])) out->n_addr++;
    }
    for (size_t i = 0; i < p->n_endpoints && i < TL_MAX_PEER_ENDPOINTS; i++) {
        if (tl_warm_ep_parse(p->endpoints[i].str, &out->ep[out->n_ep])) out->n_ep++;
    }
}

/* Back to what wg_dataplane_start takes. HomeDERP is not kept: nothing on
 * the data plane reads it (the relay is our own home region, and DERP
 * routes by NodeKey). */
static inline void tl_warm_peer_to(const tl_warm_peer_t *w, tl_peer_t *out)
{
    memset(out, 0, sizeof(*out));
    out->id = w->id;
    memcpy(out->node_pub, w->node_pub, TINYLINK_KEY_LEN);
    if (w->has_disco) {
        out->has_disco_pub = true;
        memcpy(out->disco_pub, w->disco_pub, TINYLINK_KEY_LEN);
    }
    for (size_t i = 0; i < w->n_addr && i < TL_MAX_PEER_ADDRESSES; i++) {
        tl_warm_cidr_str(&w->addr[i], &out->addresses[i]);
    }
    out->n_addresses = w->n_addr;
    for (size_t i = 0; i < w->n_ep && i < TL_MAX_PEER_ENDPOINTS; i++) {
        tl_warm_ep_str(&w->ep[i], &out->endpoints[i]);
    }
    out->n_endpoints = w->n_ep;
}

/* Our addresses + the target peer → a record (written = 0). self[0] is
 * the address the tunnel netif is attached with (wg_dataplane_start), so
 * it keeps its place: n_self = 0 when it does not parse. */
static inline void tl_warm_rec_build(const tl_cidr_t *self, size_t n_self,
                                     const tl_peer_t *peer,
                                     const uint8_t *self_pub, const uint8_t *ctl_pub,
                                     tl_warm_rec_t *out)
{
    memset(out, 0, sizeof(*out));
    memcpy(out->self_tag, self_pub, TL_WARM_TAG_LEN);
    memcpy(out->ctl_tag, ctl_pub, TL_WARM_TAG_LEN);
    if (n_self > 0 && tl_warm_cidr_parse(self[0].str, &out->self[0])) {
        out->n_self = 1;
        for (size_t i = 1; i < n_self && i < TL_MAX_PEER_ADDRESSES; i++) {
            if (tl_warm_cidr_parse(self[i].str, &out->self[out->n_self])) out->n_self++;
        }
    }
    tl_warm_peer_from(peer, &out->peer);
}

/* What a warm start can be made from — and all a cold start could start
 * from: an address to attach, a peer endpoint (wg_dataplane_start refuses
 * a peer without one). */
static inline bool tl_warm_rec_storable(const tl_warm_rec_t *r)
{
    return r->n_self >= 1 && r->n_self <= TL_MAX_PEER_ADDRESSES &&
           r->peer.n_ep >= 1 && r->peer.n_ep <= TL_MAX_PEER_ENDPOINTS &&
           r->peer.n_addr <= TL_MAX_PEER_ADDRESSES;
}

/* The tags of the keys this boot runs with. */
static inline bool tl_warm_rec_for(const tl_warm_rec_t *r, const uint8_t *self_pub,
                                   const uint8_t *ctl_pub)
{
    return memcmp(r->self_tag, self_pub, TL_WARM_TAG_LEN) == 0 &&
           memcmp(r->ctl_tag, ctl_pub, TL_WARM_TAG_LEN) == 0;
}

/* ---- Encode / decode ---------------------------------------------------- */

static inline uint8_t *tl_warm_put_cidr(uint8_t *b, const tl_warm_cidr_t *c)
{
    memcpy(b, c->ip, 4);
    b[4] = c->prefix;
    return b + TL_WARM_CIDR_LEN;
}

/* 0 when the record is not storable or `cap` too small. */
static inline size_t tl_warm_encode(const tl_warm_rec_t *r, uint8_t *b, size_t cap)
{
    if (!tl_warm_rec_storable(r)) return 0;
    const size_t n = TL_WARM_HDR + TL_WARM_CIDR_LEN * ((size_t)r->n_self + r->peer.n_addr) +
                     TL_WARM_EP_LEN * (size_t)r->peer.n_ep;
    if (cap < n) return 0;
    b[0] = TL_WARM_REC_V1;
    for (int i = 0; i < 4; i++) b[1 + i] = (uint8_t)(r->written >> (8 * i));
    memcpy(b + 5, r->self_tag, TL_WARM_TAG_LEN);
    memcpy(b + 13, r->ctl_tag, TL_WARM_TAG_LEN);
    b[21] = r->n_self;
    b[22] = r->peer.n_addr;
    b[23] = r->peer.n_ep;
    b[24] = r->peer.has_disco ? 1 : 0;
    for (int i = 0; i < 8; i++) b[25 + i] = (uint8_t)(r->peer.id >> (8 * i));
    memcpy(b + 33, r->peer.node_pub, TINYLINK_KEY_LEN);
    if (r->peer.has_disco) {
        memcpy(b + 65, r->peer.disco_pub, TINYLINK_KEY_LEN);
    } else {
        memset(b + 65, 0, TINYLINK_KEY_LEN);
    }
    uint8_t *p = b + TL_WARM_HDR;
    for (unsigned i = 0; i < r->n_self; i++) p = tl_warm_put_cidr(p, &r->self[i]);
    for (unsigned i = 0; i < r->peer.n_addr; i++) p = tl_warm_put_cidr(p, &r->peer.addr[i]);
    for (unsigned i = 0; i < r->peer.n_ep; i++) {
        memcpy(p, r->peer.ep[i].ip, 4);
        p[4] = (uint8_t)r->peer.ep[i].port;
        p[5] = (uint8_t)(r->peer.ep[i].port >> 8);
        p += TL_WARM_EP_LEN;
    }
    return n;
}

static inline bool tl_warm_get_cidr(const uint8_t *b, tl_warm_cidr_t *c)
{
    if (!tl_ipv4_usable(b) || b[4] > 32) return false;
    memcpy(c->ip, b, 4);
    c->prefix = b[4];
    return true;
}

/* Strict: the exact length for its counts, every count in range, no
 * unknown flag, a DiscoKey only with its flag, no address tl_ipv4_usable
 * refuses (0/8, 127/8, 224/3), no port 0. A blob of another version, or
 * one NVS truncated or corrupted, reads as no record. */
static inline bool tl_warm_decode(const uint8_t *b, size_t n, tl_warm_rec_t *out)
{
    if (b == NULL || n < TL_WARM_BLOB_MIN || n > TL_WARM_BLOB_MAX || b[0] != TL_WARM_REC_V1) {
        return false;
    }
    tl_warm_rec_t r;
    memset(&r, 0, sizeof(r));
    r.n_self      = b[21];
    r.peer.n_addr = b[22];
    r.peer.n_ep   = b[23];
    if (r.n_self < 1 || r.n_self > TL_MAX_PEER_ADDRESSES ||
        r.peer.n_addr > TL_MAX_PEER_ADDRESSES ||
        r.peer.n_ep < 1 || r.peer.n_ep > TL_MAX_PEER_ENDPOINTS || (b[24] & ~1u) != 0 ||
        n != TL_WARM_HDR + TL_WARM_CIDR_LEN * ((size_t)r.n_self + r.peer.n_addr) +
             TL_WARM_EP_LEN * (size_t)r.peer.n_ep) {
        return false;
    }
    for (int i = 0; i < 4; i++) r.written |= (uint32_t)b[1 + i] << (8 * i);
    memcpy(r.self_tag, b + 5, TL_WARM_TAG_LEN);
    memcpy(r.ctl_tag, b + 13, TL_WARM_TAG_LEN);
    r.peer.has_disco = b[24] & 1u;
    for (int i = 0; i < 8; i++) r.peer.id |= (uint64_t)b[25 + i] << (8 * i);
    memcpy(r.peer.node_pub, b + 33, TINYLINK_KEY_LEN);
    memcpy(r.peer.disco_pub, b + 65, TINYLINK_KEY_LEN);
    if (!r.peer.has_disco) {
        for (int i = 0; i < TINYLINK_KEY_LEN; i++) {
            if (r.peer.disco_pub[i] != 0) return false;
        }
    }
    const uint8_t *p = b + TL_WARM_HDR;
    for (unsigned i = 0; i < r.n_self; i++, p += TL_WARM_CIDR_LEN) {
        if (!tl_warm_get_cidr(p, &r.self[i])) return false;
    }
    for (unsigned i = 0; i < r.peer.n_addr; i++, p += TL_WARM_CIDR_LEN) {
        if (!tl_warm_get_cidr(p, &r.peer.addr[i])) return false;
    }
    for (unsigned i = 0; i < r.peer.n_ep; i++, p += TL_WARM_EP_LEN) {
        const uint16_t port = (uint16_t)(p[4] | (p[5] << 8));
        if (!tl_ipv4_usable(p) || port == 0) return false;
        memcpy(r.peer.ep[i].ip, p, 4);
        r.peer.ep[i].port = port;
    }
    *out = r;
    return true;
}

/* ---- What differs ------------------------------------------------------- */

#define TL_WARM_D_PEER   0x01u   /* another peer (NodeID; NodeKey when the ID is 0) */
#define TL_WARM_D_KEY    0x02u   /* its NodeKey */
#define TL_WARM_D_DISCO  0x04u   /* its DiscoKey */
#define TL_WARM_D_EP     0x08u   /* its endpoints */
#define TL_WARM_D_ADDR   0x10u   /* its tailnet addresses */
#define TL_WARM_D_SELF0  0x20u   /* the address the tunnel is attached with */
#define TL_WARM_D_SELF   0x40u   /* our address list */
#define TL_WARM_D_IDENT  0x80u   /* our NodeKey / the control key */

/* Changes the running session cannot take in place: the warm start
 * restarts into a cold boot (tinylink.c). The others go through
 * wg_dataplane_update_peers like any netmap update. */
#define TL_WARM_RESTART  (TL_WARM_D_PEER | TL_WARM_D_SELF0 | TL_WARM_D_IDENT)
/* Written to NVS at the next housekeeping; the rest at most hourly. */
#define TL_WARM_HARD     (TL_WARM_D_PEER | TL_WARM_D_KEY | TL_WARM_D_ADDR | \
                          TL_WARM_D_SELF0 | TL_WARM_D_SELF | TL_WARM_D_IDENT)

static inline bool tl_warm_cidr_eq(const tl_warm_cidr_t *a, const tl_warm_cidr_t *b)
{
    return memcmp(a->ip, b->ip, 4) == 0 && a->prefix == b->prefix;
}

/* wg_dataplane_update_peers' rule for "the session's peer". */
static inline bool tl_warm_same_peer(const tl_warm_peer_t *a, const tl_warm_peer_t *b)
{
    return a->id != 0 ? a->id == b->id
                      : memcmp(a->node_pub, b->node_pub, TINYLINK_KEY_LEN) == 0;
}

/* `was` against `now`; the write timestamp does not count. */
static inline unsigned tl_warm_diff(const tl_warm_rec_t *was, const tl_warm_rec_t *now)
{
    unsigned d = 0;
    if (memcmp(was->self_tag, now->self_tag, TL_WARM_TAG_LEN) != 0 ||
        memcmp(was->ctl_tag, now->ctl_tag, TL_WARM_TAG_LEN) != 0) {
        d |= TL_WARM_D_IDENT;
    }
    if ((was->n_self == 0) != (now->n_self == 0) ||
        (was->n_self > 0 && !tl_warm_cidr_eq(&was->self[0], &now->self[0]))) {
        d |= TL_WARM_D_SELF0 | TL_WARM_D_SELF;
    }
    if (was->n_self != now->n_self) d |= TL_WARM_D_SELF;
    for (unsigned i = 1; i < was->n_self && i < now->n_self; i++) {
        if (!tl_warm_cidr_eq(&was->self[i], &now->self[i])) d |= TL_WARM_D_SELF;
    }
    const tl_warm_peer_t *a = &was->peer, *b = &now->peer;
    if (!tl_warm_same_peer(a, b)) d |= TL_WARM_D_PEER;
    if (memcmp(a->node_pub, b->node_pub, TINYLINK_KEY_LEN) != 0) d |= TL_WARM_D_KEY;
    if (a->has_disco != b->has_disco ||
        (a->has_disco && memcmp(a->disco_pub, b->disco_pub, TINYLINK_KEY_LEN) != 0)) {
        d |= TL_WARM_D_DISCO;
    }
    if (a->n_addr != b->n_addr) d |= TL_WARM_D_ADDR;
    for (unsigned i = 0; i < a->n_addr && i < b->n_addr; i++) {
        if (!tl_warm_cidr_eq(&a->addr[i], &b->addr[i])) d |= TL_WARM_D_ADDR;
    }
    if (a->n_ep != b->n_ep) d |= TL_WARM_D_EP;
    for (unsigned i = 0; i < a->n_ep && i < b->n_ep; i++) {
        if (memcmp(a->ep[i].ip, b->ep[i].ip, 4) != 0 || a->ep[i].port != b->ep[i].port) {
            d |= TL_WARM_D_EP;
        }
    }
    return d;
}

/* "peer NodeKey, endpoints" — for the log line, no key material. */
static inline const char *tl_warm_diff_str(unsigned d, char *out, size_t cap)
{
    static const struct { unsigned bit; const char *what; } k[] = {
        { TL_WARM_D_IDENT, "our keys" },
        { TL_WARM_D_PEER,  "target peer" },
        { TL_WARM_D_SELF0, "self address" },
        { TL_WARM_D_KEY,   "peer NodeKey" },
        { TL_WARM_D_DISCO, "peer DiscoKey" },
        { TL_WARM_D_EP,    "peer endpoints" },
        { TL_WARM_D_ADDR,  "peer addresses" },
        { TL_WARM_D_SELF,  "self addresses" },
    };
    size_t at = 0;
    out[0] = '\0';
    for (size_t i = 0; i < sizeof(k) / sizeof(k[0]); i++) {
        if (!(d & k[i].bit)) continue;
        /* SELF0 implies SELF: one name for the attached address. */
        if (k[i].bit == TL_WARM_D_SELF && (d & TL_WARM_D_SELF0)) continue;
        const int w = snprintf(out + at, cap - at, "%s%s", at ? ", " : "", k[i].what);
        if (w < 0 || (size_t)w >= cap - at) break;
        at += (size_t)w;
    }
    return out;
}

/* ---- Written only on change --------------------------------------------- */

/* Write `diff` now? `stored`: NVS holds a valid record; `wrote`: this
 * boot has written it, `last_us` when. */
static inline bool tl_warm_store_due(unsigned diff, bool stored, bool wrote,
                                     int64_t now_us, int64_t last_us)
{
    if (!stored) return true;
    if (diff == 0) return false;
    if (diff & TL_WARM_HARD) return true;
    return !wrote || now_us - last_us >= TL_WARM_SOFT_MIN_US;
}

/* What NVS holds, mirrored in RAM (loaded at boot, compared before every
 * write) — and, until the first netmap, the record the warm start ran. */
typedef struct {
    bool          valid;
    bool          wrote;     /* this boot */
    int64_t       last_us;
    tl_warm_rec_t rec;
} tl_warm_nvs_t;

/* 0 = written, else failed. */
typedef int (*tl_warm_write_fn)(const uint8_t *b, size_t n, const void *ctx);

/* 0 = nothing due (unchanged, or a soft change held back), 1 = written,
 * -1 = not storable, or the write failed. As tl_addr_store, the mirror
 * takes the record even when the write fails: a broken NVS costs a write
 * attempt per change, not one per housekeeping. */
static inline int tl_warm_store(tl_warm_nvs_t *m, const tl_warm_rec_t *next,
                                uint32_t now_unix, int64_t now_us,
                                tl_warm_write_fn write, const void *ctx)
{
    if (!tl_warm_rec_storable(next)) return -1;
    const unsigned d = m->valid ? tl_warm_diff(&m->rec, next) : ~0u;
    if (!tl_warm_store_due(d, m->valid, m->wrote, now_us, m->last_us)) return 0;
    uint8_t b[TL_WARM_BLOB_MAX];
    tl_warm_rec_t r = *next;
    r.written = now_unix;
    const size_t n = tl_warm_encode(&r, b, sizeof(b));
    if (n == 0) return -1;
    m->rec     = r;
    m->valid   = true;
    m->wrote   = true;
    m->last_us = now_us;
    return write(b, n, ctx) == 0 ? 1 : -1;
}

/* ---- Log helpers -------------------------------------------------------- */

/* "cached 3 h ago" — exact once SNTP synced; before that time() is the
 * boot's floor (tl_time.c: never past real time), so the age is a lower
 * bound, and nothing at all when the floor is behind the write. */
static inline void tl_warm_age_str(char *out, size_t cap, int64_t now_unix, bool synced,
                                   uint32_t written)
{
    if (written == 0 || now_unix < (int64_t)written) {
        snprintf(out, cap, "cached, age unknown%s", synced ? "" : ", clock not synced");
        return;
    }
    const int64_t a = now_unix - (int64_t)written;
    const char *pre = synced ? "" : "≥ ";
    const char *post = synced ? "" : ", clock not synced";
    if (a < 120) {
        snprintf(out, cap, "cached %s%u s ago%s", pre, (unsigned)a, post);
    } else if (a < 2 * 3600) {
        snprintf(out, cap, "cached %s%u min ago%s", pre, (unsigned)(a / 60), post);
    } else if (a < 2 * 86400) {
        snprintf(out, cap, "cached %s%u h ago%s", pre, (unsigned)(a / 3600), post);
    } else {
        snprintf(out, cap, "cached %s%u d ago%s", pre, (unsigned)(a / 86400), post);
    }
}

/* The bound (CONFIG_TINYLINK_WARM_START_MAX_S): `since_s` is the boot
 * second the warm start fired at. */
static inline bool tl_warm_bound_due(uint32_t now_s, uint32_t since_s, uint32_t max_s)
{
    return now_s >= since_s && now_s - since_s >= max_s;
}

#ifdef __cplusplus
}
#endif
