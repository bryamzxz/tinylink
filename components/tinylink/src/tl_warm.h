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
// The record, NVS `tl_state` / "warm_rec", binary, 108..141 B:
//
//   0   version (TL_WARM_REC_V1: another layout is ignored, not parsed)
//   1   written, LE32 Unix seconds (0: the clock was not synced) — when a
//       netmap last stood behind the content: its write, or a refresh at
//       most daily while it is unchanged and control is heard
//       (tl_warm_refresh_due); a record older than TL_WARM_MAX_AGE_S is
//       not used
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
// The decisions around it are here too, as a state machine tinylink.c
// drives with one call per event (tl_warm_sm_*): whether a boot warm-
// starts (tl_warm_go: RTC marks, record, keys, age, register, heap), the
// seeding, the first frame's table reset, what the first netmap does to
// the warm session (confirm in place, wait, restart cold), the bound and
// the crash guard (tl_warm_rtc_*). Also the cold start's target pick
// (tl_warm_target_index, which wg_dataplane.c runs) and the peer-address
// update rule. Everything here is pure and host-tested
// (tools/test/test_warm.c); the NVS calls, the locking, the logging and
// the bring-up are in tinylink.c.

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

/* An unchanged record is written again to renew `written` — its "a
 * netmap stood behind it then" — once a day at most, and only while the
 * netmap is current (`fresh`: the data plane runs on this boot's netmap
 * and control was heard lately) and the clock is synced (now_unix != 0).
 * One write a day, so a device up for months does not leave a record
 * that reads as months old (TL_WARM_MAX_AGE_S) at its next boot. */
#define TL_WARM_REFRESH_S   86400u

static inline bool tl_warm_refresh_due(uint32_t written, uint32_t now_unix, bool fresh)
{
    return fresh && now_unix != 0 && (written == 0 || (now_unix >= written &&
                                                       now_unix - written >= TL_WARM_REFRESH_S));
}

/* 0 = nothing due (unchanged, or a soft change held back), 1 = written,
 * -1 = not storable, or the write failed. As tl_addr_store, the mirror
 * takes the record even when the write fails: a broken NVS costs a write
 * attempt per change, not one per housekeeping. */
static inline int tl_warm_store(tl_warm_nvs_t *m, const tl_warm_rec_t *next,
                                uint32_t now_unix, int64_t now_us, bool fresh,
                                tl_warm_write_fn write, const void *ctx)
{
    if (!tl_warm_rec_storable(next)) return -1;
    const unsigned d = m->valid ? tl_warm_diff(&m->rec, next) : ~0u;
    if (!tl_warm_store_due(d, m->valid, m->wrote, now_us, m->last_us) &&
        !(d == 0 && tl_warm_refresh_due(m->rec.written, now_unix, fresh))) {
        return 0;
    }
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

/* No warm start from a record no netmap stood behind for this long. The
 * clock before SNTP is the boot's floor (tl_time.c: never ahead of real
 * time), so floor − written is a lower bound of the age: a record it
 * already shows too old is refused at the warm start; one it cannot tell
 * (written 0, or the floor behind it — e.g. a long power-off keeps the
 * floor at its start) is used, and the pending session ends once SNTP
 * shows it too old (tl_warm_sm_bound). */
#define TL_WARM_MAX_AGE_S   (30u * 86400u)

static inline bool tl_warm_too_old(int64_t now_unix, uint32_t written)
{
    return written != 0 && now_unix > (int64_t)written &&
           now_unix - (int64_t)written > (int64_t)TL_WARM_MAX_AGE_S;
}

/* ---- The cold start's target pick ---------------------------------------
 *
 * wg_dataplane.c select_target_peer, the part without I/O: the first peer
 * with an endpoint reachable without a hairpin — a public IPv4 that is
 * not our own STUN address (any public one while STUN gave nothing) —
 * else peers[0] (`*qualified` false). The warm start must run against
 * the peer this picks from the netmap; the record stores what it picks. */

/* Not 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 0/8, 224/3
 * (wg_dataplane.c ipv4_is_public). */
static inline bool tl_warm_ipv4_public(const uint8_t ip[4])
{
    if (ip[0] == 10 || ip[0] == 127 || ip[0] == 0 || ip[0] >= 224) return false;
    if (ip[0] == 172 && (ip[1] & 0xF0) == 16) return false;
    if (ip[0] == 192 && ip[1] == 168) return false;
    if (ip[0] == 169 && ip[1] == 254) return false;
    return true;
}

static inline bool tl_warm_peer_reachable(const tl_peer_t *p, bool have_our,
                                          const uint8_t our[4])
{
    for (size_t i = 0; i < p->n_endpoints && i < TL_MAX_PEER_ENDPOINTS; i++) {
        tl_warm_ep_t e;
        if (!tl_warm_ep_parse(p->endpoints[i].str, &e) || !tl_warm_ipv4_public(e.ip)) continue;
        if (!have_our || memcmp(e.ip, our, 4) != 0) return true;
    }
    return false;
}

static inline size_t tl_warm_target_index(const tl_peer_t *peers, size_t n_peers,
                                          bool have_our, const uint8_t our[4],
                                          bool *qualified)
{
    for (size_t i = 0; i < n_peers; i++) {
        if (tl_warm_peer_reachable(&peers[i], have_our, our)) {
            *qualified = true;
            return i;
        }
    }
    *qualified = false;
    return 0;
}

/* The netmap's first /32 of the session's peer moved (network order; 0 =
 * none in the list): wg_dataplane_update_peers moves the TSMP advert's
 * destination. A list without a /32 keeps the last one. */
static inline bool tl_warm_addr_moved(uint32_t cur_be, uint32_t next_be)
{
    return next_be != 0 && next_be != cur_be;
}

/* The register sent no auth key: the node was known with these keys
 * (NVS reg_keys) and control did not refuse that (register_node). */
static inline bool tl_warm_reg_reused(bool known, bool retried_with_auth)
{
    return known && !retried_with_auth;
}

/* ---- The crash guard and the restart mark (RTC no-init memory) ----------
 *
 * RTC slow memory survives every reset but a power loss (tl_bootstat.h).
 * `attempt`: a warm start ran and no netmap confirmed it yet — set before
 * its bring-up, cleared when the netmap confirms it, when the bring-up
 * fails, or by a planned restart. A boot that finds it set after any
 * reset but a software one (panic, a WDT, a brown-out…) counts a crash:
 * the record is erased and that boot starts cold; after
 * TL_WARM_RTC_MAX_CRASHES the warm start stays off until a power cycle,
 * so a fault on the warm path costs a cold boot in between, then
 * nothing. `skip`: a planned restart out of a warm start (or for a self
 * address change) — the next boot starts cold, even if the erase failed.
 * A power-on finds garbage or stale bytes: the record restarts from zero
 * (both marks and the count go — accepted: a power cycle is also what
 * re-enables a warm start the guard switched off). */
#define TL_WARM_RTC_MAGIC        0x544C5732u   /* "TLW2" */
#define TL_WARM_RTC_MAX_CRASHES  2u
#define TL_WARM_RST_POWERON      1   /* esp_reset_reason_t, restated for the host */
#define TL_WARM_RST_SW           3

typedef struct {
    uint32_t magic;
    uint8_t  attempt;
    uint8_t  skip;
    uint8_t  crashes;
    uint8_t  pad;
    uint32_t check;
} tl_warm_rtc_t;

static inline uint32_t tl_warm_rtc_sum(const tl_warm_rtc_t *r)
{
    const uint8_t b[8] = { (uint8_t)r->magic, (uint8_t)(r->magic >> 8),
                           (uint8_t)(r->magic >> 16), (uint8_t)(r->magic >> 24),
                           r->attempt, r->skip, r->crashes, r->pad };
    uint32_t h = 2166136261u;
    for (unsigned i = 0; i < 8; i++) {
        h ^= b[i];
        h *= 16777619u;
    }
    return h;
}

static inline void tl_warm_rtc_seal(tl_warm_rtc_t *r)
{
    r->magic = TL_WARM_RTC_MAGIC;
    r->check = tl_warm_rtc_sum(r);
}

typedef enum {
    TL_WARM_RTC_CLEAN = 0,
    TL_WARM_RTC_RESTARTED,   /* planned restart out of a warm start: this boot cold */
    TL_WARM_RTC_CRASHED,     /* the last warm start ended in a crash: erase, cold */
    TL_WARM_RTC_OFF,         /* TL_WARM_RTC_MAX_CRASHES reached: off until power-on */
} tl_warm_rtc_verdict_t;

/* Once per boot, first thing (tinylink_init), whatever follows: the
 * marks are consumed here. `*erase`: a crash was found — the record goes. */
static inline tl_warm_rtc_verdict_t tl_warm_rtc_boot(tl_warm_rtc_t *r, int reset_reason,
                                                     bool *erase)
{
    *erase = false;
    if (reset_reason == TL_WARM_RST_POWERON || r->magic != TL_WARM_RTC_MAGIC ||
        r->check != tl_warm_rtc_sum(r) || r->attempt > 1 || r->skip > 1 ||
        r->crashes > TL_WARM_RTC_MAX_CRASHES || r->pad != 0) {
        memset(r, 0, sizeof(*r));
        tl_warm_rtc_seal(r);
        return TL_WARM_RTC_CLEAN;
    }
    const bool crash = r->attempt && reset_reason != TL_WARM_RST_SW;
    const bool skip  = r->skip;
    if (crash && r->crashes < TL_WARM_RTC_MAX_CRASHES) r->crashes++;
    r->attempt = 0;
    r->skip    = 0;
    tl_warm_rtc_seal(r);
    *erase = crash;
    if (r->crashes >= TL_WARM_RTC_MAX_CRASHES) return TL_WARM_RTC_OFF;
    if (crash) return TL_WARM_RTC_CRASHED;
    return skip ? TL_WARM_RTC_RESTARTED : TL_WARM_RTC_CLEAN;
}

/* A planned restart out of a warm start (or for a self address change):
 * the next boot is cold; not a crash. */
static inline void tl_warm_rtc_restart(tl_warm_rtc_t *r)
{
    r->attempt = 0;
    r->skip    = 1;
    tl_warm_rtc_seal(r);
}

/* ---- Does this boot warm-start? ----------------------------------------- */

typedef enum {
    TL_WARM_GO = 0,
    TL_WARM_NO_RECORD,       /* nothing stored, or nothing this firmware reads */
    TL_WARM_SKIP_CRASH,      /* the last warm start ended in a crash reset */
    TL_WARM_SKIP_OFF,        /* the crash guard switched it off */
    TL_WARM_SKIP_RESTART,    /* the last boot restarted out of one */
    TL_WARM_OTHER_KEYS,      /* written under another NodeKey / control key */
    TL_WARM_STALE,           /* no netmap stood behind it for TL_WARM_MAX_AGE_S */
    TL_WARM_NEEDED_AUTH,     /* the register sent the auth key: maybe a new node */
    TL_WARM_LOW_HEAP,        /* no room for wg_rx and the telemetry task now */
} tl_warm_go_t;

typedef struct {
    tl_warm_rtc_verdict_t rtc;
    bool     have_rec;
    bool     keys_ok;
    bool     reg_reused;     /* tl_warm_reg_reused */
    bool     heap_ok;
    int64_t  now_unix;       /* time(NULL), floored before SNTP */
    uint32_t written;
} tl_warm_go_in_t;

static inline tl_warm_go_t tl_warm_go(const tl_warm_go_in_t *in)
{
    if (in->rtc == TL_WARM_RTC_CRASHED) return TL_WARM_SKIP_CRASH;
    if (in->rtc == TL_WARM_RTC_OFF) return TL_WARM_SKIP_OFF;
    if (!in->have_rec) return TL_WARM_NO_RECORD;
    if (in->rtc == TL_WARM_RTC_RESTARTED) return TL_WARM_SKIP_RESTART;
    if (!in->keys_ok) return TL_WARM_OTHER_KEYS;
    if (tl_warm_too_old(in->now_unix, in->written)) return TL_WARM_STALE;
    if (!in->reg_reused) return TL_WARM_NEEDED_AUTH;
    if (!in->heap_ok) return TL_WARM_LOW_HEAP;
    return TL_WARM_GO;
}

/* ---- The warm session's state machine -----------------------------------
 *
 * tinylink.c holds one, under a spinlock (the main task starts it, the
 * long-poll task feeds it netmap frames, the telemetry task the bound),
 * and the tables the data plane starts from (s_self_addrs, s_last_peers). */

enum { TL_WARM_ST_OFF = 0, TL_WARM_ST_PENDING, TL_WARM_ST_CONFIRMED };

typedef struct {
    uint8_t  state;          /* TL_WARM_ST_* */
    bool     seeded;         /* the tables hold the record, not a netmap */
    bool     restart;        /* the long-poll erases the record and restarts */
    bool     bound_fired;    /* the bound claimed the pending session */
    uint32_t pending_s;      /* boot second + 1 of the unconfirmed start, 0 = none */
    uint32_t written;        /* the running record's (the age once SNTP synced) */
} tl_warm_sm_t;

typedef struct {
    tl_cidr_t *self;         /* [TL_MAX_PEER_ADDRESSES] */
    size_t    *n_self;
    tl_peer_t *peers;        /* [TL_MAX_PEERS] */
    size_t    *n_peers;
} tl_warm_tables_t;

/* The warm start begins (before relay_boot_join): a crash from here on
 * until the netmap confirms is the guard's. */
static inline void tl_warm_sm_begin(tl_warm_sm_t *sm, tl_warm_rtc_t *rtc,
                                    const tl_warm_rec_t *r, tl_warm_tables_t *t)
{
    memset(sm, 0, sizeof(*sm));
    rtc->attempt = 1;
    tl_warm_rtc_seal(rtc);
    /* What wg_dataplane_start is given: the record's addresses and its
     * peer, as the netmap's strings (tl_warm_peer_to). */
    for (unsigned i = 0; i < r->n_self && i < TL_MAX_PEER_ADDRESSES; i++) {
        tl_warm_cidr_str(&r->self[i], &t->self[i]);
    }
    *t->n_self = r->n_self;
    tl_warm_peer_to(&r->peer, &t->peers[0]);
    *t->n_peers = 1;
    sm->seeded = true;
}

/* wg_dataplane_start's outcome. A failure leaves the tables as a cold
 * boot has them before its netmap (empty), the guard's mark cleared. */
static inline void tl_warm_sm_started(tl_warm_sm_t *sm, tl_warm_rtc_t *rtc,
                                      tl_warm_tables_t *t, bool ok, uint32_t now_s,
                                      uint32_t written)
{
    if (!ok) {
        sm->state  = TL_WARM_ST_OFF;
        sm->seeded = false;
        *t->n_self  = 0;
        *t->n_peers = 0;
        rtc->attempt = 0;
        tl_warm_rtc_seal(rtc);
        return;
    }
    sm->state     = TL_WARM_ST_PENDING;
    sm->pending_s = now_s + 1u;
    sm->written   = written;
}

/* Every netmap frame, before the handler takes anything from it. The
 * first empties the tables the record seeded — the netmap's own replace
 * them, an omitted Peers too, as in a cold boot. True while a warm
 * session waits for its netmap: the frame goes to tl_warm_sm_netmap, not
 * the cold path (which would start the data plane a second time). */
static inline bool tl_warm_sm_frame(tl_warm_sm_t *sm, tl_warm_tables_t *t)
{
    if (sm->seeded) {
        sm->seeded  = false;
        *t->n_self  = 0;
        *t->n_peers = 0;
    }
    return sm->state == TL_WARM_ST_PENDING;
}

typedef enum {
    TL_WARM_ACT_COLD = 0,    /* no warm session pending: the handler's own path */
    TL_WARM_ACT_WAIT,        /* a frame before the full netmap */
    TL_WARM_ACT_CONFIRM,     /* the session stands: update in place (`*diff`) */
    TL_WARM_ACT_RESTART,     /* erase, restart cold (sm->restart set) */
    TL_WARM_ACT_LATE,        /* the bound claimed it first: its restart runs */
} tl_warm_act_t;

/* Why a restart (besides the diff bits): */
#define TL_WARM_WHY_EXPIRED  0x100u   /* control marks this node expired / deleted */
#define TL_WARM_WHY_EMPTY    0x200u   /* the full netmap has no self address or no peer */

typedef struct {
    bool                 expired;      /* self_node_expired(nm) */
    bool                 have_self;    /* the frame carries the self node */
    bool                 self0_moved;  /* our netmap address is not the attached one */
    const tl_warm_rec_t *now;          /* the netmap's: our addresses + the pick (NULL: none) */
} tl_warm_nm_t;

/* A netmap frame (after the merge into the tables) while the session
 * waits. `was`: the record it runs on. `*why`: diff bits, and the
 * TL_WARM_WHY_* of a restart. */
static inline tl_warm_act_t tl_warm_sm_netmap(tl_warm_sm_t *sm, tl_warm_rtc_t *rtc,
                                              const tl_warm_rec_t *was,
                                              const tl_warm_nm_t *in, unsigned *why)
{
    *why = 0;
    if (sm->state != TL_WARM_ST_PENDING) return TL_WARM_ACT_COLD;
    if (sm->bound_fired) return TL_WARM_ACT_LATE;
    if (in->expired) {
        *why = TL_WARM_WHY_EXPIRED;
    } else if (in->self0_moved) {
        *why = TL_WARM_D_SELF0 | TL_WARM_D_SELF;
    } else if (in->now == NULL) {
        if (!in->have_self) return TL_WARM_ACT_WAIT;
        *why = TL_WARM_WHY_EMPTY;
    } else {
        *why = tl_warm_diff(was, in->now);
        if (!(*why & TL_WARM_RESTART)) {
            sm->state     = TL_WARM_ST_CONFIRMED;
            sm->pending_s = 0;
            rtc->attempt  = 0;
            rtc->crashes  = 0;
            tl_warm_rtc_seal(rtc);
            return TL_WARM_ACT_CONFIRM;
        }
    }
    sm->restart   = true;
    sm->pending_s = 0;
    return TL_WARM_ACT_RESTART;
}

/* The telemetry task's housekeeping: true = end the pending session
 * (erase, restart) — the bound passed, or, the clock synced, the record
 * reads older than TL_WARM_MAX_AGE_S. Claims it against the netmap. */
#define TL_WARM_BOUND_TIME 1
#define TL_WARM_BOUND_AGE  2
static inline int tl_warm_sm_bound(tl_warm_sm_t *sm, uint32_t now_s, uint32_t max_s,
                                   bool synced, int64_t now_unix)
{
    if (sm->state != TL_WARM_ST_PENDING || sm->pending_s == 0 || sm->bound_fired) return 0;
    int why = 0;
    if (tl_warm_bound_due(now_s, sm->pending_s - 1u, max_s)) {
        why = TL_WARM_BOUND_TIME;
    } else if (synced && tl_warm_too_old(now_unix, sm->written)) {
        why = TL_WARM_BOUND_AGE;
    }
    if (why != 0) {
        sm->bound_fired = true;
        sm->pending_s   = 0;
    }
    return why;
}

/* The data plane came up from a netmap (the cold path): the record's
 * refresh may run (tl_warm_refresh_due's `fresh`). */
static inline void tl_warm_sm_cold(tl_warm_sm_t *sm)
{
    if (sm->state == TL_WARM_ST_OFF) sm->state = TL_WARM_ST_CONFIRMED;
}

#ifdef __cplusplus
}
#endif
