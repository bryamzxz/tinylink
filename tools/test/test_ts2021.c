// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// ts2021 record layer after the Noise handshake (ts2021_client.c, built
// on the host over an in-memory TLS byte stream):
//
//  - round 1.3.4, D5: consume_early_payload leaves the first HTTP/2
//    bytes in the conn's record ring as a window [h2_rx_off, h2_rx_len)
//    instead of copying them into a second 4 077-B buffer; when the
//    stream turns out not to carry an EarlyPayload after some of the
//    magic's bytes arrived in earlier records, those bytes are put back
//    in front of the window (they equal the magic);
//  - round 1.3.4, D4: records are decrypted in place in the ring
//    (ts2021_recv_record; a 4 096-B ciphertext is the limit, a bad tag
//    exposes nothing) and sealed in place there (ts2021_tx_buf /
//    ts2021_tx_send: one ≤ 2 048-B record per esp_tls write), while
//    ts2021_send's small stack records leave the ring alone;
//  - a fixed-seed fuzz: random record segmentation of
//    [EarlyPayload] || HTTP/2 bytes, empty records included — the window
//    followed by ts2021_recv_record must reproduce the HTTP/2 bytes
//    exactly;
//  - round 1.3.5, D10a: ts2021_connect over plain HTTP :80 (a real
//    socketpair, the server's bytes scripted from an independent Noise IK
//    responder) and the :443 fallback: only with a pinned key; a 308, a
//    fake 101 with garbage, a forged msg2, a msg2 from another key, an
//    error frame, a refused / silent / closed / trickling :80 all end on
//    :443 and keep the rest of the boot there, never retried on :80; a
//    key rotation fails both ports without turning :80 off; an abort is
//    not a fallback; after Noise IK the socket polls at 30 s; the
//    early-drop heuristic (a :80 conn that failed within 120 s → the next
//    dial on :443, once);
//  - round 1.3.5: the cached control address (ts2021_set_addr) is dialed
//    first on the first transport, with the host name kept for the Host
//    header and the certificate check (common_name) and a 3-s budget; any
//    failure there — refused, silent, another server without the control
//    key — is retried by name at once, so a stale address never turns :80
//    off; the address is not retried on :443 once the name was tried; an
//    outage keeps it; an abort is not retried; every conn that comes up
//    leaves its address for the next connect; on :443 the rest of the
//    handshake at the address has one 3-s poll and one deadline too; the
//    address is first for TS2021_ADDR_TTL_S from the seed or the by-name
//    conn that reached it.
//
// ts2021_client.c is #included so its static functions are reachable;
// esp_tls is faked below, records are sealed with a second Noise state
// whose send key is the client's receive key.

/* Which address a by-name conn reached: the fakes' sockets are AF_UNIX,
 * so the test answers for getpeername (s_name_v4 when s_name_peer_known). */
#include <stdbool.h>
#include <stdint.h>
static bool test_peer_v4(int fd, uint8_t ip_v4[4]);
#define TS2021_PEER_V4 test_peer_v4

#include "../../components/tinylink/src/ts2021_client.c"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>

#include "blake2s.h"
#include "chacha20poly1305.h"
#include "curve25519.h"
#include "hkdf_blake2s.h"

/* ---- fake esp_tls: the server's byte stream, delivered in chunks ---- */

struct esp_tls {
    uint8_t rx[96 * 1024];
    size_t  rx_len, rx_off;
    size_t  chunk;            /* max bytes per esp_tls_conn_read, 0 = any */
    uint8_t tx[16 * 1024];
    size_t  tx_len;
    int     writes;           /* esp_tls_conn_write calls */
    bool    has_fd;           /* fd / fd_peer: a socketpair for setsockopt */
    int     fd, fd_peer;
    bool    stall;            /* past rx: every read a socket timeout */
};

static struct esp_tls s_tls;

static void tls_fd_close(void)
{
    if (!s_tls.has_fd) return;
    close(s_tls.fd);
    close(s_tls.fd_peer);
    s_tls.has_fd = false;
}

/* The scripted servers. Replies are built when dialed (s_build_reply,
 * set by main), so s_peer always holds the transport keys of the server
 * of the last connect. "name" = dialed by host name, "addr" = at an IPv4
 * literal (the cached address). */
typedef struct {
    int  rc;                  /* :80 ESP_OK / error; :443 1 / -1 */
    int  kind;                /* reply_t */
    bool eof;                 /* :80: FIN after the reply */
} srv_t;
static srv_t  s_name80, s_name443, s_addr80, s_addr443;
static size_t (*s_build_reply)(int kind, uint8_t *b);

/* The dials of the last script, in order: "A80 N80 A443 N443". */
static char s_dials[64];
static void dial_log(const char *d)
{
    const size_t n = strlen(s_dials);
    snprintf(s_dials + n, sizeof(s_dials) - n, "%s%s", n ? " " : "", d);
}

/* :443 connect script: the result and the number of attempts. */
static int s_tls_connects;
static char s_tls_url[200];
static char s_tls_host[64];
static int  s_tls_port;
static int  s_tls_timeout_ms;
static char s_tls_cn[64];
static int  s_tls_stalls;     /* reads that timed out (stall) */

static int tls_dial(const char *what, const esp_tls_cfg_t *cfg, const srv_t *sv)
{
    s_tls_connects++;
    s_tls_timeout_ms = cfg->timeout_ms;
    snprintf(s_tls_cn, sizeof(s_tls_cn), "%s", cfg->common_name ? cfg->common_name : "");
    dial_log(what);
    if (sv->rc != 1) return sv->rc;
    tls_fd_close();
    s_tls.rx_len = s_build_reply(sv->kind, s_tls.rx);
    s_tls.rx_off = 0;
    s_tls.stall = sv->kind == 10;   /* RP_STALL, below */
    s_tls.tx_len = 0;
    s_tls.writes = 0;
    int sv2[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0) {
        s_tls.fd = sv2[0];
        s_tls.fd_peer = sv2[1];
        s_tls.has_fd = true;
    }
    return 1;
}

esp_tls_t *esp_tls_init(void) { return &s_tls; }
int esp_tls_conn_http_new_sync(const char *url, const esp_tls_cfg_t *cfg,
                               esp_tls_t *tls)
{
    (void)tls;
    snprintf(s_tls_url, sizeof(s_tls_url), "%s", url);
    return tls_dial("N443", cfg, &s_name443);
}
int esp_tls_conn_new_sync(const char *hostname, int hostlen, int port,
                          const esp_tls_cfg_t *cfg, esp_tls_t *tls)
{
    (void)tls;
    uint8_t ip[4];
    snprintf(s_tls_host, sizeof(s_tls_host), "%.*s", hostlen, hostname);
    s_tls_port = port;
    if (!tl_ipv4_parse(hostname, (size_t)hostlen, ip)) return -1;   /* only by address */
    return tls_dial("A443", cfg, &s_addr443);
}
ssize_t esp_tls_conn_read(esp_tls_t *tls, void *data, size_t datalen)
{
    size_t avail = tls->rx_len - tls->rx_off;
    if (avail == 0 && tls->stall) {
        s_tls_stalls++;
        return MBEDTLS_ERR_SSL_WANT_READ;         /* SO_RCVTIMEO fired */
    }
    if (avail == 0) return 0;                     /* EOF */
    size_t n = datalen < avail ? datalen : avail;
    if (tls->chunk && n > tls->chunk) n = tls->chunk;
    memcpy(data, tls->rx + tls->rx_off, n);
    tls->rx_off += n;
    return (ssize_t)n;
}
ssize_t esp_tls_conn_write(esp_tls_t *tls, const void *data, size_t datalen)
{
    if (tls->tx_len + datalen > sizeof(tls->tx)) return -1;
    memcpy(tls->tx + tls->tx_len, data, datalen);
    tls->tx_len += datalen;
    tls->writes++;
    return (ssize_t)datalen;
}
int esp_tls_conn_destroy(esp_tls_t *tls) { (void)tls; tls_fd_close(); return 0; }
ssize_t esp_tls_get_bytes_avail(esp_tls_t *tls)
{
    (void)tls;
    return 0;
}
esp_err_t esp_tls_get_conn_sockfd(esp_tls_t *tls, int *sockfd)
{
    (void)tls;
    *sockfd = s_tls.has_fd ? s_tls.fd : -1;
    return s_tls.has_fd ? ESP_OK : ESP_FAIL;
}
esp_err_t tl_crt_bundle_attach(void *conf) { (void)conf; return ESP_OK; }
/* noise_ik_init's ephemeral key: fixed, so the connect tests can
 * precompute the client's msg1 and answer it. */
void esp_fill_random(void *buf, size_t len) { memset(buf, 0x5a, len); }

/* Scripted monotonic clock: each read advances it by s_clock_step. */
static int64_t s_now_us = 1000000;
static int64_t s_clock_step;
int64_t esp_timer_get_time(void) { s_now_us += s_clock_step; return s_now_us; }

/* :80 connect script: refuse with the server's rc, else a socketpair
 * whose server end already holds its reply (then EOF if eof). The
 * timeouts go on the client end as esp-tls's tcp_connect sets them. */
static int       s_plain_connects;
static int       s_plain_port;
static char      s_plain_host[64];
static int       s_srv_fd = -1;
static uint8_t   s_plain_reply[16 * 1024];
static size_t    s_plain_reply_len;
static bool      s_plain_abort;      /* raise ts2021_abort_reads meanwhile */
static int       s_plain_timeout_ms;

/* The "DNS answer" a by-name conn reaches (RFC 5737), and whether the
 * peer is known at all — off for the pre-1.3.5 tests, whose dials must
 * not learn an address. */
static const uint8_t kNameV4[4] = { 198, 51, 100, 20 };
static const uint8_t kAddrV4[4] = { 192, 0, 2, 10 };
static bool s_name_peer_known;

static bool test_peer_v4(int fd, uint8_t ip_v4[4])
{
    if (fd < 0 || !s_name_peer_known) return false;
    memcpy(ip_v4, kNameV4, 4);
    return true;
}

esp_err_t esp_tls_plain_tcp_connect(const char *host, int hostlen, int port,
                                    const esp_tls_cfg_t *cfg,
                                    esp_tls_error_handle_t eh, int *sockfd)
{
    s_plain_connects++;
    s_plain_port = port;
    snprintf(s_plain_host, sizeof(s_plain_host), "%s", host);
    uint8_t ip[4];
    const bool by_addr = tl_ipv4_parse(host, strlen(host), ip);
    if (eh == NULL || sockfd == NULL || (size_t)hostlen != strlen(host) ||
        (!by_addr && strcmp(host, CONFIG_TINYLINK_CONTROL_HOST) != 0)) {
        return ESP_ERR_INVALID_ARG;
    }
    dial_log(by_addr ? "A80" : "N80");
    const srv_t *srv = by_addr ? &s_addr80 : &s_name80;
    if (s_plain_abort) ts2021_abort_reads();
    if (srv->rc != ESP_OK) return srv->rc;
    if (s_srv_fd >= 0) { close(s_srv_fd); s_srv_fd = -1; }
    s_plain_reply_len = s_build_reply(srv->kind, s_plain_reply);
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return ESP_FAIL;
    s_plain_timeout_ms = cfg->timeout_ms;
    struct timeval tv = { .tv_sec = cfg->timeout_ms / 1000,
                          .tv_usec = (cfg->timeout_ms % 1000) * 1000 };
    setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sv[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    if (s_plain_reply_len > 0 &&
        write(sv[1], s_plain_reply, s_plain_reply_len) != (ssize_t)s_plain_reply_len) {
        close(sv[0]);
        close(sv[1]);
        return ESP_FAIL;
    }
    if (srv->eof) shutdown(sv[1], SHUT_WR);
    s_srv_fd = sv[1];
    *sockfd = sv[0];
    return ESP_OK;
}

/* ts2021_connect / ts2021_close call into the HTTP/2 layer; not under
 * test here. */
esp_err_t h2_session_init(ts2021_conn_t *conn) { (void)conn; return ESP_OK; }
void h2_session_destroy(ts2021_conn_t *conn) { (void)conn; }

/* ---- helpers -------------------------------------------------------- */

static int s_fails;

static void check(const char *name, int ok)
{
    printf("[%s] %s\n", name, ok ? "OK" : "FAIL");
    if (!ok) s_fails++;
}

static const uint8_t kKey[32] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b,
    0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };

static ts2021_conn_t    s_conn;
static noise_ik_state_t s_peer;   /* the server's transport half */

static void reset(void)
{
    tls_fd_close();
    memset(&s_tls, 0, sizeof(s_tls));
    memset(&s_conn, 0, sizeof(s_conn));
    memset(&s_peer, 0, sizeof(s_peer));
    s_conn.tls = &s_tls;
    s_conn.connected = true;
    s_conn.noise.transport_ready = true;
    memcpy(s_conn.noise.k_recv, kKey, 32);
    memcpy(s_conn.noise.k_send, kKey, 32);
    s_peer.transport_ready = true;
    memcpy(s_peer.k_send, kKey, 32);
    memcpy(s_peer.k_recv, kKey, 32);
}

/* Append one controlbase record (type || BE16 len || payload) to the
 * server's stream; transport records are sealed with the peer state. */
static void add_record(uint8_t type, const uint8_t *pt, size_t n)
{
    uint8_t *p = s_tls.rx + s_tls.rx_len;
    size_t ct_len = n;
    if (type == TS2021_MSG_RECORD) {
        if (noise_ik_encrypt(&s_peer, p + 3, sizeof(s_tls.rx) - s_tls.rx_len - 3,
                             pt, n, &ct_len) != ESP_OK) {
            fprintf(stderr, "add_record: encrypt failed\n");
            exit(2);
        }
    } else {
        memcpy(p + 3, pt, n);
    }
    p[0] = type;
    p[1] = (uint8_t)(ct_len >> 8);
    p[2] = (uint8_t)ct_len;
    s_tls.rx_len += 3 + ct_len;
}

static void add_pt(const void *pt, size_t n)
{
    add_record(TS2021_MSG_RECORD, (const uint8_t *)pt, n);
}

/* Everything the HTTP/2 layer would see after consume_early_payload:
 * the h2_rx window, then whole records from ts2021_recv_record until the server
 * stream ends. Returns the byte count (or -1 on a read error before the
 * end of the scripted stream). */
static long drain_http2(uint8_t *out, size_t cap)
{
    size_t n = 0;
    if (s_conn.h2_rx_off > s_conn.h2_rx_len ||
        s_conn.h2_rx_len > sizeof(s_conn.h2_rx)) return -1;
    size_t w = s_conn.h2_rx_len - s_conn.h2_rx_off;
    if (w > cap) return -1;
    memcpy(out, s_conn.h2_rx + s_conn.h2_rx_off, w);
    n = w;
    while (s_tls.rx_off < s_tls.rx_len) {
        size_t got = 0;
        if (ts2021_recv_record(&s_conn, &got) != ESP_OK) return -1;
        if (s_conn.h2_rx_off != 0 || s_conn.h2_rx_len != got) return -1;
        if (n + got > cap) return -1;
        memcpy(out + n, s_conn.h2_rx, got);
        n += got;
    }
    return (long)n;
}

static const uint8_t kMagic[5] = { 0xff, 0xff, 0xff, 'T', 'S' };
/* A SETTINGS frame header + one setting: what a server's HTTP/2 starts
 * with (first byte 0x00). */
static const uint8_t kH2[] = { 0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0xfa, 0x00 };

static uint8_t s_out[96 * 1024];

static void test_no_early_payload(void)
{
    reset();
    add_pt(kH2, sizeof(kH2));
    esp_err_t rc = consume_early_payload(&s_conn);
    check("d5_no_ep_ok", rc == ESP_OK);
    check("d5_no_ep_window_in_place",
          s_conn.h2_rx_off == 0 && s_conn.h2_rx_len == sizeof(kH2) &&
          memcmp(s_conn.h2_rx, kH2, sizeof(kH2)) == 0);
}

static void test_early_payload_split(void)
{
    /* Observed tailscale.com shape: the magic in a record of its own, the
     * BE32 length + JSON in later records; HTTP/2 starts inside the
     * record that ends the JSON. */
    reset();
    static const char json[] = "{\"NodeKeyChallenge\":\"chalpub:00\"}";
    const uint32_t jl = (uint32_t)strlen(json);
    uint8_t len_be[4] = { (uint8_t)(jl >> 24), (uint8_t)(jl >> 16),
                          (uint8_t)(jl >> 8), (uint8_t)jl };
    add_pt(kMagic, 5);
    add_pt(len_be, 4);
    add_pt(json, 10);
    uint8_t tail[64];
    memcpy(tail, json + 10, jl - 10);
    memcpy(tail + (jl - 10), kH2, sizeof(kH2));
    add_pt(tail, jl - 10 + sizeof(kH2));
    esp_err_t rc = consume_early_payload(&s_conn);
    check("d5_ep_split_ok", rc == ESP_OK);
    check("d5_ep_split_window_by_offset",
          s_conn.h2_rx_off == jl - 10 &&
          s_conn.h2_rx_len == jl - 10 + sizeof(kH2) &&
          memcmp(s_conn.h2_rx + s_conn.h2_rx_off, kH2, sizeof(kH2)) == 0);
}

static void test_ep_ends_on_record_boundary(void)
{
    reset();
    uint8_t hdr[9] = { 0xff, 0xff, 0xff, 'T', 'S', 0, 0, 0, 2 };
    add_pt(hdr, 9);
    add_pt("{}", 2);
    add_pt(kH2, sizeof(kH2));
    esp_err_t rc = consume_early_payload(&s_conn);
    check("d5_ep_boundary_ok", rc == ESP_OK);
    check("d5_ep_boundary_window_empty", s_conn.h2_rx_off == s_conn.h2_rx_len);
    long n = drain_http2(s_out, sizeof(s_out));
    check("d5_ep_boundary_next_record",
          n == (long)sizeof(kH2) && memcmp(s_out, kH2, sizeof(kH2)) == 0);
}

static void test_magic_prefix_put_back(void)
{
    /* FF FF in one record, FF 'T' 'X' ... in the next: not an
     * EarlyPayload, and the first four bytes came from two records. */
    reset();
    static const uint8_t a[] = { 0xff, 0xff };
    static const uint8_t b[] = { 0xff, 'T', 'X', 1, 2, 3 };
    add_pt(a, sizeof(a));
    add_pt(b, sizeof(b));
    esp_err_t rc = consume_early_payload(&s_conn);
    static const uint8_t want[] = { 0xff, 0xff, 0xff, 'T', 'X', 1, 2, 3 };
    check("d5_prefix_put_back_ok", rc == ESP_OK);
    check("d5_prefix_put_back_bytes",
          s_conn.h2_rx_len - s_conn.h2_rx_off == sizeof(want) &&
          memcmp(s_conn.h2_rx + s_conn.h2_rx_off, want, sizeof(want)) == 0);
}

static void test_prefix_before_full_record(void)
{
    /* Worst case for the ring: four magic bytes from four earlier
     * records, then a maximum-size record (4 080 B plaintext, a 4 096-B
     * ciphertext) whose first byte differs → 4 084 B in the window. */
    reset();
    for (int i = 0; i < 4; i++) add_pt(&kMagic[i], 1);
    static uint8_t big[4080];
    for (size_t i = 0; i < sizeof(big); i++) big[i] = (uint8_t)(i * 7 + 1);
    big[0] = 0x00;
    add_pt(big, sizeof(big));
    esp_err_t rc = consume_early_payload(&s_conn);
    check("d5_prefix_full_record_ok", rc == ESP_OK);
    check("d5_prefix_full_record_bytes",
          s_conn.h2_rx_off == 0 && s_conn.h2_rx_len == 4 + sizeof(big) &&
          memcmp(s_conn.h2_rx, kMagic, 4) == 0 &&
          memcmp(s_conn.h2_rx + 4, big, sizeof(big)) == 0);
}

static void test_rejects(void)
{
    reset();
    uint8_t hdr[9] = { 0xff, 0xff, 0xff, 'T', 'S', 0, 1, 0, 1 };  /* 65 537 */
    add_pt(hdr, 9);
    check("d5_ep_too_large_rejected", consume_early_payload(&s_conn) == ESP_FAIL);

    reset();
    add_record(TS2021_MSG_ERROR, (const uint8_t *)"nope", 4);
    check("d5_error_record_rejected", consume_early_payload(&s_conn) == ESP_FAIL);

    reset();
    add_pt(kMagic, 3);                      /* stream ends inside the magic */
    check("d5_eof_in_magic_rejected", consume_early_payload(&s_conn) == ESP_FAIL);

    reset();
    add_pt(kH2, sizeof(kH2));
    s_tls.rx[s_tls.rx_len - 1] ^= 1;        /* tag */
    check("d5_bad_tag_rejected", consume_early_payload(&s_conn) == ESP_FAIL);
}

/* ---- D4: in-place record I/O ---------------------------------------- */

/* Open what the client wrote (s_tls.tx) with the peer state: records
 * count, the largest record on the wire, the plaintext. Returns -1 on a
 * malformed or unauthentic record. */
static long open_tx(uint8_t *out, size_t cap, int *nrec, size_t *maxrec)
{
    size_t off = 0, n = 0;
    *nrec = 0;
    *maxrec = 0;
    while (off < s_tls.tx_len) {
        if (s_tls.tx_len - off < 3) return -1;
        const uint8_t *r = s_tls.tx + off;
        const size_t rl = ((size_t)r[1] << 8) | r[2];
        if (r[0] != TS2021_MSG_RECORD || s_tls.tx_len - off < 3 + rl) return -1;
        size_t pl = 0;
        if (noise_ik_decrypt(&s_peer, out + n, cap - n, r + 3, rl, &pl) != ESP_OK) return -1;
        n += pl;
        off += 3 + rl;
        (*nrec)++;
        if (3 + rl > *maxrec) *maxrec = 3 + rl;
    }
    return (long)n;
}

static int contains(const uint8_t *h, size_t hn, const char *n, size_t nn)
{
    for (size_t i = 0; i + nn <= hn; i++)
        if (memcmp(h + i, n, nn) == 0) return 1;
    return 0;
}

static void test_d4_recv_in_place(void)
{
    /* Largest record the reader takes: a 4 096-B ciphertext (4 080 B of
     * plaintext) fills the ring exactly. */
    reset();
    static uint8_t big[4080];
    for (size_t i = 0; i < sizeof(big); i++) big[i] = (uint8_t)(i * 13 + 5);
    add_pt(big, sizeof(big));
    add_pt("x", 1);
    size_t got = 0;
    esp_err_t rc = ts2021_recv_record(&s_conn, &got);
    check("d4_recv_max_record",
          rc == ESP_OK && got == sizeof(big) && memcmp(s_conn.h2_rx, big, got) == 0 &&
          s_conn.h2_rx_off == 0 && s_conn.h2_rx_len == got);
    rc = ts2021_recv_record(&s_conn, &got);
    check("d4_recv_next_nonce", rc == ESP_OK && got == 1 && s_conn.h2_rx[0] == 'x');

    /* One byte more does not fit the ring: refused before reading it. */
    /* (the window was drained: off == len, as the h2 loop leaves it) */
    reset();
    static uint8_t over[4081];
    add_pt(over, sizeof(over));
    s_conn.h2_rx_off = s_conn.h2_rx_len = 7;
    check("d4_recv_oversize_rejected", ts2021_recv_record(&s_conn, &got) != ESP_OK &&
          s_conn.h2_rx_off == 0 && s_conn.h2_rx_len == 0);

    /* A forged record leaves an empty window, and no plaintext of it. */
    reset();
    static const char secret[] = "plaintext that must not appear";
    add_pt(secret, sizeof(secret) - 1);
    s_tls.rx[3] ^= 0x80;                    /* first ciphertext byte */
    s_conn.h2_rx_off = s_conn.h2_rx_len = 7;
    rc = ts2021_recv_record(&s_conn, &got);
    check("d4_recv_bad_tag",
          rc != ESP_OK && s_conn.h2_rx_off == 0 && s_conn.h2_rx_len == 0 &&
          !contains(s_conn.h2_rx, sizeof(s_conn.h2_rx), "must not", 8));

    reset();
    add_record(TS2021_MSG_RESPONSE, (const uint8_t *)"zz", 2);
    check("d4_recv_wrong_type_rejected", ts2021_recv_record(&s_conn, &got) != ESP_OK);

    reset();
    s_conn.connected = false;
    add_pt("x", 1);
    check("d4_recv_needs_connected", ts2021_recv_record(&s_conn, &got) == ESP_ERR_INVALID_STATE);
}

static void test_d4_send(void)
{
    static uint8_t pt[8192];
    int nrec;
    size_t maxrec;

    /* The ring as a TX buffer: 2 029 B of plaintext seal into one
     * 2 048-B record — one esp_tls write, so one TLS record at
     * MBEDTLS_SSL_OUT_CONTENT_LEN 2 048. */
    reset();
    s_conn.h2_rx_off = 3;
    s_conn.h2_rx_len = 9;
    size_t cap = 0;
    uint8_t *b = ts2021_tx_buf(&s_conn, &cap);
    check("d4_tx_buf_shape",
          cap == 2029 && b == s_conn.h2_rx + 4 && ((uintptr_t)b & 3u) == 0 &&
          s_conn.h2_rx_off == 0 && s_conn.h2_rx_len == 0);
    for (size_t i = 0; i < cap; i++) b[i] = (uint8_t)(i * 3 + 1);
    esp_err_t rc = ts2021_tx_send(&s_conn, cap);
    long n = open_tx(pt, sizeof(pt), &nrec, &maxrec);
    int ok = rc == ESP_OK && s_tls.writes == 1 && nrec == 1 && maxrec == 2048 && n == 2029;
    for (size_t i = 0; ok && i < 2029; i++) ok = pt[i] == (uint8_t)(i * 3 + 1);
    check("d4_tx_full_record_one_write", ok);

    reset();
    (void)ts2021_tx_buf(&s_conn, &cap);
    check("d4_tx_oversize_rejected",
          ts2021_tx_send(&s_conn, cap + 1) == ESP_ERR_INVALID_SIZE && s_tls.tx_len == 0);

    reset();
    (void)ts2021_tx_buf(&s_conn, &cap);
    rc = ts2021_tx_send(&s_conn, 0);
    n = open_tx(pt, sizeof(pt), &nrec, &maxrec);
    check("d4_tx_empty_record", rc == ESP_OK && nrec == 1 && maxrec == 3 + 16 && n == 0);

    /* ts2021_send: ≤ 64-B records from its own stack record, so a
     * control frame can go out while the ring holds a record being
     * parsed — the ring and the window stay as they were. */
    reset();
    add_pt(kH2, sizeof(kH2));
    size_t got = 0;
    (void)ts2021_recv_record(&s_conn, &got);
    s_conn.h2_rx_off = 5;
    static uint8_t data[200];
    for (size_t i = 0; i < sizeof(data); i++) data[i] = (uint8_t)(0xa0 ^ i);
    rc = ts2021_send(&s_conn, data, 17);
    n = open_tx(pt, sizeof(pt), &nrec, &maxrec);
    check("d4_send_small_one_record",
          rc == ESP_OK && s_tls.writes == 1 && nrec == 1 && n == 17 &&
          memcmp(pt, data, 17) == 0);
    check("d4_send_leaves_ring",
          got == sizeof(kH2) && s_conn.h2_rx_off == 5 && s_conn.h2_rx_len == sizeof(kH2) &&
          memcmp(s_conn.h2_rx, kH2, sizeof(kH2)) == 0);

    reset();
    rc = ts2021_send(&s_conn, data, sizeof(data));
    n = open_tx(pt, sizeof(pt), &nrec, &maxrec);
    check("d4_send_long_split_64",
          rc == ESP_OK && nrec == 4 && maxrec == 3 + 64 + 16 && n == (long)sizeof(data) &&
          memcmp(pt, data, sizeof(data)) == 0);

    reset();
    s_conn.connected = false;
    check("d4_send_needs_connected",
          ts2021_send(&s_conn, data, 1) == ESP_ERR_INVALID_STATE &&
          ts2021_tx_send(&s_conn, 1) == ESP_ERR_INVALID_STATE && s_tls.tx_len == 0);
}

/* ---- segmentation fuzz --------------------------------------------- */

static uint32_t s_rng = 0x2a2a2a2au;
static uint32_t rnd(void)
{
    s_rng ^= s_rng << 13; s_rng ^= s_rng >> 17; s_rng ^= s_rng << 5;
    return s_rng;
}

static void test_segmentation_fuzz(void)
{
    static uint8_t stream[40 * 1024], h2[24 * 1024];
    int bad = 0;
    for (int t = 0; t < 2000; t++) {
        reset();
        s_tls.chunk = 1 + rnd() % 64;      /* short TLS reads too */
        size_t sl = 0;
        const int ep = (int)(rnd() % 3);   /* 0: none, 1: EP, 2: magic-ish prefix */
        if (ep == 1) {
            const uint32_t jl = rnd() % 300;
            memcpy(stream, kMagic, 5);
            stream[5] = (uint8_t)(jl >> 24); stream[6] = (uint8_t)(jl >> 16);
            stream[7] = (uint8_t)(jl >> 8);  stream[8] = (uint8_t)jl;
            sl = 9;
            for (uint32_t i = 0; i < jl; i++) stream[sl++] = (uint8_t)rnd();
        }
        size_t hl = 1 + rnd() % (t < 100 ? 9000 : 600);
        for (size_t i = 0; i < hl; i++) h2[i] = (uint8_t)rnd();
        if (ep == 2) {
            /* starts like the magic for 0..4 bytes, then differs */
            size_t m = rnd() % 5;
            memcpy(h2, kMagic, m);
            if (hl <= m) hl = m + 1;
            h2[m] = (uint8_t)(kMagic[m] ^ (1 + rnd() % 255));
        } else if (ep == 0) {
            h2[0] = 0x00;
        }
        memcpy(stream + sl, h2, hl);
        sl += hl;
        /* cut into records of 0..max bytes */
        size_t off = 0;
        while (off < sl) {
            size_t r = rnd() % 8;
            size_t n = r == 0 ? 0 : r < 4 ? 1 + rnd() % 8
                     : r < 7 ? 1 + rnd() % 200 : 1 + rnd() % TS2021_RECORD_PLAINTEXT_MAX;
            if (n > sl - off) n = sl - off;
            add_pt(stream + off, n);
            off += n;
        }
        if (consume_early_payload(&s_conn) != ESP_OK) { bad++; continue; }
        long got = drain_http2(s_out, sizeof(s_out));
        if (got != (long)hl || memcmp(s_out, h2, hl) != 0) bad++;
    }
    check("d5_segmentation_fuzz_2000", bad == 0);
}

/* ---- D10a: ts2021_connect over :80, the :443 fallback --------------- */

static const uint8_t kMachinePriv[32] = {
    0x5d, 0x9f, 0x83, 0xf9, 0x23, 0xfa, 0x7c, 0x7f, 0xeb, 0xae, 0x1e, 0x98,
    0x37, 0x78, 0x69, 0xfb, 0x9f, 0xf9, 0x56, 0xfb, 0x46, 0xd8, 0x4e, 0xc7,
    0xfc, 0x5c, 0x6a, 0x87, 0x83, 0x3f, 0x09, 0x7f };
static const uint8_t kControlPriv[32] = {
    0x58, 0x21, 0x40, 0xa8, 0xee, 0x2b, 0x94, 0x43, 0x29, 0xb5, 0xb9, 0x21,
    0x43, 0xbd, 0x25, 0x2f, 0x68, 0xf6, 0xef, 0x72, 0xf1, 0x62, 0x22, 0x0d,
    0x50, 0x11, 0xbf, 0x53, 0xde, 0x75, 0xe3, 0x40 };
/* An on-path server without the control key: its own static. */
static const uint8_t kAttackerPriv[32] = {
    0x60, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x5f };
static const uint8_t kServerEphPriv[32] = {
    0xf8, 0x39, 0x93, 0x09, 0x47, 0xe4, 0x60, 0xd0, 0xa1, 0xb0, 0x35, 0x5d,
    0x6d, 0x20, 0x58, 0x29, 0xbd, 0x58, 0x62, 0x31, 0xfe, 0x54, 0x1b, 0x1f,
    0xcd, 0x08, 0x3a, 0xee, 0x90, 0xbf, 0x2d, 0x4b };

static uint8_t s_machine_pub[32], s_control_pub[32];

/* An independent IK responder (the Noise spec's pattern, as in
 * test_noise_ik.c): answers msg1 as the holder of `priv` for the static
 * `pub` the client pinned. With a priv that does not match pub (an
 * attacker), es / ss differ from the client's — the msg2 it seals cannot
 * verify. Returns the server's transport keys. */
typedef struct { uint8_t h[32], ck[32], k[32]; } rsym_t;

static void r_hash(rsym_t *r, const uint8_t *d, size_t n)
{
    blake2s_state S;
    blake2s_init(&S, 32);
    blake2s_update(&S, r->h, 32);
    if (n) blake2s_update(&S, d, n);
    blake2s_final(&S, r->h, 32);
}
static void r_key(rsym_t *r, const uint8_t ikm[32])
{
    uint8_t ck[32];
    noise_hkdf2(r->ck, ikm, 32, ck, r->k);
    memcpy(r->ck, ck, 32);
}
static void r_nonce0(uint8_t n[12]) { memset(n, 0, 12); }

static void responder(const uint8_t priv[32], const uint8_t msg1[NOISE_IK_MSG1_LEN],
                      uint8_t msg2[NOISE_IK_MSG2_LEN],
                      uint8_t k_c2s[32], uint8_t k_s2c[32])
{
    char prologue[40];
    int plen = snprintf(prologue, sizeof(prologue), "%s%d",
                        TS2021_PROLOGUE_PREFIX, TS2021_PROTOCOL_VERSION);
    rsym_t r;
    blake2s(r.h, 32, TS2021_PROTOCOL_NAME, strlen(TS2021_PROTOCOL_NAME), NULL, 0);
    memcpy(r.ck, r.h, 32);
    r_hash(&r, (const uint8_t *)prologue, (size_t)plen);
    r_hash(&r, s_control_pub, 32);
    const uint8_t *ie = msg1;
    r_hash(&r, ie, 32);
    uint8_t dh[32], nonce[12];
    curve25519_dh(dh, priv, ie);                        /* es */
    r_key(&r, dh);
    r_hash(&r, msg1 + 32, 48);
    /* The client's static: an honest server opens it; the attacker is
     * even handed it (it is public), only the DHs with the key fail. */
    curve25519_dh(dh, priv, s_machine_pub);             /* ss */
    r_key(&r, dh);
    r_hash(&r, msg1 + 80, 16);
    uint8_t re[32];
    curve25519_derive_pub(re, kServerEphPriv);
    memcpy(msg2, re, 32);
    r_hash(&r, re, 32);
    curve25519_dh(dh, kServerEphPriv, ie);              /* ee */
    r_key(&r, dh);
    curve25519_dh(dh, kServerEphPriv, s_machine_pub);   /* se */
    r_key(&r, dh);
    r_nonce0(nonce);
    chacha20poly1305_encrypt(msg2 + 32, NULL, 0, r.h, 32, r.k, nonce);
    noise_hkdf2(r.ck, NULL, 0, k_c2s, k_s2c);
}

/* The client's msg1 for this boot's fixed ephemeral: what ts2021_connect
 * will put in X-Tailscale-Handshake. */
static void client_msg1(uint8_t msg1[NOISE_IK_MSG1_LEN])
{
    static noise_ik_state_t st;
    char prologue[40];
    int plen = snprintf(prologue, sizeof(prologue), "%s%d",
                        TS2021_PROLOGUE_PREFIX, TS2021_PROTOCOL_VERSION);
    noise_ik_init(&st, kMachinePriv, s_machine_pub, s_control_pub, TS2021_PROTOCOL_NAME,
                  (const uint8_t *)prologue, (size_t)plen);
    noise_ik_write_msg1(&st, msg1);
}

typedef enum {
    RP_OK,            /* 101, msg2 from the control key, EarlyPayload + H2 */
    RP_OK_NO_EP,      /* 101, msg2, H2 straight away */
    RP_REDIRECT,      /* 308 from a reverse proxy */
    RP_FAKE_101,      /* 101, then a "msg2" of random bytes */
    RP_FORGED_TAG,    /* 101, the real msg2 with one tag bit flipped */
    RP_WRONG_KEY,     /* 101, msg2 from a server without the control key */
    RP_ERROR_FRAME,   /* 101, a controlbase error frame */
    RP_HUGE_FRAME,    /* 101, a frame header announcing 60 000 B */
    RP_HALF_101,      /* half a status line, then EOF */
    RP_SILENT,        /* nothing */
    RP_STALL,         /* nothing; on :443 every read times out (no EOF) */
} reply_t;
_Static_assert(RP_STALL == 10, "tls_dial's stall test");

static const char k101[] = "HTTP/1.1 101 Switching Protocols\r\n"
                           "Upgrade: tailscale-control-protocol\r\n"
                           "Connection: upgrade\r\n\r\n";

static void put(uint8_t *b, size_t *n, const void *d, size_t len)
{
    memcpy(b + *n, d, len);
    *n += len;
}

/* A sealed transport record from the server, with s_peer's next nonce. */
static void put_record(uint8_t *b, size_t *n, const void *pt, size_t len)
{
    size_t ct = 0;
    noise_ik_encrypt(&s_peer, b + *n + 3, 4096, (const uint8_t *)pt, len, &ct);
    b[*n] = TS2021_MSG_RECORD;
    b[*n + 1] = (uint8_t)(ct >> 8);
    b[*n + 2] = (uint8_t)ct;
    *n += 3 + ct;
}

static size_t build_reply(reply_t kind, uint8_t *b)
{
    size_t n = 0;
    uint8_t msg1[NOISE_IK_MSG1_LEN], msg2[NOISE_IK_MSG2_LEN], kc[32], ks[32];
    client_msg1(msg1);
    responder(kind == RP_WRONG_KEY ? kAttackerPriv : kControlPriv, msg1, msg2, kc, ks);
    memset(&s_peer, 0, sizeof(s_peer));
    s_peer.transport_ready = true;
    memcpy(s_peer.k_send, ks, 32);
    memcpy(s_peer.k_recv, kc, 32);
    static const uint8_t hdr2[3] = { TS2021_MSG_RESPONSE, 0, NOISE_IK_MSG2_LEN };
    switch (kind) {
    case RP_SILENT:
    case RP_STALL:
        return 0;
    case RP_HALF_101:
        put(b, &n, "HTTP/1.1 10", 11);
        return n;
    case RP_REDIRECT: {
        static const char r308[] = "HTTP/1.1 308 Permanent Redirect\r\n"
                                   "Location: https://controlplane.test/ts2021\r\n"
                                   "Content-Length: 0\r\n\r\n";
        put(b, &n, r308, sizeof(r308) - 1);
        return n;
    }
    default:
        break;
    }
    put(b, &n, k101, sizeof(k101) - 1);
    if (kind == RP_ERROR_FRAME) {
        static const uint8_t ef[] = { TS2021_MSG_ERROR, 0, 4, 'n', 'o', 'p', 'e' };
        put(b, &n, ef, sizeof(ef));
        return n;
    }
    if (kind == RP_HUGE_FRAME) {
        static const uint8_t hf[] = { TS2021_MSG_RESPONSE, 0xea, 0x60 };
        put(b, &n, hf, sizeof(hf));
        return n;
    }
    put(b, &n, hdr2, sizeof(hdr2));
    if (kind == RP_FAKE_101) {
        for (int i = 0; i < NOISE_IK_MSG2_LEN; i++) b[n++] = (uint8_t)(i * 37 + 11);
        return n;
    }
    if (kind == RP_FORGED_TAG) msg2[40] ^= 0x01;
    put(b, &n, msg2, sizeof(msg2));
    if (kind == RP_OK) {
        /* tailscale.com's shape: the magic in a record of its own, then
         * length + JSON, HTTP/2 starting in the same record */
        static const char json[] = "{\"NodeKeyChallenge\":\"chalpub:00\"}";
        uint8_t ep[9 + sizeof(json) - 1 + sizeof(kH2)];
        memcpy(ep, kMagic, 5);
        ep[5] = 0; ep[6] = 0; ep[7] = 0; ep[8] = (uint8_t)(sizeof(json) - 1);
        memcpy(ep + 9, json, sizeof(json) - 1);
        memcpy(ep + 9 + sizeof(json) - 1, kH2, sizeof(kH2));
        put_record(b, &n, ep, 5);
        put_record(b, &n, ep + 5, sizeof(ep) - 5);
        return n;
    }
    put_record(b, &n, kH2, sizeof(kH2));
    return n;
}

/* Fresh boot state, the :80 server scripted with `p80`, :443 with
 * `p443` (connect refused when tls_rc != 1). */
static void boot_reset(void)
{
    s_plain_off = false;
    s_tls_next = false;
    s_abort_reads = false;
    s_clock_step = 0;
    ts2021_set_addr(NULL);
    s_addr_skip = false;
    s_name_peer_known = false;
}

/* The by-name servers; the cached address (if any) is refused on both
 * ports unless script_addr says otherwise. */
static void script(int plain_rc, reply_t p80, bool eof80, int tls_rc, reply_t p443)
{
    if (s_srv_fd >= 0) { close(s_srv_fd); s_srv_fd = -1; }
    tls_fd_close();
    memset(&s_tls, 0, sizeof(s_tls));
    s_name80  = (srv_t){ plain_rc, p80, eof80 };
    s_name443 = (srv_t){ tls_rc, p443, false };
    s_addr80  = (srv_t){ ESP_FAIL, RP_SILENT, false };
    s_addr443 = (srv_t){ -1, RP_SILENT, false };
    s_plain_abort = false;
    s_plain_connects = 0;
    s_tls_connects = 0;
    s_plain_port = 0;
    s_dials[0] = '\0';
    s_tls_url[0] = '\0';
    s_tls_host[0] = '\0';
}

static void script_addr(int plain_rc, reply_t p80, bool eof80, int tls_rc, reply_t p443)
{
    s_addr80  = (srv_t){ plain_rc, p80, eof80 };
    s_addr443 = (srv_t){ tls_rc, p443, false };
}

static size_t build_reply_int(int kind, uint8_t *b) { return build_reply((reply_t)kind, b); }

static esp_err_t dial(bool pinned)
{
    return ts2021_connect(&s_conn, kMachinePriv, s_machine_pub, s_control_pub, pinned);
}

/* Everything the client sent on the :80 socket. */
static size_t srv_drain(uint8_t *out, size_t cap)
{
    size_t n = 0;
    int fl = fcntl(s_srv_fd, F_GETFL, 0);
    fcntl(s_srv_fd, F_SETFL, fl | O_NONBLOCK);
    for (;;) {
        ssize_t r = read(s_srv_fd, out + n, cap - n);
        if (r <= 0) break;
        n += (size_t)r;
    }
    fcntl(s_srv_fd, F_SETFL, fl);
    return n;
}

static bool request_ok(const uint8_t *req, size_t n)
{
    uint8_t msg1[NOISE_IK_MSG1_LEN];
    client_msg1(msg1);
    uint8_t init[TS2021_INIT_HEADER_LEN + NOISE_IK_MSG1_LEN];
    init[0] = (uint8_t)(TS2021_PROTOCOL_VERSION >> 8);
    init[1] = (uint8_t)TS2021_PROTOCOL_VERSION;
    init[2] = TS2021_MSG_INITIATION;
    init[3] = 0;
    init[4] = NOISE_IK_MSG1_LEN;
    memcpy(init + 5, msg1, sizeof(msg1));
    char b64[((sizeof(init) + 2) / 3) * 4 + 1];
    b64_encode(init, sizeof(init), b64, sizeof(b64));
    char want[512];
    int w = snprintf(want, sizeof(want),
                     "POST /ts2021 HTTP/1.1\r\nHost: controlplane.test\r\n"
                     "Upgrade: tailscale-control-protocol\r\nConnection: upgrade\r\n"
                     "X-Tailscale-Handshake: %s\r\nContent-Length: 0\r\n\r\n", b64);
    return (size_t)w == n && memcmp(req, want, n) == 0;
}

static bool window_is_h2(void)
{
    return s_conn.h2_rx_len - s_conn.h2_rx_off == sizeof(kH2) &&
           memcmp(s_conn.h2_rx + s_conn.h2_rx_off, kH2, sizeof(kH2)) == 0;
}

static void test_plain_ok(void)
{
    boot_reset();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    esp_err_t rc = dial(true);
    check("d10_plain_connects", rc == ESP_OK && s_conn.connected && s_conn.plain &&
          s_conn.tls == NULL && s_plain_connects == 1 && s_tls_connects == 0 &&
          s_plain_port == 80 && s_plain_timeout_ms == TS2021_PLAIN_TIMEOUT_MS);
    check("d10_plain_window_h2_after_ep", window_is_h2());
    struct timeval tv = { 0 };
    socklen_t tl = sizeof(tv);
    getsockopt(s_conn.sock, SOL_SOCKET, SO_RCVTIMEO, &tv, &tl);
    struct timeval tw = { 0 };
    socklen_t twl = sizeof(tw);
    getsockopt(s_conn.sock, SOL_SOCKET, SO_SNDTIMEO, &tw, &twl);
    check("d10_plain_stream_timeouts_30s",
          tv.tv_sec == 30 && tw.tv_sec == 30 && s_conn.hs_idle == 0 &&
          s_conn.hs_deadline_us == 0 && s_conn.up_us != 0);
    uint8_t req[1024];
    size_t rn = srv_drain(req, sizeof(req));
    /* the request, then the HTTP/2 layer's (faked) start sent nothing */
    check("d10_plain_request_bytes", request_ok(req, rn));
    /* records flow both ways over the socket */
    uint8_t ping[9] = { 0, 0, 0, 6, 0, 0, 0, 0, 0 };
    check("d10_plain_send", ts2021_send(&s_conn, ping, sizeof(ping)) == ESP_OK);
    uint8_t rec[64];
    size_t rl = srv_drain(rec, sizeof(rec));
    size_t pl = 0;
    uint8_t pt[64];
    check("d10_plain_record_sealed",
          rl == 3 + sizeof(ping) + 16 && rec[0] == TS2021_MSG_RECORD &&
          noise_ik_decrypt(&s_peer, pt, sizeof(pt), rec + 3, rl - 3, &pl) == ESP_OK &&
          pl == sizeof(ping) && memcmp(pt, ping, pl) == 0);
    uint8_t in[128];
    size_t inn = 0;
    put_record(in, &inn, "pong", 4);
    s_conn.h2_rx_off = s_conn.h2_rx_len;
    size_t got = 0;
    check("d10_plain_recv",
          write(s_srv_fd, in, inn) == (ssize_t)inn &&
          ts2021_recv_record(&s_conn, &got) == ESP_OK && got == 4 &&
          memcmp(s_conn.h2_rx, "pong", 4) == 0);
    ts2021_close(&s_conn);
    check("d10_plain_close", !s_conn.plain && s_conn.sock == -1 && !s_conn.connected &&
          !s_tls_next && !s_plain_off);

    /* no EarlyPayload: the first record is HTTP/2 */
    boot_reset();
    script(ESP_OK, RP_OK_NO_EP, false, 1, RP_OK);
    rc = dial(true);
    check("d10_plain_no_ep", rc == ESP_OK && s_conn.plain && window_is_h2());
    ts2021_close(&s_conn);
}

static void test_not_pinned_tls_only(void)
{
    boot_reset();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    esp_err_t rc = dial(false);
    check("d10_unpinned_never_80",
          rc == ESP_OK && !s_conn.plain && s_conn.tls == &s_tls &&
          s_plain_connects == 0 && s_tls_connects == 1 &&
          strcmp(s_tls_url, "https://controlplane.test:443") == 0);
    check("d10_unpinned_tls_request", request_ok(s_tls.tx, s_tls.tx_len) && window_is_h2());
    ts2021_close(&s_conn);
    check("d10_unpinned_leaves_80_on", !s_plain_off && !s_tls_next);
}

/* Every way :80 can fail ends on :443 within the same connect, and keeps
 * the rest of the boot there. */
static void fallback_case(const char *name, int plain_rc, reply_t p80, bool eof80)
{
    char n1[64], n2[64];
    boot_reset();
    script(plain_rc, p80, eof80, 1, RP_OK);
    const int64_t t0 = s_now_us;
    struct timespec w0, w1;
    clock_gettime(CLOCK_MONOTONIC, &w0);
    esp_err_t rc = dial(true);
    clock_gettime(CLOCK_MONOTONIC, &w1);
    const long wall_ms = (w1.tv_sec - w0.tv_sec) * 1000 + (w1.tv_nsec - w0.tv_nsec) / 1000000;
    snprintf(n1, sizeof(n1), "d10_fallback_%s", name);
    check(n1, rc == ESP_OK && s_conn.connected && !s_conn.plain &&
          s_conn.tls == &s_tls && s_plain_connects == 1 && s_tls_connects == 1 &&
          s_plain_off && window_is_h2() &&
          request_ok(s_tls.tx, s_tls.tx_len) &&
          wall_ms < 4 * TS2021_PLAIN_TIMEOUT_MS && s_now_us >= t0);
    ts2021_close(&s_conn);
    /* the next dial goes straight to :443 */
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(true);
    snprintf(n2, sizeof(n2), "d10_fallback_%s_sticky", name);
    check(n2, rc == ESP_OK && !s_conn.plain && s_plain_connects == 0 && s_tls_connects == 1);
    ts2021_close(&s_conn);
}

static void test_fallbacks(void)
{
    fallback_case("refused", ESP_FAIL, RP_SILENT, false);
    fallback_case("redirect_308", ESP_OK, RP_REDIRECT, false);
    fallback_case("redirect_308_eof", ESP_OK, RP_REDIRECT, true);
    fallback_case("fake_101_garbage", ESP_OK, RP_FAKE_101, false);
    fallback_case("forged_msg2_tag", ESP_OK, RP_FORGED_TAG, false);
    fallback_case("wrong_key_msg2", ESP_OK, RP_WRONG_KEY, false);
    fallback_case("error_frame", ESP_OK, RP_ERROR_FRAME, false);
    fallback_case("huge_frame", ESP_OK, RP_HUGE_FRAME, false);
    fallback_case("half_101_eof", ESP_OK, RP_HALF_101, true);
    fallback_case("silent", ESP_OK, RP_SILENT, false);   /* one 3-s poll on target */

    /* A middlebox trickling the 101 (one byte per poll): the deadline
     * ends it — here a clock that moves 1/4 of the budget per read. */
    boot_reset();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    s_clock_step = (int64_t)TS2021_PLAIN_TIMEOUT_MS * 1000 / 4;
    esp_err_t rc = dial(true);
    s_clock_step = 0;
    check("d10_fallback_trickle_deadline",
          rc == ESP_OK && !s_conn.plain && s_plain_connects == 1 && s_tls_connects == 1 &&
          s_plain_off);
    ts2021_close(&s_conn);
}

static void test_both_fail(void)
{
    /* :80 broken and :443 down: an outage, not evidence against :80 —
     * the next dial tries :80 again. */
    boot_reset();
    script(ESP_OK, RP_REDIRECT, false, -1, RP_OK);
    esp_err_t rc = dial(true);
    check("d10_both_fail", rc != ESP_OK && !s_conn.connected && s_plain_connects == 1 &&
          s_tls_connects == 1 && !s_plain_off && s_conn.sock == -1 && !s_conn.plain);
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(true);
    check("d10_both_fail_then_80", rc == ESP_OK && s_conn.plain && s_plain_connects == 1 &&
          s_tls_connects == 0);
    ts2021_close(&s_conn);

    /* Control key rotated: Noise refuses the pinned key on both ports.
     * The connect fails (the caller backs off), :80 stays on, nothing
     * else happens — the pin is never re-fetched from here. */
    boot_reset();
    script(ESP_OK, RP_WRONG_KEY, false, 1, RP_WRONG_KEY);
    rc = dial(true);
    check("d10_key_rotation_fails_both", rc != ESP_OK && s_plain_connects == 1 &&
          s_tls_connects == 1 && !s_plain_off && !s_conn.connected);
    script(ESP_OK, RP_WRONG_KEY, false, 1, RP_WRONG_KEY);
    rc = dial(true);
    check("d10_key_rotation_retries_80", rc != ESP_OK && s_plain_connects == 1 &&
          s_tls_connects == 1 && !s_plain_off);

    /* An abort raised during the :80 attempt is for this dial: no :443. */
    boot_reset();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    s_plain_abort = true;
    rc = dial(true);
    check("d10_abort_no_fallback", rc != ESP_OK && s_plain_connects == 1 &&
          s_tls_connects == 0 && !s_plain_off);
    s_abort_reads = false;
}

/* The early-drop heuristic: a :80 conn that failed at the transport
 * within TS2021_PLAIN_EARLY_DROP_S of its handshake sends the next dial
 * to :443, once. */
static void drop_case(const char *name, int64_t age_s, int how, bool want_tls_next)
{
    char n1[64], n2[64];
    boot_reset();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    esp_err_t rc = dial(true);
    s_now_us += age_s * 1000000;
    size_t got = 0;
    s_conn.h2_rx_off = s_conn.h2_rx_len;
    if (how == 0) {                       /* server closed the TCP conn */
        shutdown(s_srv_fd, SHUT_WR);
        (void)ts2021_recv_record(&s_conn, &got);
    } else if (how == 1) {                /* tampered record */
        uint8_t in[128];
        size_t inn = 0;
        put_record(in, &inn, "data", 4);
        in[5] ^= 0x40;
        if (write(s_srv_fd, in, inn) != (ssize_t)inn) s_fails++;
        (void)ts2021_recv_record(&s_conn, &got);
    } else if (how == 2) {                /* deliberate recycle */
        ts2021_abort_reads();
        (void)ts2021_recv_record(&s_conn, &got);
    }                                     /* 3: clean close, no failure */
    ts2021_close(&s_conn);
    snprintf(n1, sizeof(n1), "d10_drop_%s", name);
    check(n1, rc == ESP_OK && s_tls_next == want_tls_next && !s_plain_off);
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(true);
    snprintf(n2, sizeof(n2), "d10_drop_%s_next", name);
    check(n2, rc == ESP_OK && s_conn.plain == !want_tls_next &&
          s_plain_connects == (want_tls_next ? 0 : 1) && !s_tls_next && !s_plain_off);
    ts2021_close(&s_conn);
    if (want_tls_next) {                  /* only one dial */
        script(ESP_OK, RP_OK, false, 1, RP_OK);
        rc = dial(true);
        snprintf(n2, sizeof(n2), "d10_drop_%s_then_80", name);
        check(n2, rc == ESP_OK && s_conn.plain && s_plain_connects == 1);
        ts2021_close(&s_conn);
    }
}

static void test_early_drop(void)
{
    drop_case("fin_at_30s", 30, 0, true);
    drop_case("tamper_at_5s", 5, 1, true);
    drop_case("fin_at_121s", TS2021_PLAIN_EARLY_DROP_S + 1, 0, false);
    drop_case("abort_at_5s", 5, 2, false);
    drop_case("clean_at_5s", 5, 3, false);
}

/* ---- Round 1.3.5: the cached control address ------------------------ */

static bool addr_is(const uint8_t a[4], const uint8_t b[4]) { return memcmp(a, b, 4) == 0; }

/* A fresh boot whose NVS record holds kAddrV4; by-name conns reach kNameV4. */
static void addr_boot(void)
{
    boot_reset();
    ts2021_set_addr(kAddrV4);
    s_name_peer_known = true;
}

static long wall_ms_since(const struct timespec *w0)
{
    struct timespec w1;
    clock_gettime(CLOCK_MONOTONIC, &w1);
    return (w1.tv_sec - w0->tv_sec) * 1000 + (w1.tv_nsec - w0->tv_nsec) / 1000000;
}

static void test_addr_80(void)
{
    /* The cached address answers on :80: one dial, no DNS, the same
     * request bytes (Host: the control host). */
    addr_boot();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    script_addr(ESP_OK, RP_OK, false, 1, RP_OK);
    esp_err_t rc = dial(true);
    uint8_t req[1024];
    size_t rn = srv_drain(req, sizeof(req));
    check("dns_addr_80_first",
          rc == ESP_OK && s_conn.plain && strcmp(s_dials, "A80") == 0 &&
          addr_is(s_conn.peer_v4, kAddrV4) && addr_is(s_addr, kAddrV4) &&
          request_ok(req, rn) && window_is_h2() && s_plain_timeout_ms == TS2021_PLAIN_TIMEOUT_MS);
    ts2021_close(&s_conn);

    /* Stale address, three ways: refused, silent (one :80 budget), and
     * another server there now — no control key, so its msg2 fails. Each
     * is retried by name in the same connect, :80 stays on, and the next
     * connect starts at the address the name reached. */
    static const struct { const char *name; int rc; reply_t kind; } stale[] = {
        { "refused", ESP_FAIL, RP_SILENT },
        { "silent", ESP_OK, RP_SILENT },
        { "other_server", ESP_OK, RP_WRONG_KEY },
        { "http_redirect", ESP_OK, RP_REDIRECT },
    };
    for (size_t i = 0; i < sizeof(stale) / sizeof(stale[0]); i++) {
        char n1[64], n2[64];
        addr_boot();
        script(ESP_OK, RP_OK, false, 1, RP_OK);
        script_addr(stale[i].rc, stale[i].kind, false, -1, RP_OK);
        struct timespec w0;
        clock_gettime(CLOCK_MONOTONIC, &w0);
        rc = dial(true);
        const long ms = wall_ms_since(&w0);
        snprintf(n1, sizeof(n1), "dns_stale_addr_%s_then_name", stale[i].name);
        check(n1, rc == ESP_OK && s_conn.plain && strcmp(s_dials, "A80 N80") == 0 &&
                  !s_plain_off && !s_tls_next && addr_is(s_conn.peer_v4, kNameV4) &&
                  addr_is(s_addr, kNameV4) && window_is_h2() &&
                  ms < 2 * TS2021_PLAIN_TIMEOUT_MS + 300);
        ts2021_close(&s_conn);
        /* next connect: :80 again, at the new address */
        script(ESP_OK, RP_OK, false, 1, RP_OK);
        script_addr(ESP_OK, RP_OK, false, 1, RP_OK);
        rc = dial(true);
        snprintf(n2, sizeof(n2), "dns_stale_addr_%s_no_80_latch", stale[i].name);
        check(n2, rc == ESP_OK && s_conn.plain && strcmp(s_dials, "A80") == 0 &&
                  strcmp(s_plain_host, "198.51.100.20") == 0 && !s_plain_off);
        ts2021_close(&s_conn);
    }

    /* :80 broken for real (a redirecting proxy at every address): the
     * name fails too, so :443 takes over and :80 is off — decided by the
     * name's failure. The address is not retried on :443 (lwIP has the
     * name cached by then). */
    addr_boot();
    script(ESP_OK, RP_REDIRECT, false, 1, RP_OK);
    script_addr(ESP_OK, RP_REDIRECT, false, 1, RP_OK);
    rc = dial(true);
    check("dns_80_broken_latches_on_the_name_only",
          rc == ESP_OK && !s_conn.plain && strcmp(s_dials, "A80 N80 N443") == 0 &&
          s_plain_off && strcmp(s_tls_url, "https://controlplane.test:443") == 0 &&
          addr_is(s_addr, kNameV4));
    ts2021_close(&s_conn);
    /* ... and the next connect is :443 at the address, first */
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    script_addr(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(true);
    check("dns_80_off_then_443_at_addr",
          rc == ESP_OK && !s_conn.plain && strcmp(s_dials, "A443") == 0 &&
          strcmp(s_tls_host, "198.51.100.20") == 0);
    ts2021_close(&s_conn);

    /* An outage (nothing answers): the connect fails, the address stays
     * for the next one, :80 stays on. */
    addr_boot();
    script(ESP_FAIL, RP_SILENT, false, -1, RP_OK);
    rc = dial(true);
    check("dns_outage_keeps_addr",
          rc != ESP_OK && strcmp(s_dials, "A80 N80 N443") == 0 && addr_is(s_addr, kAddrV4) &&
          !s_plain_off && !s_conn.connected);

    /* An abort raised during the address dial ends the connect there:
     * neither the name nor :443. */
    addr_boot();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    script_addr(ESP_OK, RP_OK, false, 1, RP_OK);
    s_plain_abort = true;
    rc = dial(true);
    check("dns_abort_at_addr_not_retried",
          rc != ESP_OK && strcmp(s_dials, "A80") == 0 && !s_plain_off && addr_is(s_addr, kAddrV4));
    s_abort_reads = false;

    /* No record: by name, as before; the conn's peer becomes the address. */
    boot_reset();
    s_name_peer_known = true;
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(true);
    check("dns_no_addr_by_name_then_learnt",
          rc == ESP_OK && strcmp(s_dials, "N80") == 0 && addr_is(s_addr, kNameV4));
    ts2021_close(&s_conn);
    /* A by-name conn whose peer is unknown leaves no address behind. */
    boot_reset();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(true);
    static const uint8_t zero[4];
    check("dns_unknown_peer_no_addr", rc == ESP_OK && addr_is(s_addr, zero) &&
                                      addr_is(s_conn.peer_v4, zero));
    ts2021_close(&s_conn);

    /* ts2021_set_addr takes only addresses worth a connect. */
    static const uint8_t lo[4] = { 127, 0, 0, 1 }, mc[4] = { 239, 1, 2, 3 };
    ts2021_set_addr(lo);
    const bool r1 = addr_is(s_addr, zero);
    ts2021_set_addr(kAddrV4);
    ts2021_set_addr(mc);
    check("dns_set_addr_rejects_unusable", r1 && addr_is(s_addr, zero));
}

/* A conn at the cached address that fails young (transport, GOAWAY)
 * sends the next dial to the name, once; an old failure, a recycle or a
 * clean end keep the address. how: 0 FIN, 1 GOAWAY, 2 recycle, 3 clean. */
static void young_case(const char *name, int64_t age_s, int how, const char *want_next)
{
    char n1[80];
    addr_boot();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    script_addr(ESP_OK, RP_OK, false, 1, RP_OK);
    esp_err_t rc = dial(true);
    const bool at = s_conn.at_addr;
    s_now_us += age_s * 1000000;
    size_t got = 0;
    s_conn.h2_rx_off = s_conn.h2_rx_len;
    if (how == 0) {
        shutdown(s_srv_fd, SHUT_WR);
        (void)ts2021_recv_record(&s_conn, &got);
    } else if (how == 1) {
        s_conn.h2_goaway = true;
    } else if (how == 2) {
        ts2021_abort_reads();
        (void)ts2021_recv_record(&s_conn, &got);
    }
    ts2021_close(&s_conn);
    s_abort_reads = false;
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    script_addr(ESP_OK, RP_OK, false, 1, RP_OK);
    const esp_err_t rc2 = dial(true);
    snprintf(n1, sizeof(n1), "dns_at_addr_%s_next_%s", name, want_next);
    check(n1, rc == ESP_OK && at && rc2 == ESP_OK && strcmp(s_dials, want_next) == 0);
    ts2021_close(&s_conn);
    /* only once: the dial after that is at the address again */
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    script_addr(ESP_OK, RP_OK, false, 1, RP_OK);
    const esp_err_t rc3 = dial(true);
    snprintf(n1, sizeof(n1), "dns_at_addr_%s_then_addr", name);
    check(n1, rc3 == ESP_OK && strcmp(s_dials, "A80") == 0);
    ts2021_close(&s_conn);
}

static void test_addr_young_failure(void)
{
    /* FIN at 30 s: the :80 early drop sends it to :443 too — by name */
    young_case("fin_30s", 30, 0, "N443");
    young_case("goaway_5s", 5, 1, "N80");
    young_case("fin_121s", TS2021_PLAIN_EARLY_DROP_S + 1, 0, "A80");
    young_case("recycle_5s", 5, 2, "A80");
    young_case("clean_5s", 5, 3, "A80");
}

static void test_addr_443(void)
{
    /* TLS only (no pinned key): the address first, the certificate
     * checked against the host name (common_name), the 3-s budget for
     * the connect and handshake, then the stream's 30-s socket polls. */
    addr_boot();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    script_addr(ESP_OK, RP_OK, false, 1, RP_OK);
    esp_err_t rc = dial(false);
    struct timeval tv = { 0 }, tw = { 0 };
    socklen_t tl = sizeof(tv), twl = sizeof(tw);
    getsockopt(s_tls.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, &tl);
    getsockopt(s_tls.fd, SOL_SOCKET, SO_SNDTIMEO, &tw, &twl);
    check("dns_addr_443_first_host_name_kept",
          rc == ESP_OK && !s_conn.plain && strcmp(s_dials, "A443") == 0 &&
          strcmp(s_tls_host, "192.0.2.10") == 0 && s_tls_port == 443 &&
          strcmp(s_tls_cn, "controlplane.test") == 0 &&
          s_tls_timeout_ms == TS2021_ADDR_TIMEOUT_MS && request_ok(s_tls.tx, s_tls.tx_len) &&
          addr_is(s_conn.peer_v4, kAddrV4));
    check("dns_addr_443_stream_polls_30s", tv.tv_sec == 30 && tw.tv_sec == 30);
    ts2021_close(&s_conn);

    /* The address fails (refused / not the control host's certificate):
     * by name, with the full TLS budget, in the same connect. */
    addr_boot();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    script_addr(ESP_OK, RP_OK, false, -1, RP_OK);
    rc = dial(false);
    check("dns_addr_443_fails_then_name",
          rc == ESP_OK && strcmp(s_dials, "A443 N443") == 0 &&
          strcmp(s_tls_url, "https://controlplane.test:443") == 0 &&
          s_tls_timeout_ms == TLS_TIMEOUT_MS && strcmp(s_tls_cn, "controlplane.test") == 0 &&
          addr_is(s_addr, kNameV4) && !s_plain_off);
    ts2021_close(&s_conn);

    /* A stale address that still terminates TLS for the name but never
     * answers the upgrade: the rest of the handshake gets one 3-s poll,
     * not the stream's 4 × 30 s per read, then the name. */
    addr_boot();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    script_addr(ESP_OK, RP_OK, false, 1, RP_STALL);
    s_tls_stalls = 0;
    rc = dial(false);
    check("dns_addr_443_silent_after_tls_one_poll",
          rc == ESP_OK && strcmp(s_dials, "A443 N443") == 0 && s_tls_stalls == 1 &&
          addr_is(s_addr, kNameV4) && s_conn.hs_idle == 0 && s_conn.hs_deadline_us == 0);
    ts2021_close(&s_conn);
    /* ... and one that trickles: the deadline is absolute (the clock moves
     * 0.4 × the budget per read). */
    addr_boot();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    script_addr(ESP_OK, RP_OK, false, 1, RP_OK);
    s_clock_step = (int64_t)TS2021_ADDR_TIMEOUT_MS * 1000 * 4 / 10;
    rc = dial(false);
    s_clock_step = 0;
    check("dns_addr_443_trickle_hits_the_deadline",
          rc == ESP_OK && strcmp(s_dials, "A443 N443") == 0);
    ts2021_close(&s_conn);
}

/* The cached address is first for TS2021_ADDR_TTL_S from the NVS seed or
 * from the by-name conn that reached it — a conn at it does not extend
 * that — so an address that left the name's answer is not kept forever. */
static void test_addr_ttl(void)
{
    addr_boot();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    script_addr(ESP_OK, RP_OK, false, 1, RP_OK);
    esp_err_t rc = dial(true);
    const bool first = rc == ESP_OK && strcmp(s_dials, "A80") == 0;
    ts2021_close(&s_conn);
    s_now_us += ((int64_t)TS2021_ADDR_TTL_S - 2) * 1000000;
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    script_addr(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(true);
    const bool within = rc == ESP_OK && strcmp(s_dials, "A80") == 0;
    ts2021_close(&s_conn);
    s_now_us += 3 * 1000000;
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    script_addr(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(true);
    check("dns_addr_ttl_seed_then_name",
          first && within && rc == ESP_OK && strcmp(s_dials, "N80") == 0 &&
          addr_is(s_addr, kNameV4) && !s_plain_off);
    ts2021_close(&s_conn);
    /* the name's answer is first for another TTL, then the name again */
    s_now_us += ((int64_t)TS2021_ADDR_TTL_S - 2) * 1000000;
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    script_addr(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(true);
    const bool renewed = rc == ESP_OK && strcmp(s_dials, "A80") == 0 &&
                         strcmp(s_plain_host, "198.51.100.20") == 0;
    ts2021_close(&s_conn);
    s_now_us += 3 * 1000000;
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    script_addr(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(true);
    check("dns_addr_ttl_renewed_by_the_name", renewed && rc == ESP_OK &&
                                              strcmp(s_dials, "N80") == 0);
    ts2021_close(&s_conn);
}

/* ---- Round 1.3.5: the one-shot request deadline ---------------------- */

static long rcvtimeo_ms(int fd)
{
    struct timeval tv = { 0 };
    socklen_t tl = sizeof(tv);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, &tl) != 0) return -1;
    return (long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void test_request_deadline(void)
{
    /* A one-shot request on :80 meets a silent server: it fails after the
     * deadline (300 ms in 100-ms polls here; 10 s in 2-s polls on the
     * device), not after the stream's 4 × 30 s, as a transport failure. */
    boot_reset();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    esp_err_t rc = dial(true);
    s_conn.h2_rx_off = s_conn.h2_rx_len;
    const esp_err_t arm = ts2021_request_deadline(&s_conn, TS2021_REQ_TIMEOUT_MS);
    const long armed_ms = rcvtimeo_ms(s_conn.sock);
    const uint8_t idle = s_conn.req_idle;
    struct timespec w0;
    clock_gettime(CLOCK_MONOTONIC, &w0);
    size_t got = 0;
    esp_err_t rr = ts2021_recv_record(&s_conn, &got);
    const long ms = wall_ms_since(&w0);
    check("deadline_silent_server_fires",
          rc == ESP_OK && s_conn.plain && arm == ESP_OK && armed_ms == TS2021_REQ_POLL_MS &&
          idle == (TS2021_REQ_TIMEOUT_MS + TS2021_REQ_POLL_MS - 1) / TS2021_REQ_POLL_MS &&
          rr != ESP_OK && s_conn.req_expired && s_conn.io_failed && !s_conn.aborted &&
          ms >= TS2021_REQ_TIMEOUT_MS - 50 && ms < TS2021_REQ_TIMEOUT_MS + 2 * TS2021_REQ_POLL_MS);
    /* :80 escalation: the caller drops the conn — an early drop, so the
     * next dial goes to :443 (once). */
    ts2021_close(&s_conn);
    const bool next_tls = s_tls_next;
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(true);
    check("deadline_80_stall_next_dial_443",
          next_tls && rc == ESP_OK && !s_conn.plain && strcmp(s_dials, "N443") == 0);
    ts2021_close(&s_conn);

    /* An answer within the deadline is read, and disarming puts the
     * socket back on the stream's 30-s polls. */
    boot_reset();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(true);
    s_conn.h2_rx_off = s_conn.h2_rx_len;
    ts2021_request_deadline(&s_conn, TS2021_REQ_TIMEOUT_MS);
    uint8_t in[128];
    size_t inn = 0;
    put_record(in, &inn, "resp", 4);
    const bool wrote = write(s_srv_fd, in, inn) == (ssize_t)inn;
    rr = ts2021_recv_record(&s_conn, &got);
    const esp_err_t dis = ts2021_request_deadline(&s_conn, 0);
    check("deadline_answer_in_time_then_disarmed",
          wrote && rr == ESP_OK && got == 4 && memcmp(s_conn.h2_rx, "resp", 4) == 0 &&
          dis == ESP_OK && rcvtimeo_ms(s_conn.sock) == 30000 && s_conn.req_idle == 0 &&
          s_conn.req_deadline_us == 0 && !s_conn.req_expired && !s_conn.io_failed &&
          idle_budget(&s_conn) == TS2021_MAX_IDLE_POLLS && poll_ms(&s_conn) == TLS_TIMEOUT_MS);

    /* Stream reads are not under it: a frame that arrives after the
     * deadline's time (the scripted clock moves 11 s per read — a netmap
     * can take ~11 s server-side) is read normally when nothing is armed. */
    put_record(in, &inn, "netmap", 6);   /* appended after "resp"'s bytes */
    s_clock_step = 11 * 1000000LL;
    const bool wrote2 = write(s_srv_fd, in + (inn - (3 + 6 + 16)), 3 + 6 + 16) == 3 + 6 + 16;
    rr = ts2021_recv_record(&s_conn, &got);
    s_clock_step = 0;
    check("deadline_stream_read_unaffected",
          wrote2 && rr == ESP_OK && got == 6 && memcmp(s_conn.h2_rx, "netmap", 6) == 0 &&
          !s_conn.req_expired);

    /* A server trickling the answer cannot hold a request past its time:
     * the deadline is absolute, checked before every read (a clock that
     * moves 0.6 × the budget per read). */
    ts2021_request_deadline(&s_conn, TS2021_REQ_TIMEOUT_MS);
    inn = 0;
    put_record(in, &inn, "late", 4);
    const bool wrote3 = write(s_srv_fd, in, inn) == (ssize_t)inn;
    s_clock_step = (int64_t)TS2021_REQ_TIMEOUT_MS * 1000 * 6 / 10;
    rr = ts2021_recv_record(&s_conn, &got);
    check("deadline_trickle_is_absolute",
          wrote3 && rr != ESP_OK && s_conn.req_expired && s_conn.io_failed);
    /* writes too */
    s_conn.io_failed = false;
    s_conn.req_expired = false;
    const uint8_t ping[9] = { 0, 0, 0, 6, 0, 0, 0, 0, 0 };
    const esp_err_t ws = ts2021_send(&s_conn, ping, sizeof(ping));
    s_clock_step = 0;
    check("deadline_write_side", ws != ESP_OK && s_conn.req_expired && s_conn.io_failed);
    ts2021_close(&s_conn);

    /* :443: the same socket timeouts on esp-tls's fd; an expiry there is
     * no :80 early drop. */
    boot_reset();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(false);
    s_conn.h2_rx_off = s_conn.h2_rx_len;
    const esp_err_t arm2 = ts2021_request_deadline(&s_conn, TS2021_REQ_TIMEOUT_MS);
    const long tls_armed = rcvtimeo_ms(s_tls.fd);
    s_clock_step = (int64_t)TS2021_REQ_TIMEOUT_MS * 1000 * 2;
    rr = ts2021_recv_record(&s_conn, &got);
    s_clock_step = 0;
    const bool expired = s_conn.req_expired;
    ts2021_request_deadline(&s_conn, 0);
    const long tls_disarmed = rcvtimeo_ms(s_tls.fd);
    ts2021_close(&s_conn);
    check("deadline_443_socket_and_expiry",
          rc == ESP_OK && arm2 == ESP_OK && tls_armed == TS2021_REQ_POLL_MS && rr != ESP_OK &&
          expired && tls_disarmed == 30000 && !s_tls_next);

    /* A conn whose socket timeouts cannot be set is not used (it would
     * run the stream on short polls). */
    reset();
    check("deadline_unsettable_socket_fails",
          ts2021_request_deadline(&s_conn, TS2021_REQ_TIMEOUT_MS) == ESP_FAIL && s_conn.io_failed &&
          s_conn.req_deadline_us == 0);
}

/* ---- Round 1.3.5: a requested recycle is marked, not a failure -------- */

static void test_recycle_marked(void)
{
    boot_reset();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    esp_err_t rc = dial(true);
    s_conn.h2_rx_off = s_conn.h2_rx_len;
    ts2021_abort_reads();
    size_t got = 0;
    esp_err_t rr = ts2021_recv_record(&s_conn, &got);
    check("recycle_marks_aborted_not_io_failed",
          rc == ESP_OK && rr != ESP_OK && s_conn.aborted && !s_conn.io_failed &&
          !s_conn.req_expired);
    ts2021_close(&s_conn);
    s_abort_reads = false;
    /* a real failure is not marked aborted */
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(true);
    s_conn.h2_rx_off = s_conn.h2_rx_len;
    shutdown(s_srv_fd, SHUT_WR);
    rr = ts2021_recv_record(&s_conn, &got);
    check("real_failure_not_aborted", rc == ESP_OK && rr != ESP_OK && !s_conn.aborted &&
                                      s_conn.io_failed);
    ts2021_close(&s_conn);
    /* a fresh conn clears both marks */
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(true);
    check("marks_cleared_by_connect", rc == ESP_OK && !s_conn.aborted && !s_conn.req_expired &&
                                      s_conn.req_deadline_us == 0);
    ts2021_close(&s_conn);
}

/* Round 1.3.7, B2: msg1's DH work ahead of the connect — ss once per key
 * pair, the boot's precomputed ephemeral for one handshake only. */
static void test_precompute(void)
{
    static const uint8_t zero[32] = { 0 };
    uint8_t req[1024];

    /* the cache is keyed to this pair after any connect, ss kept, no e */
    boot_reset();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    esp_err_t rc = dial(true);
    check("pre_ss_kept_after_connect",
          rc == ESP_OK && s_pre.keyed && s_pre.pre.have_ss && !s_pre.pre.have_e &&
          memcmp(s_pre.machine_pub, s_machine_pub, 32) == 0 &&
          memcmp(s_pre.control_pub, s_control_pub, 32) == 0);
    ts2021_close(&s_conn);

    /* the cached ss is what msg1 uses: a corrupted one fails msg2 */
    uint8_t good_ss[32];
    memcpy(good_ss, s_pre.pre.ss, 32);
    s_pre.pre.ss[0] ^= 1;
    boot_reset();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(true);
    check("pre_ss_is_used", rc != ESP_OK && !s_conn.connected);
    memcpy(s_pre.pre.ss, good_ss, 32);

    /* the precomputed ephemeral: taken by the next handshake, scrubbed */
    ts2021_precompute(kMachinePriv, s_machine_pub, s_control_pub);
    const bool armed = s_pre.pre.have_e && s_pre.pre.have_ss;
    uint8_t e_pub[32];
    memcpy(e_pub, s_pre.pre.e_pub, 32);
    boot_reset();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(true);
    size_t rn = srv_drain(req, sizeof(req));
    check("pre_e_taken_once",
          armed && rc == ESP_OK && request_ok(req, rn) && !s_pre.pre.have_e &&
          memcmp(s_pre.pre.e_priv, zero, 32) == 0 && memcmp(s_pre.pre.es, zero, 32) == 0 &&
          memcmp(s_pre.pre.e_pub, zero, 32) == 0 && memcmp(s_conn.noise.e_pub, e_pub, 32) == 0);
    ts2021_close(&s_conn);

    /* consumed even when the attempt fails (a :80 that never answers
     * → :443): the fallback's handshake draws its own */
    ts2021_precompute(kMachinePriv, s_machine_pub, s_control_pub);
    boot_reset();
    script(ESP_OK, RP_REDIRECT, false, 1, RP_OK);
    rc = dial(true);
    check("pre_e_single_use_across_fallback", rc == ESP_OK && !s_conn.plain &&
          !s_pre.pre.have_e && s_pre.pre.have_ss);
    ts2021_close(&s_conn);

    /* a precompute for another control key is dropped at the connect */
    uint8_t other[32];
    curve25519_derive_pub(other, kAttackerPriv);
    ts2021_precompute(kMachinePriv, s_machine_pub, other);
    const bool other_keyed = memcmp(s_pre.control_pub, other, 32) == 0 && s_pre.pre.have_e;
    boot_reset();
    script(ESP_OK, RP_OK, false, 1, RP_OK);
    rc = dial(true);
    check("pre_other_key_rekeyed",
          other_keyed && rc == ESP_OK && memcmp(s_pre.control_pub, s_control_pub, 32) == 0 &&
          !s_pre.pre.have_e && s_pre.pre.have_ss && memcmp(s_pre.pre.ss, good_ss, 32) == 0);
    ts2021_close(&s_conn);

    /* a low-order control key: nothing kept */
    ts2021_precompute(kMachinePriv, s_machine_pub, zero);
    check("pre_low_order_nothing_kept", !s_pre.keyed && !s_pre.pre.have_ss && !s_pre.pre.have_e);
}

int main(void)
{
    s_build_reply = build_reply_int;
    curve25519_derive_pub(s_machine_pub, kMachinePriv);
    curve25519_derive_pub(s_control_pub, kControlPriv);
    test_no_early_payload();
    test_early_payload_split();
    test_ep_ends_on_record_boundary();
    test_magic_prefix_put_back();
    test_prefix_before_full_record();
    test_rejects();
    test_d4_recv_in_place();
    test_d4_send();
    test_segmentation_fuzz();
    test_plain_ok();
    test_not_pinned_tls_only();
    test_fallbacks();
    test_both_fail();
    test_early_drop();
    test_addr_80();
    test_addr_young_failure();
    test_addr_443();
    test_addr_ttl();
    test_request_deadline();
    test_recycle_marked();
    test_precompute();
    if (s_srv_fd >= 0) close(s_srv_fd);
    if (s_fails == 0) printf("\nALL OK\n");
    return s_fails ? 1 : 0;
}
