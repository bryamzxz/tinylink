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
//    exactly.
//
// ts2021_client.c is #included so its static functions are reachable;
// esp_tls is faked below, records are sealed with a second Noise state
// whose send key is the client's receive key.

#include "../../components/tinylink/src/ts2021_client.c"

#include <stdio.h>
#include <stdlib.h>

/* ---- fake esp_tls: the server's byte stream, delivered in chunks ---- */

struct esp_tls {
    uint8_t rx[96 * 1024];
    size_t  rx_len, rx_off;
    size_t  chunk;            /* max bytes per esp_tls_conn_read, 0 = any */
    uint8_t tx[16 * 1024];
    size_t  tx_len;
    int     writes;           /* esp_tls_conn_write calls */
};

static struct esp_tls s_tls;

esp_tls_t *esp_tls_init(void) { return &s_tls; }
int esp_tls_conn_http_new_sync(const char *url, const esp_tls_cfg_t *cfg,
                               esp_tls_t *tls)
{
    (void)url; (void)cfg; (void)tls;
    return -1;
}
ssize_t esp_tls_conn_read(esp_tls_t *tls, void *data, size_t datalen)
{
    size_t avail = tls->rx_len - tls->rx_off;
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
int esp_tls_conn_destroy(esp_tls_t *tls) { (void)tls; return 0; }
esp_err_t esp_tls_get_conn_sockfd(esp_tls_t *tls, int *sockfd)
{
    (void)tls; *sockfd = -1;
    return ESP_FAIL;
}
esp_err_t tl_crt_bundle_attach(void *conf) { (void)conf; return ESP_OK; }
/* noise_ik_init's ephemeral key (not used: the tests start after the
 * handshake). */
void esp_fill_random(void *buf, size_t len) { memset(buf, 0x5a, len); }

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

int main(void)
{
    test_no_early_payload();
    test_early_payload_split();
    test_ep_ends_on_record_boundary();
    test_magic_prefix_put_back();
    test_prefix_before_full_record();
    test_rejects();
    test_d4_recv_in_place();
    test_d4_send();
    test_segmentation_fuzz();
    if (s_fails == 0) printf("\nALL OK\n");
    return s_fails ? 1 : 0;
}
