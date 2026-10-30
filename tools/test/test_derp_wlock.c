/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * The DERP write lock (round 1.3.9, derp_wlock.h) as derp_client.c runs
 * it: derp_client.c itself is #included and built over host fakes, so
 * the tests call derp_client_connect_login (a real login against a
 * scripted server), derp_client_send_packet / _try_send_packet, the pong
 * writer derp_send_frame_locked and derp_client_close. Until 1.3.9 the
 * supervisor's close (and its pongs, and wg_tx behind them) waited for
 * the lock with portMAX_DELAY while the other task could sit in a
 * waiting write on a stalled conn for 4 x 30 s — no task-WDT feed
 * meanwhile, a 60-s budget.
 *
 * The fakes: an esp_tls conn that keeps mbedtls's write semantics (a
 * record is copied once and flushed across calls, a blocked send returns
 * WANT_WRITE after its poll — SO_SNDTIMEO — and a call made while a
 * record's tail is still out flushes THAT tail and reports the new buffer
 * as written: ssl_write_real, out_left != 0); select() answering
 * "writable" as lwIP does (room above a low-water mark); a shutdown that
 * wakes a blocked send with an error, unless the test makes it a no-op.
 * The lock primitives are the test's (DERP_CLIENT_HOST_TEST): pthread
 * mutexes, and each thread counts its lock waits and feeds — a wait for
 * the lock right after a timed-out one with no feed between would starve
 * the WDT. The races are forced at fixed points (a writer inside a
 * stalled write, a waiter parked inside its take while the conn closes
 * or is replaced), then shaken in a seeded stress with closes,
 * reconnects, stalls and refused shutdowns at random instants.
 */

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

/* derp_client.c's numbers, scaled down: slices of 2 ms, a 5-ms grace, a
 * 1-s cap on the fed waits (a variable: the cap tests lower it). */
static uint32_t s_fed_max_ms = 1000;
#define DERP_CLIENT_HOST_TEST 1
#define DERP_WL_SLICE_MS   2u
#define DERP_WL_GRACE_MS   5u
#define DERP_WL_FED_MAX_MS s_fed_max_ms
#define CONFIG_TINYLINK_STREAM_IDLE_TIMEOUT_S 120

static int fake_select(int n, fd_set *r, fd_set *w, fd_set *e, struct timeval *tv);
#define DERP_SELECT fake_select

#include "derp_client.c"       /* -I components/tinylink/src */

#include "crypto/curve25519.h"
#include "crypto/nacl_box.h"

#define SLICE_MS  DERP_WL_SLICE_MS
#define GRACE_MS  DERP_WL_GRACE_MS
#define MAX_IDLE  DERP_MAX_IDLE_POLLS
/* MBEDTLS_ERR_NET_SEND_FAILED / _RECV_FAILED: lwIP failed the call
 * (ERR_CLSD after a shutdown) — not in the host stub. */
#define ERR_SEND_FAILED (-0x004E)
#define ERR_RECV_FAILED (-0x004C)
/* A poll no forced interleaving waits out: a close that does not cut
 * (the 1.3.8 shape) shows as a FAIL a few seconds late, not a hang. */
#define LONG_POLL_MS 3000u

static int fails = 0;

static int check_eq_int(const char *name, long got, long want)
{
    if (got == want) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL: %ld != %ld\n", name, got, want);
    return 1;
}

static int check_true(const char *name, bool cond, long detail)
{
    if (cond) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL (%ld)\n", name, detail);
    return 1;
}

static double now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6;
}

static struct timespec deadline_in(uint32_t ms)
{
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    t.tv_sec  += ms / 1000u;
    t.tv_nsec += (long)(ms % 1000u) * 1000000L;
    if (t.tv_nsec >= 1000000000L) { t.tv_sec++; t.tv_nsec -= 1000000000L; }
    return t;
}

/* --- What derp_client.c links against ---------------------------------- */

int64_t esp_timer_get_time(void) { return (int64_t)(now_ms() * 1000.0); }

static uint64_t s_rng = 0xCAFEBABEDEADBEEFULL;
static pthread_mutex_t s_rng_m = PTHREAD_MUTEX_INITIALIZER;
void esp_fill_random(void *buf, size_t len)
{
    pthread_mutex_lock(&s_rng_m);
    uint8_t *o = (uint8_t *)buf;
    for (size_t i = 0; i < len; i++) {
        s_rng ^= s_rng << 13; s_rng ^= s_rng >> 7; s_rng ^= s_rng << 17;
        o[i] = (uint8_t)s_rng;
    }
    pthread_mutex_unlock(&s_rng_m);
}

esp_err_t tl_crt_bundle_attach(void *conf) { (void)conf; return ESP_OK; }

/* --- Per-thread counters and the five primitives ---------------------- */

typedef struct {
    int      takes, timeouts, feeds, overdue;
    int      unfed;        /* a take after a timed-out one, no feed between */
    bool     owed;         /* the last take timed out, no feed since */
    uint32_t longest;      /* longest wait asked for */
    uint32_t last_conn;    /* the conn this thread last wrote a frame on */
    ssize_t  last_ret;     /* what that write call returned */
    void   (*before_take)(int n);   /* forced interleavings (n: this take's index) */
} tl_t;

static __thread tl_t tl;
static int s_overdue_calls;       /* every thread's (atomic) */

static void tl_reset(void (*before_take)(int))
{
    memset(&tl, 0, sizeof(tl));
    tl.before_take = before_take;
}

/* Every call into derp_client.c starts afresh: a timed-out take that
 * ended in "the conn closed" owes no feed. */
static void tl_call(void)
{
    tl.owed = false;
    tl.last_conn = 0;
    tl.last_ret = 0;
}

static bool derp_wl_take(void *lock, uint32_t ms)
{
    if (tl.owed) tl.unfed++;
    if (ms > tl.longest) tl.longest = ms;
    if (tl.before_take != NULL) tl.before_take(tl.takes);
    tl.takes++;
    int rc;
    if (ms == 0) {
        rc = pthread_mutex_trylock((pthread_mutex_t *)lock);
    } else {
        const struct timespec dl = deadline_in(ms);
        rc = pthread_mutex_timedlock((pthread_mutex_t *)lock, &dl);
    }
    if (rc == 0) { tl.owed = false; return true; }
    tl.timeouts++;
    tl.owed = true;
    return false;
}

static void derp_wl_give(void *lock) { pthread_mutex_unlock((pthread_mutex_t *)lock); }

static void derp_wl_feed(void) { tl.feeds++; tl.owed = false; }

static void derp_wl_overdue(uint32_t waited_ms)
{
    (void)waited_ms;
    tl.overdue++;
    __atomic_fetch_add(&s_overdue_calls, 1, __ATOMIC_RELAXED);
}

/* --- A fake esp_tls conn with mbedtls's write semantics ---------------- */

#define WIRE_CAP 8192
#define REC_CAP  256
#define RX_CAP   512
#define LOWAT    64           /* select(): writable with this much room */

struct esp_tls {
    pthread_mutex_t m;
    pthread_cond_t  cv;
    uint32_t id;           /* the client's connect count for this conn */
    int      fd;
    bool     stalled;      /* the peer stopped ACKing: `room` more bytes fit */
    size_t   room;
    bool     cut_works;    /* false: the shutdown is refused */
    uint32_t poll_ms;      /* SO_SNDTIMEO / SO_RCVTIMEO */
    bool     cut, freed;
    int      cuts, uaf, in_write, writes;
    uint8_t  rec[REC_CAP];          /* mbedtls's out record */
    size_t   rec_len, rec_sent;     /* out_left = rec_len - rec_sent */
    uint8_t  wire[WIRE_CAP];        /* what went out after the login */
    size_t   wire_len;
    uint8_t  rx[RX_CAP];            /* the server's login bytes */
    size_t   rx_len, rx_off;
};
typedef struct esp_tls conn_t;

/* Fake fds: under FD_SETSIZE (the writability check FD_SETs them), far
 * above any this process opens (setsockopt on them fails, harmless),
 * unique among the few conns alive at once. */
static int s_fd_next;

static void conn_init(conn_t *k, bool stalled, size_t room, bool cut_works, uint32_t poll_ms)
{
    memset(k, 0, sizeof(*k));
    pthread_mutex_init(&k->m, NULL);
    pthread_cond_init(&k->cv, NULL);
    k->fd = 700 + (s_fd_next++ % 256);
    k->stalled = stalled;
    k->room = room;
    k->cut_works = cut_works;
    k->poll_ms = poll_ms;
}

static void conn_unregister(conn_t *k);

static void conn_destroy(conn_t *k)
{
    conn_unregister(k);
    pthread_mutex_destroy(&k->m);
    pthread_cond_destroy(&k->cv);
}

/* The conn the next esp_tls_init hands out (one connect at a time). */
static conn_t *s_next_conn;

esp_tls_t *esp_tls_init(void) { return s_next_conn; }

int esp_tls_conn_http_new_sync(const char *url, const esp_tls_cfg_t *cfg, esp_tls_t *tls)
{
    (void)url; (void)cfg;
    return tls != NULL ? 1 : -1;
}

int esp_tls_conn_new_sync(const char *h, int hl, int port, const esp_tls_cfg_t *cfg,
                          esp_tls_t *tls)
{
    (void)h; (void)hl; (void)port; (void)cfg;
    return tls != NULL ? 1 : -1;
}

ssize_t esp_tls_conn_write(esp_tls_t *k, const void *data, size_t len)
{
    const uint8_t *buf = (const uint8_t *)data;
    pthread_mutex_lock(&k->m);
    if (k->rx_off < k->rx_len) {         /* the login's own writes */
        pthread_mutex_unlock(&k->m);
        return (ssize_t)len;
    }
    k->writes++;
    if (k->freed) {
        k->uaf++;
        pthread_mutex_unlock(&k->m);
        return ERR_SEND_FAILED;
    }
    k->in_write++;
    pthread_cond_broadcast(&k->cv);
    if (k->rec_len == 0) {               /* a new record */
        if (len > REC_CAP) len = REC_CAP;
        memcpy(k->rec, buf, len);
        k->rec_len = len;
        k->rec_sent = 0;
    }                                    /* else the old record's tail, whatever buf is */
    const struct timespec dl = deadline_in(k->poll_ms);
    ssize_t ret;
    for (;;) {
        if (k->cut) { ret = ERR_SEND_FAILED; break; }
        const size_t left = k->rec_len - k->rec_sent;
        size_t n = left;
        if (k->stalled && n > k->room) n = k->room;
        if (n > 0 && k->wire_len + n <= WIRE_CAP) {
            memcpy(k->wire + k->wire_len, k->rec + k->rec_sent, n);
            k->wire_len += n;
            k->rec_sent += n;
            if (k->stalled) k->room -= n;
        }
        if (k->rec_sent == k->rec_len) { k->rec_len = 0; ret = (ssize_t)len; break; }
        if (pthread_cond_timedwait(&k->cv, &k->m, &dl) == ETIMEDOUT) {
            ret = MBEDTLS_ERR_SSL_WANT_WRITE;
            break;
        }
    }
    k->in_write--;
    tl.last_conn = k->id;
    tl.last_ret = ret;
    pthread_cond_broadcast(&k->cv);
    pthread_mutex_unlock(&k->m);
    return ret;
}

ssize_t esp_tls_conn_read(esp_tls_t *k, void *data, size_t len)
{
    pthread_mutex_lock(&k->m);
    if (k->rx_off < k->rx_len) {
        size_t n = k->rx_len - k->rx_off;
        if (n > len) n = len;
        memcpy(data, k->rx + k->rx_off, n);
        k->rx_off += n;
        pthread_mutex_unlock(&k->m);
        return (ssize_t)n;
    }
    const struct timespec dl = deadline_in(k->poll_ms);
    while (!k->cut && pthread_cond_timedwait(&k->cv, &k->m, &dl) != ETIMEDOUT) {
    }
    const bool cut = k->cut;
    pthread_mutex_unlock(&k->m);
    return cut ? ERR_RECV_FAILED : MBEDTLS_ERR_SSL_WANT_READ;
}

int esp_tls_conn_destroy(esp_tls_t *k)
{
    pthread_mutex_lock(&k->m);
    if (k->in_write > 0) k->uaf++;
    k->freed = true;
    pthread_mutex_unlock(&k->m);
    return 0;
}

esp_err_t esp_tls_get_conn_sockfd(esp_tls_t *k, int *fd)
{
    if (k == NULL || fd == NULL) return ESP_ERR_INVALID_ARG;
    *fd = k->fd;
    return ESP_OK;
}

esp_err_t esp_tls_get_error_handle(esp_tls_t *k, esp_tls_error_handle_t *h)
{
    (void)k;
    *h = NULL;
    return ESP_FAIL;
}

void *esp_tls_get_ssl_context(esp_tls_t *k) { (void)k; return NULL; }
uint32_t mbedtls_ssl_get_verify_result(const mbedtls_ssl_context *ssl) { (void)ssl; return 0; }

/* derp_wl_cut: shutdown(SHUT_RDWR) */
static void derp_wl_cut(void *io)
{
    conn_t *k = (conn_t *)io;
    pthread_mutex_lock(&k->m);
    k->cuts++;
    if (k->cut_works) {
        k->cut = true;
        pthread_cond_broadcast(&k->cv);
    }
    pthread_mutex_unlock(&k->m);
}

/* The registry of live fakes, for select() by fd. */
#define FD_MAX_CONNS 64
static conn_t *s_by_fd[FD_MAX_CONNS];
static pthread_mutex_t s_by_fd_m = PTHREAD_MUTEX_INITIALIZER;

static void conn_unregister(conn_t *k)
{
    pthread_mutex_lock(&s_by_fd_m);
    if (s_by_fd[k->fd % FD_MAX_CONNS] == k) s_by_fd[k->fd % FD_MAX_CONNS] = NULL;
    pthread_mutex_unlock(&s_by_fd_m);
}

static int fake_select(int n, fd_set *r, fd_set *w, fd_set *e, struct timeval *tv)
{
    (void)r; (void)e; (void)tv;
    pthread_mutex_lock(&s_by_fd_m);
    conn_t *k = s_by_fd[(n - 1) % FD_MAX_CONNS];
    if (k != NULL && k->fd != n - 1) k = NULL;
    pthread_mutex_unlock(&s_by_fd_m);
    if (k == NULL || w == NULL) return -1;
    pthread_mutex_lock(&k->m);
    const bool ok = !k->cut && (!k->stalled || k->room >= LOWAT);
    pthread_mutex_unlock(&k->m);
    if (!ok) FD_ZERO(w);
    return ok ? 1 : 0;
}

static void conn_set_stall(conn_t *k, bool stalled, size_t room)
{
    pthread_mutex_lock(&k->m);
    k->stalled = stalled;
    k->room = room;
    pthread_cond_broadcast(&k->cv);
    pthread_mutex_unlock(&k->m);
}

/* Until a writer is inside a write of k (10-s cap: a FAIL, not a hang). */
static bool conn_wait_in_write(conn_t *k)
{
    bool ok = true;
    pthread_mutex_lock(&k->m);
    const struct timespec dl = deadline_in(10000);
    while (k->in_write == 0 && ok) {
        ok = pthread_cond_timedwait(&k->cv, &k->m, &dl) != ETIMEDOUT;
    }
    pthread_mutex_unlock(&k->m);
    return ok;
}

static int conn_in_write(conn_t *k)
{
    pthread_mutex_lock(&k->m);
    const int n = k->in_write;
    pthread_mutex_unlock(&k->m);
    return n;
}

/* --- The scripted DERP server's login ---------------------------------- */

static uint8_t s_cli_priv[32], s_cli_pub[32];
static uint8_t s_login[RX_CAP];
static size_t  s_login_len;
static const uint8_t s_dst[DERP_KEY_LEN] = { 0x5a, 0x01, 0x02, 0x03 };

/* HTTP 101, FrameServerKey, FrameServerInfo (sealed to our key). */
static void login_script_init(void)
{
    uint8_t srv_priv[32], srv_pub[32];
    curve25519_keypair(srv_priv, srv_pub);
    curve25519_keypair(s_cli_priv, s_cli_pub);
    static const char up[] = "HTTP/1.1 101 Switching Protocols\r\n"
                             "Upgrade: DERP\r\nConnection: Upgrade\r\n\r\n";
    size_t n = 0;
    memcpy(s_login, up, sizeof(up) - 1);
    n += sizeof(up) - 1;
    n += derp_write_frame_header(s_login + n, DERP_FRAME_SERVER_KEY,
                                 DERP_MAGIC_LEN + DERP_KEY_LEN);
    memcpy(s_login + n, DERP_MAGIC, DERP_MAGIC_LEN);
    n += DERP_MAGIC_LEN;
    memcpy(s_login + n, srv_pub, DERP_KEY_LEN);
    n += DERP_KEY_LEN;
    static const char js[] = "{\"version\":2}";
    const size_t box = DERP_NONCE_LEN + DERP_TAG_LEN + sizeof(js) - 1;
    n += derp_write_frame_header(s_login + n, DERP_FRAME_SERVER_INFO, (uint32_t)box);
    uint8_t nonce[DERP_NONCE_LEN];
    for (int i = 0; i < DERP_NONCE_LEN; i++) nonce[i] = (uint8_t)(0x40 + i);
    memcpy(s_login + n, nonce, DERP_NONCE_LEN);
    nacl_box(s_login + n + DERP_NONCE_LEN, (const uint8_t *)js, sizeof(js) - 1, nonce,
             s_cli_pub, srv_priv);
    n += box;
    s_login_len = n;
}

/* derp_client_connect_login onto k, as the supervisor's loop does. */
static bool test_connect(derp_client_t *c, conn_t *k)
{
    pthread_mutex_lock(&k->m);
    memcpy(k->rx, s_login, s_login_len);
    k->rx_len = s_login_len;
    k->rx_off = 0;
    pthread_mutex_unlock(&k->m);
    k->id = derp_wl_gen(&c->wl) + 1u;   /* the count this connect sets */
    pthread_mutex_lock(&s_by_fd_m);
    s_by_fd[k->fd % FD_MAX_CONNS] = k;
    pthread_mutex_unlock(&s_by_fd_m);
    s_next_conn = k;
    const esp_err_t err = derp_client_connect_login(c, "derp.test", 443, NULL,
                                                    s_cli_priv, s_cli_pub);
    s_next_conn = NULL;
    return err == ESP_OK && c->tls == k && derp_wl_gen(&c->wl) == k->id;
}

static void test_close(derp_client_t *c)
{
    tl_call();
    derp_client_close(c);
}

static void client_free(derp_client_t *c)
{
    if (c->wl.lock != NULL) {
        pthread_mutex_destroy((pthread_mutex_t *)c->wl.lock);
        free(c->wl.lock);
    }
}

/* --- Frames: an inner one per relayed packet / pong -------------------- */

/* Inner: A5 writer seq len payload[len] xor; relayed in a FrameSendPacket
 * to s_dst (derp_client_send_packet) or as a pong's payload. */
#define FRAME_MAX 24

static size_t frame_make(uint8_t *f, uint8_t writer, uint8_t seq)
{
    const uint8_t plen = (uint8_t)(6 + (seq * 7 + writer) % 12);
    uint8_t x = 0;
    f[0] = 0xA5; f[1] = writer; f[2] = seq; f[3] = plen;
    for (uint8_t i = 0; i < plen; i++) f[4 + i] = (uint8_t)(writer * 31 + seq * 17 + i);
    for (size_t i = 0; i < 4u + plen; i++) x ^= f[i];
    f[4 + plen] = x;
    return 5u + plen;
}

typedef struct {
    int     n;              /* whole frames */
    uint8_t writer[256], seq[256];
    bool    tail;           /* a frame cut short at the end */
    bool    corrupt;
} wire_t;

static bool inner_ok(const uint8_t *f, size_t len)
{
    if (len < 5 || f[0] != 0xA5 || len != 5u + f[3]) return false;
    uint8_t x = 0;
    for (size_t j = 0; j + 1 < len; j++) x ^= f[j];
    return x == f[len - 1];
}

/* The DERP frames in order; only the end may hold one cut short. */
static wire_t wire_parse(conn_t *k)
{
    wire_t w;
    memset(&w, 0, sizeof(w));
    pthread_mutex_lock(&k->m);
    size_t i = 0;
    while (i < k->wire_len) {
        const size_t left = k->wire_len - i;
        if (left < DERP_FRAME_HDR_LEN) { w.tail = true; break; }
        derp_frame_type_t t;
        uint32_t blen;
        if (derp_read_frame_header(k->wire + i, DERP_FRAME_HDR_LEN, &t, &blen) != 0) {
            w.corrupt = true;
            break;
        }
        if (left < DERP_FRAME_HDR_LEN + blen) { w.tail = true; break; }
        const uint8_t *b = k->wire + i + DERP_FRAME_HDR_LEN;
        const uint8_t *in = NULL;
        size_t ilen = 0;
        if (t == DERP_FRAME_SEND_PACKET && blen > DERP_KEY_LEN &&
            memcmp(b, s_dst, DERP_KEY_LEN) == 0) {
            in = b + DERP_KEY_LEN;
            ilen = blen - DERP_KEY_LEN;
        } else if (t == DERP_FRAME_PONG) {
            in = b;
            ilen = blen;
        }
        if (in == NULL || !inner_ok(in, ilen)) { w.corrupt = true; break; }
        if (w.n < 256) {
            w.writer[w.n] = in[1];
            w.seq[w.n] = in[2];
            w.n++;
        }
        i += DERP_FRAME_HDR_LEN + blen;
    }
    pthread_mutex_unlock(&k->m);
    return w;
}

static int wire_count(const wire_t *w, uint8_t writer, uint8_t seq)
{
    int n = 0;
    for (int i = 0; i < w->n; i++) n += w->writer[i] == writer && w->seq[i] == seq;
    return n;
}

/* --- Sends, mapped to what wg_tx sees ---------------------------------- */

enum { R_OK, R_STATE, R_BUSY, R_FAIL, R_OTHER };

typedef struct {
    int      res;
    uint32_t on;          /* the conn its last write call went to (0: none) */
    ssize_t  last_ret;    /* that call's return */
} sent_t;

static int res_of(esp_err_t e)
{
    switch (e) {
    case ESP_OK:                return R_OK;
    case ESP_ERR_INVALID_STATE: return R_STATE;
    case ESP_ERR_TIMEOUT:       return R_BUSY;
    case ESP_FAIL:              return R_FAIL;
    default:                    return R_OTHER;
    }
}

/* A relayed frame (`pong`: the recv loop's pong writer instead). */
static sent_t send_one(derp_client_t *c, uint8_t writer, uint8_t seq, bool no_wait, bool pong)
{
    uint8_t f[FRAME_MAX];
    const size_t n = frame_make(f, writer, seq);
    tl_call();
    esp_err_t e;
    if (pong) {
        /* -1 either way: refused (nothing written) or failed */
        e = derp_send_frame_locked(c, DERP_FRAME_PONG, f, n) == 0 ? ESP_OK
          : tl.last_conn != 0 ? ESP_FAIL : ESP_ERR_INVALID_STATE;
    } else if (no_wait) {
        e = derp_client_try_send_packet(c, s_dst, f, n);
    } else {
        e = derp_client_send_packet(c, s_dst, f, n);
    }
    sent_t s = { res_of(e), tl.last_conn, tl.last_ret };
    return s;
}

/* --- One writer on its own thread, with a "done" signal ---------------- */

typedef struct {
    derp_client_t *c;
    uint8_t        writer, seq;
    bool           no_wait;
    void         (*before_take)(int n);
    sent_t         r;
    tl_t           tl;
    pthread_mutex_t m;
    pthread_cond_t  cv;
    bool           done;
} wjob_t;

static void *writer_main(void *arg)
{
    wjob_t *j = (wjob_t *)arg;
    tl_reset(j->before_take);
    j->r = send_one(j->c, j->writer, j->seq, j->no_wait, false);
    j->tl = tl;
    pthread_mutex_lock(&j->m);
    j->done = true;
    pthread_cond_broadcast(&j->cv);
    pthread_mutex_unlock(&j->m);
    return NULL;
}

static void wjob(wjob_t *j, derp_client_t *c, uint8_t writer, uint8_t seq)
{
    memset(j, 0, sizeof(*j));
    j->c = c;
    j->writer = writer;
    j->seq = seq;
    pthread_mutex_init(&j->m, NULL);
    pthread_cond_init(&j->cv, NULL);
}

static bool wjob_wait_done(wjob_t *j, uint32_t ms)
{
    bool ok = true;
    pthread_mutex_lock(&j->m);
    const struct timespec dl = deadline_in(ms);
    while (!j->done && ok) ok = pthread_cond_timedwait(&j->cv, &j->m, &dl) != ETIMEDOUT;
    const bool done = j->done;
    pthread_mutex_unlock(&j->m);
    return done;
}

static void wjob_free(wjob_t *j)
{
    pthread_mutex_destroy(&j->m);
    pthread_cond_destroy(&j->cv);
}

/* --- Rendezvous -------------------------------------------------------- */

static pthread_mutex_t s_rv_m = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  s_rv_cv = PTHREAD_COND_INITIALIZER;
static int  s_rv_takes;       /* takes of the hooked thread */
static int  s_rv_park_at;     /* its take index that parks, -1 none */
static bool s_rv_parked, s_rv_release;

static void rv_reset(int park_at)
{
    pthread_mutex_lock(&s_rv_m);
    s_rv_takes = 0;
    s_rv_park_at = park_at;
    s_rv_parked = s_rv_release = false;
    pthread_mutex_unlock(&s_rv_m);
}

static void rv_hook(int n)
{
    pthread_mutex_lock(&s_rv_m);
    s_rv_takes = n + 1;
    pthread_cond_broadcast(&s_rv_cv);
    if (n == s_rv_park_at) {
        s_rv_parked = true;
        pthread_cond_broadcast(&s_rv_cv);
        const struct timespec dl = deadline_in(10000);
        while (!s_rv_release &&
               pthread_cond_timedwait(&s_rv_cv, &s_rv_m, &dl) != ETIMEDOUT) {
        }
    }
    pthread_mutex_unlock(&s_rv_m);
}

/* Until the hooked thread made `takes` takes, or parked (10-s cap). */
static bool rv_wait(int takes, bool parked)
{
    bool ok = true;
    pthread_mutex_lock(&s_rv_m);
    const struct timespec dl = deadline_in(10000);
    while (ok && (parked ? !s_rv_parked : s_rv_takes < takes)) {
        ok = pthread_cond_timedwait(&s_rv_cv, &s_rv_m, &dl) != ETIMEDOUT;
    }
    pthread_mutex_unlock(&s_rv_m);
    return ok;
}

static void rv_release(void)
{
    pthread_mutex_lock(&s_rv_m);
    s_rv_release = true;
    pthread_cond_broadcast(&s_rv_cv);
    pthread_mutex_unlock(&s_rv_m);
}

/* A conn and a client logged in on it. */
static bool setup(derp_client_t *c, conn_t *k, bool stalled, size_t room, bool cut_works,
                  uint32_t poll_ms)
{
    memset(c, 0, sizeof(*c));
    conn_init(k, false, 0, cut_works, poll_ms);
    const bool ok = test_connect(c, k);
    conn_set_stall(k, stalled, room);
    return ok;
}

/* --- Forced interleavings ---------------------------------------------- */

/* The defect: wg_tx in a waiting write on a stalled conn (its budget here
 * 4 x 3 s), the supervisor closes. The close cuts it after the grace,
 * feeding, and gets the lock at once — not when a poll ends. */
static void test_close_cuts_stalled_writer(void)
{
    derp_client_t c;
    conn_t k;
    fails += check_true("close/login", setup(&c, &k, true, 0, true, LONG_POLL_MS), 0);
    wjob_t w;
    wjob(&w, &c, 1, 0);
    pthread_t t;
    pthread_create(&t, NULL, writer_main, &w);
    fails += check_true("close/stalled-writer-inside", conn_wait_in_write(&k), 0);
    tl_reset(NULL);
    const double t0 = now_ms();
    test_close(&c);
    const double dt = now_ms() - t0;
    pthread_join(t, NULL);
    const wire_t wr = wire_parse(&k);
    fails += check_eq_int("close/stalled-one-shutdown", k.cuts, 1);
    fails += check_eq_int("close/stalled-writer-failed", w.r.res, R_FAIL);
    fails += check_eq_int("close/stalled-woken-by-shutdown", w.r.last_ret, ERR_SEND_FAILED);
    fails += check_eq_int("close/stalled-conn-freed", k.freed, 1);
    fails += check_eq_int("close/stalled-no-use-after-free", k.uaf, 0);
    fails += check_true("close/stalled-fed-past-grace", tl.feeds >= 1, tl.feeds);
    fails += check_eq_int("close/stalled-every-wait-fed", tl.unfed, 0);
    fails += check_true("close/stalled-waits-bounded", tl.longest <= GRACE_MS, (long)tl.longest);
    fails += check_true("close/stalled-before-the-poll-ends", dt < 1500.0, (long)dt);
    fails += check_eq_int("close/stalled-frame-not-whole", wr.n, 0);
    const sent_t after = send_one(&c, 1, 1, false, false);
    fails += check_eq_int("close/stalled-then-refused", after.res, R_STATE);
    wjob_free(&w);
    conn_destroy(&k);
    client_free(&c);
}

/* The cut is refused (a shutdown that fails): the writer waits out its
 * poll, and the abort flag stops it before the next one — one poll, not
 * MAX_IDLE. The close feeds in slices meanwhile. */
static void test_close_shutdown_refused(void)
{
    derp_client_t c;
    conn_t k;
    fails += check_true("refused/login", setup(&c, &k, true, 0, false, 150), 0);
    wjob_t w;
    wjob(&w, &c, 1, 0);
    pthread_t t;
    pthread_create(&t, NULL, writer_main, &w);
    fails += check_true("refused/writer-inside", conn_wait_in_write(&k), 0);
    tl_reset(NULL);
    test_close(&c);
    pthread_join(t, NULL);
    fails += check_eq_int("refused/one-shutdown", k.cuts, 1);
    fails += check_eq_int("refused/writer-failed", w.r.res, R_FAIL);
    fails += check_eq_int("refused/its-poll-ran-out", w.r.last_ret, MBEDTLS_ERR_SSL_WANT_WRITE);
    fails += check_eq_int("refused/one-poll-not-four", k.writes, 1);
    fails += check_true("refused/close-fed-every-slice", tl.feeds >= 3, tl.feeds);
    fails += check_eq_int("refused/every-wait-fed", tl.unfed, 0);
    fails += check_true("refused/waits-bounded", tl.longest <= GRACE_MS, (long)tl.longest);
    fails += check_eq_int("refused/no-use-after-free", k.uaf, 0);
    wjob_free(&w);
    conn_destroy(&k);
    client_free(&c);
}

/* No writer: one take, no cut, no feed — the 1.3.8 path. */
static void test_close_idle(void)
{
    derp_client_t c;
    conn_t k;
    fails += check_true("idle/login", setup(&c, &k, false, 0, true, LONG_POLL_MS), 0);
    tl_reset(NULL);
    test_close(&c);
    fails += check_eq_int("idle/no-shutdown", k.cuts, 0);
    fails += check_eq_int("idle/one-take", tl.takes, 1);
    fails += check_eq_int("idle/no-feed", tl.feeds, 0);
    fails += check_eq_int("idle/conn-freed", k.freed, 1);
    fails += check_eq_int("idle/refuses-after", derp_client_is_connected(&c), 0);
    /* Again with no conn: the lock is still taken. */
    tl_reset(NULL);
    test_close(&c);
    fails += check_eq_int("idle/no-conn-one-take", tl.takes, 1);
    /* Never connected (no lock): nothing to take. */
    derp_client_t z;
    memset(&z, 0, sizeof(z));
    tl_reset(NULL);
    test_close(&z);
    fails += check_eq_int("idle/never-connected-no-take", tl.takes, 0);
    conn_destroy(&k);
    client_free(&c);
}

/* A writer that ends its frame within the grace is not cut: the frame is
 * whole on the wire and reported sent (derp_wl_close_lock with a long
 * grace, the supervisor's close after it). */
typedef struct { derp_client_t *c; bool cut; tl_t tl; } cjob_t;

static void *closer_main(void *arg)
{
    cjob_t *j = (cjob_t *)arg;
    tl_reset(rv_hook);
    j->cut = derp_wl_close_lock(&j->c->wl, j->c->tls, 10000, SLICE_MS, s_fed_max_ms);
    derp_wl_give(j->c->wl.lock);
    j->tl = tl;
    return NULL;
}

static void test_close_grace(void)
{
    derp_client_t c;
    conn_t k;
    fails += check_true("grace/login", setup(&c, &k, true, 0, true, LONG_POLL_MS), 0);
    wjob_t w;
    wjob(&w, &c, 1, 0);
    pthread_t tw, tc;
    pthread_create(&tw, NULL, writer_main, &w);
    fails += check_true("grace/writer-inside", conn_wait_in_write(&k), 0);
    rv_reset(-1);
    cjob_t cj = { &c, true, { 0 } };
    pthread_create(&tc, NULL, closer_main, &cj);
    fails += check_true("grace/closer-waiting", rv_wait(1, false), 0);
    conn_set_stall(&k, false, 0);        /* the ACKs come back */
    pthread_join(tw, NULL);
    pthread_join(tc, NULL);
    test_close(&c);
    const wire_t wr = wire_parse(&k);
    fails += check_eq_int("grace/writer-sent", w.r.res, R_OK);
    fails += check_eq_int("grace/no-cut", cj.cut, 0);
    fails += check_eq_int("grace/no-shutdown", k.cuts, 0);
    fails += check_eq_int("grace/frame-whole", wire_count(&wr, 1, 0), 1);
    fails += check_eq_int("grace/no-tail", wr.tail, 0);
    wjob_free(&w);
    conn_destroy(&k);
    client_free(&c);
}

/* wg_tx behind the supervisor's stalled write (or the reverse): it feeds
 * each slice, and leaves without the lock once the conn closes. */
static void test_waiter_feeds_then_leaves(void)
{
    derp_client_t c;
    conn_t k;
    fails += check_true("waiter/login", setup(&c, &k, true, 0, true, LONG_POLL_MS), 0);
    wjob_t w1, w2;
    wjob(&w1, &c, 1, 0);
    wjob(&w2, &c, 2, 0);
    rv_reset(-1);
    w2.before_take = rv_hook;
    pthread_t t1, t2;
    pthread_create(&t1, NULL, writer_main, &w1);
    fails += check_true("waiter/holder-inside", conn_wait_in_write(&k), 0);
    pthread_create(&t2, NULL, writer_main, &w2);
    fails += check_true("waiter/several-slices", rv_wait(5, false), 0);
    tl_reset(NULL);
    test_close(&c);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    const wire_t wr = wire_parse(&k);
    fails += check_eq_int("waiter/holder-failed", w1.r.res, R_FAIL);
    fails += check_eq_int("waiter/left-without-writing", w2.r.res, R_STATE);
    fails += check_true("waiter/fed-while-waiting", w2.tl.feeds >= 4, w2.tl.feeds);
    fails += check_eq_int("waiter/every-wait-fed", w2.tl.unfed, 0);
    fails += check_eq_int("waiter/waits-one-slice", (long)w2.tl.longest, SLICE_MS);
    fails += check_eq_int("waiter/nothing-on-wire", wr.n, 0);
    fails += check_eq_int("waiter/no-use-after-free", k.uaf, 0);
    wjob_free(&w1);
    wjob_free(&w2);
    conn_destroy(&k);
    client_free(&c);
    /* no_wait behind a holder: one try, refused as busy, no wait. */
    conn_t k2;
    fails += check_true("waiter/try-login", setup(&c, &k2, true, 0, true, LONG_POLL_MS), 0);
    wjob(&w1, &c, 1, 0);
    pthread_create(&t1, NULL, writer_main, &w1);
    fails += check_true("waiter/try-holder-inside", conn_wait_in_write(&k2), 0);
    wjob(&w2, &c, 2, 0);
    w2.no_wait = true;
    writer_main(&w2);
    fails += check_eq_int("waiter/try-busy", w2.r.res, R_BUSY);
    fails += check_eq_int("waiter/try-one-take", w2.tl.takes, 1);
    fails += check_eq_int("waiter/try-no-wait", (long)w2.tl.longest, 0);
    test_close(&c);
    pthread_join(t1, NULL);
    wjob_free(&w1);
    wjob_free(&w2);
    conn_destroy(&k2);
    client_free(&c);
}

/* A waiter leaves within a slice once the close began — while the holder
 * still sits in its write, the lock not given yet. */
static void test_waiter_leaves_lock_held(void)
{
    derp_client_t c;
    conn_t k;
    fails += check_true("leave/login", setup(&c, &k, true, 0, true, LONG_POLL_MS), 0);
    wjob_t w1, w2;
    wjob(&w1, &c, 1, 0);
    wjob(&w2, &c, 2, 0);
    rv_reset(-1);
    w2.before_take = rv_hook;
    pthread_t t1, t2;
    pthread_create(&t1, NULL, writer_main, &w1);
    fails += check_true("leave/holder-inside", conn_wait_in_write(&k), 0);
    pthread_create(&t2, NULL, writer_main, &w2);
    fails += check_true("leave/waiter-waiting", rv_wait(2, false), 0);
    /* derp_wl_close_lock's first step, the holder untouched */
    __atomic_store_n(&c.wl.connected, false, __ATOMIC_RELEASE);
    const bool left = wjob_wait_done(&w2, 1000);
    const int holder_in = conn_in_write(&k);
    tl_reset(NULL);
    test_close(&c);
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    fails += check_eq_int("leave/waiter-left", left, 1);
    fails += check_eq_int("leave/holder-still-writing", holder_in, 1);
    fails += check_eq_int("leave/waiter-refused", w2.r.res, R_STATE);
    fails += check_eq_int("leave/waiter-never-wrote", w2.r.on, 0);
    wjob_free(&w1);
    wjob_free(&w2);
    conn_destroy(&k);
    client_free(&c);
}

/* Review 1.3.9: a waiter that wins the lock after the close dropped
 * `connected` (the holder finished, the closer has not taken the lock
 * yet) is refused, though the connect count still matches. */
static void test_waiter_wins_after_close_began(void)
{
    derp_client_t c;
    conn_t k;
    fails += check_true("gap/login", setup(&c, &k, true, 0, true, LONG_POLL_MS), 0);
    wjob_t w1, w2;
    wjob(&w1, &c, 1, 0);
    wjob(&w2, &c, 2, 0);
    rv_reset(1);                       /* park before its 2nd take */
    w2.before_take = rv_hook;
    pthread_t t1, t2;
    pthread_create(&t1, NULL, writer_main, &w1);
    fails += check_true("gap/holder-inside", conn_wait_in_write(&k), 0);
    pthread_create(&t2, NULL, writer_main, &w2);
    fails += check_true("gap/waiter-parked", rv_wait(0, true), 0);
    /* derp_wl_close_lock's first step, then the holder ends its frame */
    __atomic_store_n(&c.wl.connected, false, __ATOMIC_RELEASE);
    conn_set_stall(&k, false, 0);
    pthread_join(t1, NULL);
    rv_release();                      /* the lock is free: the waiter wins it */
    pthread_join(t2, NULL);
    tl_reset(NULL);
    test_close(&c);
    fails += check_eq_int("gap/holder-sent", w1.r.res, R_OK);
    fails += check_eq_int("gap/waiter-refused-not-held", w2.r.res, R_STATE);
    fails += check_eq_int("gap/waiter-never-wrote", k.writes, 1);
    wjob_free(&w1);
    wjob_free(&w2);
    conn_destroy(&k);
    client_free(&c);
}

/* A waiter that set out for conn A, parked in its take while A closes and
 * B comes up: it gets the lock with B up, and the connect count refuses
 * it. A frame queued behind a dying write never lands on the next conn. */
static void test_waiter_never_crosses(void)
{
    derp_client_t c;
    conn_t a, b;
    fails += check_true("cross/login", setup(&c, &a, true, 0, true, LONG_POLL_MS), 0);
    conn_init(&b, false, 0, true, LONG_POLL_MS);
    wjob_t w1, w2;
    wjob(&w1, &c, 1, 0);
    wjob(&w2, &c, 2, 0);
    rv_reset(2);
    w2.before_take = rv_hook;
    pthread_t t1, t2;
    pthread_create(&t1, NULL, writer_main, &w1);
    fails += check_true("cross/holder-inside", conn_wait_in_write(&a), 0);
    pthread_create(&t2, NULL, writer_main, &w2);
    fails += check_true("cross/waiter-parked", rv_wait(0, true), 0);
    tl_reset(NULL);
    test_close(&c);
    pthread_join(t1, NULL);
    fails += check_true("cross/next-login", test_connect(&c, &b), 0);
    rv_release();
    pthread_join(t2, NULL);
    const wire_t wb = wire_parse(&b);
    fails += check_eq_int("cross/next-conn-up", derp_client_is_connected(&c), 1);
    fails += check_eq_int("cross/waiter-refused", w2.r.res, R_STATE);
    fails += check_eq_int("cross/next-conn-empty", wb.n, 0);
    fails += check_eq_int("cross/no-use-after-free", a.uaf + b.uaf, 0);
    /* A frame that sets out once B is up goes on B. */
    const sent_t s = send_one(&c, 2, 1, false, false);
    const wire_t wb2 = wire_parse(&b);
    fails += check_eq_int("cross/fresh-send-ok", s.res, R_OK);
    fails += check_eq_int("cross/fresh-send-on-next", (long)s.on, (long)b.id);
    fails += check_eq_int("cross/fresh-send-whole", wire_count(&wb2, 2, 1), 1);
    test_close(&c);
    wjob_free(&w1);
    wjob_free(&w2);
    conn_destroy(&a);
    conn_destroy(&b);
    client_free(&c);
}

/* A write that failed on its own (4 polls, part of the frame out): the
 * conn takes no more frames and the reader is told to leave
 * (frame_failed_locked); the socket is left to the close. With 1.3.8's
 * rule (the conn left up) the next frame, its record never written —
 * mbedtls flushed the first one's tail instead — was reported sent. */
static void test_failed_write(void)
{
    derp_client_t c;
    conn_t k;
    fails += check_true("failed/login", setup(&c, &k, true, 7, true, 3), 0);
    const sent_t first = send_one(&c, 1, 0, false, false);
    const bool up = derp_client_is_connected(&c);
    const bool abort_reads = c.abort_reads;
    conn_set_stall(&k, false, 0);        /* the ACKs come back */
    const sent_t next = send_one(&c, 1, 1, false, false);
    const wire_t wr = wire_parse(&k);
    fails += check_eq_int("failed/first-fails", first.res, R_FAIL);
    fails += check_eq_int("failed/first-ran-its-polls", k.writes, (long)MAX_IDLE);
    fails += check_eq_int("failed/conn-closed-to-frames", up, 0);
    fails += check_eq_int("failed/reader-told-to-leave", abort_reads, 1);
    fails += check_eq_int("failed/no-cut-on-the-writer", k.cuts, 0);
    fails += check_eq_int("failed/next-refused", next.res, R_STATE);
    fails += check_eq_int("failed/first-cut-short", wr.tail, 1);
    fails += check_eq_int("failed/nothing-whole", wr.n, 0);
    test_close(&c);
    conn_destroy(&k);
    client_free(&c);
    /* 1.3.8's rule, emulated: the conn put back up after the failure. */
    fails += check_true("failed/1.3.8-login", setup(&c, &k, true, 7, true, 3), 0);
    (void)send_one(&c, 1, 0, false, false);
    derp_wl_set_up(&c.wl);
    c.abort_reads = false;
    conn_set_stall(&k, false, 0);
    const sent_t old = send_one(&c, 1, 1, false, false);
    const wire_t wo = wire_parse(&k);
    fails += check_eq_int("failed/1.3.8-next-reported-sent", old.res, R_OK);
    fails += check_eq_int("failed/1.3.8-next-not-on-wire", wire_count(&wo, 1, 1), 0);
    fails += check_eq_int("failed/1.3.8-first-tail-flushed", wire_count(&wo, 1, 0), 1);
    test_close(&c);
    conn_destroy(&k);
    client_free(&c);
    /* The pong writer the same way. */
    fails += check_true("failed/pong-login", setup(&c, &k, true, 0, true, 3), 0);
    const sent_t pong = send_one(&c, 2, 0, false, true);
    fails += check_eq_int("failed/pong-fails", pong.res, R_FAIL);
    fails += check_eq_int("failed/pong-conn-closed", derp_client_is_connected(&c), 0);
    fails += check_eq_int("failed/pong-reader-told", c.abort_reads, 1);
    test_close(&c);
    conn_destroy(&k);
    client_free(&c);
}

/* A best-effort copy (B7): refused while the socket cannot take it, with
 * the lock free — nothing written — and sent once it can. */
static void test_try_not_writable(void)
{
    derp_client_t c;
    conn_t k;
    fails += check_true("try/login", setup(&c, &k, true, LOWAT - 1, true, LONG_POLL_MS), 0);
    const sent_t no = send_one(&c, 1, 0, true, false);
    fails += check_eq_int("try/not-writable-busy", no.res, R_BUSY);
    fails += check_eq_int("try/not-writable-nothing-written", k.writes, 0);
    fails += check_eq_int("try/conn-still-up", derp_client_is_connected(&c), 1);
    conn_set_stall(&k, true, LOWAT);
    const sent_t yes = send_one(&c, 1, 1, true, false);
    const wire_t wr = wire_parse(&k);
    fails += check_eq_int("try/writable-sent", yes.res, R_OK);
    fails += check_eq_int("try/writable-whole", wire_count(&wr, 1, 1), 1);
    test_close(&c);
    conn_destroy(&k);
    client_free(&c);
}

/* The supervisor's close on its own thread (the cap test). */
static tl_t s_cap_close_tl;

static void *closer_cap_main(void *arg)
{
    tl_reset(rv_hook);
    test_close((derp_client_t *)arg);
    s_cap_close_tl = tl;
    return NULL;
}

/* A lock never given back (a leak): the fed waits stop after the cap with
 * one overdue call, so the task WDT would take it from there; the wait
 * goes on and ends when the lock comes back. Writer and close alike. */
static void test_cap(void)
{
    const uint32_t keep = s_fed_max_ms;
    s_fed_max_ms = 100;                  /* 50 slices */
    derp_client_t c;
    conn_t k;
    fails += check_true("cap/login", setup(&c, &k, false, 0, true, LONG_POLL_MS), 0);
    pthread_mutex_t *lock = (pthread_mutex_t *)c.wl.lock;
    __atomic_store_n(&s_overdue_calls, 0, __ATOMIC_RELAXED);
    pthread_mutex_lock(lock);            /* the leak */
    wjob_t w;
    wjob(&w, &c, 1, 0);
    rv_reset(-1);
    w.before_take = rv_hook;
    pthread_t t;
    pthread_create(&t, NULL, writer_main, &w);
    fails += check_true("cap/writer-past-cap", rv_wait(60, false), 0);
    pthread_mutex_unlock(lock);
    pthread_join(t, NULL);
    fails += check_eq_int("cap/writer-overdue-once", w.tl.overdue, 1);
    fails += check_true("cap/writer-fed-up-to-cap", w.tl.feeds >= 45 && w.tl.feeds <= 51,
                        w.tl.feeds);
    fails += check_true("cap/writer-unfed-after", w.tl.unfed >= 5, w.tl.unfed);
    fails += check_eq_int("cap/writer-sent-once-free", w.r.res, R_OK);
    /* The close behind the same leak. */
    pthread_mutex_lock(lock);
    rv_reset(-1);
    pthread_t tc;
    pthread_create(&tc, NULL, closer_cap_main, &c);
    fails += check_true("cap/close-past-cap", rv_wait(60, false), 0);
    pthread_mutex_unlock(lock);
    pthread_join(tc, NULL);
    fails += check_eq_int("cap/close-overdue-once", s_cap_close_tl.overdue, 1);
    fails += check_true("cap/close-unfed-after", s_cap_close_tl.unfed >= 5,
                        s_cap_close_tl.unfed);
    fails += check_eq_int("cap/close-cut-the-conn", k.cuts, 1);
    fails += check_eq_int("cap/close-freed", k.freed, 1);
    fails += check_eq_int("cap/overdue-calls",
                          __atomic_load_n(&s_overdue_calls, __ATOMIC_RELAXED), 2);
    wjob_free(&w);
    conn_destroy(&k);
    client_free(&c);
    s_fed_max_ms = keep;
}

/* --- Stress ------------------------------------------------------------ */

#define ST_ROUNDS   60
#define ST_CONNS    8
#define ST_BATCHES  4
#define ST_BATCH    5
#define ST_PONGS    10
#define ST_INIT     0x80          /* seq flag: the INIT behind a batch */
#define ST_LOG      64

typedef struct { uint8_t seq; sent_t r; } st_sent_t;

static int s_st_running;          /* writers still sending (atomic) */

typedef struct {
    derp_client_t *c;
    uint32_t  seed;
    st_sent_t log[ST_LOG];
    int       n;
    int       cross;              /* INITs on another conn than their failed batch */
    int       init_on_failed;     /* INITs on the conn their batch failed on */
    tl_t      tl;
} st_writer_t;

static uint32_t xs(uint32_t *s)
{
    *s ^= *s << 13; *s ^= *s >> 17; *s ^= *s << 5;
    return *s;
}

static void st_pause(uint32_t *s, uint32_t max_us)
{
    const uint32_t us = xs(s) % (max_us + 1);
    if (us < 50) { sched_yield(); return; }
    struct timespec t = { 0, (long)us * 1000L };
    nanosleep(&t, NULL);
}

/* wg_tx: batches of waiting writes (the re-send: stops at the first
 * frame refused or failed, as wg_rescue_flush), each with its INIT copy
 * behind, now and then a best-effort copy. */
static void *st_wgtx(void *arg)
{
    st_writer_t *w = (st_writer_t *)arg;
    tl_reset(NULL);
    uint8_t seq = 0;
    for (int b = 0; b < ST_BATCHES; b++) {
        uint32_t failed_on = 0;
        for (int i = 0; i < ST_BATCH; i++) {
            const bool try_only = xs(&w->seed) % 5 == 0;
            const sent_t r = send_one(w->c, 1, seq, try_only, false);
            w->log[w->n++] = (st_sent_t){ seq, r };
            seq++;
            if (r.res == R_FAIL) failed_on = r.on;
            if (r.res == R_FAIL || r.res == R_STATE) break;   /* kept for the next login */
            st_pause(&w->seed, 1200);
        }
        const uint8_t iseq = (uint8_t)(ST_INIT | b);
        const sent_t r = send_one(w->c, 1, iseq, false, false);
        w->log[w->n++] = (st_sent_t){ iseq, r };
        if (failed_on != 0 && r.res == R_OK) {
            if (r.on == failed_on) w->init_on_failed++; else w->cross++;
        }
        st_pause(&w->seed, 3000);
    }
    w->tl = tl;
    __atomic_fetch_sub(&s_st_running, 1, __ATOMIC_RELEASE);
    return NULL;
}

/* The supervisor's pongs. */
static void *st_pongs(void *arg)
{
    st_writer_t *w = (st_writer_t *)arg;
    tl_reset(NULL);
    for (uint8_t seq = 0; seq < ST_PONGS; seq++) {
        const sent_t r = send_one(w->c, 2, seq, false, true);
        w->log[w->n++] = (st_sent_t){ seq, r };
        st_pause(&w->seed, 3000);
    }
    w->tl = tl;
    __atomic_fetch_sub(&s_st_running, 1, __ATOMIC_RELEASE);
    return NULL;
}

static void test_stress(void)
{
    int uaf = 0, corrupt = 0, ok_missing = 0, ok_dup = 0, ok_elsewhere = 0, whole_unreported = 0;
    int out_of_order = 0, unfed = 0, unbounded = 0, init_on_failed = 0, logins = 0;
    int cuts = 0, writer_fails = 0, refused = 0, busy = 0, cross = 0, sent = 0, conns_used = 0;
    int failed_closed = 0;
    __atomic_store_n(&s_overdue_calls, 0, __ATOMIC_RELAXED);
    for (int round = 0; round < ST_ROUNDS; round++) {
        uint32_t seed = 0x9E3779B9u ^ (uint32_t)(round * 2654435761u);
        if (seed == 0) seed = 1;
        derp_client_t c;
        memset(&c, 0, sizeof(c));
        static conn_t k[ST_CONNS];
        /* polls shorter than the grace (the abort flag stops a writer
         * first, or its own budget runs out) and longer (the close cuts) */
        static const uint32_t polls[] = { 1, 2, 3, 30, 60 };
        for (int i = 0; i < ST_CONNS; i++) {
            conn_init(&k[i], false, 0, xs(&seed) % 4 != 0, polls[xs(&seed) % 5]);
        }
        logins += test_connect(&c, &k[0]);
        int used = 1;
        st_writer_t a, p;
        memset(&a, 0, sizeof(a));
        memset(&p, 0, sizeof(p));
        a.c = p.c = &c;
        a.seed = xs(&seed) | 1u;
        p.seed = xs(&seed) | 1u;
        pthread_t ta, tp;
        __atomic_store_n(&s_st_running, 2, __ATOMIC_RELEASE);
        pthread_create(&ta, NULL, st_wgtx, &a);
        pthread_create(&tp, NULL, st_pongs, &p);
        /* The supervisor: stalls, recoveries, closes and reconnects at
         * random instants, with the writers mid-frame or waiting. */
        tl_reset(NULL);
        while (used < ST_CONNS && __atomic_load_n(&s_st_running, __ATOMIC_ACQUIRE) > 0) {
            conn_t *cur = c.tls;
            st_pause(&seed, 1000);
            const bool stall = xs(&seed) % 3 != 0;
            if (stall) conn_set_stall(cur, true, xs(&seed) % 24);
            /* a third of the stalls long enough for a stalled write to
             * run out of polls on its own (4 x 1-3 ms) */
            st_pause(&seed, stall && xs(&seed) % 3 == 0 ? 16000 : 2000);
            if (xs(&seed) % 3 == 0) conn_set_stall(cur, false, 0);
            st_pause(&seed, 500);
            failed_closed += !derp_client_is_connected(&c);   /* a write closed it */
            test_close(&c);
            st_pause(&seed, 1000);
            logins += test_connect(&c, &k[used++]);
        }
        unfed += tl.unfed;
        unbounded += tl.longest > GRACE_MS;
        pthread_join(ta, NULL);
        pthread_join(tp, NULL);
        test_close(&c);
        unfed += tl.unfed + a.tl.unfed + p.tl.unfed;
        unbounded += a.tl.longest > SLICE_MS || p.tl.longest > SLICE_MS;
        init_on_failed += a.init_on_failed;
        cross += a.cross;
        conns_used += used;

        wire_t wr[ST_CONNS];
        for (int i = 0; i < ST_CONNS; i++) {
            wr[i] = wire_parse(&k[i]);
            uaf += k[i].uaf;
            corrupt += wr[i].corrupt;
            cuts += k[i].cuts;
            /* each writer's frames in its order on every conn (wg_tx's
             * INITs and data apart: both counters only grow) */
            int last[3][2] = { { -1, -1 }, { -1, -1 }, { -1, -1 } };
            for (int j = 0; j < wr[i].n; j++) {
                const int wtr = wr[i].writer[j];
                const int s = wr[i].seq[j];
                if (wtr < 1 || wtr > 2) { corrupt++; continue; }
                const int cls = (s & ST_INIT) != 0;
                if (s <= last[wtr][cls]) out_of_order++;
                last[wtr][cls] = s;
            }
        }
        st_writer_t *ws[2] = { &a, &p };
        for (int wi = 0; wi < 2; wi++) {
            const uint8_t wtr = (uint8_t)(wi + 1);
            for (int j = 0; j < ws[wi]->n; j++) {
                const st_sent_t *e = &ws[wi]->log[j];
                int on_any = 0, on_its = 0;
                for (int i = 0; i < ST_CONNS; i++) {
                    const int n = wire_count(&wr[i], wtr, e->seq);
                    on_any += n;
                    if (k[i].id == e->r.on) on_its += n;
                }
                if (e->r.res == R_OK) {
                    sent++;
                    if (on_its == 0) ok_missing++;
                    if (on_any > 1) ok_dup++;
                    if (on_any > on_its) ok_elsewhere++;
                } else {
                    if (on_any > 0) whole_unreported++;
                    if (e->r.res == R_FAIL) writer_fails++;
                    if (e->r.res == R_STATE) refused++;
                    if (e->r.res == R_BUSY) busy++;
                }
            }
        }
        for (int i = 0; i < ST_CONNS; i++) conn_destroy(&k[i]);
        client_free(&c);
    }
    const int overdue = __atomic_load_n(&s_overdue_calls, __ATOMIC_RELAXED);
    printf("stress: %d rounds, %d logins, %d frames sent, %d failed, %d refused, %d busy, "
           "%d shutdowns, %d conns closed by a failed write, "
           "%d INITs on a later conn than their failed batch\n",
           ST_ROUNDS, logins, sent, writer_fails, refused, busy, cuts, failed_closed, cross);
    fails += check_eq_int("stress/every-login-ok", logins, conns_used);
    fails += check_eq_int("stress/no-use-after-free", uaf, 0);
    fails += check_eq_int("stress/wire-never-corrupt", corrupt, 0);
    fails += check_eq_int("stress/every-sent-frame-whole-on-its-conn", ok_missing, 0);
    fails += check_eq_int("stress/no-frame-twice", ok_dup, 0);
    fails += check_eq_int("stress/no-sent-frame-on-another-conn", ok_elsewhere, 0);
    fails += check_eq_int("stress/no-whole-frame-reported-failed", whole_unreported, 0);
    fails += check_eq_int("stress/per-writer-order", out_of_order, 0);
    fails += check_eq_int("stress/init-never-behind-its-failed-frame", init_on_failed, 0);
    fails += check_eq_int("stress/every-lock-wait-fed", unfed, 0);
    fails += check_eq_int("stress/every-lock-wait-bounded", unbounded, 0);
    fails += check_eq_int("stress/no-wait-overdue", overdue, 0);
    fails += check_true("stress/writers-were-cut", writer_fails > 0, writer_fails);
    fails += check_true("stress/closes-cut-writers", cuts > 0, cuts);
    fails += check_true("stress/failed-writes-closed-conns", failed_closed > 0, failed_closed);
    fails += check_true("stress/frames-were-refused", refused > 0, refused);
}

int main(void)
{
    /* As tinylink.c: the writers' polls feed (tls_io_set_poll_hook). */
    tls_io_set_poll_hook(derp_wl_feed);
    login_script_init();
    test_close_cuts_stalled_writer();
    test_close_shutdown_refused();
    test_close_idle();
    test_close_grace();
    test_waiter_feeds_then_leaves();
    test_waiter_leaves_lock_held();
    test_waiter_wins_after_close_began();
    test_waiter_never_crosses();
    test_failed_write();
    test_try_not_writable();
    test_cap();
    test_stress();
    if (fails) {
        printf("FAIL: %d\n", fails);
        return 1;
    }
    printf("ALL OK\n");
    return 0;
}
