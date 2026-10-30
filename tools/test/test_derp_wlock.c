/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * The DERP write lock (round 1.3.9, derp_wlock.h): the protocol
 * derp_client.c runs, compiled here over pthreads. Until 1.3.9 the
 * supervisor's derp_client_close (and its pongs, and wg_tx behind them)
 * waited for the lock with portMAX_DELAY while the other task could sit
 * in a waiting write on a stalled conn for 4 x 30 s — no task-WDT feed
 * meanwhile, a 60-s budget.
 *
 * The glue below mirrors derp_client.c (send_packet, derp_tls_write,
 * frame_failed_locked, derp_client_close, derp_client_connect_login) over
 * the real tls_io_write_full, with a fake TLS conn that keeps mbedtls's
 * write semantics: a record is copied once and flushed across calls, a
 * blocked send returns WANT_WRITE after its poll (SO_SNDTIMEO), and a
 * call made while a record's tail is still out flushes THAT tail and
 * reports the new buffer as written (ssl_write_real, out_left != 0). A
 * shutdown wakes a blocked send with an error, unless the test makes it
 * a no-op. Each thread counts its lock waits and feeds; a wait for the
 * lock right after a timed-out one with no feed between would starve the
 * WDT. The races are forced at fixed points (a writer inside a stalled
 * write, a waiter parked inside its take while the conn is replaced),
 * then shaken in a seeded stress with closes, reconnects, stalls and
 * refused shutdowns at random instants.
 */

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "mbedtls/ssl.h"
#include "tls_io.h"

#define DERP_WL_IMPL
#include "derp_wlock.h"

/* derp_client.h's (ESP-only header). */
#define DERP_ERR_WRITE_ABORTED (-0x10005)
/* MBEDTLS_ERR_NET_SEND_FAILED: lwIP failed the send (ERR_CLSD after a
 * shutdown) — not in the host stub. */
#define ERR_SEND_FAILED        (-0x004E)

/* derp_client.c's numbers, scaled down: slices of 2 ms, a 5-ms grace,
 * DERP_MAX_IDLE_POLLS polls per write. */
#define SLICE_MS  2u
#define GRACE_MS  5u
#define MAX_IDLE  4u
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

/* --- Per-thread counters and the four primitives ---------------------- */

typedef struct {
    int      takes, timeouts, feeds;
    int      unfed;        /* a take after a timed-out one, no feed between */
    bool     owed;         /* the last take timed out, no feed since */
    uint32_t longest;      /* longest wait asked for */
    void   (*before_take)(int n);   /* forced interleavings (n: this take's index) */
} tl_t;

static __thread tl_t tl;

static void tl_reset(void (*before_take)(int))
{
    memset(&tl, 0, sizeof(tl));
    tl.before_take = before_take;
}

/* Every protocol call starts afresh: a timed-out take that ended in "the
 * conn closed" owes no feed (the caller's loop feeds). */
static void tl_call(void) { tl.owed = false; }

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

/* --- A fake TLS conn with mbedtls's write semantics ------------------- */

#define WIRE_CAP 8192
#define REC_CAP  64

typedef struct {
    pthread_mutex_t m;
    pthread_cond_t  cv;
    uint32_t id;           /* the client's gen when it connected */
    bool     stalled;      /* the peer stopped ACKing: `room` more bytes fit */
    size_t   room;
    bool     cut_works;    /* false: the shutdown is refused */
    uint32_t poll_ms;      /* SO_SNDTIMEO */
    bool     cut, freed;
    int      cuts, uaf, in_write, writes;
    uint8_t  rec[REC_CAP];          /* mbedtls's out record */
    size_t   rec_len, rec_sent;     /* out_left = rec_len - rec_sent */
    uint8_t  wire[WIRE_CAP];
    size_t   wire_len;
} conn_t;

static void conn_init(conn_t *k, bool stalled, size_t room, bool cut_works, uint32_t poll_ms)
{
    memset(k, 0, sizeof(*k));
    pthread_mutex_init(&k->m, NULL);
    pthread_cond_init(&k->cv, NULL);
    k->stalled = stalled;
    k->room = room;
    k->cut_works = cut_works;
    k->poll_ms = poll_ms;
}

static void conn_destroy(conn_t *k)
{
    pthread_mutex_destroy(&k->m);
    pthread_cond_destroy(&k->cv);
}

static ssize_t conn_write(conn_t *k, const uint8_t *buf, size_t len)
{
    pthread_mutex_lock(&k->m);
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
    pthread_cond_broadcast(&k->cv);
    pthread_mutex_unlock(&k->m);
    return ret;
}

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

static void conn_free(conn_t *k)
{
    pthread_mutex_lock(&k->m);
    if (k->in_write > 0) k->uaf++;
    k->freed = true;
    pthread_mutex_unlock(&k->m);
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

/* Frames: A5 writer seq len payload[len] xor. The wire is parsed in
 * order; only the end may hold a frame cut short. */
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
    int    n;              /* whole frames */
    uint8_t writer[256], seq[256];
    bool   tail;           /* a frame cut short at the end */
    bool   corrupt;
} wire_t;

static wire_t wire_parse(conn_t *k)
{
    wire_t w;
    memset(&w, 0, sizeof(w));
    pthread_mutex_lock(&k->m);
    size_t i = 0;
    while (i < k->wire_len) {
        const size_t left = k->wire_len - i;
        if (k->wire[i] != 0xA5) { w.corrupt = true; break; }
        if (left < 4 || left < 5u + k->wire[i + 3]) { w.tail = true; break; }
        const size_t flen = 5u + k->wire[i + 3];
        uint8_t x = 0;
        for (size_t j = 0; j + 1 < flen; j++) x ^= k->wire[i + j];
        if (x != k->wire[i + flen - 1]) { w.corrupt = true; break; }
        if (w.n < 256) {
            w.writer[w.n] = k->wire[i + 1];
            w.seq[w.n] = k->wire[i + 2];
            w.n++;
        }
        i += flen;
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

/* --- The glue: derp_client.c over the fakes --------------------------- */

typedef struct {
    derp_wl_t       wl;
    conn_t         *conn;      /* c->tls */
    pthread_mutex_t lock;
} client_t;

/* 1.3.8's rule for the negative control: a failed write leaves the conn up. */
static bool s_old_rules;
static int  s_failed_closed;      /* conns a failed write closed (atomic) */

static void client_init(client_t *c)
{
    memset(c, 0, sizeof(*c));
    pthread_mutex_init(&c->lock, NULL);
    c->wl.lock = &c->lock;
}

/* derp_tls_write */
static ssize_t glue_write(void *ctx, const uint8_t *buf, size_t len)
{
    client_t *c = (client_t *)ctx;
    if (!derp_wl_may_write(&c->wl)) return DERP_ERR_WRITE_ABORTED;
    return conn_write(c->conn, buf, len);
}

enum { R_OK, R_STATE, R_BUSY, R_FAIL };

typedef struct {
    int      res;
    uint32_t on;          /* the conn it held the lock for (R_OK / R_FAIL) */
    int      io_rc;
} sent_t;

/* send_packet (+ frame_failed_locked) */
static sent_t glue_send(client_t *c, const uint8_t *f, size_t len, bool no_wait)
{
    sent_t s = { R_STATE, 0, 0 };
    tl_call();
    uint32_t gen;
    if (!derp_wl_admits(&c->wl, &gen)) return s;
    switch (derp_wl_acquire(&c->wl, gen, no_wait, SLICE_MS)) {
    case DERP_WL_HELD: break;
    case DERP_WL_BUSY: s.res = R_BUSY; return s;
    default:           return s;
    }
    conn_t *k = c->conn;
    s.on = k->id;
    s.io_rc = tls_io_write_full(glue_write, c, f, len, MAX_IDLE);
    if (s.io_rc != 0 && !s_old_rules && derp_wl_write_failed(&c->wl)) {
        __atomic_fetch_add(&s_failed_closed, 1, __ATOMIC_RELAXED);
    }
    derp_wl_give(c->wl.lock);
    s.res = s.io_rc == 0 ? R_OK : R_FAIL;
    return s;
}

/* derp_client_close: true when a writer was cut. */
static bool glue_close(client_t *c, uint32_t grace_ms)
{
    tl_call();
    const bool cut = derp_wl_close_lock(&c->wl, c->conn, grace_ms, SLICE_MS);
    if (c->conn != NULL) {
        conn_free(c->conn);
        c->conn = NULL;
    }
    derp_wl_give(c->wl.lock);
    return cut;
}

/* derp_client_connect_login: new gen, the conn, then up. */
static void glue_connect(client_t *c, conn_t *k)
{
    derp_wl_new_conn(&c->wl);
    k->id = derp_wl_gen(&c->wl);
    c->conn = k;
    derp_wl_set_up(&c->wl);
}

/* --- One writer on its own thread ------------------------------------- */

typedef struct {
    client_t *c;
    uint8_t   f[FRAME_MAX];
    size_t    len;
    bool      no_wait;
    void    (*before_take)(int n);
    sent_t    r;
    tl_t      tl;
} wjob_t;

static void *writer_main(void *arg)
{
    wjob_t *j = (wjob_t *)arg;
    tl_reset(j->before_take);
    j->r = glue_send(j->c, j->f, j->len, j->no_wait);
    j->tl = tl;
    return NULL;
}

static void wjob(wjob_t *j, client_t *c, uint8_t writer, uint8_t seq)
{
    memset(j, 0, sizeof(*j));
    j->c = c;
    j->len = frame_make(j->f, writer, seq);
}

/* --- Rendezvous -------------------------------------------------------- */

static pthread_mutex_t s_rv_m = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  s_rv_cv = PTHREAD_COND_INITIALIZER;
static int s_rv_takes;        /* takes of the hooked thread */
static int s_rv_park_at;      /* its take index that parks, -1 none */
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

/* --- Forced interleavings ---------------------------------------------- */

/* The defect: wg_tx in a waiting write on a stalled conn (its budget
 * here 4 x 3 s), the supervisor closes. The close cuts it after the
 * grace, feeding, and gets the lock at once — not when a poll ends. */
static void test_close_cuts_stalled_writer(void)
{
    client_t c;
    conn_t k;
    client_init(&c);
    conn_init(&k, true, 0, true, LONG_POLL_MS);
    glue_connect(&c, &k);
    wjob_t w;
    wjob(&w, &c, 1, 0);
    pthread_t t;
    pthread_create(&t, NULL, writer_main, &w);
    fails += check_true("close/stalled-writer-inside", conn_wait_in_write(&k), 0);
    tl_reset(NULL);
    const double t0 = now_ms();
    const bool cut = glue_close(&c, GRACE_MS);
    const double dt = now_ms() - t0;
    pthread_join(t, NULL);
    const wire_t wr = wire_parse(&k);
    fails += check_eq_int("close/stalled-cut", cut, 1);
    fails += check_eq_int("close/stalled-one-shutdown", k.cuts, 1);
    fails += check_eq_int("close/stalled-writer-failed", w.r.res, R_FAIL);
    fails += check_eq_int("close/stalled-woken-by-shutdown", w.r.io_rc, ERR_SEND_FAILED);
    fails += check_eq_int("close/stalled-no-use-after-free", k.uaf, 0);
    fails += check_true("close/stalled-fed-past-grace", tl.feeds >= 1, tl.feeds);
    fails += check_eq_int("close/stalled-every-wait-fed", tl.unfed, 0);
    fails += check_true("close/stalled-waits-bounded", tl.longest <= GRACE_MS, (long)tl.longest);
    fails += check_true("close/stalled-before-the-poll-ends", dt < 1500.0, (long)dt);
    fails += check_eq_int("close/stalled-frame-not-whole", wr.n, 0);
    wjob_t w2;
    wjob(&w2, &c, 1, 1);
    writer_main(&w2);
    fails += check_eq_int("close/stalled-then-refused", w2.r.res, R_STATE);
    conn_destroy(&k);
    pthread_mutex_destroy(&c.lock);
}

/* The cut is refused (a shutdown that fails): the writer waits out its
 * poll, and the abort flag stops it before the next one — one poll, not
 * MAX_IDLE. The close feeds in slices meanwhile. */
static void test_close_shutdown_refused(void)
{
    client_t c;
    conn_t k;
    client_init(&c);
    conn_init(&k, true, 0, false, 150);
    glue_connect(&c, &k);
    wjob_t w;
    wjob(&w, &c, 1, 0);
    pthread_t t;
    pthread_create(&t, NULL, writer_main, &w);
    fails += check_true("refused/writer-inside", conn_wait_in_write(&k), 0);
    tl_reset(NULL);
    const bool cut = glue_close(&c, GRACE_MS);
    pthread_join(t, NULL);
    fails += check_eq_int("refused/cut-tried", cut, 1);
    fails += check_eq_int("refused/one-shutdown", k.cuts, 1);
    fails += check_eq_int("refused/writer-aborted-at-next-poll", w.r.io_rc,
                          DERP_ERR_WRITE_ABORTED);
    fails += check_eq_int("refused/one-poll-not-four", k.writes, 1);
    fails += check_true("refused/close-fed-every-slice", tl.feeds >= 3, tl.feeds);
    fails += check_eq_int("refused/every-wait-fed", tl.unfed, 0);
    fails += check_true("refused/waits-bounded", tl.longest <= GRACE_MS, (long)tl.longest);
    fails += check_eq_int("refused/no-use-after-free", k.uaf, 0);
    conn_destroy(&k);
    pthread_mutex_destroy(&c.lock);
}

/* No writer: one take, no cut, no feed — the 1.3.8 path. */
static void test_close_idle(void)
{
    client_t c;
    conn_t k;
    client_init(&c);
    conn_init(&k, false, 0, true, LONG_POLL_MS);
    glue_connect(&c, &k);
    tl_reset(NULL);
    const bool cut = glue_close(&c, GRACE_MS);
    fails += check_eq_int("idle/no-cut", cut, 0);
    fails += check_eq_int("idle/no-shutdown", k.cuts, 0);
    fails += check_eq_int("idle/one-take", tl.takes, 1);
    fails += check_eq_int("idle/no-feed", tl.feeds, 0);
    fails += check_eq_int("idle/refuses-after", derp_wl_up(&c.wl), 0);
    /* A close with no conn (never connected): the lock is still taken. */
    tl_reset(NULL);
    fails += check_eq_int("idle/no-conn-no-cut", glue_close(&c, GRACE_MS), 0);
    fails += check_eq_int("idle/no-conn-one-take", tl.takes, 1);
    conn_destroy(&k);
    pthread_mutex_destroy(&c.lock);
}

/* A writer that ends its frame within the grace is not cut: the frame
 * is whole on the wire and reported sent. */
typedef struct { client_t *c; uint32_t grace; bool cut; tl_t tl; } cjob_t;

static void *closer_main(void *arg)
{
    cjob_t *j = (cjob_t *)arg;
    tl_reset(rv_hook);
    j->cut = glue_close(j->c, j->grace);
    j->tl = tl;
    return NULL;
}

static void test_close_grace(void)
{
    client_t c;
    conn_t k;
    client_init(&c);
    conn_init(&k, true, 0, true, LONG_POLL_MS);
    glue_connect(&c, &k);
    wjob_t w;
    wjob(&w, &c, 1, 0);
    pthread_t tw, tc;
    pthread_create(&tw, NULL, writer_main, &w);
    fails += check_true("grace/writer-inside", conn_wait_in_write(&k), 0);
    rv_reset(-1);
    cjob_t cj = { &c, 10000, true, { 0 } };
    pthread_create(&tc, NULL, closer_main, &cj);
    fails += check_true("grace/closer-waiting", rv_wait(1, false), 0);
    conn_set_stall(&k, false, 0);        /* the ACKs come back */
    pthread_join(tw, NULL);
    pthread_join(tc, NULL);
    const wire_t wr = wire_parse(&k);
    fails += check_eq_int("grace/writer-sent", w.r.res, R_OK);
    fails += check_eq_int("grace/no-cut", cj.cut, 0);
    fails += check_eq_int("grace/no-shutdown", k.cuts, 0);
    fails += check_eq_int("grace/frame-whole", wire_count(&wr, 1, 0), 1);
    fails += check_eq_int("grace/no-tail", wr.tail, 0);
    conn_destroy(&k);
    pthread_mutex_destroy(&c.lock);
}

/* wg_tx behind the supervisor's stalled write (or the reverse): it feeds
 * each slice, and leaves without the lock once the conn closes. */
static void test_waiter_feeds_then_leaves(void)
{
    client_t c;
    conn_t k;
    client_init(&c);
    conn_init(&k, true, 0, true, LONG_POLL_MS);
    glue_connect(&c, &k);
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
    (void)glue_close(&c, GRACE_MS);
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
    /* no_wait behind a holder: one try, refused as busy, no wait. */
    client_t c2;
    conn_t k2;
    client_init(&c2);
    conn_init(&k2, true, 0, true, LONG_POLL_MS);
    glue_connect(&c2, &k2);
    wjob(&w1, &c2, 1, 0);
    pthread_create(&t1, NULL, writer_main, &w1);
    fails += check_true("waiter/try-holder-inside", conn_wait_in_write(&k2), 0);
    wjob(&w2, &c2, 2, 0);
    w2.no_wait = true;
    writer_main(&w2);
    fails += check_eq_int("waiter/try-busy", w2.r.res, R_BUSY);
    fails += check_eq_int("waiter/try-one-take", w2.tl.takes, 1);
    fails += check_eq_int("waiter/try-no-wait", (long)w2.tl.longest, 0);
    (void)glue_close(&c2, GRACE_MS);
    pthread_join(t1, NULL);
    conn_destroy(&k);
    conn_destroy(&k2);
    pthread_mutex_destroy(&c.lock);
    pthread_mutex_destroy(&c2.lock);
}

/* A waiter that set out for conn A, parked in its take while A closes and
 * B comes up: it gets the lock with B up, and the generation refuses it.
 * A frame queued behind a dying write never lands on the next conn. */
static void test_waiter_never_crosses(void)
{
    client_t c;
    conn_t a, b;
    client_init(&c);
    conn_init(&a, true, 0, true, LONG_POLL_MS);
    conn_init(&b, false, 0, true, LONG_POLL_MS);
    glue_connect(&c, &a);
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
    (void)glue_close(&c, GRACE_MS);
    pthread_join(t1, NULL);
    glue_connect(&c, &b);
    rv_release();
    pthread_join(t2, NULL);
    const wire_t wb = wire_parse(&b);
    fails += check_eq_int("cross/next-conn-up", derp_wl_up(&c.wl), 1);
    fails += check_eq_int("cross/waiter-refused", w2.r.res, R_STATE);
    fails += check_eq_int("cross/next-conn-empty", wb.n, 0);
    fails += check_eq_int("cross/no-use-after-free", a.uaf + b.uaf, 0);
    /* A frame that sets out once B is up goes on B. */
    wjob(&w2, &c, 2, 1);
    writer_main(&w2);
    const wire_t wb2 = wire_parse(&b);
    fails += check_eq_int("cross/fresh-send-ok", w2.r.res, R_OK);
    fails += check_eq_int("cross/fresh-send-on-next", (long)w2.r.on, (long)b.id);
    fails += check_eq_int("cross/fresh-send-whole", wire_count(&wb2, 2, 1), 1);
    (void)glue_close(&c, GRACE_MS);
    conn_destroy(&a);
    conn_destroy(&b);
    pthread_mutex_destroy(&c.lock);
}

/* A write that failed on its own (4 polls, part of the frame out): with
 * 1.3.8's rule the conn stayed up, and the next frame, its record never
 * written — mbedtls flushed the first one's tail instead — was reported
 * sent. Now the conn takes no more frames (the reader is told to leave;
 * the socket is left to the close). */
typedef struct { sent_t first, next; wire_t wire; int cuts; bool up; } failed_t;

static failed_t run_failed_write(bool old_rules)
{
    failed_t out;
    client_t c;
    conn_t k;
    s_old_rules = old_rules;
    client_init(&c);
    conn_init(&k, true, 7, true, 3);
    glue_connect(&c, &k);
    uint8_t f[FRAME_MAX];
    tl_reset(NULL);
    size_t n = frame_make(f, 1, 0);
    out.first = glue_send(&c, f, n, false);
    out.up = derp_wl_up(&c.wl);
    conn_set_stall(&k, false, 0);        /* the ACKs come back */
    n = frame_make(f, 1, 1);
    out.next = glue_send(&c, f, n, false);
    out.wire = wire_parse(&k);
    out.cuts = k.cuts;
    (void)glue_close(&c, GRACE_MS);
    s_old_rules = false;
    conn_destroy(&k);
    pthread_mutex_destroy(&c.lock);
    return out;
}

static void test_failed_write(void)
{
    const failed_t now = run_failed_write(false);
    fails += check_eq_int("failed/first-fails", now.first.res, R_FAIL);
    fails += check_eq_int("failed/first-idle-budget", now.first.io_rc, TLS_IO_ERR_IDLE_TIMEOUT);
    fails += check_eq_int("failed/conn-closed-to-frames", now.up, 0);
    fails += check_eq_int("failed/no-cut-on-the-writer", now.cuts, 0);
    fails += check_eq_int("failed/next-refused", now.next.res, R_STATE);
    fails += check_eq_int("failed/first-cut-short", now.wire.tail, 1);
    fails += check_eq_int("failed/nothing-whole", now.wire.n, 0);
    const failed_t old = run_failed_write(true);
    fails += check_eq_int("failed/1.3.8-next-reported-sent", old.next.res, R_OK);
    fails += check_eq_int("failed/1.3.8-next-not-on-wire", wire_count(&old.wire, 1, 1), 0);
    fails += check_eq_int("failed/1.3.8-first-tail-flushed", wire_count(&old.wire, 1, 0), 1);
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
    client_t *c;
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
            uint8_t f[FRAME_MAX];
            const size_t n = frame_make(f, 1, seq);
            const bool try_only = xs(&w->seed) % 5 == 0;
            const sent_t r = glue_send(w->c, f, n, try_only);
            w->log[w->n++] = (st_sent_t){ seq, r };
            seq++;
            if (r.res == R_FAIL) failed_on = r.on;
            if (r.res == R_FAIL || r.res == R_STATE) break;   /* kept for the next login */
            st_pause(&w->seed, 1200);
        }
        uint8_t f[FRAME_MAX];
        const uint8_t iseq = (uint8_t)(ST_INIT | b);
        const size_t n = frame_make(f, 1, iseq);
        const sent_t r = glue_send(w->c, f, n, false);
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
        uint8_t f[FRAME_MAX];
        const size_t n = frame_make(f, 2, seq);
        const sent_t r = glue_send(w->c, f, n, false);
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
    int out_of_order = 0, unfed = 0, unbounded = 0, init_on_failed = 0;
    int cuts = 0, writer_fails = 0, refused = 0, cross = 0, sent = 0, conns_used = 0;
    int closes_cut = 0;
    s_failed_closed = 0;
    for (int round = 0; round < ST_ROUNDS; round++) {
        uint32_t seed = 0x9E3779B9u ^ (uint32_t)(round * 2654435761u);
        if (seed == 0) seed = 1;
        client_t c;
        client_init(&c);
        static conn_t k[ST_CONNS];
        /* polls shorter than the grace (the abort flag stops a writer
         * first, or its own budget runs out) and longer (the close cuts) */
        static const uint32_t polls[] = { 1, 2, 3, 30, 60 };
        for (int i = 0; i < ST_CONNS; i++) {
            conn_init(&k[i], false, 0, xs(&seed) % 4 != 0, polls[xs(&seed) % 5]);
        }
        glue_connect(&c, &k[0]);
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
            conn_t *cur = c.conn;
            st_pause(&seed, 1000);
            const bool stall = xs(&seed) % 3 != 0;
            if (stall) conn_set_stall(cur, true, xs(&seed) % 24);
            /* a third of the stalls long enough for a stalled write to
             * run out of polls on its own (4 x 1-3 ms) */
            st_pause(&seed, stall && xs(&seed) % 3 == 0 ? 16000 : 2000);
            if (xs(&seed) % 3 == 0) conn_set_stall(cur, false, 0);
            st_pause(&seed, 500);
            closes_cut += glue_close(&c, GRACE_MS);
            st_pause(&seed, 1000);
            glue_connect(&c, &k[used++]);
        }
        unfed += tl.unfed;
        unbounded += tl.longest > GRACE_MS;
        pthread_join(ta, NULL);
        pthread_join(tp, NULL);
        (void)glue_close(&c, GRACE_MS);
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
                }
            }
        }
        for (int i = 0; i < ST_CONNS; i++) conn_destroy(&k[i]);
        pthread_mutex_destroy(&c.lock);
    }
    const int failed_closed = __atomic_load_n(&s_failed_closed, __ATOMIC_RELAXED);
    printf("stress: %d rounds, %d conns, %d frames sent, %d failed, %d refused, "
           "%d shutdowns (%d closes cut a writer), %d failed writes closed the conn, "
           "%d INITs on a later conn than their failed batch\n",
           ST_ROUNDS, conns_used, sent, writer_fails, refused, cuts, closes_cut,
           failed_closed, cross);
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
    fails += check_true("stress/writers-were-cut", writer_fails > 0, writer_fails);
    fails += check_true("stress/closes-cut-writers", closes_cut > 0, closes_cut);
    fails += check_true("stress/failed-writes-closed-conns", failed_closed > 0, failed_closed);
    fails += check_true("stress/frames-were-refused", refused > 0, refused);
}

int main(void)
{
    /* As tinylink.c: the writers' polls feed (tls_io_set_poll_hook). */
    tls_io_set_poll_hook(derp_wl_feed);
    test_close_cuts_stalled_writer();
    test_close_shutdown_refused();
    test_close_idle();
    test_close_grace();
    test_waiter_feeds_then_leaves();
    test_waiter_never_crosses();
    test_failed_write();
    test_stress();
    if (fails) {
        printf("FAIL: %d\n", fails);
        return 1;
    }
    printf("ALL OK\n");
    return 0;
}
