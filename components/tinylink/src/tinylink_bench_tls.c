// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// TLS handshake crypto bench (round 1.3.8, CONFIG_TINYLINK_BENCH_TLS).
//
// What a full TLS handshake to a Tailscale server costs the CPU, one
// primitive at a time, with this image's mbedTLS configuration (hardware
// MPI or not, ECP window, fixed-point tables, in-tree X25519): the
// signature verifies of the two chains derp16b.tailscale.com serves
// (tls_offer.h; the certificates themselves, bench_tls_vectors.h), each
// whole chain through the certificate bundle exactly as the handshake
// does it, and the ECDHE. Every line is best-of-RUNS µs; every verify
// must return 0 (a wrong result is reported, never timed as "fast").
// Lines (tools/tls_bench/sdkconfig.bench has the build matrix), as the
// 1.3.8 default image prints them under QEMU (µs there = k-instructions):
//
//   bench-tls: config hw_mpi=1 mul_sw=1 window=4 fixed_point=1 x25519=intree rsa_first=1
//   bench-tls: verify ecdsa-p384 (YE2 <- Root YE)        47317 us rc=-0x0000 heap 5768
//   bench-tls: verify ecdsa-p256 (ServerKeyExchange)     21325 us rc=-0x0000 heap 3228
//   bench-tls: verify rsa-2048 (leaf <- YR2)               580 us rc=-0x0000 heap 5856
//   bench-tls: verify rsa-4096 (YR2 <- Root YR)           2620 us rc=-0x0000 heap 9952
//   bench-tls: verify rsa-4096 (Root YR <- X1 bundle)     2923 us rc=-0x0000 heap 8268
//   bench-tls: chain ecdsa: parse 146 us verify 144877 us flags=0x0 rc=-0x0000 heap 14736
//   bench-tls: chain rsa  : parse 62 us verify 6188 us flags=0x0 rc=-0x0000 heap 15952
//   bench-tls: ecdhe x25519 (in-tree) : keygen 2436 us shared 2437 us rc=-0x0000 heap 200
//   bench-tls: ecdhe x25519 (mbedtls) : keygen 12294 us shared 12488 us rc=-0x0000
//   bench-tls: x25519 in-tree == mbedtls: 16/16
//   bench-tls: ecdhe p256             : keygen 5026 us shared 13796 us rc=-0x0000 heap 2960
//   bench-tls: ecdhe p384             : keygen 10298 us shared 31589 us rc=-0x0000 heap 4208
//   bench-tls: handshake cpu ecdsa 171221 us rsa 11703 us (chain parse + verify + SKE verify + ECDHE)
//   bench-tls: done in 1162 ms, stack hwm 4220 B of 8192
//
// rc is -0x0000 on success (mbedTLS's negative codes printed positive); a
// chain's flags are the X.509 verify flags left after the bundle callback.
// `heap` is the largest heap drop during the operation (the local
// minimum-free monitor). Runs first thing in bringup(), before NVS and
// Wi-Fi: no other task competes, and nothing it allocates outlives it.

#include "tinylink_bench.h"

#if CONFIG_TINYLINK_BENCH_TLS

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "sdkconfig.h"

#include "bench_tls_vectors.h"
#include "crypto/curve25519.h"

static const char *TAG = "bench-tls";

#define RUNS 3

/* IDF's bundle verify callback (declared the same way in tl_time.c). */
extern int esp_crt_verify_callback(void *buf, mbedtls_x509_crt *const crt,
                                   const int depth, uint32_t *const flags);

#if CONFIG_TINYLINK_TLS_X25519_INTREE
int __real_mbedtls_ecp_mul_restartable(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                                       const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                                       int (*f_rng)(void *, unsigned char *, size_t),
                                       void *p_rng, mbedtls_ecp_restart_ctx *rs_ctx);
int __wrap_mbedtls_ecp_mul_restartable(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                                       const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                                       int (*f_rng)(void *, unsigned char *, size_t),
                                       void *p_rng, mbedtls_ecp_restart_ctx *rs_ctx);
#endif

static int rng(void *ctx, unsigned char *buf, size_t len)
{
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}

/* Heap drop while monitored (the local minimum-free watermark). */
static size_t s_heap_before;
static void heap_mark(void)
{
    s_heap_before = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    (void)heap_caps_monitor_local_minimum_free_size_start();
}
static unsigned heap_peak(void)
{
    const size_t lo = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
    (void)heap_caps_monitor_local_minimum_free_size_stop();
    return lo < s_heap_before ? (unsigned)(s_heap_before - lo) : 0;
}

/* Verify child's signature with the key in parent_der (a certificate,
 * or a SubjectPublicKeyInfo when spki) — what x509_crt_check_signature
 * does — best of RUNS. The key is parsed afresh for every run, outside
 * the timing, as every handshake parses it: an RSA context caches its
 * Montgomery constant (R^2 mod N, a software division) after the first
 * public operation, which a reused context would hide. */
static int64_t verify_sig(const mbedtls_x509_crt *child, const uint8_t *parent_der,
                          size_t parent_len, bool spki, int *rc_out)
{
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(child->MBEDTLS_PRIVATE(sig_md));
    int rc = md == NULL ? -1 : mbedtls_md(md, child->tbs.p, child->tbs.len, hash);
    int64_t best = INT64_MAX;
    for (int i = 0; i < RUNS && rc == 0; i++) {
        mbedtls_x509_crt parent;
        mbedtls_pk_context key;
        mbedtls_x509_crt_init(&parent);
        mbedtls_pk_init(&key);
        rc = spki ? mbedtls_pk_parse_public_key(&key, parent_der, parent_len)
                  : mbedtls_x509_crt_parse_der(&parent, parent_der, parent_len);
        mbedtls_pk_context *pk = spki ? &key : &parent.pk;
        const int64_t t0 = esp_timer_get_time();
        if (rc == 0) {
            rc = mbedtls_pk_verify(pk, child->MBEDTLS_PRIVATE(sig_md), hash,
                                   mbedtls_md_get_size(md), child->MBEDTLS_PRIVATE(sig).p,
                                   child->MBEDTLS_PRIVATE(sig).len);
        }
        const int64_t dt = esp_timer_get_time() - t0;
        if (dt < best) best = dt;
        mbedtls_pk_free(&key);
        mbedtls_x509_crt_free(&parent);
    }
    *rc_out = rc;
    return rc == 0 ? best : -1;
}

static const mbedtls_x509_crt *nth(const mbedtls_x509_crt *c, int n)
{
    while (c != NULL && n-- > 0) c = c->next;
    return c;
}

static int bench_vrfy_cb(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
    /* The certificates' dates are not the point here (and the clock is
     * at 1970 before NTP): what tl_verify_cb does until the first sync. */
    *flags &= ~(MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE);
    return esp_crt_verify_callback(ctx, crt, depth, flags);
}

/* Parse a served chain (the Ed25519 meta certificate DERP appends is
 * skipped by the TLS layer too: MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG), then
 * verify it with an empty trust list and the bundle callback — the
 * handshake's path (esp_crt_bundle_attach installs exactly that). */
static int64_t bench_chain(const char *name, const uint8_t *const *der, const size_t *len,
                           int n, int64_t *verify_us)
{
    static const mbedtls_x509_crt s_empty_ca;   /* as esp_crt_bundle.c's s_dummy_crt */
    int64_t best_parse = INT64_MAX, best_verify = INT64_MAX;
    uint32_t flags = 0;
    int rc = 0;
    unsigned heap = 0;
    for (int r = 0; r < RUNS && rc == 0; r++) {
        mbedtls_x509_crt chain;
        mbedtls_x509_crt_init(&chain);
        heap_mark();
        int64_t t0 = esp_timer_get_time();
        for (int i = 0; i < n; i++) {
            const int prc = mbedtls_x509_crt_parse_der(&chain, der[i], len[i]);
            if (prc != 0 && prc != MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG + MBEDTLS_ERR_OID_NOT_FOUND &&
                rc == 0) {
                rc = prc;
            }
        }
        int64_t t1 = esp_timer_get_time();
        if (rc == 0) {
            rc = mbedtls_x509_crt_verify(&chain, (mbedtls_x509_crt *)&s_empty_ca, NULL,
                                         "derp16b.tailscale.com", &flags, bench_vrfy_cb, NULL);
        }
        const int64_t t2 = esp_timer_get_time();
        const unsigned h = heap_peak();
        if (h > heap) heap = h;
        mbedtls_x509_crt_free(&chain);
        if (t1 - t0 < best_parse) best_parse = t1 - t0;
        if (t2 - t1 < best_verify) best_verify = t2 - t1;
    }
    ESP_LOGI(TAG, "chain %-5s: parse %ld us verify %ld us flags=0x%lx rc=-0x%04x heap %u",
             name, (long)best_parse, (long)best_verify, (unsigned long)flags,
             (unsigned)-rc, heap);
    *verify_us = rc == 0 && flags == 0 ? best_verify : -1;
    return best_parse;
}

/* keygen (d·G) + shared (d·Qp) for one group, best of RUNS each. */
static void bench_ecdhe(const char *name, mbedtls_ecp_group_id id, int64_t *total_us)
{
    mbedtls_ecp_group g;
    mbedtls_mpi d, dp, z;
    mbedtls_ecp_point Q, Qp;
    mbedtls_ecp_group_init(&g);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&dp); mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&Q); mbedtls_ecp_point_init(&Qp);
    int64_t best_k = INT64_MAX, best_s = INT64_MAX;
    unsigned heap = 0;
    int rc = mbedtls_ecp_group_load(&g, id);
    if (rc == 0) rc = mbedtls_ecdh_gen_public(&g, &dp, &Qp, rng, NULL);   /* the peer */
    for (int r = 0; r < RUNS && rc == 0; r++) {
        heap_mark();
        const int64_t t0 = esp_timer_get_time();
        rc = mbedtls_ecdh_gen_public(&g, &d, &Q, rng, NULL);
        const int64_t t1 = esp_timer_get_time();
        if (rc == 0) rc = mbedtls_ecdh_compute_shared(&g, &z, &Qp, &d, rng, NULL);
        const int64_t t2 = esp_timer_get_time();
        const unsigned h = heap_peak();
        if (h > heap) heap = h;
        if (t1 - t0 < best_k) best_k = t1 - t0;
        if (t2 - t1 < best_s) best_s = t2 - t1;
    }
    ESP_LOGI(TAG, "ecdhe %-17s: keygen %ld us shared %ld us rc=-0x%04x heap %u",
             name, (long)best_k, (long)best_s, (unsigned)-rc, heap);
    if (total_us != NULL) *total_us = rc == 0 ? best_k + best_s : -1;
    mbedtls_ecp_point_free(&Q); mbedtls_ecp_point_free(&Qp);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&dp); mbedtls_mpi_free(&z);
    mbedtls_ecp_group_free(&g);
}

#if CONFIG_TINYLINK_TLS_X25519_INTREE
/* mbedTLS's own ladder (the wrap's __real side), timed, and both halves
 * of the wrap (d·9 and d·Q) checked against it on random keys / points. */
static void bench_x25519_mbedtls(void)
{
    mbedtls_ecp_group g;
    mbedtls_mpi d, dp;
    mbedtls_ecp_point Qp, Rm, Ri;
    mbedtls_ecp_group_init(&g);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&dp);
    mbedtls_ecp_point_init(&Qp); mbedtls_ecp_point_init(&Rm); mbedtls_ecp_point_init(&Ri);
    int rc = mbedtls_ecp_group_load(&g, MBEDTLS_ECP_DP_CURVE25519);
    int64_t best_k = INT64_MAX, best_s = INT64_MAX;
    int equal = 0, tried = 0;
    for (int r = 0; r < 8 && rc == 0; r++) {
        rc = mbedtls_ecp_gen_privkey(&g, &d, rng, NULL);
        if (rc == 0) rc = mbedtls_ecdh_gen_public(&g, &dp, &Qp, rng, NULL);   /* a peer */
        for (int half = 0; half < 2 && rc == 0; half++) {
            const mbedtls_ecp_point *P = half == 0 ? &g.G : &Qp;
            const int64_t t0 = esp_timer_get_time();
            rc = __real_mbedtls_ecp_mul_restartable(&g, &Rm, &d, P, rng, NULL, NULL);
            const int64_t dt = esp_timer_get_time() - t0;
            if (rc == 0) rc = __wrap_mbedtls_ecp_mul_restartable(&g, &Ri, &d, P, rng, NULL, NULL);
            if (rc == 0) {
                tried++;
                equal += mbedtls_mpi_cmp_mpi(&Rm.MBEDTLS_PRIVATE(X), &Ri.MBEDTLS_PRIVATE(X)) == 0 &&
                         mbedtls_mpi_cmp_mpi(&Rm.MBEDTLS_PRIVATE(Z), &Ri.MBEDTLS_PRIVATE(Z)) == 0;
            }
            int64_t *best = half == 0 ? &best_k : &best_s;
            if (r < RUNS && dt < *best) *best = dt;
        }
    }
    ESP_LOGI(TAG, "ecdhe %-17s: keygen %ld us shared %ld us rc=-0x%04x",
             "x25519 (mbedtls)", (long)best_k, (long)best_s, (unsigned)-rc);
    ESP_LOGI(TAG, "x25519 in-tree == mbedtls: %d/%d", equal, tried);
    mbedtls_ecp_point_free(&Qp); mbedtls_ecp_point_free(&Rm); mbedtls_ecp_point_free(&Ri);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&dp);
    mbedtls_ecp_group_free(&g);
}
#else
/* The in-tree X25519 for comparison (two scalarmults = keygen + shared). */
static void bench_x25519_intree(void)
{
    uint8_t k[32], u[32], q[32];
    esp_fill_random(k, sizeof(k));
    esp_fill_random(u, sizeof(u));
    u[31] &= 0x7f;
    int64_t best = INT64_MAX;
    int rc = 0;
    for (int r = 0; r < RUNS; r++) {
        const int64_t t0 = esp_timer_get_time();
        rc |= curve25519_scalarmult(q, k, u);
        const int64_t dt = esp_timer_get_time() - t0;
        if (dt < best) best = dt;
    }
    ESP_LOGI(TAG, "ecdhe %-17s: keygen %ld us shared %ld us rc=%d",
             "x25519 (in-tree)", (long)best, (long)best, rc);
}
#endif

esp_err_t tinylink_bench_tls(void)
{
    const int64_t t_start = esp_timer_get_time();
    ESP_LOGI(TAG, "config hw_mpi=%d mul_sw=%d window=%d fixed_point=%d x25519=%s rsa_first=%d",
#if CONFIG_MBEDTLS_HARDWARE_MPI
             1,
#else
             0,
#endif
#if CONFIG_TINYLINK_TLS_MPI_MUL_SW
             1,
#else
             0,
#endif
             MBEDTLS_ECP_WINDOW_SIZE, MBEDTLS_ECP_FIXED_POINT_OPTIM + 0,
#if CONFIG_TINYLINK_TLS_X25519_INTREE
             "intree",
#else
             "mbedtls",
#endif
#if CONFIG_TINYLINK_TLS_RSA_FIRST
             1
#else
             0
#endif
             );
    if (esp_crt_bundle_attach(NULL) != ESP_OK) {
        ESP_LOGE(TAG, "bundle attach failed — bench aborted");
        return ESP_FAIL;
    }

    static const uint8_t *const e_der[] = { k_ecdsa_0, k_ecdsa_1, k_ecdsa_2, k_ecdsa_3, k_ecdsa_4 };
    static const size_t e_len[] = { sizeof(k_ecdsa_0), sizeof(k_ecdsa_1), sizeof(k_ecdsa_2),
                                    sizeof(k_ecdsa_3), sizeof(k_ecdsa_4) };
    static const uint8_t *const r_der[] = { k_rsa_0, k_rsa_1, k_rsa_2, k_rsa_3 };
    static const size_t r_len[] = { sizeof(k_rsa_0), sizeof(k_rsa_1), sizeof(k_rsa_2),
                                    sizeof(k_rsa_3) };

    /* --- single signature verifies ------------------------------------ */
    mbedtls_x509_crt ce, cr;
    mbedtls_pk_context p256;
    mbedtls_x509_crt_init(&ce); mbedtls_x509_crt_init(&cr);
    mbedtls_pk_init(&p256);
    int rc = 0;
    for (int i = 0; i < 3 && rc == 0; i++) rc = mbedtls_x509_crt_parse_der(&ce, e_der[i], e_len[i]);
    for (int i = 0; i < 3 && rc == 0; i++) rc = mbedtls_x509_crt_parse_der(&cr, r_der[i], r_len[i]);
    if (rc == 0) rc = mbedtls_pk_parse_public_key(&p256, k_p256_spki, sizeof(k_p256_spki));
    if (rc != 0) {
        ESP_LOGE(TAG, "vector parse failed: -0x%04x — bench aborted", (unsigned)-rc);
        mbedtls_x509_crt_free(&ce); mbedtls_x509_crt_free(&cr);
        mbedtls_pk_free(&p256);
        return ESP_FAIL;
    }
    int vrc;
    int64_t us;
    unsigned heap;

    heap_mark();
    us = verify_sig(nth(&ce, 1), k_ecdsa_2, sizeof(k_ecdsa_2), false, &vrc);
    heap = heap_peak();
    ESP_LOGI(TAG, "verify %-32s %7ld us rc=-0x%04x heap %u", "ecdsa-p384 (YE2 <- Root YE)",
             (long)us, (unsigned)-vrc, heap);
    const int64_t p384_us = us;

    int64_t p256_us = INT64_MAX;
    heap_mark();
    for (int i = 0; i < RUNS; i++) {
        mbedtls_pk_free(&p256);
        mbedtls_pk_init(&p256);
        vrc = mbedtls_pk_parse_public_key(&p256, k_p256_spki, sizeof(k_p256_spki));
        const int64_t t0 = esp_timer_get_time();
        if (vrc == 0) {
            vrc = mbedtls_pk_verify(&p256, MBEDTLS_MD_SHA256, k_p256_hash, sizeof(k_p256_hash),
                                    k_p256_sig, sizeof(k_p256_sig));
        }
        const int64_t dt = esp_timer_get_time() - t0;
        if (dt < p256_us) p256_us = dt;
        if (vrc != 0) break;
    }
    heap = heap_peak();
    if (vrc != 0) p256_us = -1;
    ESP_LOGI(TAG, "verify %-32s %7ld us rc=-0x%04x heap %u", "ecdsa-p256 (ServerKeyExchange)",
             (long)p256_us, (unsigned)-vrc, heap);

    heap_mark();
    us = verify_sig(nth(&cr, 0), k_rsa_1, sizeof(k_rsa_1), false, &vrc);
    heap = heap_peak();
    ESP_LOGI(TAG, "verify %-32s %7ld us rc=-0x%04x heap %u", "rsa-2048 (leaf <- YR2)",
             (long)us, (unsigned)-vrc, heap);
    const int64_t rsa2048_us = us;

    heap_mark();
    us = verify_sig(nth(&cr, 1), k_rsa_2, sizeof(k_rsa_2), false, &vrc);
    heap = heap_peak();
    ESP_LOGI(TAG, "verify %-32s %7ld us rc=-0x%04x heap %u", "rsa-4096 (YR2 <- Root YR)",
             (long)us, (unsigned)-vrc, heap);

    heap_mark();
    us = verify_sig(nth(&cr, 2), k_x1_spki, sizeof(k_x1_spki), true, &vrc);
    heap = heap_peak();
    ESP_LOGI(TAG, "verify %-32s %7ld us rc=-0x%04x heap %u", "rsa-4096 (Root YR <- X1 bundle)",
             (long)us, (unsigned)-vrc, heap);
    (void)p384_us;

    mbedtls_x509_crt_free(&ce); mbedtls_x509_crt_free(&cr);
    mbedtls_pk_free(&p256);

    vTaskDelay(1);   /* let IDLE0 run (task WDT) between sections */

    /* --- whole chains through the bundle ------------------------------ */
    int64_t ecdsa_chain_us = -1, rsa_chain_us = -1;
    const int64_t ecdsa_parse = bench_chain("ecdsa", e_der, e_len, K_ECDSA_N, &ecdsa_chain_us);
    const int64_t rsa_parse = bench_chain("rsa", r_der, r_len, K_RSA_N, &rsa_chain_us);

    vTaskDelay(1);

    /* --- ECDHE -------------------------------------------------------- */
    int64_t x25519_us = -1;
#if CONFIG_TINYLINK_TLS_X25519_INTREE
    bench_ecdhe("x25519 (in-tree)", MBEDTLS_ECP_DP_CURVE25519, &x25519_us);
    bench_x25519_mbedtls();
#else
    bench_ecdhe("x25519 (mbedtls)", MBEDTLS_ECP_DP_CURVE25519, &x25519_us);
    bench_x25519_intree();
#endif
    bench_ecdhe("p256", MBEDTLS_ECP_DP_SECP256R1, NULL);
    bench_ecdhe("p384", MBEDTLS_ECP_DP_SECP384R1, NULL);

    /* The client's crypto in one full handshake, per offer: parse + chain
     * verify (bundle included) + ServerKeyExchange verify + both ECDHE
     * halves (record keys, SHA and AES are noise next to these). */
    if (ecdsa_chain_us >= 0 && rsa_chain_us >= 0 && p256_us >= 0 && rsa2048_us >= 0 &&
        x25519_us >= 0) {
        ESP_LOGI(TAG, "handshake cpu ecdsa %ld us rsa %ld us "
                      "(chain parse + verify + SKE verify + ECDHE)",
                 (long)(ecdsa_parse + ecdsa_chain_us + p256_us + x25519_us),
                 (long)(rsa_parse + rsa_chain_us + rsa2048_us + x25519_us));
    }
    ESP_LOGI(TAG, "done in %ld ms, stack hwm %u B of %u",
             (long)((esp_timer_get_time() - t_start) / 1000),
             (unsigned)uxTaskGetStackHighWaterMark(NULL),
             (unsigned)CONFIG_ESP_MAIN_TASK_STACK_SIZE);
    return ESP_OK;
}

#endif /* CONFIG_TINYLINK_BENCH_TLS */
