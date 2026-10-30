// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// The TLS ECDHE's X25519 on the in-tree Curve25519 (round 1.3.8).
//
// Both servers pick X25519 from mbedTLS's supported_groups (openssl
// s_client "Peer Temp Key: X25519", 2026-10-30), so every full TLS
// handshake does two X25519 scalar multiplications: the client's
// ephemeral public key (d·9) and the shared secret (d·Q). mbedTLS runs
// them as a Montgomery ladder over its generic bignum, every field
// multiplication a call through mbedtls_mpi_mul_mpi (on the RSA
// accelerator with CONFIG_MBEDTLS_HARDWARE_MPI, operands padded to 512
// bits) plus a reduction. The firmware already carries a constant-time
// X25519 for WireGuard / Noise / DISCO (crypto/curve25519_fiat32.c, 12.55
// ms per scalarmult on the chip since 1.3.3). The numbers for both are
// printed by CONFIG_TINYLINK_BENCH_TLS.
//
// How it is hooked: the link wraps mbedtls_ecp_mul_restartable
// (-Wl,--wrap, CMakeLists.txt). ecdh.c reaches it from
// mbedtls_ecdh_gen_public / mbedtls_ecdh_compute_shared — what the TLS
// 1.2 client's ClientKeyExchange calls — and a --wrap only redirects
// references from other objects, so mbedTLS's own internal calls
// (mbedtls_ecp_mul, keypair generation inside ecp.c) keep the original.
// Only Curve25519 is diverted; every other curve, and a restartable
// context, goes to the original function unchanged.
//
// Same contract as mbedTLS's path (ecp_mul_restartable_internal): the
// scalar must pass mbedtls_ecp_check_privkey (a clamped X25519 key, as
// mbedtls_ecp_gen_privkey makes them) and the point
// mbedtls_ecp_check_pubkey (u < 2^255, not one of the low-order points);
// the result is R = (X, Z = 1) with Y freed, exactly what ecp_mul_mxz
// leaves. The in-tree scalarmult re-clamps (idempotent on a clamped
// key) and masks bit 255 of u (already clear: mbedtls_ecp_point_read_
// binary clears it), so the output equals mbedTLS's for every input;
// an all-zero result (mbedTLS: Z = 0, whose inversion fails) is an
// error here too. The in-tree code has no secret-dependent branch or
// address (round 1.3.3), so mbedTLS's projective-coordinate
// randomisation (its only use of f_rng here) has nothing to add.
// CONFIG_TINYLINK_BENCH_TLS checks the two against each other on the
// device.

#include "sdkconfig.h"

#if CONFIG_TINYLINK_TLS_X25519_INTREE

#include <stdint.h>

#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"

#include "crypto/curve25519.h"
#include "crypto/secure_zero.h"

int __real_mbedtls_ecp_mul_restartable(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                                       const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                                       int (*f_rng)(void *, unsigned char *, size_t),
                                       void *p_rng, mbedtls_ecp_restart_ctx *rs_ctx);

int __wrap_mbedtls_ecp_mul_restartable(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                                       const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                                       int (*f_rng)(void *, unsigned char *, size_t),
                                       void *p_rng, mbedtls_ecp_restart_ctx *rs_ctx)
{
    if (grp == NULL || grp->id != MBEDTLS_ECP_DP_CURVE25519 || rs_ctx != NULL ||
        R == NULL || m == NULL || P == NULL) {
        return __real_mbedtls_ecp_mul_restartable(grp, R, m, P, f_rng, p_rng, rs_ctx);
    }
    if (f_rng == NULL) return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;   /* as the original */

    int ret = mbedtls_ecp_check_privkey(grp, m);
    if (ret == 0) ret = mbedtls_ecp_check_pubkey(grp, P);
    if (ret != 0) return ret;

    uint8_t k[CURVE25519_KEY_LEN], u[CURVE25519_KEY_LEN], q[CURVE25519_KEY_LEN];
    ret = mbedtls_mpi_write_binary_le(m, k, sizeof(k));
    if (ret == 0) ret = mbedtls_mpi_write_binary_le(&P->MBEDTLS_PRIVATE(X), u, sizeof(u));
    if (ret == 0 && curve25519_scalarmult(q, k, u) != 0) {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    if (ret == 0) ret = mbedtls_mpi_read_binary_le(&R->MBEDTLS_PRIVATE(X), q, sizeof(q));
    if (ret == 0) ret = mbedtls_mpi_lset(&R->MBEDTLS_PRIVATE(Z), 1);
    if (ret == 0) mbedtls_mpi_free(&R->MBEDTLS_PRIVATE(Y));
    tl_secure_zero(k, sizeof(k));
    tl_secure_zero(q, sizeof(q));
    return ret;
}

#endif /* CONFIG_TINYLINK_TLS_X25519_INTREE */
