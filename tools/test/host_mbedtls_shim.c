/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Tiny host-only shim that satisfies the single mbedtls symbol pulled
 * in by crypto/nacl_box.c (mbedtls_poly1305_mac). On-target the IDF
 * provides mbedtls; on the host KAT runner we replay it through the
 * in-tree poly1305-donna so we don't need mbedtls dev headers.
 *
 * The mbedtls signature is:
 *   int mbedtls_poly1305_mac(const unsigned char key[32],
 *                            const unsigned char *input, size_t ilen,
 *                            unsigned char mac[16]);
 */

#include <stddef.h>

#include "poly1305_donna.h"

int mbedtls_poly1305_mac(const unsigned char key[32],
                         const unsigned char *input, size_t ilen,
                         unsigned char mac[16])
{
    poly1305_context ctx;
    poly1305_init(&ctx, key);
    poly1305_update(&ctx, input, ilen);
    poly1305_finish(&ctx, mac);
    return 0;
}
