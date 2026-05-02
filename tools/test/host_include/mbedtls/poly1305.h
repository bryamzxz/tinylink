/* SPDX-License-Identifier: MIT
 * Host-only stub header — declares only the single mbedtls symbol used
 * by crypto/nacl_box.c. The implementation is provided by
 * tools/test/host_mbedtls_shim.c (poly1305-donna under the hood). */

#ifndef HOST_STUB_MBEDTLS_POLY1305_H_
#define HOST_STUB_MBEDTLS_POLY1305_H_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int mbedtls_poly1305_mac(const unsigned char key[32],
                         const unsigned char *input, size_t ilen,
                         unsigned char mac[16]);

#ifdef __cplusplus
}
#endif

#endif
