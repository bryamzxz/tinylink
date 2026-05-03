/* SPDX-License-Identifier: MIT
 * Host-only stub header — declares only the mbedtls error constants
 * used by tls_io.c. Real mbedtls/ssl.h is huge and pulls in the entire
 * TLS state machine; the host tests only care about the WANT_READ /
 * WANT_WRITE return-code constants. */

#ifndef HOST_STUB_MBEDTLS_SSL_H_
#define HOST_STUB_MBEDTLS_SSL_H_

#define MBEDTLS_ERR_SSL_WANT_READ   -0x6900   /* -26880 */
#define MBEDTLS_ERR_SSL_WANT_WRITE  -0x6880   /* -26752 */

#endif
