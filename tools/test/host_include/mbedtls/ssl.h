/* SPDX-License-Identifier: MIT
 * Host-only stub header — declares only the mbedtls error constants
 * used by tls_io.c. Real mbedtls/ssl.h is huge and pulls in the entire
 * TLS state machine; the host tests only care about the WANT_READ /
 * WANT_WRITE return-code constants. */

#ifndef HOST_STUB_MBEDTLS_SSL_H_
#define HOST_STUB_MBEDTLS_SSL_H_

#define MBEDTLS_ERR_SSL_WANT_READ   -0x6900   /* -26880 */
#define MBEDTLS_ERR_SSL_WANT_WRITE  -0x6880   /* -26752 */

/* The fields of mbedtls_ssl_session that tls_resume.c (round 1.3.5) and
 * tls_offer.c (round 1.3.8: the ciphersuite) read, for their host builds;
 * MBEDTLS_PRIVATE as mbedtls/private_access.h defines it for
 * library-external code. */
#include <stddef.h>
#ifndef MBEDTLS_PRIVATE
#define MBEDTLS_PRIVATE(member) member
#endif
typedef struct {
    int            ciphersuite;
    size_t         id_len;
    unsigned char  master[48];
    unsigned char *ticket;
    size_t         ticket_len;
} mbedtls_ssl_session;

/* The verify result of a (failed) handshake, read by tls_offer.c (round
 * 1.3.8); the host tests define it over their fake contexts. */
#include <stdint.h>
typedef struct mbedtls_ssl_context mbedtls_ssl_context;
uint32_t mbedtls_ssl_get_verify_result(const mbedtls_ssl_context *ssl);

/* Session (de)serialization (tls_resume.c's RTC copy, round 1.3.8): the
 * host test defines them over the fields above. */
#define MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL  -0x6A00
#define MBEDTLS_ERR_SSL_BAD_INPUT_DATA    -0x7100
void mbedtls_ssl_session_init(mbedtls_ssl_session *session);
int mbedtls_ssl_session_save(const mbedtls_ssl_session *session, unsigned char *buf,
                             size_t buf_len, size_t *olen);
int mbedtls_ssl_session_load(mbedtls_ssl_session *session, const unsigned char *buf,
                             size_t len);

#endif
