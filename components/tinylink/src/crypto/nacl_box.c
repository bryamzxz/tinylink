// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "nacl_box.h"

#include <string.h>

#include "curve25519.h"
#include "poly1305_donna.h"
#include "salsa20.h"
#include "secure_zero.h"

/* Maximum stack-resident keystream + tag-input buffer used by
 * nacl_box / nacl_box_open. The largest inner plaintext the firmware
 * needs to handle is the DISCO CallMeMaybe (146 B); the EarlyNoise
 * payload tops out around 96 B; with TAG(16) + keystream prefix(32),
 * 256 + 32 = 288 covers everything with comfortable slack. Avoiding
 * malloc on the RX hot path eliminates a heap-fragmentation surface
 * after long uptime (esp32 heap fragments badly under nghttp2/mbedtls
 * churn) and a malloc-fails-returns-0 false-positive auth failure. */
#define NACL_BOX_MAX_INNER  256
#define NACL_BOX_STREAM_BUF (NACL_BOX_MAX_INNER + 32)

/* crypto_box_beforenm: derive shared key K = HSalsa20(X25519(my_priv, peer_pub), zero16). */
static int box_beforenm(uint8_t k[NACL_BOX_KEY_LEN],
                        const uint8_t peer_pub[NACL_BOX_KEY_LEN],
                        const uint8_t my_priv[NACL_BOX_KEY_LEN])
{
    uint8_t shared[CURVE25519_KEY_LEN];
    static const uint8_t zero16[16] = {0};

    if (curve25519_dh(shared, my_priv, peer_pub) != 0) {
        return -1;
    }
    hsalsa20(k, shared, zero16);
    tl_secure_zero(shared, sizeof(shared));
    return 0;
}

int nacl_box_compute_shared(uint8_t k[NACL_BOX_KEY_LEN],
                            const uint8_t peer_pub[NACL_BOX_KEY_LEN],
                            const uint8_t my_priv[NACL_BOX_KEY_LEN])
{
    return box_beforenm(k, peer_pub, my_priv);
}

/* One-shot Poly1305 (crypto_onetimeauth) on the in-tree poly1305-donna —
 * the same IRAM code the WireGuard AEAD uses. Byte-identical to the
 * mbedtls_poly1305_mac() it replaced in round 1.3.2 (RFC 8439 §2.5 both;
 * tools/test: libsodium vectors + the mbedTLS differential). The context
 * holds r and the pad s, so it is scrubbed. noinline: the 144-byte
 * context then lives only in this frame, not in nacl_box() /
 * nacl_box_open_after_shared() across the XSalsa20 call (wg_rx stack). */
static __attribute__((noinline)) void onetimeauth(uint8_t mac[NACL_BOX_TAG_LEN],
                        const uint8_t *m, size_t mlen,
                        const uint8_t key[32])
{
    poly1305_context p;
    poly1305_init(&p, key);
    poly1305_update(&p, m, mlen);
    poly1305_finish(&p, mac);
    tl_secure_zero(&p, sizeof(p));
}

/* Constant-time memcmp for auth tag verification. Returns 0 on equal,
 * non-zero otherwise. */
static int ct_memeq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff;
}

int nacl_box(uint8_t *c,
             const uint8_t *m, size_t mlen,
             const uint8_t nonce[NACL_BOX_NONCE_LEN],
             const uint8_t peer_pub[NACL_BOX_KEY_LEN],
             const uint8_t my_priv[NACL_BOX_KEY_LEN])
{
    if (mlen > NACL_BOX_MAX_INNER) return -1;

    uint8_t k[NACL_BOX_KEY_LEN];
    if (box_beforenm(k, peer_pub, my_priv) != 0) return -1;

    /* Generate keystream of length mlen + 32 (first 32 bytes are the
     * Poly1305 one-time key). Stack-resident, sized for the worst case
     * we ever box (DISCO CMM @ 146 B, EarlyNoise @ ~96 B). */
    uint8_t stream[NACL_BOX_STREAM_BUF];
    xsalsa20_keystream(stream, mlen + 32, k, nonce);

    /* Encrypt: ciphertext = m XOR stream[32..]. Place at c + 16
     * (after the future tag). */
    for (size_t i = 0; i < mlen; i++) {
        c[NACL_BOX_TAG_LEN + i] = m[i] ^ stream[32 + i];
    }
    /* Authenticate ciphertext with Poly1305 keyed by stream[0..32]. */
    onetimeauth(c, c + NACL_BOX_TAG_LEN, mlen, stream);

    tl_secure_zero(stream, sizeof(stream));
    tl_secure_zero(k, sizeof(k));
    return 0;
}

int nacl_box_open_after_shared(uint8_t *m,
                               const uint8_t *c, size_t clen,
                               const uint8_t nonce[NACL_BOX_NONCE_LEN],
                               const uint8_t k[NACL_BOX_KEY_LEN])
{
    if (clen < NACL_BOX_TAG_LEN) return -1;
    size_t mlen = clen - NACL_BOX_TAG_LEN;
    if (mlen > NACL_BOX_MAX_INNER) return -1;

    uint8_t stream[NACL_BOX_STREAM_BUF];
    xsalsa20_keystream(stream, mlen + 32, k, nonce);

    uint8_t tag[NACL_BOX_TAG_LEN];
    onetimeauth(tag, c + NACL_BOX_TAG_LEN, mlen, stream);
    if (ct_memeq(tag, c, NACL_BOX_TAG_LEN) != 0) {
        tl_secure_zero(stream, sizeof(stream));
        return -1;
    }
    for (size_t i = 0; i < mlen; i++) {
        m[i] = c[NACL_BOX_TAG_LEN + i] ^ stream[32 + i];
    }
    tl_secure_zero(stream, sizeof(stream));
    return 0;
}

int nacl_box_open(uint8_t *m,
                  const uint8_t *c, size_t clen,
                  const uint8_t nonce[NACL_BOX_NONCE_LEN],
                  const uint8_t peer_pub[NACL_BOX_KEY_LEN],
                  const uint8_t my_priv[NACL_BOX_KEY_LEN])
{
    uint8_t k[NACL_BOX_KEY_LEN];
    if (box_beforenm(k, peer_pub, my_priv) != 0) return -1;
    int rc = nacl_box_open_after_shared(m, c, clen, nonce, k);
    tl_secure_zero(k, sizeof(k));
    return rc;
}
