/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Differential test: in-tree ChaCha20-Poly1305 / Poly1305 against the
 * mbedTLS implementations they replaced in round 1.3.2 (noise_ik.c used
 * mbedtls_chachapoly_*, nacl_box.c mbedtls_poly1305_mac). Not part of
 * `make test` — it links IDF's mbedTLS sources:
 *
 *   make mbedtls-ref IDF_PATH=/path/to/esp-idf
 *
 * A fixed-seed xorshift drives every case, so a failure reproduces. The
 * nonce shapes cover arbitrary RFC 8439 nonces, WireGuard's
 * 0^32 || LE64(n) and ts2021's 0^32 || BE64(n); lengths straddle the
 * 16-byte Poly1305 and 64-byte ChaCha20 block edges; buffers run at
 * every alignment 0..3 and in place.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "mbedtls/chachapoly.h"
#include "mbedtls/poly1305.h"

#include "chacha20poly1305.h"
#include "poly1305_donna.h"

static uint64_t s_x = 0x9E3779B97F4A7C15ULL;
static uint64_t rnd(void)
{
    s_x ^= s_x << 13;
    s_x ^= s_x >> 7;
    s_x ^= s_x << 17;
    return s_x;
}
static void rnd_fill(uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) p[i] = (uint8_t)rnd();
}
static size_t rnd_len(size_t max)
{
    /* Half the draws near a block edge, half uniform. */
    if (rnd() & 1) {
        size_t edge = (size_t)(rnd() % (max / 64 + 1)) * 64;
        size_t len = edge + (size_t)(rnd() % 5) - 2;
        return len > max ? max : len;   /* wraps to huge when edge==0 */
    }
    return (size_t)(rnd() % (max + 1));
}

static int s_fails;
static void report(const char *name, int bad, int total)
{
    printf("[%s] %s (%d cases)\n", name, bad ? "FAIL" : "OK", total);
    if (bad) s_fails++;
}

#define ITER   3000
#define MAXLEN 1500
#define MAXAAD 80

int main(void)
{
    static uint8_t pt[MAXLEN + 8], ad[MAXAAD + 8], key[32], nonce[12];
    static uint8_t ref[MAXLEN + 16 + 8], buf[MAXLEN + 16 + 8], out[MAXLEN + 8];
    static uint8_t scratch[MAXLEN + 8];
    int bad_enc = 0, bad_dec = 0, bad_tamper = 0, bad_inplace = 0, bad_poly = 0;

    for (int it = 0; it < ITER; it++) {
        size_t len = rnd_len(MAXLEN);
        size_t ad_len = (it % 3 == 0) ? 0 : (it % 3 == 1) ? 32 : (size_t)(rnd() % (MAXAAD + 1));
        size_t ao = it & 3, bo = (it >> 2) & 3;
        rnd_fill(key, 32);
        rnd_fill(pt + ao, len);
        rnd_fill(ad, ad_len);
        uint64_t n = rnd();
        switch (it % 3) {
        case 0: rnd_fill(nonce, 12); break;                       /* RFC 8439 */
        case 1: memset(nonce, 0, 4);                              /* WG LE64 */
                for (int i = 0; i < 8; i++) nonce[4 + i] = (uint8_t)(n >> (8 * i));
                break;
        default: memset(nonce, 0, 4);                             /* ts2021 BE64 */
                for (int i = 0; i < 8; i++) nonce[11 - i] = (uint8_t)(n >> (8 * i));
                break;
        }

        /* Reference: mbedTLS exactly as noise_ik.c called it. */
        mbedtls_chachapoly_context cp;
        mbedtls_chachapoly_init(&cp);
        mbedtls_chachapoly_setkey(&cp, key);
        mbedtls_chachapoly_encrypt_and_tag(&cp, len, nonce, ad_len ? ad : NULL, ad_len,
                                           pt + ao, ref, ref + len);
        mbedtls_chachapoly_free(&cp);

        chacha20poly1305_encrypt(buf + bo, len ? pt + ao : NULL, len,
                                 ad_len ? ad : NULL, ad_len, key, nonce);
        if (memcmp(buf + bo, ref, len + 16) != 0) bad_enc++;

        if (chacha20poly1305_decrypt(out + ao, ref, len + 16, ad_len ? ad : NULL,
                                     ad_len, key, nonce) != 0 ||
            memcmp(out + ao, pt + ao, len) != 0) bad_dec++;

        /* One flipped bit anywhere (ct, tag, or AAD): both reject. */
        size_t span = len + 16 + ad_len;
        size_t pos = (size_t)(rnd() % span);
        uint8_t bit = (uint8_t)(1u << (rnd() & 7));
        if (pos < len + 16) buf[bo + pos] ^= bit; else ad[pos - len - 16] ^= bit;
        memset(out, 0xA5, sizeof(out));
        int ours = chacha20poly1305_decrypt(out + ao, buf + bo, len + 16,
                                            ad_len ? ad : NULL, ad_len, key, nonce);
        mbedtls_chachapoly_init(&cp);
        mbedtls_chachapoly_setkey(&cp, key);
        int theirs = mbedtls_chachapoly_auth_decrypt(&cp, len, nonce,
                                                     ad_len ? ad : NULL, ad_len,
                                                     (pos < len + 16) ? buf + bo + len : ref + len,
                                                     (pos < len + 16) ? buf + bo : ref,
                                                     scratch);
        mbedtls_chachapoly_free(&cp);
        int untouched = 1;
        for (size_t i = 0; i < len; i++) if (out[ao + i] != 0xA5) untouched = 0;
        if (ours == 0 || theirs != MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED || !untouched)
            bad_tamper++;
        if (pos >= len + 16) ad[pos - len - 16] ^= bit;

        /* In place, both directions (ts2021_client decrypts into a
         * separate buffer today; noise_ik.h allows out == ct). */
        memcpy(buf, pt + ao, len);
        chacha20poly1305_encrypt(buf, buf, len, ad_len ? ad : NULL, ad_len, key, nonce);
        int ok = memcmp(buf, ref, len + 16) == 0 &&
                 chacha20poly1305_decrypt(buf, buf, len + 16, ad_len ? ad : NULL,
                                          ad_len, key, nonce) == 0 &&
                 memcmp(buf, pt + ao, len) == 0;
        if (!ok) bad_inplace++;

        /* One-shot Poly1305 as nacl_box computes it (in-tree, streamed in
         * random chunks) vs mbedtls_poly1305_mac. */
        uint8_t t_ref[16], t_ours[16];
        mbedtls_poly1305_mac(key, pt + ao, len, t_ref);
        poly1305_context pc;
        poly1305_init(&pc, key);
        for (size_t off = 0; off < len;) {
            size_t chunk = 1 + (size_t)(rnd() % 70);
            if (chunk > len - off) chunk = len - off;
            poly1305_update(&pc, pt + ao + off, chunk);
            off += chunk;
        }
        poly1305_finish(&pc, t_ours);
        if (memcmp(t_ref, t_ours, 16) != 0) bad_poly++;
    }

    report("mbedtls-diff-encrypt", bad_enc, ITER);
    report("mbedtls-diff-decrypt", bad_dec, ITER);
    report("mbedtls-diff-tamper", bad_tamper, ITER);
    report("mbedtls-diff-in-place", bad_inplace, ITER);
    report("mbedtls-diff-poly1305", bad_poly, ITER);

    if (s_fails == 0) printf("\nALL OK\n");
    return s_fails ? 1 : 0;
}
