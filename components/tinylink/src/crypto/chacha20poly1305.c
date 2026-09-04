// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// RFC 8439 §2.8 AEAD construction. The math primitives (ChaCha20
// keystream and Poly1305 one-time MAC) are lifted from well-audited
// public references (BSD-3 / public-domain). This file owns the
// composition glue, where most past CVEs in ChaCha20-Poly1305
// implementations have lived:
//
//   - pad16 of AAD before the ciphertext block enters Poly1305
//   - pad16 of ciphertext before the lengths block enters Poly1305
//   - lengths block is exactly LE u64 aad_len || LE u64 ct_len (16 B)
//   - constant-time tag compare on decrypt
//   - secret scrubbing in all return paths
//
// End-to-end validated by host KAT against RFC 8439 §2.8.2.

#include "chacha20poly1305.h"

#include <string.h>

#include "chacha20.h"
#include "poly1305_donna.h"
#include "secure_zero.h"
#include "tl_hot.h"

#define TAG_LEN CHACHA20POLY1305_TAG_LEN

/* --- helpers -------------------------------------------------------- */

/* LE pack/unpack via __builtin_memcpy. Xtensa LX6 + host builds are
 * little-endian, so this folds to 1× l32i/s32i (aligned) or 4× l8ui/s8i
 * (unaligned) — identical to wg_transport.c's load_u32_le / store_u32_le
 * and chacha20.c's U8TO32_LITTLE / U32TO8_LITTLE. Avoids the byte-loop
 * pattern the rest of the crypto module phased out. */

static uint32_t le_u32_load(const uint8_t in[4])
{
    uint32_t v;
    __builtin_memcpy(&v, in, sizeof(v));
    return v;
}

static uint64_t le_u64_load(const uint8_t in[8])
{
    uint64_t v;
    __builtin_memcpy(&v, in, sizeof(v));
    return v;
}

static void le_u64_store(uint8_t out[8], uint64_t v)
{
    __builtin_memcpy(out, &v, sizeof(v));
}

/* Constant-time byte compare. Returns 0 iff equal. Same idiom used
 * by nacl_box.c:ct_memeq to keep timing independent of mismatch
 * position. */
static int ct_memeq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff;
}

/* Build the chacha20_ctx for an RFC 8439 12-byte nonce. The lifted
 * chacha20_init() is WG-shaped (8-byte nonce → state[14..15], state[13]
 * forced to 0); we patch state[13] from the first 4 bytes of the
 * 12-byte nonce so this wrapper accepts any RFC 8439 nonce, not only
 * those whose first 4 bytes are zero. */
static void init_ctx_with_nonce12(struct chacha20_ctx *ctx,
                                  const uint8_t key[CHACHA20POLY1305_KEY_LEN],
                                  const uint8_t nonce[CHACHA20POLY1305_NONCE_LEN])
{
    uint64_t nonce_lo = le_u64_load(nonce + 4);
    chacha20_init(ctx, key, nonce_lo);
    ctx->state[13] = le_u32_load(nonce);
    /* state[12] (the per-block counter) is left at 0 — chacha20_init
     * zeroed it. The first chacha20() call will use counter=0 and
     * leave state[12]=1 ready for the plaintext stream. */
}

/* RFC 8439 §2.6 poly1305_key_gen: take the first 32 bytes of the
 * ChaCha20 keystream at counter=0. After this call, ctx->state[12] is
 * 1, ready for plaintext encryption to start at counter=1 (per §2.8). */
static void poly1305_keygen(uint8_t otk[32], struct chacha20_ctx *ctx)
{
    /* Word-aligned so chacha20()'s XOR takes its l32i/s32i fast path
     * (the caller's otk[] is declared aligned too). */
    static const uint8_t __attribute__((aligned(4))) zeros[32] = {0};
    chacha20(ctx, otk, zeros, 32);
}

/* Pad Poly1305 input to a 16-byte boundary by feeding zero bytes. */
static void poly1305_pad16(poly1305_context *p, size_t already_in_len)
{
    static const uint8_t __attribute__((aligned(4))) zeros[16] = {0};
    size_t pad = (16 - (already_in_len % 16)) % 16;
    if (pad) {
        poly1305_update(p, zeros, pad);
    }
}

/* Compute the AEAD tag over (aad || pad16 || ct || pad16 || u64 LE
 * aad_len || u64 LE ct_len). Used by both encrypt and decrypt. */
static TL_HOT_ATTR void aead_tag(uint8_t tag[TAG_LEN],
                     const uint8_t otk[32],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ct,  size_t ct_len)
{
    poly1305_context p;
    uint8_t __attribute__((aligned(4))) lengths[16];

    poly1305_init(&p, otk);
    if (aad_len) poly1305_update(&p, aad, aad_len);
    poly1305_pad16(&p, aad_len);
    if (ct_len)  poly1305_update(&p, ct, ct_len);
    poly1305_pad16(&p, ct_len);

    le_u64_store(lengths + 0, (uint64_t)aad_len);
    le_u64_store(lengths + 8, (uint64_t)ct_len);
    poly1305_update(&p, lengths, sizeof(lengths));
    poly1305_finish(&p, tag);
}

/* --- public API ----------------------------------------------------- */

TL_HOT_ATTR void chacha20poly1305_encrypt(uint8_t *out,
                              const uint8_t *m, size_t mlen,
                              const uint8_t *aad, size_t aad_len,
                              const uint8_t key[CHACHA20POLY1305_KEY_LEN],
                              const uint8_t nonce[CHACHA20POLY1305_NONCE_LEN])
{
    struct chacha20_ctx ctx;
    uint8_t __attribute__((aligned(4))) otk[32];

    init_ctx_with_nonce12(&ctx, key, nonce);
    poly1305_keygen(otk, &ctx);

    /* Encrypt plaintext into out[0..mlen]. chacha20() XORs in-place;
     * we prime out with m by passing m as input. */
    if (mlen) {
        chacha20(&ctx, out, m, (uint32_t)mlen);
    }

    /* Tag goes after the ciphertext: out[mlen..mlen+16]. */
    aead_tag(out + mlen, otk, aad, aad_len, out, mlen);

    tl_secure_zero(otk, sizeof(otk));
    tl_secure_zero(&ctx, sizeof(ctx));
}

TL_HOT_ATTR int chacha20poly1305_decrypt(uint8_t *out,
                             const uint8_t *c, size_t clen,
                             const uint8_t *aad, size_t aad_len,
                             const uint8_t key[CHACHA20POLY1305_KEY_LEN],
                             const uint8_t nonce[CHACHA20POLY1305_NONCE_LEN])
{
    if (clen < TAG_LEN) return -1;
    size_t mlen = clen - TAG_LEN;

    struct chacha20_ctx ctx;
    uint8_t __attribute__((aligned(4))) otk[32];
    uint8_t expected_tag[TAG_LEN];

    init_ctx_with_nonce12(&ctx, key, nonce);
    poly1305_keygen(otk, &ctx);

    /* Tag is computed over the on-wire ciphertext, NOT the recovered
     * plaintext, so we MAC before we decrypt. */
    aead_tag(expected_tag, otk, aad, aad_len, c, mlen);

    if (ct_memeq(expected_tag, c + mlen, TAG_LEN) != 0) {
        tl_secure_zero(otk, sizeof(otk));
        tl_secure_zero(&ctx, sizeof(ctx));
        tl_secure_zero(expected_tag, sizeof(expected_tag));
        return -1;
    }

    if (mlen) {
        chacha20(&ctx, out, c, (uint32_t)mlen);
    }

    tl_secure_zero(otk, sizeof(otk));
    tl_secure_zero(&ctx, sizeof(ctx));
    tl_secure_zero(expected_tag, sizeof(expected_tag));
    return 0;
}
