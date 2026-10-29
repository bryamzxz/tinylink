// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#include "wg_handshake.h"

#include <stddef.h>
#include <string.h>

#include "crypto/chacha20poly1305.h"
#include "crypto/curve25519.h"
#include "crypto/hkdf_blake2s.h"
#include "crypto/secure_zero.h"
#include "wg_proto.h"

/* Build the 12-byte AEAD nonce used during handshake. WG handshake
 * payloads always use counter=0; the 12-byte nonce is then 4 zero
 * bytes followed by the 8-byte LE counter. Counter=0 → all zeros. */
static void zero_nonce(uint8_t out[CHACHA20POLY1305_NONCE_LEN])
{
    memset(out, 0, CHACHA20POLY1305_NONCE_LEN);
}

/* Byte difference accumulator: 0 iff a == b. No early exit — one of the
 * operands is our static private key. */
static uint8_t diff_bytes(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d;
}

/* True when *st already holds this exact identity and its derivations. */
static int identity_cached(const struct wg_handshake_state *st,
                           const uint8_t local_static_priv[WG_KEY_LEN],
                           const uint8_t local_static_pub[WG_KEY_LEN],
                           const uint8_t peer_static_pub[WG_KEY_LEN],
                           const uint8_t preshared_key[WG_KEY_LEN])
{
    static const uint8_t no_psk[WG_KEY_LEN] = {0};
    if (!st->identity_valid) return 0;
    uint8_t d = diff_bytes(st->local_static_priv, local_static_priv, WG_KEY_LEN);
    d |= diff_bytes(st->local_static_pub, local_static_pub, WG_KEY_LEN);
    d |= diff_bytes(st->peer_static_pub,  peer_static_pub,  WG_KEY_LEN);
    d |= diff_bytes(st->preshared_key, preshared_key ? preshared_key : no_psk,
                    WG_KEY_LEN);
    return d == 0;
}

int wg_handshake_init(struct wg_handshake_state *st,
                      const uint8_t local_static_priv[WG_KEY_LEN],
                      const uint8_t local_static_pub[WG_KEY_LEN],
                      const uint8_t peer_static_pub[WG_KEY_LEN],
                      const uint8_t preshared_key[WG_KEY_LEN])
{
    /* Same identity as the cached one (every retry and rekey towards the
     * same peer): reuse mac1 keys + static-static DH, ~20 ms of X25519
     * saved per INIT. Anything else recomputes from scratch below. */
    if (identity_cached(st, local_static_priv, local_static_pub,
                        peer_static_pub, preshared_key)) {
        wg_handshake_scrub_live(st);
        return 0;
    }

    memset(st, 0, sizeof(*st));

    memcpy(st->local_static_priv, local_static_priv, WG_KEY_LEN);
    memcpy(st->local_static_pub,  local_static_pub,  WG_KEY_LEN);
    memcpy(st->peer_static_pub,   peer_static_pub,   WG_KEY_LEN);
    if (preshared_key) {
        memcpy(st->preshared_key, preshared_key, WG_KEY_LEN);
    }

    /* mac1 key: BLAKE2s(LABEL_MAC1 || peer_static_pub). */
    wg_mac1_key(st->mac1_key, peer_static_pub);
    /* The responder keys the response's mac1 with OUR static public
     * (wireguard-go cookieChecker.Init(pk)) — constant for the identity. */
    wg_mac1_key(st->mac1_key_self, local_static_pub);

    /* Long-term static-static DH, computed once and reused per
     * handshake attempt (per WG whitepaper §5.4.3). */
    if (curve25519_dh(st->static_static_dh,
                      st->local_static_priv,
                      st->peer_static_pub) != 0) {
        memset(st, 0, sizeof(*st));
        return -1;
    }
    st->identity_valid = 1;
    return 0;
}

int wg_handshake_create_initiation(struct wg_handshake_state *st,
                                   uint32_t local_index,
                                   struct wg_msg_initiation *msg)
{
    uint8_t key[WG_KEY_LEN];
    uint8_t dh_e_s[WG_KEY_LEN];
    uint8_t timestamp[WG_TAI64N_LEN];
    uint8_t nonce[CHACHA20POLY1305_NONCE_LEN];
    int rc = -1;

    memset(msg, 0, sizeof(*msg));
    zero_nonce(nonce);

    /* Ci = H(Construction) — cached. */
    memcpy(st->chain_key, wg_initial_chain_key(), WG_HASH_LEN);
    /* Hi = H(Ci || Identifier) — cached. */
    memcpy(st->hash, wg_initial_hash(), WG_HASH_LEN);

    /* Hi = H(Hi || S_pub_responder). */
    wg_mix_hash(st->hash, st->peer_static_pub, WG_KEY_LEN);

    /* (E_priv, E_pub) = DH-Generate(). */
    if (curve25519_keypair(st->ephemeral_priv, st->ephemeral_pub) != 0) {
        goto out_scrub;
    }
    memcpy(msg->ephemeral, st->ephemeral_pub, WG_KEY_LEN);

    /* Ci = KDF1(Ci, E_pub).
     * Hi = H(Hi || E_pub). */
    wg_mix_chain_only(st->chain_key, msg->ephemeral, WG_KEY_LEN);
    wg_mix_hash(st->hash, msg->ephemeral, WG_KEY_LEN);

    /* DH(E_priv, S_pub_responder). */
    if (curve25519_dh(dh_e_s, st->ephemeral_priv, st->peer_static_pub) != 0) {
        /* Low-order peer pub. We never have a recovery for this; the
         * caller should have validated peer_pub at registration time. */
        goto out_scrub;
    }
    /* (Ci, k) = KDF2(Ci, DH(E_priv, S_pub_resp)). */
    wg_mix_key(st->chain_key, dh_e_s, WG_KEY_LEN, key);

    /* msg.encrypted_static = AEAD(k, 0, S_pub_initiator, Hi). */
    chacha20poly1305_encrypt(msg->encrypted_static,
                             st->local_static_pub, WG_KEY_LEN,
                             st->hash, WG_HASH_LEN,
                             key, nonce);
    /* Hi = H(Hi || msg.encrypted_static). */
    wg_mix_hash(st->hash, msg->encrypted_static, sizeof(msg->encrypted_static));

    /* (Ci, k) = KDF2(Ci, DH(S_priv_initiator, S_pub_responder))
     * — using the cached static_static_dh. */
    wg_mix_key(st->chain_key, st->static_static_dh, WG_KEY_LEN, key);

    /* msg.encrypted_timestamp = AEAD(k, 0, TAI64N(now), Hi). */
    wg_tai64n_now(timestamp);
    chacha20poly1305_encrypt(msg->encrypted_timestamp,
                             timestamp, WG_TAI64N_LEN,
                             st->hash, WG_HASH_LEN,
                             key, nonce);
    /* Hi = H(Hi || msg.encrypted_timestamp). */
    wg_mix_hash(st->hash, msg->encrypted_timestamp, sizeof(msg->encrypted_timestamp));

    /* Header bytes. */
    msg->message_type  = WG_MSG_INITIATION;
    msg->reserved[0]   = 0;
    msg->reserved[1]   = 0;
    msg->reserved[2]   = 0;
    msg->sender_index  = local_index;  /* native LE on ESP32 + x86 hosts */
    st->local_index    = local_index;
    st->armed          = 1;

    /* mac1 covers everything before the mac1 field, i.e. everything
     * except mac1 (16 B) + mac2 (16 B). */
    const size_t macd_off = offsetof(struct wg_msg_initiation, mac1);
    wg_keyed_mac16(msg->mac1, st->mac1_key, (const uint8_t *)msg, macd_off);

    /* mac2 stays zero. We never have a fresh cookie because we are
     * outbound-only; there's nobody to rate-limit us. */
    memset(msg->mac2, 0, sizeof(msg->mac2));

    rc = 0;

out_scrub:
    tl_secure_zero(key,        sizeof(key));
    tl_secure_zero(dh_e_s,     sizeof(dh_e_s));
    memset(timestamp,  0, sizeof(timestamp));
    memset(nonce,      0, sizeof(nonce));
    return rc;
}

int wg_handshake_process_response(struct wg_handshake_state *st,
                                  const struct wg_msg_response *msg,
                                  uint8_t send_key[WG_KEY_LEN],
                                  uint8_t recv_key[WG_KEY_LEN],
                                  uint32_t *out_remote_index)
{
    uint8_t key[WG_KEY_LEN];
    uint8_t dh_e_e[WG_KEY_LEN];
    uint8_t dh_e_s[WG_KEY_LEN];
    uint8_t tau[WG_HASH_LEN];
    uint8_t plaintext_zero[1];   /* dummy; AEAD payload is empty */
    uint8_t nonce[CHACHA20POLY1305_NONCE_LEN];
    int rc = -1;

    uint8_t ck[WG_HASH_LEN];         /* working copies: a response that   */
    uint8_t h[WG_HASH_LEN];          /* fails to authenticate leaves st   */
    uint8_t mac[WG_MAC_LEN];         /* untouched (see below)             */

    memset(nonce, 0, sizeof(nonce));
    memcpy(ck, st->chain_key, WG_HASH_LEN);
    memcpy(h,  st->hash,      WG_HASH_LEN);

    /* Validate message header before doing any crypto. Reserved bytes
     * must be zero per WireGuard whitepaper §5.4.2; wg_transport_decrypt
     * already enforces this on data frames, so mirror the check here. */
    /* No INIT in flight (never built, or already answered and scrubbed):
     * the zeroed chain would let anyone forge an "accepted" response. */
    if (!st->armed) goto out_scrub;
    if (msg->message_type != WG_MSG_RESPONSE) goto out_scrub;
    if (msg->reserved[0] | msg->reserved[1] | msg->reserved[2]) goto out_scrub;
    if (msg->receiver_index != st->local_index) goto out_scrub;

    /* mac1 = MAC(HASH(LABEL_MAC1 || S_pub_initiator), msg[..mac1]) — the
     * responder keys it with OUR static public key. wireguard-go checks it
     * on every handshake message before any DH; so do we now: one keyed
     * BLAKE2s (key cached by wg_handshake_init) instead of two X25519 for
     * junk aimed at our receiver index. */
    {
        wg_keyed_mac16(mac, st->mac1_key_self, (const uint8_t *)msg,
                       offsetof(struct wg_msg_response, mac1));
        uint8_t diff = 0;
        for (size_t i = 0; i < WG_MAC_LEN; i++) diff |= (uint8_t)(mac[i] ^ msg->mac1[i]);
        if (diff != 0) goto out_scrub;
    }

    /* Everything below runs on the copies ck / h. Until round 1.3.0 it
     * mixed straight into st->chain_key / st->hash BEFORE the AEAD tag
     * was checked, so one forged response carrying our receiver index
     * (visible in our INIT on the wire) corrupted the in-flight
     * handshake and the genuine response that followed failed — a
     * repeatable 5-s (REKEY_TIMEOUT) stall per attempt. */

    /* Ci = KDF1(Ci, E_pub_responder).
     * Hi = H(Hi || E_pub_responder). */
    wg_mix_chain_only(ck, msg->ephemeral, WG_KEY_LEN);
    wg_mix_hash(h, msg->ephemeral, WG_KEY_LEN);

    /* Ci = KDF1(Ci, DH(E_priv_initiator, E_pub_responder)). */
    if (curve25519_dh(dh_e_e, st->ephemeral_priv, msg->ephemeral) != 0) {
        goto out_scrub;
    }
    wg_mix_chain_only(ck, dh_e_e, WG_KEY_LEN);

    /* Ci = KDF1(Ci, DH(S_priv_initiator, E_pub_responder)). */
    if (curve25519_dh(dh_e_s, st->local_static_priv, msg->ephemeral) != 0) {
        goto out_scrub;
    }
    wg_mix_chain_only(ck, dh_e_s, WG_KEY_LEN);

    /* PSK mix: (Ci, Tau, K) = KDF3(Ci, PSK).
     *           Hi = H(Hi || Tau).
     * If no PSK was set, st->preshared_key is all zeros — Noise spec
     * still mandates the KDF3 step regardless. */
    {
        uint8_t new_ck[WG_HASH_LEN];
        noise_hkdf3(ck, st->preshared_key, WG_KEY_LEN,
                    new_ck, tau, key);
        memcpy(ck, new_ck, WG_HASH_LEN);
        tl_secure_zero(new_ck, sizeof(new_ck));
    }
    wg_mix_hash(h, tau, WG_HASH_LEN);

    /* AEAD-decrypt the empty payload. The on-wire ciphertext is just
     * the 16-byte tag; mlen = 0 after subtracting TAG_LEN. The tag
     * verification IS the handshake authentication. */
    if (chacha20poly1305_decrypt(plaintext_zero,
                                 msg->encrypted_nothing,
                                 sizeof(msg->encrypted_nothing),
                                 h, WG_HASH_LEN,
                                 key, nonce) != 0) {
        goto out_scrub;
    }

    /* Transport keys: (T_init→resp, T_resp→init) = KDF2(C_final, "").
     * From the initiator's perspective:
     *   send_key = T_init→resp = first slot
     *   recv_key = T_resp→init = second slot. The final
     * Hi = H(Hi || encrypted_nothing) is never used by an initiator (the
     * caller scrubs st once the keys are installed), so it is not mixed. */
    if (noise_hkdf2(ck, NULL, 0, send_key, recv_key) != 0) {
        goto out_scrub;
    }

    *out_remote_index = msg->sender_index;
    rc = 0;

out_scrub:
    tl_secure_zero(ck,              sizeof(ck));
    tl_secure_zero(h,               sizeof(h));
    tl_secure_zero(key,             sizeof(key));
    tl_secure_zero(dh_e_e,          sizeof(dh_e_e));
    tl_secure_zero(dh_e_s,          sizeof(dh_e_s));
    tl_secure_zero(tau,             sizeof(tau));
    memset(plaintext_zero,  0, sizeof(plaintext_zero));
    memset(nonce,           0, sizeof(nonce));
    if (rc != 0) {
        /* On failure, scrub any transport keys we may have partially
         * written so the caller doesn't leak them. */
        tl_secure_zero(send_key, WG_KEY_LEN);
        tl_secure_zero(recv_key, WG_KEY_LEN);
    }
    return rc;
}

void wg_handshake_scrub_live(struct wg_handshake_state *st)
{
    tl_secure_zero(st->chain_key,      sizeof(st->chain_key));
    tl_secure_zero(st->hash,           sizeof(st->hash));
    tl_secure_zero(st->ephemeral_priv, sizeof(st->ephemeral_priv));
    tl_secure_zero(st->ephemeral_pub,  sizeof(st->ephemeral_pub));
    st->local_index = 0;
    st->armed       = 0;
}

void wg_handshake_scrub(struct wg_handshake_state *st)
{
    tl_secure_zero(st, sizeof(*st));
}
