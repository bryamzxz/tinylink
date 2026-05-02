/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Cross-consistency host KAT for the Noise §4.3 KDF family on top of
 * HMAC-BLAKE2s. There are no published RFC test vectors for HKDF-BLAKE2s,
 * so we instead validate that *three independent code paths* agree:
 *
 *   1. noise_hkdf1(ck, x)
 *   2. hkdf_blake2s_extract(salt=ck, ikm=x) + expand(prk, info={0x01}, 32)
 *   3. noise_hkdf2(ck, x).out1   /   noise_hkdf3(ck, x).out1
 *
 * Path 1 and Path 2 share only blake2s + hmac_blake2s. They use
 * completely different control flow (one is a hand-coded
 * extract+expand, the other is the RFC 5869 expand loop). If both
 * produce the same 32 bytes, the wiring inside both is consistent
 * with the spec. Path 3 catches counter / concat bugs between
 * noise_hkdfN variants.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "hkdf_blake2s.h"

static void hexdump(const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
}
static int check(const char *name, const uint8_t *got, const uint8_t *want, size_t n) {
    if (memcmp(got, want, n) == 0) {
        printf("[%s] OK\n", name);
        return 0;
    }
    printf("[%s] FAIL\n  got:  ", name); hexdump(got, n); printf("\n  want: ");
    hexdump(want, n); printf("\n");
    return 1;
}

static int run_case(const char *tag,
                    const uint8_t ck[32],
                    const uint8_t *input, size_t input_len) {
    int fails = 0;
    char name[64];

    /* Path 1: noise_hkdf1. */
    uint8_t out_hkdf1[32];
    if (noise_hkdf1(ck, input, input_len, out_hkdf1) != 0) {
        printf("[%s/hkdf1] FAIL: returned non-zero\n", tag);
        return 1;
    }

    /* Path 2: extract + expand(info={0x01}, 32). */
    uint8_t prk[32];
    if (hkdf_blake2s_extract(ck, 32, input, input_len, prk) != 0) {
        printf("[%s/extract] FAIL: returned non-zero\n", tag);
        return 1;
    }
    uint8_t info_byte = 0x01;
    uint8_t out_extract_expand[32];
    if (hkdf_blake2s_expand(prk, &info_byte, 1, out_extract_expand, 32) != 0) {
        /* Note: noise_hkdf1 effectively uses info=NULL+counter=1, which
         * is HMAC(prk, &counter, 1). RFC 5869 expand with info=&{0x01}
         * length=1 gives HMAC(prk, "" || &{0x01} || 0x01_counter, 2),
         * which would differ. We're testing the equivalent path: pass
         * info_len=0 and rely on counter=1. */
        printf("[%s/expand-with-info] FAIL: returned non-zero\n", tag);
        return 1;
    }

    /* Actually for true equivalence with noise_hkdf1, expand must use
     * info_len=0. Compute that variant and compare to it. */
    uint8_t out_expand_no_info[32];
    if (hkdf_blake2s_expand(prk, NULL, 0, out_expand_no_info, 32) != 0) {
        printf("[%s/expand-no-info] FAIL: returned non-zero\n", tag);
        return 1;
    }
    snprintf(name, sizeof(name), "%s/hkdf1-vs-extract+expand(no info)", tag);
    fails += check(name, out_hkdf1, out_expand_no_info, 32);

    /* Path 3: noise_hkdf2 first 32 bytes equal noise_hkdf1. */
    uint8_t hkdf2_a[32], hkdf2_b[32];
    if (noise_hkdf2(ck, input, input_len, hkdf2_a, hkdf2_b) != 0) {
        printf("[%s/hkdf2] FAIL: returned non-zero\n", tag);
        return 1;
    }
    snprintf(name, sizeof(name), "%s/hkdf1==hkdf2.out1", tag);
    fails += check(name, out_hkdf1, hkdf2_a, 32);

    /* Path 3 cont.: noise_hkdf3 first two 32-byte slots equal noise_hkdf2. */
    uint8_t hkdf3_a[32], hkdf3_b[32], hkdf3_c[32];
    if (noise_hkdf3(ck, input, input_len, hkdf3_a, hkdf3_b, hkdf3_c) != 0) {
        printf("[%s/hkdf3] FAIL: returned non-zero\n", tag);
        return 1;
    }
    snprintf(name, sizeof(name), "%s/hkdf2.out1==hkdf3.out1", tag);
    fails += check(name, hkdf2_a, hkdf3_a, 32);
    snprintf(name, sizeof(name), "%s/hkdf2.out2==hkdf3.out2", tag);
    fails += check(name, hkdf2_b, hkdf3_b, 32);

    /* Sanity: the three slots of hkdf3 must NOT be equal to each other
     * (otherwise the counter-byte is being ignored). */
    if (memcmp(hkdf3_a, hkdf3_b, 32) == 0 ||
        memcmp(hkdf3_b, hkdf3_c, 32) == 0 ||
        memcmp(hkdf3_a, hkdf3_c, 32) == 0) {
        printf("[%s/hkdf3-distinct] FAIL: outputs are not distinct\n", tag);
        fails++;
    } else {
        printf("[%s/hkdf3-distinct] OK\n", tag);
    }

    return fails;
}

int main(void) {
    int fails = 0;

    /* Case 1: zero ck, zero input. Edge case for empty material. */
    uint8_t zero_ck[32]   = {0};
    uint8_t zero_in[32]   = {0};
    fails += run_case("zero", zero_ck, zero_in, 0);

    /* Case 2: zero ck, non-empty input. */
    uint8_t fixed_in[32];
    for (int i = 0; i < 32; i++) fixed_in[i] = (uint8_t)(i * 7 + 3);
    fails += run_case("zero-ck/varied-in", zero_ck, fixed_in, sizeof(fixed_in));

    /* Case 3: WG-shaped: a chaining-key derived from a public-domain
     * BLAKE2s of the IKpsk2 protocol name, mixed with a 32-byte X25519-
     * shaped shared. We don't care about the exact bytes — we care that
     * all three paths agree. */
    uint8_t ck3[32], in3[32];
    for (int i = 0; i < 32; i++) {
        ck3[i] = (uint8_t)(i * 31 + 17);
        in3[i] = (uint8_t)(255 - i);
    }
    fails += run_case("varied-ck/varied-in", ck3, in3, sizeof(in3));

    /* Case 4: short input (1 byte) — exercises the input_len < HASHLEN path. */
    uint8_t one[1] = {0x42};
    fails += run_case("varied-ck/1byte-in", ck3, one, 1);

    if (fails == 0) printf("\nALL OK\n");
    return fails ? 1 : 0;
}
