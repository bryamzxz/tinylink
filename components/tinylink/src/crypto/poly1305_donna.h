// SPDX-License-Identifier: MIT
//
// tinylink note: lifted verbatim from
// https://github.com/floodyberry/poly1305-donna (Andrew Moon).
// The upstream license is "public domain or MIT"; we declare MIT
// here for SPDX clarity. Used by libsodium and other widely-audited
// projects. Validated by host KAT against RFC 8439 §2.5.2.

#ifndef TINYLINK_POLY1305_DONNA_H_
#define TINYLINK_POLY1305_DONNA_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

typedef struct poly1305_context {
    size_t aligner;
    unsigned char opaque[136];
} poly1305_context;

void poly1305_init(poly1305_context *ctx, const unsigned char key[32]);
void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes);
void poly1305_finish(poly1305_context *ctx, unsigned char mac[16]);

#ifdef __cplusplus
}
#endif

#endif /* TINYLINK_POLY1305_DONNA_H_ */
