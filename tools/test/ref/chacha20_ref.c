// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// The 1.3.2 ChaCha20 (chacha20_132.c) under ref_* names, so a test can
// link it next to the current crypto/chacha20.c. Same struct
// chacha20_ctx (a different token, not renamed).

#define chacha20      ref_chacha20
#define chacha20_init ref_chacha20_init
#define hchacha20     ref_hchacha20
#include "chacha20_132.c"
