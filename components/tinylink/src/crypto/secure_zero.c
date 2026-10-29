// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Target body of tl_secure_zero() — see secure_zero.h. In IRAM with the
// rest of the AEAD hot path (CONFIG_TINYLINK_CRYPTO_IN_IRAM).

#include "secure_zero.h"

#include "tl_hot.h"

TL_HOT_ATTR void tl_secure_zero(void *buf, size_t len)
{
    tl_secure_zero_inline(buf, len);
}
