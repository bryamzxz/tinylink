// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// DISCO replay window. NaCl box (XSalsa20-Poly1305) is a stateless AEAD —
// `nacl_box_open(peer_pub, my_priv, nonce, ct)` is deterministic, so an
// attacker who passively captures one DISCO PING/PONG can replay it from
// a spoofed/owned source AddrPort and trigger handle_disco_direct's roam
// path again. Replay protection therefore must live above the AEAD.
//
// Window of last N nonces seen on inbound DISCO frames (post-decrypt-
// success). A replay matches the recorded nonce → caller drops it before
// any side-effect. Single-peer scope: dedup on nonce alone — the roam_-
// allowed gate already filters out frames sealed by a different DiscoKey.
//
// Pure C, no FreeRTOS / lwIP / esp_* dependencies — host-testable.

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "disco.h"   /* DISCO_NONCE_LEN */

#ifdef __cplusplus
extern "C" {
#endif

/* 128 entries × 24 bytes ≈ 3 KiB BSS. Covers >2 minutes of typical
 * Tailscale DISCO cadence (1 frame per 5-30 s during path discovery). */
#ifndef DISCO_REPLAY_WINDOW_SIZE
#define DISCO_REPLAY_WINDOW_SIZE 128
#endif

/* True if the (peer-side-generated) nonce has been recorded in the
 * window already — caller must drop the frame. False otherwise; in that
 * case the nonce is recorded so the next replay matches. */
bool disco_replay_check_and_record(const uint8_t nonce[DISCO_NONCE_LEN]);

/* Wipe the window. Used by tests; the production code never needs this
 * because the static state is zero-initialised at boot. */
void disco_replay_reset(void);

#ifdef __cplusplus
}
#endif
