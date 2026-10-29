// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// One static buffer for every control-plane HTTP body (round 1.3.2, B15).
//
// Before: mapreq.c's 32 KiB MapResponse `body_buf` + a static 2 KiB
// stream request body, register.c's static 4 KiB response, and stack
// bodies in register_emit (2 KiB), mapreq_push_endpoints (1.25 KiB) and
// the TOFU fetch (0.7 KiB). They are never live at the same time, so
// they now share this one buffer:
//
//   * The control plane is driven by ONE task at a time. The main task
//     runs control_key_get (tinylink_init), the register loop and
//     tinylink_dataplane_start, strictly in that order, and only then
//     creates the long-poll task (tinylink_long_poll_start); after that
//     the main task never touches the control plane again (main.c
//     bringup). From then on only the long-poll task does: endpoint
//     push → map stream → (on rejection) re-register, sequentially. This
//     is the same invariant the unlocked `s_conn` in tinylink.c already
//     relies on.
//   * No user nests inside another: the stream's chunk callback runs
//     mapresp_parse and long_poll_handler (tinylink.c), which only touch
//     the data plane / telemetry — never register, push or /key.
//
// tl_ctrl_buf_claim() turns any future violation of that into a clean
// request failure (logged) instead of two users silently corrupting each
// other's bytes. Every user claims at its entry point and releases on its
// single exit (wrapper functions), so a claim can never leak.
//
// Layout. The map stream keeps its full 32 KiB MapResponse cap
// (observed peak 25 838 B) at offset 0 and sends its MapRequest from a
// separate tail region, because nghttp2 may still be reading the request
// body while response DATA is already being assembled:
//
//   [0, TL_CTRL_MAPRESP_CAP)          response bodies (MapResponse, register,
//                                     /key, push) — or register's request
//   [TL_CTRL_REQ_OFF, TL_CTRL_BUF_SZ) MapRequest bodies (stream + push), the
//                                     /key request

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TL_CTRL_MAPRESP_CAP 32768u   /* one assembled MapResponse, as before */
/* MapRequest bodies: the largest (Stream=true, 63-char hostname, NetInfo +
 * Endpoints) is < 640 B; this is the size the endpoint push always had. */
#define TL_CTRL_REQ_CAP     1024u
#define TL_CTRL_REQ_OFF     TL_CTRL_MAPRESP_CAP
#define TL_CTRL_BUF_SZ      (TL_CTRL_MAPRESP_CAP + TL_CTRL_REQ_CAP)

/* Take the buffer for `who` (a short static string for the log). Returns
 * the TL_CTRL_BUF_SZ-byte buffer, or NULL — with an error log naming both
 * users — if it is already claimed. Callable from any task. */
uint8_t *tl_ctrl_buf_claim(const char *who);

/* Give it back. Only the current owner may call this. */
void tl_ctrl_buf_release(void);

#ifdef __cplusplus
}
#endif
