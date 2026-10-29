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
//     the MapResponse parser and long_poll_handler (tinylink.c), which
//     only touch the data plane / telemetry — never register, push or
//     /key.
//
// tl_ctrl_buf_claim() turns any future violation of that into a clean
// request failure (logged) instead of two users silently corrupting each
// other's bytes. Every user claims at its entry point and releases on its
// single exit (wrapper functions), so a claim can never leak.
//
// Layout. The map stream collects MapResponse elements at offset 0 and
// sends its MapRequest from a separate tail region, because nghttp2 may
// still be reading the request body while response DATA is already
// being parsed:
//
//   [0, TL_CTRL_MAPRESP_CAP)          the MapResponse element being parsed;
//                                     response bodies (register, /key, push)
//                                     — or register's request
//   [TL_CTRL_REQ_OFF, TL_CTRL_BUF_SZ) MapRequest bodies (stream + push), the
//                                     /key request
//
// MapResponse area, round 1.3.4 (D2): 32 → 8 KiB. Until 1.3.3 each
// long-poll frame was assembled whole here (initial netmap 25 972 B at
// most over every 1.3.x capture). The stream now splits a frame as it
// arrives (mapreq.c) and only ever holds ONE element: the self Node, one
// peer, one DERP region, one PeersChangedPatch / PeersRemoved entry. The
// largest the sensor has logged is a 179-token element in the initial
// netmap (`mapresp peak: tokens=179/640`, every boot since 1.3.0; the
// log has no byte size). Its delta frames run 11–13 B per token (55
// tokens in 722 B): ≈ 2.3 KB; test_mapresp.c's real-shaped initial
// netmap (25.5 KB) puts the 179 tokens in a CapMap-heavy self node of
// 3 154 B (17.6 B per token); even 30 B per token would be 5.4 KB. So
// 8 KiB is ≥ 2.6× the fixture and 1.5× that pessimistic bound — and
// about what the 640-token table holds at 12.5 B per token, so neither
// limit sits far below the other. A larger element is skipped with an
// error log (mapreq.c ms_element); `stream peak: … elem=` reports the
// largest one per frame. The register response (4 KiB behind its 2 KiB
// request) and the /key response (4 KiB) still fit.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TL_CTRL_MAPRESP_CAP 8192u    /* one MapResponse element (D2, see above) */
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
