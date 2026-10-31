// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)
//
// Boot STUN probe hand-off (round 1.3.5): who may read the WG socket,
// and whose result the endpoint push uses.
//
// Until 1.3.4 the boot probe ran on the main task between the socket
// bind and the register, all of it ahead of the register: got-ip →
// "public endpoint" took 0.04 / 0.34 / 2.10 / 7.09 s in four boots of
// the 1.3.4 reboot series (DNS + one round trip to the STUN server; the
// slow one lost answers). Only the endpoint push after the register
// needs the result, so the probe now runs on its own short-lived task
// while the register runs (tinylink.c, tinylink_stun_probe_start), and
// tinylink_dataplane_start waits for it briefly — then gives up on it.
//
// The probe reads the WG socket itself: wg_rx, the socket's only reader
// afterwards, is spawned by the first netmap on the long-poll task,
// which starts after tinylink_dataplane_start returns. Invariant: once
// the waiter has given up, the probe never reads the socket again and
// never publishes — otherwise the probe and wg_rx would both recvfrom
// and either could eat the other's datagram (the WG handshake response,
// the STUN answer), and a result published after the push would never
// be pushed (the re-probe only pushes a CHANGED endpoint). The probe
// blocks in select() holding nothing and reads with MSG_DONTWAIT inside
// the lock, so giving up never waits for a blocked read.
//
//   probe:  RESOLVING --claim--> ON_SOCKET --publish--> DONE
//                \                    \--finish (no answer)--> DONE
//                 \--finish (DNS failed)----------------------> DONE
//   waiter: RESOLVING / ON_SOCKET --give_up--> ABANDONED
//           (claim, may_read and publish then fail; finish reports it)
//
// Every call runs under the caller's lock (a mutex on the target: the
// probe's read happens inside it); the functions are pure so the host
// tests can walk every interleaving of the two sides.

#pragma once

#include <stdbool.h>

typedef enum {
    STUN_BOOT_IDLE = 0,     /* no boot probe task */
    STUN_BOOT_RESOLVING,    /* DNS in flight; the socket is untouched */
    STUN_BOOT_ON_SOCKET,    /* request sent; the probe reads the socket */
    STUN_BOOT_DONE,         /* finished: a result is published, or none will be */
    STUN_BOOT_ABANDONED,    /* the waiter left first: the probe stays off the socket */
} stun_boot_state_t;

/* Probe, after its DNS lookup: may it send and start reading?
 * RESOLVING → ON_SOCKET; false once abandoned. */
static inline bool stun_boot_claim(stun_boot_state_t *s)
{
    if (*s != STUN_BOOT_RESOLVING) return false;
    *s = STUN_BOOT_ON_SOCKET;
    return true;
}

/* Probe, around every (non-blocking) read: still the socket's reader? */
static inline bool stun_boot_may_read(const stun_boot_state_t *s)
{
    return *s == STUN_BOOT_ON_SOCKET;
}

/* Probe, holding a matching answer: may it publish the result?
 * ON_SOCKET → DONE; false once abandoned (the answer is dropped). */
static inline bool stun_boot_publish(stun_boot_state_t *s)
{
    if (*s != STUN_BOOT_ON_SOCKET) return false;
    *s = STUN_BOOT_DONE;
    return true;
}

/* Probe, last step: it is off the socket for good. Returns whether the
 * waiter still takes the completion signal — false after an abandon,
 * when nobody ever waits for it again (the probe then frees it). */
static inline bool stun_boot_finish(stun_boot_state_t *s)
{
    if (*s == STUN_BOOT_ABANDONED) return false;
    *s = STUN_BOOT_DONE;
    return true;
}

/* Waiter, when its bounded wait ran out. Returns true when the probe has
 * already finished (DONE: its result, if any, is published and the
 * completion signal is on its way — take it). Otherwise the probe is
 * abandoned: it will not read the socket or publish from now on. */
static inline bool stun_boot_give_up(stun_boot_state_t *s)
{
    if (*s == STUN_BOOT_DONE) return true;
    *s = STUN_BOOT_ABANDONED;
    return false;
}
