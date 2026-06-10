// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Bryam (bryamzxz)

#pragma once

#include <stdbool.h>

/* Pure identity-regeneration policy for keys.c, factored out so it can be
 * host-tested without an NVS mock (see tools/test/test_keys_regen.c).
 *
 * headscale main enforces a 1:1 NodeKey<->MachineKey binding on BOTH
 * registration and re-auth (upstream commits eb57a3a6 + 4914f9f2). So the
 * machine and node keys form ONE identity unit: if either is missing or
 * corrupt in NVS after a partial loss, BOTH must be regenerated together —
 * never a fresh-node/stale-machine (or vice-versa) mix, which the server
 * would reject permanently. The disco key is not part of that binding and
 * is regenerated independently. */
typedef struct {
    bool machine;   /* regenerate + persist the machine keypair */
    bool node;      /* regenerate + persist the node keypair    */
    bool disco;     /* regenerate + persist the disco keypair   */
} keys_regen_plan_t;

/* Given whether each key loaded cleanly from NVS, decide what to (re)generate.
 * machine_ok/node_ok/disco_ok are false when the key is absent OR corrupt. */
static inline keys_regen_plan_t keys_plan_regen(bool machine_ok,
                                                bool node_ok,
                                                bool disco_ok)
{
    bool identity_broken = !machine_ok || !node_ok;
    keys_regen_plan_t p;
    p.machine = identity_broken;
    p.node    = identity_broken;
    p.disco   = !disco_ok;
    return p;
}
