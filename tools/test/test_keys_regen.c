/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Bryam (bryamzxz)
 *
 * Host KAT for keys_regen.h — the identity-regeneration policy used by
 * keys.c on boot. The invariant under test (the bug this guards against):
 * machine and node form a 1:1 unit for headscale's NodeKey<->MachineKey
 * binding, so if EITHER is absent/corrupt BOTH must regenerate — never a
 * fresh/stale mix. The disco key is independent. We exhaustively cover all
 * 2^3 (machine_ok, node_ok, disco_ok) input combinations.
 */

#include <stdio.h>

#include "keys_regen.h"

static int fails = 0;

static int ok(const char *name, int condition) {
    if (condition) { printf("[%s] OK\n", name); return 0; }
    printf("[%s] FAIL\n", name);
    return 1;
}

static int check(const char *name, bool m_ok, bool n_ok, bool d_ok,
                 bool exp_m, bool exp_n, bool exp_d) {
    keys_regen_plan_t p = keys_plan_regen(m_ok, n_ok, d_ok);
    return ok(name, p.machine == exp_m && p.node == exp_n && p.disco == exp_d);
}

int main(void) {
    /*           name                     m_ok   n_ok   d_ok    regen: m,     n,     d   */
    /* All present: regenerate nothing. */
    fails += check("all-ok",              true,  true,  true,   false, false, false);
    /* First boot (all absent): regenerate all three. */
    fails += check("all-absent",          false, false, false,  true,  true,  true);

    /* THE BUG CLASS — partial loss of the identity unit must regen BOTH
     * machine and node, regardless of which one survived, and must NOT
     * leave a fresh/stale mix. */
    fails += check("machine-gone",        false, true,  true,   true,  true,  false);
    fails += check("node-gone",           true,  false, true,   true,  true,  false);
    fails += check("machine+node-gone",   false, false, true,   true,  true,  false);

    /* Disco is independent of the machine/node binding. */
    fails += check("disco-gone-only",     true,  true,  false,  false, false, true);
    fails += check("machine+disco-gone",  false, true,  false,  true,  true,  true);
    fails += check("all-but-node",        true,  false, false,  true,  true,  true);

    if (fails == 0) { printf("\n[PASS] all keys_regen assertions passed\n"); return 0; }
    printf("\n[FAIL] %d keys_regen assertion(s) failed\n", fails);
    return 1;
}
