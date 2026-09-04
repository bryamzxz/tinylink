# Security model

This document captures the threat model and the rationale behind the
cryptographic choices that the README and `PROTOCOL.md` summarize.

## Adversary

We assume an attacker who:

- Controls the local WiFi network (passive sniffing, active MITM, DHCP
  spoofing, ARP poisoning).
- Can reach `controlplane.tailscale.com` from the same internet path the
  device uses.
- Cannot mount physical attacks beyond casual inspection: no decapping,
  no laser fault injection, no nanoprobing. Side channels at the level
  of electromagnetic emissions are out of scope.
- May know that a tinylink device exists at a given IP.

We **do not** defend against:

- Physical attackers with persistent access to the board (e.g. an attacker
  who can clip onto the I²C lines, read flash with a programmer, or burn
  fresh eFuses). On the current build the bar is even lower than the
  encrypted-NVS scenario implies: flash encryption is **not** enabled
  (`CONFIG_SECURE_FLASH_ENC_ENABLED` / `CONFIG_FLASH_ENCRYPTION_ENABLED`
  unset in `sdkconfig`), so the NVS partition holding the Curve25519
  private keys is plaintext on flash — a single `esptool.py read_flash`
  recovers every identity without touching eFuses. See the **at-rest key
  storage** note under "Long-term keys": closing this gap is on the
  hardening roadmap, not done.
- Compromise of `controlplane.tailscale.com` itself.

## Long-term keys

| Key             | Purpose                       | Storage                        |
|-----------------|-------------------------------|--------------------------------|
| MachineKey      | Noise IK static (ts2021)      | NVS `tl_keys/machine` (32 B)   |
| NodeKey         | WireGuard static (M2+)        | NVS `tl_keys/node` (32 B)      |
| DiscoKey        | NaCl-box (DISCO, M3+)         | NVS `tl_keys/disco` (32 B)     |
| NLKey           | TKA / network-lock signing    | currently sent as 32 zero bytes (`"nlpub:" + 64 zeros`) — TKA is disabled in M1 and the server tolerates a zero NLKey. M7 hardening swaps in real Ed25519 NLPrivate generation and NVS persistence. |
| Tailscale auth key (`tskey-auth-…`) | one-time register | NVS `tl_creds/auth_key` (str)  |
| WiFi PSK        | local network association     | NVS `tl_creds/wifi_pass` (str) |
| Pinned control plane pub | TOFU pin               | NVS `tl_pin/control_pub` (32 B)|

**At-rest key storage — NOT currently encrypted.** The keys are read and
written through the plain default NVS partition (`keys.c` calls
`nvs_open("tl_keys", …)` against the default `nvs` partition; the
`nvs_creds` slot in `partitions.csv` only ever holds provisioner-written
credentials, and its `encrypted` flag is inert without flash
encryption). NVS encryption is off: `sdkconfig.defaults` used to carry
`CONFIG_NVS_ENCRYPTION=y`, but on the ESP32 that option depends on
`CONFIG_SECURE_FLASH_ENC_ENABLED`, which is unset, so Kconfig dropped it
silently — the line was removed 2026-09 and the state documented. Net
effect: the
Curve25519 MachineKey / NodeKey / DiscoKey private blobs sit in flash in
the clear. Enabling eFuse-backed flash encryption + a real encrypted-NVS
partition is **explicitly declined** (owner decision 2026-07-16,
reaffirming the M7 out-of-scope call: eFuse burns are irreversible and
recovery would depend on a control plane the project does not operate)
— do not assume at-rest confidentiality, now or in future releases.

The Curve25519 identities are generated on first boot using
`esp_fill_random()` (RF-derived entropy) and never leave the chip over
the wire. As of the identity-regen hardening (`keys.c`
`keys_load_or_generate`), the MachineKey and NodeKey are regenerated
**atomically as a unit** if either is absent or corrupt — matching
headscale's 1:1 NodeKey↔MachineKey binding — while the DiscoKey
regenerates independently. A hard NVS fault is propagated, never papered
over by silently minting a fresh identity over a recoverable one.

The Tailscale auth key is **single-use by convention** — once
`MachineAuthorized=true` returns, the auth key has done its job and
should be revoked from the admin panel. Because the device persists its
NodeKey, future re-registrations would require a new auth key flashed
into NVS.

## X25519 — constant-time donna (landed in PR #61)

`components/tinylink/src/crypto/curve25519.c` is now a thin shim over
`agl/curve25519-donna` (BSD-3, Google, see `curve25519_donna.c`). Donna
is the canonical constant-time 32-bit X25519 implementation. The
MachineKey and NodeKey private keys are exercised on every Noise IK
handshake and every WG `handshake_init` (DH e/s, s/s); under donna the
scalar multiplication has data-independent timing in both the ladder
and the limb arithmetic, eliminating the timing-channel that the
previous TweetNaCl-derived reference left open.

API unchanged: `curve25519_scalarmult`, `curve25519_keypair`,
`curve25519_dh`, `curve25519_derive_pub` all behave identically modulo
internal timing. RFC 7748 §5.2 (two single-scalarmult vectors) + §6.1
(DH round-trip Alice↔Bob) are verified in
`tools/test/test_curve25519.c`; the full host KAT battery stays
green (452 OK / 0 FAIL).

### Why donna, not mbedTLS

The same argument applies even more strongly to mbedTLS's curve25519
path: it has not historically been written with the same constant-time
discipline as donna, and on ESP32 the HW assistance is weaker than the
generic "mbedTLS uses HW MPI" narrative suggests. IDF source review
(v5.5.4):

- `port/mbedtls/esp_config.h` defines `MBEDTLS_MPI_MUL_MPI_ALT` only —
  there are **no** `_MXZ_ALT` hooks for the Montgomery-curve operations
  (NORMALIZE_MXZ_ALT / DOUBLE_ADD_MXZ_ALT / RANDOMIZE_MXZ_ALT), so the
  curve25519 ladder runs in pure SW with HW assist only on individual
  modular multiplications.
- `port/include/bignum_impl.h:8-14`: ESP32 sets `ESP_MPI_USE_MONT_EXP`
  and uses SW Montgomery exponentiation because IDF documents the
  ESP32 RSA peripheral as "slow for public key operations". So `exp_mod`
  doesn't even hit hardware on ESP32.

Net: mbedTLS X25519 on ESP32 would not be measurably faster than donna
pure-C, and would cost `MBEDTLS_ECP_C` + `MBEDTLS_ECDH_C` flash + a
non-constant-time risk profile. ChaCha20-Poly1305 stays on the
in-tree vendored implementations because the ESP32's hardware AES
accelerator is irrelevant to ChaCha and the implementations are
already constant-time. BLAKE2s is small enough that vendoring is
cheaper than dragging in another dependency.

## What we explicitly do not enforce on-device

- **ACLs / packet filter from MapResponse.** The device assumes the
  upstream peer or the broader Tailscale ACL system enforces who is
  allowed to connect to it. This matches MicroLink's posture and avoids
  shipping a filter engine on a 4 MiB-flash device.
- **MagicDNS resolution.** We use raw `100.x.y.z` peer IPs.
- **Tailnet Lock.** tinylink does not verify the tailnet-lock signature
  on `NodeKey` updates. If you need this, do not use tinylink.
- **TLS certificate validity windows.** Since M16 (2026-09-04)
  `MBEDTLS_HAVE_TIME_DATE=y` and `tl_time.c` floors the clock at boot
  and runs SNTP: `notBefore`/`notAfter` are enforced on every handshake
  after the first NTP sync, and tolerated before it (the first seconds
  of a connected boot; the whole session of an offline one). During
  that window the pinned control key + chain signatures are the trust
  anchors, as they were for every handshake before M16.
- **NVS private keys are plaintext at rest.** See "Long-term keys":
  flash encryption is off, so the Curve25519 identities are recoverable
  from a raw flash dump. Accepted permanently by owner decision
  (2026-07-16) — irreversible eFuse burns paired with recovery that
  depends on a third-party control plane are a worse failure mode than
  the (out-of-scope) physical-access risk they mitigate.
- ~~**No general task-WDT coverage for application tasks.**~~ *Closed in
  M15 (2026-09-04)*: every application task subscribes (`tl_wdt.h`),
  `CONFIG_ESP_TASK_WDT_PANIC=y`, 90-s budget. What remains is the
  multi-hour validation soak. Historical note kept below for context:
  before M15 the task WDT only subscribed the two idle tasks.
  *Narrowed in the 2026-07 round:* the control path now has a dedicated
  self-recovery ladder (bounded stream silence → reconnect → in-place
  re-register → `esp_restart` after
  `CONFIG_TINYLINK_CONTROL_WEDGE_RESTART_S` of total control silence,
  plus restart-on-failed-bringup), so a control-plane wedge is no longer
  a brick. A wedge confined to a *data-plane* task still bricks that
  function until the control-path watchdog happens to reboot the device
  (only if the wedge also starves the control stream) or a physical
  power-cycle.

## Audit + optimization round (2026-09) — memory safety + upstream drift

Fourth audit round; details per item in `CHANGELOG.md`, threat-model
view here.

- **Stack overflow in the endpoint-push task (memory safety, HIGH).**
  `tinylink_ep_up` ran `ts2021_connect` + the TLS handshake from a
  12 KiB static stack that the call chain (stack-local `ts2021_conn_t`
  8 648 B + 9 888 B + 4 176 B + ~5 KiB mbedTLS) exceeds by ~16 KiB; every
  real push wrote into the BSS below the stack (DERP frame buffer,
  FreeRTOS ready lists, WiFi driver tables). Not attacker-triggerable
  on its own — it fires on NAT rebind / WiFi re-association /
  re-register — but a network-positioned attacker can provoke all three
  (drop the NAT flow, deauth, delete/expire the node). Fixed by removing
  the task: the push runs on the long-poll task after a cooperative
  stream recycle. Verified from the compiled `entry` frame sizes.
- **Use-after-free in the DERP client teardown.** `derp_client_close`
  freed the TLS context and deleted the write mutex while the wg_tx
  relay could be inside a write or blocked on the mutex. The mutex is
  now per-client and permanent, teardown takes it, and both writers
  re-validate under it. TLS renegotiation is disabled so `ssl_read` on
  the reader task can never write on the shared SSL context.
- **Control-plane compatibility.** headscale now gates `/key` on its
  `MinSupportedCapabilityVersion` (115); the bootstrap sends
  `TINYLINK_CAPVER`. The floor tracks the ten latest minor releases, so
  138 has a shelf life of roughly four headscale releases — a tracked
  dependency, not a vulnerability.
- **Noise state scrub.** `ts2021_close` now `tl_secure_zero`s the
  Noise IK state (machine-key copy, ephemeral key, transport keys) —
  the last secret struct left out of the 2026-06 sweep.
- **Constant-time posture of the AEAD fast paths.** The new
  ChaCha20/Poly1305 aligned-vs-unaligned dispatch branches on buffer
  *addresses* (loop-invariant, set by the caller's buffer layout),
  never on key or message bytes; the round loop has a fixed trip count.
  The host suite runs under UBSan's alignment check so the aligned
  branch can never be reached with an unaligned pointer.
- **TSMP.** Peer-sent `TSMPDiscoKeyAdvertisement` packets (capver 144)
  are dropped before lwIP rather than answered with ICMP — one fewer
  reflected packet per handshake, no parsing of a new in-tunnel format.
- **Provisioning.** NVS is confirmed plaintext (the inert
  `CONFIG_NVS_ENCRYPTION=y` was removed so nobody believes otherwise);
  the credential lookup order is documented in `docs/PROVISIONING.md`.
- **Poly1305 block loop made constant-time (M16 ISA pass).** The Xtensa
  ISA manual's preferred 64-bit-add idiom is a branch (`bgeu`), and GCC
  used it 24 times per Poly1305 block — data-dependent branches on the
  MAC accumulator that the M7-6 / PR #86 review had only caught in
  `poly1305_finish`. The accumulation is now radix-2^26 split with
  32-bit-only arithmetic: 2 branches per block, both loop control.
  Rotates/funnel shifts use explicit `ssai`/`src`; neither depends on
  data. Re-verified from the disassembly of the release objects.
- **Part 2 (M15), same day.** Application tasks are under the task WDT
  (90 s, panic → reboot) — closes the "wedge in a data-plane task
  bricks its function" gap below for good, pending the multi-hour
  soak. The MapResponse is parsed one value at a time, so an oversized
  or adversarially large element is skipped rather than failing the
  map (and the 40 KiB token table is 10 KiB). The NaCl box now has
  independent libsodium vectors; the TAI64N floor has host coverage.
  CapVer 142 claims only client-side node attributes tinylink ignores.
  TLS is compiled client-only.

## Reconnect-hardening round (2026-07) — control-path availability

Four fixes, driven by the observed production failure "node stops
reconnecting after a control-plane change" and a fresh two-sided
upstream audit (zero wire drift; capver 138 still valid — headscale
floor unchanged at 113, upstream current 142). This round is an
**availability** hardening: none of it changes the confidentiality /
integrity posture, all of it removes ways the device can silently fall
off the tailnet. Commit detail in `CHANGELOG.md`. **HW smoke pending**
(no device attached when the round landed).

- **Bounded stream silence.** All blocking control/DERP TLS I/O now
  carries an idle budget (`CONFIG_TINYLINK_STREAM_IDLE_TIMEOUT_S`,
  default 120 s, mirroring upstream `watchdogTimeout`): a half-open TCP
  connection — control instance replaced without FIN/RST, NAT flow
  expired, or an adversary black-holing the flow — can park the
  long-poll / DERP supervisor for at most one budget window instead of
  forever. Availability note: an *active* MITM able to drop packets
  could always deny control-plane service; the change removes the
  amplification where one dropped flow denied it permanently.
- **`PeersChangedPatch` identity refetch.** A patch rotating the peer's
  `NodeKey`/`DiscoKey` forces a full-netmap refetch instead of being
  silently ignored — the data plane no longer keeps handshaking against
  dead peer keys for hours. (Trust in the patch content itself is
  unchanged: it arrives over the Noise-authenticated control channel,
  and tinylink acts on it only by refetching from the same channel.)
- **In-place re-register on persistent map 4xx.** Server-side
  node-state loss (node deleted, control DB migrated) self-heals with
  the NVS authkey instead of requiring a power-cycle. The authkey was
  already the boot-time trust anchor; this reuses the identical code
  path at runtime, introducing no new credential exposure.
- **Wedge `esp_restart` last resort.** One hour
  (`CONFIG_TINYLINK_CONTROL_WEDGE_RESTART_S`) of *zero* control-plane
  bytes → diagnostic dump + reboot into the known-good boot path; a
  failed bringup likewise retries via reboot after 60 s. TAI64N floor
  persistence (2026-05) is what makes surprise reboots safe against WG
  handshake-replay rejection, so the two mechanisms compose.

## Audit-fix round (2026-06) — control + transport posture

Six fixes from the 2026-06 cluster, all hardware-validated against the
live `tailscale.com` control plane. Each is summarized here for the
threat-model record; the commit-level detail lives in `CHANGELOG.md`.

- **Control-channel capability floor.** The ts2021 Noise handshake now
  advertises `TINYLINK_CAPVER = 138` (= Tailscale v1.98) as the single
  source of truth (`components/tinylink/include/tinylink.h`). It is mixed
  into the Noise prologue (`ts2021_client.c`: `"Tailscale Control
  Protocol v138"`, was hardcoded `1`) and into `RegisterRequest.Version`
  / `MapRequest.Version`. 138 clears headscale's
  `MinSupportedCapabilityVersion` earlyNoise floor (113 at the time,
  115 as of 2026-09 — it moves with every release, so the bump is a
  tracked dependency), so the device is no longer silently rejected by
  a current headscale. Since M14 the `/key?v=` TLS-bootstrap fetch in
  `control_key.c` sends the same macro (headscale gates `/key` on the
  same floor). Changing the macro re-hashes the prologue, so a bump
  requires a hardware A/B smoke against the live control plane.
- **EarlyNoise payload drained, not trusted.** `consume_early_payload`
  (`ts2021_client.c`) now reads the 9-byte EarlyNoise header
  (`magic[5] || BE32 len || JSON`) as a byte **stream** spanning Noise
  records — the control plane flushes the 5-byte magic as its own
  record, so the prior record-aligned reader desynced the HTTP/2 stream.
  The EarlyNoise JSON (which carries the `NodeKeyChallenge`) is length-
  checked and then **drained and discarded**: tinylink does not act on
  the challenge, it only consumes the bytes so the HTTP/2 residual lines
  up. The challenge is a server-anti-replay hint, not a client secret,
  so discarding it costs nothing.
- **WGN-1 transport-key race — FULLY closed.** PR #105 had wrapped only
  the session-init *writer* (the recv-key swap) under `g.lock`. The rx
  *reader* path is now also locked: `handle_transport` (`wg_netif.c`)
  takes `g.lock` around `wg_transport_decrypt`, which does a non-atomic
  read-modify-write of the replay-window bitmap and reads
  `g.transport.recv_key`. `handle_transport` is reachable from two
  unpinned tasks (`wg_rx` and `tinylink_derp`), so without the lock a
  concurrent session swap could let two decrypts race the same
  `(recv_key, replay-window)` state — the classic `(key, nonce)`-reuse /
  replay-window corruption. With both the writer lock (#105) and this
  reader lock, the WGN-1 window is closed; the rx path is **no longer
  unlocked**.
- **Relayed-DISCO sender gate (`knownPeerDiscoKey`).**
  `handle_disco_relayed` (`tinylink.c`) now drops a DERP-relayed
  `PING` / `PONG` / `CallMeMaybe` whose decrypted sender `DiscoKey` does
  not match the active WG peer's, via the new
  `wg_netif_get_peer_disco_pub` accessor. This mirrors the direct-UDP
  path's existing gate. `disco_open` only proves the frame was sealed
  *to* us — any tailnet node can do that — so before this gate an
  attacker-sealed `CallMeMaybe` could make the device fire a UDP ping
  flood at attacker-chosen endpoints. The gate is permissive only during
  early bringup, before any peer DiscoKey is known (same as the direct
  path). Relayed *WireGuard* traffic falls through to
  `wg_netif_inject_packet`, which gates separately by source NodeKey.
- **Adversarial-MapResponse depth bound.** `jsmn_skip` (`jsmn_skip.h`)
  is now depth-bounded at `JSMN_SKIP_MAX_DEPTH = 64`: a malicious
  control plane (or MITM past the Noise layer) can no longer hand the
  long-poll task a pathologically nested JSON object that recurses the
  skip walk deep enough to overflow that task's stack. Legitimate
  netmaps are nowhere near 64 levels deep, so well-formed responses are
  unaffected.

## Verification status

Done (host KATs in `tools/test`, run in CI plain and under ASan/UBSan):
RFC 7693 BLAKE2s, RFC 7748 X25519, RFC 8439 ChaCha20 / Poly1305 /
AEAD, the WireGuard handshake transcript, DISCO / STUN / DERP codecs.

Still open:

- The ts2021 Noise IK transcript (`noise_ik.c`) end-to-end on the host —
  today it is validated only by the live control plane accepting the
  handshake.
- Cross-check `TS2021_VERIFY` markers in
  `components/tinylink/src/ts2021_client.c` against the live Tailscale
  control plane source (see `PROTOCOL.md` for the exact files).

## Cross-cutting security warnings

Distilled from the protocol research artifact §L.

- **Validate peer public keys.** RFC 7748 §5 lists low-order points that,
  if accepted, leak your private key. The `curve25519_scalarmult` call
  rejects all-zero outputs in constant time; do not bypass that check.
- **Nonce uniqueness across two AEAD contexts.** ts2021 (LE64 counter)
  and DISCO (24-byte random) have different nonce schemes. Force a
  rekey on every boot by zeroing all transport keys at startup; never
  reuse a counter across reboots.
- **Secret-key scrubbing — sweep COMPLETE.** Every site that holds
  secret key material now zeroes it with `tl_secure_zero` (a
  `volatile`-pointer scrub the optimizer cannot elide), not plain
  `memset`. This covers the WG session keys (`wg_netif.c`), the WG
  handshake DH / chaining / tau / derived keys and `wg_handshake_scrub`
  (`wg_handshake.c`), and the AEAD/KDF scratch in `salsa20.c`,
  `hkdf_blake2s.c`, and `chacha20poly1305.c`. Public, non-secret values
  (nonces, timestamps, on-wire message buffers) deliberately keep plain
  `memset` — scrubbing them buys nothing. The earlier state where WG
  session/handshake keys were torn down with a dead-code-eliminable
  `memset` is resolved.
- **Hardware RNG.** `esp_random()` is only a true TRNG *after*
  `esp_wifi_start()`. Generate Curve25519 long-term identities only
  after WiFi is up — `tinylink_init()` is called from `app_main()`
  exactly for this reason.
- **Toolchain pinning.** Build with the default ESP-IDF
  `xtensa-esp32-elf-gcc`. LLVM's `select-optimize` pass has been known
  to transform mbedTLS's constant-time-select macros into branchy code.
  Do not switch to Clang without disassembling the crypto primitives.
- **Compile-in fallback control pub** (mitigation available, opt-in).
  TLS-only TOFU on the first `/key?v=<capver>` fetch is the weakest link in
  ts2021 (man-in-the-middle via a corporate TLS root). Set
  `CONFIG_TINYLINK_CONTROL_PUB_FALLBACK_HEX` to the operator's known
  control plane pubkey (64 hex chars): on first boot the device
  installs that value as the NVS pin without any network round-trip, so
  no fetched key can ever override it. Empty (the default) preserves the
  legacy TOFU behavior for development. Production firmware MUST set this;
  logged as a WARN at boot when empty. (The old `control_key_refresh()`
  re-fetch primitive was removed in the 2026-06 audit round — it was
  dead code that also unconditionally clobbered the TOFU pin on every
  call, so deleting it strengthens the pin rather than weakening it.)
- **Replay window.** A 64-bit single-word bitmap is fine for single-peer
  single-flow. If tinylink ever extends to multi-peer, switch to the
  RFC 6479 2000-entry scheme or accept replay risk.
- **Do not invent.** Noise IK, WG `Noise_IKpsk2`, and NaCl-box all have
  subtle state-transition rules (e.g., responder cannot send WG
  transport data until it receives one from initiator — §5.4.5 of the
  WG paper). Follow the papers verbatim.

## Constant-time review (M7-6, post-AEAD-perf-sprint)

Disassembled all crypto primitives (`xtensa-esp-elf-objdump -d -S`)
on the post-#51 build to verify no secret-dependent branches survived
the optimizer, particularly after the AEAD perf sprint that added
`__builtin_memcpy` + aligned-u32 paths. Reviewed:
`chacha20`, `chacha20poly1305`, `blake2s`, `curve25519`, `poly1305_donna`.

**Clean (verified branch-free at the ASM level):**

- **`poly1305_finish` mask select** (the documented high-risk site):
  the `mask = (g4 >> 31) - 1` + `g[0..4] &= mask` + `mask = ~mask` +
  `h[0..4] = (h[i] & mask) | g[i]` block compiled to a straight run of
  `extui` / `addi` / `srai` / `and` / `or` — zero branches in the
  selection region (offsets 0x93–0xc5 in the disasm).
- **`sel25519`** (curve25519 conditional swap): the `c = ~(b - 1)`
  mask compiled to `neg` + `srai 31` (sign-extend) — branch-free —
  followed by 16 iterations of pure `xor`/`and`/`store`. Only branch
  in the function is the `i ≤ 15` loop counter.
- **`chacha20_block`** quarter-round and the post-sprint
  `xor_block_u32`: branches are exclusively the `i < 16` row loop and
  the byte-tail length compare. The fallback path (4× `l8ui` + `xor`
  + 4× `s8i`) is the conservative branch-free shape — slower than the
  aligned-u32 path but the alignment-prove fast path doesn't trigger
  for `uint8_t *` callers, which is fine.
- **`blake2s_compress`** G function: the secret-state mixing (XOR /
  ADD / rotate) is branch-free; the only branches are the fixed-size
  loops (`i < 16`, `i < 8`).
- **`curve25519_scalarmult`** Montgomery ladder body: the bit-by-bit
  ladder uses `sel25519` (verified above) for conditional swaps; the
  ladder iteration count is a fixed loop bound, not a secret bit. The
  final low-order-output reject (`for (i=0;i<32;i++) nonzero |= q[i];
  return nonzero == 0 ? -1 : 0`) does have a branch on `nonzero`, but
  that bit is the result the protocol caller receives — no
  side-channel beyond what the protocol itself reveals.

**Closed in this review pass (was the residual finding):**

- **`poly1305_finish` 64-bit-add carry detection** — fixed by PR replacing
  the four `f = (uint64_t)h[i] + st->pad[i] + (f >> 32)` lines in
  `crypto/poly1305_donna_32.h` with an explicit 32-bit branch-free
  carry chain.

  Pre-fix shape: the chain compiled, on Xtensa LX6, to a 32-bit `add.n`
  followed by `bgeu Aresult, Aoperand, +5` to detect the carry — the LX6
  ISA has no add-with-carry, so GCC fell back to the branched form. The
  branch was data-dependent on secret-derived 32-bit values (`h` from
  message+key, `pad` from key). Net leak: ~4 bits per MAC of
  timing-side-channel information, bounded by WG key rotation (≤ ~22
  MACs per same key per the 110 s proactive rekey window).

  Post-fix: rewrite uses the standard branch-free unsigned-add carry
  identity (Hacker's Delight §2-13):

  ```c
  sum   = a + b + carry_in;
  carry = ((a & b) | ((a | b) & ~sum)) >> 31;
  ```

  which compiles to a straight run of `and`/`or`/`xor`/`srli`/`extui`
  ops — no conditional branches. Verified by disassembling the post-fix
  `poly1305_finish`: zero `bgeu`/`bltu`/`beq` etc. in the final-add
  region (the two remaining branches in the prologue are
  `if (st->leftover)` and the zero-padding loop bound — both gated on
  *public* message-length pattern, not key/message bits). The four
  `extui` ops counted across the function map to: 1× existing
  `(g4 >> 31) - 1` mask select (line ~191, already documented clean
  above) + 3× new carry-out extractions for steps 0..2 (step 3 discards
  carry-out, since the MAC is mod 2^128).

  Correctness re-validated against `tools/test/test_poly1305`
  (RFC 8439 §2.5.2 one-shot + streamed-chunk vectors) — bit-identical
  MAC output. Full downstream KAT (`make test`: chacha20poly1305, WG
  transport encrypt/decrypt, DISCO seal/open, DERP frame codec) passes
  unchanged: 493 OK, 0 FAIL.

  Cost: +48 B flash on the ESP32 build; zero DRAM/IRAM change.
