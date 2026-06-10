# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Audit fix round (2026-06-10, branch `fix/audit-cluster-1-protocol-wg`)

Six fixes from the 2026-06-10 upstream + security audit, each built, host-
tested (`make test` 531/0, up from 513 — +9 `keys_regen`, +9 `jsmn_skip`)
and hardware-validated A/B against `controlplane.tailscale.com`. Net flash
≈ +0.5 KiB. The remaining audit items are deferred on external conditions:
netmap `PeersChanged`/`PeersRemoved` delta-merge (needs a multi-peer
tailnet to validate), backoff consolidation (needs an extended soak), and
the forced-flap relay soak (needs Servidor1 root).

#### 1 — capver 138 at the Noise layer + stream-based early-payload (`971419c`)

Closes the standing headscale-compatibility item and fixes a dormant
control-channel framing bug that the bump exposed.

**The capver bump.** tinylink advertised Tailscale `CapabilityVersion`
`138` in its `RegisterRequest`/`MapRequest` JSON since 2026-05-02, but
the **Noise-layer** version field stayed hardcoded at `1`
(`ts2021_client.h` `TS2021_PROTOCOL_VERSION`). headscale `main` rejects
that in `earlyNoise` (`hscontrol/noise.go`) the moment the
`/ts2021` upgrade completes — `MinSupportedCapabilityVersion=113`
(`capver_generated.go`) is checked **before any JSON is read** — so
tinylink was never headscale-compatible at the Noise layer; it only
worked because tailscale.com SaaS tolerates a v1 client. Introduces a
single source of truth, `TINYLINK_CAPVER 138`
(`components/tinylink/include/tinylink.h`), from which the Noise
initiation header + prologue (`"Tailscale Control Protocol v138"`),
`RegisterRequest.Version` (`register.c`) and `MapRequest.Version`
(`mapreq.c`) all derive, so the three wire sites can never silently
diverge again. The bump is wire-safe: the server reconstructs the Noise
prologue from the client-claimed version
(`controlbase/handshake.go`), so both ends agree by construction.
(`control_key.c`'s `/key?v=100` is a deliberately separate, lower floor
— only needs `>= NoiseCapabilityVersion` — and is intentionally **not**
tied to the macro.) Upstream `tailcfg.CurrentCapabilityVersion` is `141`
as of 2026-06; `138` (= Tailscale v1.98) clears the headscale floor with
~9–10 minors of headroom.

**The bug the bump exposed.** Claiming v138 makes tailscale.com SaaS
send the optional `tailcfg.EarlyNoise` payload
(`magic[5] || BE32 length || JSON`) that it never sent to a v1 client.
The 9-byte header is **not** packed into one Noise record — observed in
vivo, the 5-byte magic `\xff\xff\xffTS` arrives as its **own** record,
with the length + 95-byte JSON in later records. The old
`consume_early_payload` (`ts2021_client.c`) was record-aligned: it
assumed the whole 9-byte header fit in the first record and, seeing a
5-byte record (`< 9`), mis-stashed the magic as HTTP/2 data — desyncing
the stream so the server closed the connection
(`h2_session_init` → EOF, nghttp2 `-902`). Rewritten to read the
early-payload header as a byte **stream** that spans Noise records,
mirroring upstream `control/ts2021/conn.go` `readHeader`
(`io.ReadFull` over the decrypted stream). The `EarlyNoise`
`NodeKeyChallenge` is drained and discarded — auth-key registration does
not require responding to it, same posture the upstream client takes in
production.

**Validation.** ESP32 boot against tailscale.com:
`EarlyPayload sentinel found, 95 bytes JSON (skipping)` →
`/machine/register status=200 MachineAuthorized=true` → dataplane up →
telemetry `seq 1..50` continuous → WG rekey at session age 110 s OK →
0 errors over a multi-minute soak. Flash delta ≈ 0 (the value change is
a constant; the early-payload rewrite adds ~320 B). Follow-up: a
host-side regression test feeding a split-record early-payload header
(magic and length in separate records) would lock in the fix.

#### 2 — lock rx transport decrypt + gate relayed DISCO (`e8997d7`)

**WGN-1 (rx side).** PR #105 closed the WGN-1 writer race but left the
reader unlocked: `wg_transport_decrypt` does a non-atomic read-modify-write
of the replay window and reads `recv_key` with no `g.lock`, while
`handle_transport` runs from **two** unpinned tasks — the `wg_rx` UDP task
and the `tinylink_derp` relay task (via `wg_netif_inject_packet`) — which
run in parallel on the dual-core LX6 whenever direct UDP and DERP traffic
overlap (NAT-traversal transitions, path-stale fallback). Concurrent RMWs
could accept a replayed packet or corrupt the window across a rekey. Take
`g.lock` around the decrypt, released **before** `g.rx_cb` (which re-enters
lwIP → `wg_netif_send_plaintext` → `g.lock`, a deadlock if held). Severity
is High/P1, not P0 — the rx race can't reuse a nonce or leak a key.

**Relayed DISCO knownPeerDiscoKey gate.** `handle_disco_relayed` acted on a
PING/CallMeMaybe sealed by **any** tailnet node's DiscoKey — and a
CallMeMaybe makes the node fire a UDP ping flood to the endpoints named in
it (attacker-chosen). Add the same pre-action gate the direct UDP path uses
(new `wg_netif_get_peer_disco_pub` accessor): drop relayed DISCO whose
decrypted sender DiscoKey ≠ the active WG peer's. (The pre-AEAD CPU-DoS
variant and the shared-K fast path are a noted follow-on.)

#### 3 — atomic machine+node identity regeneration (`573312f`)

headscale `main` now enforces a 1:1 `NodeKey`↔`MachineKey` binding on
registration **and** re-auth (upstream `eb57a3a6` + `4914f9f2`). `keys.c`
regenerated each key independently, so a partial NVS loss (e.g. machine
present, node missing) regenerated only the missing one → a
fresh-node/stale-machine pair the server rejects permanently. Treat machine
+ node as one unit: if either is absent **or corrupt**, regenerate and
persist **both**; the disco key stays independent. A hard NVS fault now
fails loudly instead of silently regenerating over a transient error. The
policy lives in the pure header `keys_regen.h`, host-tested across all 8
`(machine, node, disco)` presence combinations (`test_keys_regen`).

#### 4 — bound `skip_value` recursion depth (`0d5ec30`)

`skip_value` recursed once per JSON nesting level, so a control plane (or a
MITM past TLS) could send deeply-nested JSON to recurse it deep enough to
overflow the 24 KiB long-poll task stack. Factored into the pure header
`jsmn_skip.h` with a `JSMN_SKIP_MAX_DEPTH` (64) cap that returns a shallow,
always-in-bounds advance past the limit. Legitimate netmaps nest only a
handful of levels, so their skipping is byte-for-byte unchanged. Host-tested
(`test_skip_value`: exact at/below the cap, provably bounded past it).
Note: `jsmn_skip_d` is plain `static` (not `inline`) on purpose — the inline
hint makes -O2 recursively inline the self-call ~8 levels deep, +8–11 KiB
for no gain on this cold path.

#### 5 — secure_zero sweep (`df7b6bd`)

PR #105 added `crypto/secure_zero.h` but only adopted `tl_secure_zero` in
`chacha20poly1305.c`. Extend it to the remaining secret scrubs (39 sites):
WG session keys (`wg_netif.c`), handshake DH/chaining/tau/derived keys and
`wg_handshake_scrub` (`wg_handshake.c`), the XSalsa20 subkey (`salsa20.c`),
and the HKDF temp keys / HMAC pads / keystream (`hkdf_blake2s.c`). Public
values (nonces, timestamps, wire messages) keep plain `memset`. Behaviorally
identical — the crypto KATs are unchanged — but the scrub now holds by
construction across LTO / inlining / toolchain changes (CWE-14).

#### 6 — wifi-connect logging + dead-code + hygiene (`22969c4`)

- `app_wifi.c`: capture `esp_wifi_connect()`'s return and `ESP_LOGW` on
  failure — a synchronous error queues no `DISCONNECTED` event, so the
  silent call could leave an unattended node permanently offline.
- Remove `control_key_refresh()` — a dead primitive (zero callers) that
  also overwrote the TOFU pin unconditionally.
- Remove `CONFIG_TINYLINK_LOG_LEVEL` — defined + documented but never
  consumed.
- Fix a `derp_client.c` comment that wrongly claimed `DERPPort` is absent
  from the wire (`mapreq.c` parses it; the field is json `omitempty`).
- `.gitignore`: self-maintaining `test_*` pattern, ignore `.claude/`, and
  remove the orphan `test_disco_replay` binary that ran deleted code.

### Security audit round (2026-05-29, PR #105 — `d11dfd2`)

WGN-1 (HIGH) + four protocol hardenings, driven by a crypto/protocol
audit verified against ASM + upstream + a multi-agent workflow.

- **WGN-1 (HIGH, fixed):** `handle_handshake_response` called
  `wg_transport_session_init` (installs new `send_key`, resets
  `send_counter=0`) **without** `g.lock`, while
  `wg_netif_send_plaintext` does the counter RMW + key read **under**
  `g.lock`. `wg_rx` is unpinned and lwIP TCPIP is pinned to CPU0 → true
  dual-core parallelism → a concurrent encrypt could latch the OLD
  counter then read the NEW key, emitting `(new_key, old_counter)` and
  re-using it as the fresh session climbs from 0 — catastrophic
  ChaCha20-Poly1305 nonce reuse. Fix: wrap the swap in the same
  `g.lock`. HW-verified: 110 s rekey completed in ~60 ms, telemetry
  uninterrupted, no deadlock.
- **ROAM-3:** `disco_prober_match_and_remove` now binds a Pong match to
  the *probed destination* `(src_v4, src_port)`, rejecting spoofed-source
  Pong replays without burning the outstanding-probe slot
  (magicsock `sentPing.to` model). TDD'd (`test_disco_prober.c`).
- **CWE-14 scrub:** new `crypto/secure_zero.h` (`tl_secure_zero` =
  `mbedtls_platform_zeroize` on ESP, volatile-indirect memset on host);
  `chacha20poly1305.c` scrubs converted. (ASM showed plain `memset` was
  *not* actually elided at -O2 here, so this is by-construction
  hardening, not an active-leak fix.)
- **RC-2:** new pure `backoff.h` (`tl_backoff_ms`, exp + jitter, TDD'd in
  `test_backoff.c`); `long_poll_task` now exp-backoff (base 1 s, cap 30 s,
  reset after a ≥10 s healthy stream) instead of fixed 30 s. Retry-After
  still overrides.
- **ROAM-2:** STUN re-probe now waits on a binary sem; an
  `IP_EVENT_STA_GOT_IP` handler signals it → re-STUN within ~1 RTT on a
  local WiFi/DHCP change instead of waiting 5 min.
- Skipped **WGN-2** (message-count rekey): never fires at telemetry
  cadence → would be a dead primitive.

Host `make test` 513/0; ESP build clean; 150 s HW capture clean.

### Performance + resource round (2026-05-13, PRs #88–#104)

17 PRs, net **−68.1 KiB flash** and largest-contiguous-heap-block
**6 656 → 9 216 B**. Two stack trims were caught regressing and
reverted, which is why the round nets fewer than 17 wins.

- **#88** turn off `CONFIG_LWIP_PPP_SUPPORT` — dead code since the
  raw-IP WG netif (`4a915df`). **−21.4 KiB**.
- **#89** `EXCLUDE_COMPONENTS` for IDF subsystems with 0 callers.
- **#90–#93** mbedTLS 4-stage prune (**−13.6 KiB**): ECP curves trimmed
  to `{P-256, P-384, Curve25519}` (drop 8 unused), static-ECDH key
  exchanges off, X509 CRL + CSR parsers off, and CCM/PKCS7/non-AES-GCM/
  deterministic-ECDSA off. Curves verified against the live TLS cert
  chain first (LE E8 P-384 → ISRG Root X2 P-384).
- **#94** WiFi + lwIP trimmed for the single-AP/single-STA workload.
- **#95** `NEWLIB_NANO_FORMAT` + convert 11 `%lld/%llu` log call-sites.
  **−30.3 KiB**.
- **#96** `chacha20poly1305.c` LE helpers via `__builtin_memcpy`, drop
  byte loops.
- **#97** soak observability: per-task stack-hwm dump + jsmn/body-buf
  peak logs (the data source for the deferred stack/jsmn trims).
- **#98–#102** five stack trims, of which **two were reverted**:
  long-poll **#99 reverted by #103** (the 100 s smoke missed a 20 KiB
  peak at 18 min uptime); endpoint-push **#102 reverted by #104**
  (a 30-min stress soak hit a NAT-rebind + heap-frag panic). **#104**
  also bumped `CONFIG_LWIP_TCPIP_TASK_STACK_SIZE` 3 K → 4.5 K (`tiT` was
  at 95.5 % steady-state and overflowed under ENOMEM `sendto` pressure).
  Lesson recorded: stack trims of tasks with TLS reconnect/retry loops
  need a multi-hour soak, not a boot smoke (`uxTaskGetStackHighWaterMark`
  is a lifetime max). Final 30-min soak: 0 panics, heap stable.

### Misc round (2026-05-12, PRs #85–#87)

- **#85** (`a827843`) `h2_client` honors a server `Retry-After` header on
  429/503 throttles (`h2_retry_after.h`, parsed delta-seconds clamped
  into `[1, 300]`). +15 host tests.
- **#86** (`e2b4594`) branch-free carry in `poly1305_finish` — closes a
  documented LX6 timing side-channel. Bit-identical KAT vs the baseline
  tags.
- **#87** (`1be9708`) bump `IPNVersion` to `1.0.0-tinylink`, flipping the
  admin-panel `tsReleaseTrack` from unstable → stable (MINOR even via
  `version.IsUnstableBuild`). Derived from `TINYLINK_VERSION_*`, single
  source of truth in `tinylink.h`.

### DERP outbound round (2026-05-12 evening, PR-D0 + PR-D1)

Two PRs that together unlock the full DERP-mediated fallback path the
firmware already had wired in source but couldn't actually use because
of a chronic boot-time bug. After landing these, the failure mode that
the 2026-05-12 PM peer-loss incident demonstrated (~35 min telemetry
gap when Servidor1's WAN endpoint changed) gets reduced to a ~30 s
detection window with zero packet loss during recovery.

**PR-D0 — `feat/derp-supervisor-spawn-pre-tls`**: closes the chronic
`xTaskCreate(derp supervisor) failed — heap_free=~11.7K largest=~11.2K
need 12K contiguous` failure that fired on every boot across 3 soaks
(2026-05-11 post-#67, 2026-05-12 morning post-η, 2026-05-12 PM
combined post-perf-trim). Pre-PR the spawn happened AFTER the long-
poll's TLS handshake fragmented the heap below the 12 KiB the task
stack needs; xTaskCreate returned `ESP_ERR_NO_MEM`, the supervisor
never spawned, and ALL DERP-mediated features stayed dead (relayed
DISCO, CallMeMaybe ingestion, the upcoming relay TX path). Fix
mirrors PR #67's pattern: spawn the task EARLY (pre-TLS, heap
pristine) and move the wait-for-first-netmap into the task body so
the actual DERP TLS handshake still happens post-netmap. Pure
code-move + comment-update (60 insertions / 47 deletions, ~0 net
flash change).

**PR-D1 — `feat/derp-outbound-wg-transport-fallback`**: lossless
WG transport via DERP relay when direct UDP looks broken. Adds a
`wg_netif_relay_fn` callback typedef + setter and registers
`tinylink_relay_via_derp` (a thin wrapper over the existing
`derp_client_send_packet`). The TX worker (`wg_netif.c::tx_task_fn`)
decides on each packet:

  1. **Preemptive route**: if path-stale (`now -
     last_transport_recv_us > WG_RX_STALE_THRESHOLD_MS`) AND relay is
     registered, ship via DERP and skip the direct sendto entirely.
     Relay success increments `g.relayed_stale`; failure falls
     through to direct sendto.
  2. **Reactive route**: if direct sendto returns errno != 0 (and we
     didn't already try relay above), try the relay as last resort.
     Increments `g.relayed_errno` on success.

Three new public stats accessors (`wg_netif_get_relayed_stale`,
`_errno`, `_get_relay_errors`) for soak observability. The relay
goes through the callback so wg_netif stays decoupled from
tinylink/derp_client.

Combined effect on the incident scenario:

| Symptom | Pre-DERP-round | Post-DERP-round |
|---|---|---|
| Telemetry gap during Servidor1 WAN flap | 35 min | 0 packets (relay) + ~30 s detection |
| Recovery mechanism | Wait for `PeersChangedPatch[]` (35 min in practice) | CMM via DERP → prepunch new endpoints (seconds) |
| derp supervisor at boot | xTaskCreate fail; DERP path dead | task spawned, login OK, recv loop active |
| `disco_cmms_seen` counter | always 0 | live counter increments per CMM |

Measured impact (PR-D0 + PR-D1, esp32, IDF v5.5.4):
  flash app .text   +0.37 KiB  (728994 → 729382)
  DRAM               +32 B     (148484 → 148516)
  IRAM               0
  total app .bin    +0.39 KiB  (1015145 → 1015533)
  bootloader.bin     0

Smoke validated on hardware (30 min, INTELCOM-CARDONA WPA2+PMF):
  - 0 panics / asserts / WDT / xTaskCreate fails (3 prior soaks had
    the supervisor xTaskCreate fail; this one didn't)
  - derp supervisor task spawned t=5.9 s + login OK t=16.9 s on
    derp16b.tailscale.com
  - 9 CMMs processed via DERP supervisor (peer Servidor1 actively
    sending CMMs as part of its NAT-punch routine; each CMM triggers
    `cmm punch ping` to the 3 announced endpoints; prober matches the
    pongs; no roam needed because the direct path was already healthy)
  - 361 telemetry packets at 5 s cadence (seq 2..362)
  - 0 RX-stale forced rekeys, 0 path-stale events, single WG session
    survived the entire 30 min (`remote_idx=0x049221a7` constant)
  - 16 successful rekeys (within-session key rotation per WG spec)
  - 130 disco ping↔pong direct
  - 4 W-lines, all benign: 2 early-boot `telemetry sendto errno=-1`
    transients pre-dataplane, 1 normal handshake retry, 1 long-poll
    stream-reconnect (rc=0x0 = clean close)

External validation from peer-side ICMP-over-WG (`ping -c 2755
100.67.60.92` Servidor1 → ESP32 tailnet IP):

```
2755 packets transmitted, 2640 received, 4.17423% packet loss
rtt min/avg/max/mdev = 22.349/136.704/3230.099/97.257 ms
```

95.83 % delivery, RTT min/avg/max 22 / 137 / 3230 ms. The 4.17 %
loss matches the pre-DERP-round ICMP-over-WG baseline (M5 60-min
mega-ping at 3.86 % loss / 154 ms avg); no regression from the
DERP round.

PR-D1's relay path remained dormant during the 30-min soak — direct
UDP stayed healthy so no path-stale event fired. To explicitly
exercise the lossless-during-flap path, force a Servidor1-side UDP
block while the ESP32 is running:

```
# On Servidor1, with $ESP32_WAN known from `tailscale debug netmap`:
sudo iptables -A INPUT -p udp --dport 5815 -s $ESP32_WAN -j DROP
sleep 60
sudo iptables -D INPUT -p udp --dport 5815 -s $ESP32_WAN -j DROP
```

`wg_netif_get_relayed_stale()` should then be > 0 in the next status
dump. That validation is intentionally separated from this round —
the relay code is in place; whether it fires under a forced flap is
left for a follow-up soak.

### sdkconfig perf-trim round (2026-05-12 afternoon)

Five `feat/perf-*` branches landed in one afternoon after the post-η
4-h NAT-rebind soak was cut at t=35 min (clean baseline: 0 panics,
telemetry @ 5 s, PR #75 `KeepAlive:true` confirmed on-wire). The
round targets sdkconfig only — no `.c`/`.h` changes, no API surface
change. Each PR was validated independently by a 60-120 s smoke
(boot + register + initial netmap + ≥5 telemetry @ 5 s + 0 panic /
assert / WDT) on the same INTELCOM-CARDONA WPA2+PMF AP, then
pushed.

| PR (branch) | Δ flash app | Δ DRAM | Δ IRAM | Other |
|---|---:|---:|---:|---|
| `feat/perf-error-strings-and-assertions` | **−75.6 KiB** | −2.6 KiB (83.78%→82.32%) | −3.4 KiB (79.64%→77.02%) | – |
| `feat/perf-vfs-trim` | −9.4 KiB | 0 | −1.1 KiB | – |
| `feat/perf-bootloader-log-none` | 0 | 0 | 0 | bootloader.bin −8 KiB (27808→19584) |
| `feat/perf-wifi-station-only-no-wpa3` | **−74.6 KiB** | −0.3 KiB | −0.1 KiB | wifi assoc 10s→2.7s |
| `feat/perf-iram-to-flash-moves` | +0.9 KiB | 0 | **−25.9 KiB (79.64%→59.42%)** | – |
| **Combined (projected)** | **−158.7 KiB** | **−2.9 KiB (~82.2%)** | **−30.5 KiB (~56.4%)** | bootloader.bin −8 KiB |

The IRAM relief is the headline: from ~80 % used down to ~56 %
unlocks future work that needs IRAM (a second persistent TLS
connection, selective IRAM_ATTR on hot WG paths, multi-peer state)
without crowding wifi/rtos/lwip.

**`feat/perf-error-strings-and-assertions`** flips three Kconfig
knobs that all attack the panic + error-return path while leaving
panic/abort behaviour itself intact:
- `CONFIG_COMPILER_OPTIMIZATION_ASSERTIONS_SILENT=y` (level 2→1).
  `assert()` still aborts on failure but does not print the message
  + `__FILE__` + `__LINE__` literal. Re-enable to level 2 in a
  "diag" overlay for field repro.
- `CONFIG_COMPILER_OPTIMIZATION_CHECKS_SILENT=y`. ESP_RETURN_ON_ERROR
  and ESP_GOTO_ON_ERROR drop their format-string parameter — error
  goto/return still taken, only the per-callsite log line elided.
  Removes a ~30 KiB cluster of "%s:%d at <fn>" literals scattered
  across IDF + components.
- `CONFIG_ESP_ERR_TO_NAME_LOOKUP not set`. Removes the ~7 KiB
  `esp_err_msg_table[]` rodata; `esp_err_to_name()` now returns
  "UNKNOWN ERROR" plus the hex code, which is still greppable
  against `include/esp_err.h`.
- `CONFIG_HAL_DEFAULT_ASSERTION_LEVEL` follows the compiler level
  via `HAL_ASSERTION_EQUALS_SYSTEM=y`, so the HAL surface inherits
  the new level=1 automatically.

**`feat/perf-vfs-trim`** turns off `VFS_SUPPORT_TERMIOS` and
`VFS_SUPPORT_DIR` (keeps `IO` for newlib stdout and `SELECT` for
lwIP socket select). Audited that tinylink has no `opendir`,
`readdir`, `tcsetattr`, `tcgetattr`, `isatty`, or any other VFS-
TERMIOS/DIR caller. Drops the dispatch tables (~1 KiB IRAM) plus
the backing implementations.

**`feat/perf-bootloader-log-none`** sets `BOOTLOADER_LOG_LEVEL_NONE
=y`. The bootloader's UART chatter (`ets Jul 29 2019…` reset banner,
partition table dump, `boot:` lines, `esp_image: segment` per-
segment load lines) disappears. The bootloader still runs the same
code; only the log prints compile out. Bootloader binary slot is
separate from the app partition so the app .bin is unchanged.
Recovery on a stuck boot is still possible by re-flashing with a
"diag" overlay that flips this back to INFO.

**`feat/perf-wifi-station-only-no-wpa3`** drops three WiFi feature
families that tinylink never exercises (audit: zero hits across
`main/` + `components/` for `WIFI_MODE_AP`, `esp_wifi_set_mode
(WIFI_MODE_AP)`, `softap_start`, `SAE`, `OWE`, `WPA3`):
- `CONFIG_ESP_WIFI_SOFTAP_SUPPORT not set` — removes the AP-side
  state machine (beacon scheduler, AID table, DTIM management on AP
  side, AP-side WPA supplicant, AP-side WPS). The bulk of the
  savings (~65 KiB of code only reachable through
  `esp_wifi_set_mode(WIFI_MODE_AP)`).
- `CONFIG_ESP_WIFI_ENABLE_WPA3_SAE not set` — drops the SAE-PWE
  Dragonfly + SAE-H2E handshake variants (~10 KiB). The production
  AP is WPA2-PSK-SHA256 + PMF, not WPA3-Personal.
- `CONFIG_ESP_WIFI_ENABLE_WPA3_OWE_STA not set` — drops the OWE
  handshake (open networks with encryption). Tinylink never
  associates to open APs.

Side effect: WiFi assoc is faster post-trim (2.7 s vs ~10 s in the
post-η baseline) because there's less init code to walk.

**`feat/perf-iram-to-flash-moves`** trades 0.9 KiB of net flash for
25.9 KiB of IRAM by moving never-from-cache-disabled-ISR code paths
into flash-XIP:
- `CONFIG_ESP_WIFI_RX_IRAM_OPT not set` — biggest single mover
  (~15 KiB). WiFi RX path runs from flash. Documented cost: WiFi
  RX throughput drops a few percent on the first call after a quiet
  window (flash cache miss). Tinylink's load (1 Hz telemetry +
  ~6/min long-poll inbound + WG handshake every ~85 s) is 3 orders
  of magnitude below the WiFi ceiling — invisible.
- `CONFIG_FREERTOS_PLACE_FUNCTIONS_INTO_FLASH=y` — vTaskSwitchContext
  / xQueue* / xSemaphore* into flash. Safe: tinylink never calls
  FreeRTOS from a cache-disabled ISR, and SPI flash auto-suspend is
  off (no IRAM-only critical sections).
- `CONFIG_RINGBUF_PLACE_FUNCTIONS_INTO_FLASH=y` — no ISR
  producer/consumer for any RingBuffer in tinylink (`esp_event`
  queue's producer is a regular task).
- `CONFIG_LIBC_LOCKS_PLACE_IN_IRAM not set` — newlib lock helpers
  leave IRAM. Same justification: no cache-disabled ISR mutates
  newlib state.

**Skipped after measurement** (the optimization research had
suggested these, but the build proved them wrong or harmful for
this target):
- `CONFIG_COMPILER_SAVE_RESTORE_LIBCALLS=y` — Kconfig does NOT
  exist in IDF v5.5.4 for Xtensa LX6. It's a GCC RISC-V flag
  (`-msave-restore`) only relevant for ESP32-C3/C6.
- `CONFIG_MBEDTLS_PEM_WRITE_C not set` — Δ = 8 B (noise). Section
  GC already strips PEM_WRITE because the cert-bundle path only
  needs PEM_PARSE.
- `CONFIG_MBEDTLS_ERROR_STRINGS not set` — Δ = 0. `nm tinylink.elf`
  shows zero references to `mbedtls_strerror`; the table is
  already dead-stripped by section GC.
- `CONFIG_LOG_MAXIMUM_LEVEL=ESP_LOG_WARN` — IDF's Kconfig clamps
  `LOG_MAXIMUM_LEVEL_X` with `depends on LOG_DEFAULT_LEVEL < N`,
  so with `DEFAULT=INFO` the MAXIMUM is already 3. The only real
  win is lowering DEFAULT to WARN, which strips every `ESP_LOGI`
  call site — and breaks tinylink's serial-grep smoke (no more
  "tinylink up", "telemetry tx seq", "netmap (initial)"). Deferred
  until the smoke can verify operation via Servidor1 tcpdump
  instead of UART logs.

A 4-hour soak with the COMBINED set is the remaining validation.
Each PR was 60-120 s smoke individually; cross-PR interaction is
unlikely (no .c changes, no API surface) but unverified.

### WG persistent keepalive + long-poll `KeepAlive:true` (2026-05-12)

Two upstream-tailscale alignment fixes for keepalive primitives at
different layers (WG data plane + control-plane long-poll).

**WG persistent keepalive originator** (`wg_netif.c`). Pre-PR tinylink
relied entirely on the peer to keep the upstream NAT mapping warm:
peer's keepalives flowed in, ours never went out unless we had data.
In normal operation the 5 s telemetry cadence keeps the mapping warm,
but if telemetry pauses (sensor disabled, I²C stall, app paused) the
mapping expires after ~30-60 s of CGNAT idle and the next packet is
silently dropped at the peer's upstream NAT until our path-stale
machinery kicks in 30 s later. Matches the typical wireguard.conf
`PersistentKeepalive=25` recommendation.

- New constant `WG_PERSISTENT_KEEPALIVE_MS = 25000`.
- New field `g.last_tx_us` (int64, 8 B BSS) updated by every successful
  `wg_netif_send_plaintext`.
- `wg_netif_send_plaintext` now accepts `pkt=NULL, len=0` and wraps
  encrypt+enqueue under the existing `g.lock` mutex — required because
  the rx_task-driven keepalive path becomes a SECOND writer to
  `g.transport.send_counter`, which is read-modify-written and NOT
  atomic on ESP32-LX6.
- Rx_task tick triggers the keepalive when `state == UP &&
  now - last_tx_us > 25 s`.

Mutex cost: ~1 µs per send (negligible vs ChaCha20 of ~25 µs / 1.4 KB).
No new threads, no new heap, +8 B BSS.

**Long-poll `KeepAlive:true`** (`mapreq.c`). Pre-PR the MapRequest body
omitted the `KeepAlive` field (Go default `false`). Upstream sets
`KeepAlive:true` on every MapRequest (direct.go:1078) to request
periodic server-emitted KeepAlive frames on the long-poll stream — an
application-layer liveness signal beyond TCP keepalives. Tinylink's
existing parser already handles `KeepAlive=true` frames
(`mapreq.c:746-799`); only the request flag was missing. One-line
change.

Smoke validation (`/tmp/tinylink_pr_eta_smoke_2026-05-12.log`):
0 panics / 0 errors / boot + session-up / 5 telemetry tx in 35 s
(5 s cadence preserved) / 0 keepalive sends (expected — telemetry
keeps the NAT mapping warm) / 2 server-emitted KeepAlive=true frames
received on the long-poll (validates the new request field worked
end-to-end without breaking the response parser).

The keepalive path is exercised in operation only when telemetry pauses
for more than 25 s. The user's 4-hour soak will confirm under realistic
conditions; a forced test would be disabling
`CONFIG_TINYLINK_TELEMETRY_ENABLE` for a build.

### Endpoint-updater exponential backoff (2026-05-12)

Closes the "fixed 3 s retry" gap surfaced by the 2026-05-12
comparative audit (Agent C against upstream
`controlclient.Auto.updateRoutine`). Pre-PR behavior: any failure of
`ts2021_connect` or `mapreq_push_endpoints` slept exactly
`TINYLINK_EP_PUSH_ERR_BACKOFF_MS = 3000 ms` before re-enqueueing —
sustained server unreachability meant 200 connect attempts in 10
minutes, hammering the unreachable host with no headroom.

Replace with an exponential capped backoff modeled on upstream
`auto.go:57` `backoff.NewBackoff("updateRoutine", c.logf,
30*time.Second)`:

- Base: `TINYLINK_EP_PUSH_ERR_BACKOFF_BASE_MS = 1000` ms.
- Cap:  `TINYLINK_EP_PUSH_ERR_BACKOFF_MAX_MS  = 30000` ms.
- On each consecutive failure (either failure path), double until
  hitting the cap.
- On first success after one or more failures, reset to base —
  matches `bo.Reset()` (auto.go:91-94) so a fresh outage starts the
  ramp over.

Result: in a 10-minute server outage the device now spends roughly
`1 + 2 + 4 + 8 + 16 + 30·N` seconds across retries (≈ 20 attempts)
instead of 200. The fastest path back to a healthy state on a
transient blip is unchanged (1 s — actually faster than the pre-PR
3 s).

Cost: +4 bytes BSS (the int counter). No new logs in steady state
(only logs on failure with the current backoff value).

Smoke validation (`/tmp/tinylink_pr_zeta_smoke_2026-05-12.log`):
0 panics, 0 errors, telemetry 5 s cadence preserved. Behaviour
under sustained outage is not yet measured — full validation is
the user's 4-h soak.

What this PR does NOT do (deferred):
- The CMM endpoint freshness cache (Agent B item #12) — marginal
  benefit for the single-peer model (CMM endpoints merge into the
  next netmap update), defer until a multi-peer scenario surfaces.
- `trustBestAddrUntil` analog (Agent B item #8) — overlaps with
  the RX-stale watchdog for tinylink's always-transmitting-telemetry
  workload, defer.

### DISCO outbound prober + tx-id binding (M3 step 3, 2026-05-12)

Closes deferred item #5 from the 2026-05-10 security audit. Pre-PR
behavior: `handle_disco_direct` roamed `g.peer.peer_endpoint_*` on
EITHER an inbound PING or PONG, gated only by the DiscoKey match and
the post-decrypt `disco_replay_check_and_record` nonce window (PR
#58). Upstream tailscale never accepted a PING as a roam trigger;
its `endpoint.handlePongConnLocked` (`endpoint.go:1706-1798`) is
keyed on a `sentPing` map populated when the local node *sent* the
corresponding probe — a Pong whose txid isn't there returns false
and no state changes.

This PR ports that primary control to tinylink:

- **New `disco_prober.{c,h}`** module. 16-entry table of
  `{txid, dst_v4_be, dst_port, sent_us, valid}` (~512 B BSS). On
  ESP-IDF the table is protected by a `portMUX_TYPE` so the
  supervisor task (recording records) and the wg_rx task (looking
  up + removing on inbound pong) don't tear slots mid-update. Host
  build uses no-op locks (single-threaded). Eviction is LRU with a
  fresh-entries-only cap: an in-flight slot is evicted only when no
  free or expired slot is available.

- **`tinylink.c`**: every successful `sendto` in
  `prepunch_pings_to_peers` and `send_disco_pings_to_cmm_endpoints`
  now records the outbound txid via `disco_prober_record`.

- **`wg_netif.c::handle_disco_direct`**:
    - PING branch: sends the sealed PONG reply as before but no
      longer roams `g.peer.peer_endpoint_*`. Replying to a ping
      remains useful (lets the peer learn that our AddrPort works)
      but the roam decision is deferred to the round-trip pong.
    - PONG branch: now gated by `disco_prober_match_and_remove`.
      A pong whose txid is not in the table is dropped silently;
      a fresh match removes the entry and triggers the existing
      roam + fast-INIT logic.

- **Deletes `disco_replay.{c,h}` + `test_disco_replay.c`**. The
  txid-table is a strictly stronger primary control: a replayed
  pong with no matching outstanding ping fails the `match_and_remove`
  check. (PR #58's window was defense-in-depth post-decrypt against
  replayed pings; with PING-roam removed the window has no remaining
  consumer.)

Net BSS: -2 560 bytes (-3 072 disco_replay + +512 prober). Flash:
+~290 B for the new module. CMakeLists / tools/test/Makefile
updated to match.

End-to-end validation
(`/tmp/tinylink_pr_delta_smoke_2026-05-12.log`): boot prepunch sends
11 pings across 3 peers, peer responds with a pong whose txid
matches the original `txid=960459a3..` prepunch, prober matches and
removes the entry, would-have-roamed but src == current endpoint so
no log. 0 panics, 0 errors, telemetry 5 s cadence preserved.

Host KAT 464 → 466 (16 new prober tests in
`tools/test/test_disco_prober.c` covering roundtrip, multi-txid,
timeout, LRU eviction, unknown txid, NULL safety; 14 deleted
`disco_replay` tests).

### Control-plane key bootstrap: explicit production profile (2026-05-12)

Closes deferred item #6 from the 2026-05-10 security audit. New
`TINYLINK_CONTROL_PROFILE` Kconfig choice:

- **Custom / development** (default): legacy behavior, empty
  `_FALLBACK_HEX` allowed → first boot does TOFU via
  `GET /key?v=100`. Suitable for Headscale / development.
- **Official / production**: a `_Static_assert` in `control_key.c`
  rejects builds with empty / wrong-length
  `CONFIG_TINYLINK_CONTROL_PUB_FALLBACK_HEX` at compile time, so
  production firmware cannot silently fall through to TOFU.

New overlay `sdkconfig.defaults.prod.example` documents the
discovery flow (curl /key?v=100, strip `mkey:` prefix, paste 64 hex)
and the canonical build invocation. Runtime path
(`parse_fallback`, `control_key_get`) unchanged — the production
profile is purely a compile-time gate on what hex value can ship.

Negative test verified: setting OFFICIAL profile with an empty
fallback fails the build with

    control_key.c: error: static assertion failed:
      "CONFIG_TINYLINK_CONTROL_PROFILE_OFFICIAL requires
       CONFIG_TINYLINK_CONTROL_PUB_FALLBACK_HEX to be exactly
       64 hex chars."

Smoke validation (`/tmp/tinylink_pr_epsilon_smoke_2026-05-12.log`):
0 panics, boot picks up pin from NVS unchanged.

### DISCO AEAD CPU-DoS defense (2026-05-12)

Closes the deferred item #4 from the 2026-05-10 security audit
(`reference_tinylink_security_audit_2026_05_10`). Pre-#58 audit raised
that an attacker who learned our public AddrPort could flood DISCO
frames sealed by arbitrary DiscoKeys; each frame forced our recv path
to run Curve25519 + HSalsa20 + XSalsa20 + Poly1305 (~5-10 ms per
frame on Xtensa LX6) before the existing roam-allowed gate dropped
the frame. PR #58's `disco_replay.c` mitigated replay-of-captured
frames but did NOT mitigate fresh-nonce floods because those never
hit the replay window — every frame still paid the full AEAD cost.

Two layered defenses, modeled on upstream tailscale
`wgengine/magicsock/magicsock.go::handleDiscoMessage`:

- **Pre-AEAD DiscoKey gate** (`wg_netif.c::handle_disco_direct`).
  Before invoking the codec, compare `frame[6..37]` (cleartext
  senderDiscoPub) against `g.peer.peer_disco_pub` when we know the
  peer's DiscoKey. Mismatch → drop pre-crypto. Upstream's analog is
  `c.peerMap.knownPeerDiscoKey(sender)` at
  `magicsock.go:2170-2177` which gates everything behind a
  netmap-derived allow-list. Reduces the per-frame attacker budget
  from "any unknown sender forces ~5-10 ms of CPU" to "must already
  be in our netmap and present the right DiscoKey".

- **Cached NaCl-box shared key K** (`crypto/nacl_box.{c,h}`,
  `wg_netif.c`). Add a new pair of functions
  `nacl_box_compute_shared` + `nacl_box_open_after_shared` that split
  the per-frame cost: the X25519 + HSalsa20 step is amortized once at
  `wg_netif_start` and the K = HSalsa20(X25519(my_priv, peer_pub),
  0^16) is cached in `g.peer_disco_shared_k`. The hot path then
  only runs XSalsa20 + Poly1305 per inbound DISCO frame. Models
  upstream `magicsock.discoInfoForKnownPeerLocked` at
  `magicsock.go:2631-2642` which lazily caches
  `box.Precompute(peer)` per known DiscoKey. Saved CPU per direct
  inbound: ~5-10 ms on the Xtensa LX6 (Curve25519 + HSalsa20 vs the
  ~1-2 ms of XSalsa20 + Poly1305 alone).

Drive-by improvement: `nacl_box.c` no longer `malloc`s its
keystream/tag buffer. Stack-resident `NACL_BOX_STREAM_BUF` (288 B)
covers every legitimate inner plaintext (DISCO CMM ≤ 146 B, EarlyNoise
~96 B). This removes a heap-fragmentation surface (after hours of
nghttp2+mbedtls churn the heap fragments and `malloc(146+32)` can
return NULL → false-positive auth failure that drops legitimate
DISCO frames) and removes two heap ops per inbound DISCO. Worst-case
RX stack is unchanged (still well under the 8 KiB budget).

API additions (non-breaking):
- `nacl_box_compute_shared(K, peer_pub, my_priv)` — expose
  `box_beforenm`.
- `nacl_box_open_after_shared(m, c, clen, nonce, K)` — opens with
  precomputed K.
- `disco_open_with_shared(pt, ..., shared_k)` — parallel to
  `disco_open` taking K.
- `disco_handle_recv_with_shared(...)` — parallel handler taking K.

Existing `nacl_box_open` / `disco_open` / `disco_handle_recv` still
work and now internally compose on top of the with_shared variants —
host KAT 452 → 462 (10 new equivalence assertions in `test_disco.c`).

Net cost: ~+500 B flash. +32 B BSS (cached K). No heap allocs on
the RX hot path. Smoke validation
(`/tmp/tinylink_pr_gamma_smoke_2026-05-12.log`): 0 panics, 11 DISCO
ping→pong roundtrips, 0 spurious "drop DISCO from unknown" (peer's
real DiscoKey passes the gate), telemetry 5 s cadence preserved.

What this PR does NOT do (deliberate split):
- It does NOT extend the pre-AEAD gate to the DERP-relayed path
  (`handle_disco_relayed` in `tinylink.c`). That path receives CMM
  frames from peers we are not WG-connected to (e.g. laptop in the
  netmap announcing endpoints) — gating it requires plumbing the
  netmap peer set into the relayed handler. Deferred to a follow-on PR.
- It does NOT yet remove `disco_replay.c`. The replay window still
  guards against replayed legitimate-peer frames; M3-step-3 (outbound
  prober + tx-id table) would obsolete it but is a bigger PR.

### Recovery after peer NAT rebind (2026-05-11)

Four commits fixing a "sometimes the device doesn't reconnect after
servidor1 reboots" pattern. Forensics in
`/tmp/tinylink_capture_2026-05-11_validate_v2.log` (pre-fix capture)
showed three independent failure modes stacking on the same trigger
(peer's outbound NAT mapping rotating during a brief outage):

1. **Endpoint-push `xTaskCreate` failed on fragmented heap.** After
   hours of operation the legacy
   `tinylink_endpoint_push_async` couldn't find a contiguous 24 KiB
   block to spawn its one-shot ts2021+push task. The push was dropped
   silently; the control plane kept the device's stale public AddrPort
   and the peer kept sending WG to a NAT mapping that no longer routed
   to the WG socket. Pattern reproduced at uptime 2716 s:
   `stun re-probe: endpoint changed :60697 → :40959` immediately
   followed by `endpoint_push: xTaskCreate failed`.
2. **Peer-endpoint selection sticky on stale.**
   `wg_dataplane.c::pick_peer_endpoint` selects the first public
   candidate from the peer's netmap-advertised endpoint list. After
   the peer's tailscale rebound to a new outbound port, the control
   plane often kept the stale entry at index 0 for a while; the device
   then hammered handshake INITs at the dead AddrPort indefinitely
   (60 s rekey budget + 60 s cold-handshake budget + 30 s backoff,
   repeating). LAN-direct (`192.168.1.x:41641`) was usually in the
   same list but never tried because the first public matched.
3. **wg_tx stack overflow at the moment of recovery.** When a
   handshake finally landed on a working endpoint, the first
   legitimate packet through the now-UP transport tripped a stack
   overflow in the wg_tx worker: `wg_netif: session up` immediately
   followed by `***ERROR*** A stack overflow in task wg_tx`
   + SW_CPU_RESET. The 4 KiB stack was marginal pre-#65 and
   insufficient post-#65 (per-component -O2 inlines more aggressively
   in the sendto → WiFi-TX chain). WG_TX_QUEUE_LEN=3 rules out a
   recovery-flood story; the crash fires on the first send.

**Fix (PR #66, 4 commits on branch `fix/endpoint-push-persistent-task`):**

- **Persistent endpoint-updater task** (`tinylink.c`). Replaces the
  one-shot `xTaskCreate` per re-probe with a single persistent worker
  signaled via semaphore + monotonic generation counter. Coalesces
  rapid concurrent triggers (multiple STUN re-probes during a flap
  fire only one push). Pattern mirrors upstream tailscale
  `controlclient.Auto.updateRoutine` in `auto.go:55-99`. Static
  allocation (`xTaskCreateStatic` with BSS-backed stack/TCB) so the
  spawn-vs-heap-fragmentation failure mode is eliminated entirely.
  Documents the `s_conn == NULL` path: if long-poll hasn't yet
  established the control-plane channel, the worker re-enqueues and
  waits (no fresh TLS handshake while the network path is unhealthy).
- **DISCO-driven path probe on transport-stale** (`wg_netif.c` +
  `wg_netif.h`). New callback fires from rx_task when WG transport
  has been silent past `WG_RX_STALE_THRESHOLD_MS` (30 s) AND the
  cooldown (`WG_PATH_PROBE_COOLDOWN_MS` = 10 s) has elapsed.
  Tinylink's handler runs `prepunch_pings_to_peers` against the
  latest known peer endpoints, sending sealed DISCO pings to all of
  them. The peer's pong from a different AddrPort is roamed by the
  existing `handle_disco_direct` PONG branch — so the next rekey or
  cold-handshake INIT lands on a live address instead of hammering
  the stale one for the full handshake budget. Modeled on upstream
  `wgengine/magicsock/endpoint.go::addrForSendLocked` +
  `setBestAddrLocked`: DISCO pong is the canonical path-liveness
  signal, not WG handshake.
- **wg_tx stack 4 KiB → 8 KiB**. Match `WG_RX_TASK_STACK_BYTES`,
  absorb the -O2 frame growth. +4 KiB permanent RAM cost.
- **Static-allocation + shrunk peers cache**. The persistent task's
  stack lives in BSS via `xTaskCreateStatic`, NOT in the DRAM heap
  arena that long-poll's nghttp2 + mbedtls draws from at boot. The
  path-stale callback caches `tl_peer_t[TL_MAX_PEERS]` (~1 KiB) not
  the full `tl_netmap_t` (~7.5 KiB; `derp_regions[28]` dominates)
  so total BSS impact fits WiFi init's contiguous-DRAM budget.

Net cost: ~13 KiB BSS + ~80 B heap (semaphore) + ~+4 KiB on wg_tx
task. Net runtime allocation: zero — once boot completes, neither
the persistent task nor the path probe touches the allocator.

The DERP-relay fallback that upstream tailscale's `addrForSendLocked`
provides (send to both direct + DERP while trust expires) is NOT in
this PR — it depends on M5-step-3 work (wiring DERP-relayed traffic
back into wg_demux from the supervisor task). The path-stale probe
already cuts recovery from ~9 min to <10 s in the validation
capture, so the DERP fallback is a longer-tail enhancement.

### Performance + power round (2026-05-10)

Five consecutive PRs took the firmware from the M7-close baseline to a
constant-time, light-sleep-managed, QIO@80, -O2 build. Aggregate cost
~+13 KiB flash; 26 % of the app partition still free. RAM unchanged.
The 60-min mega-ping regression gate (3.86 % loss / 154 ms avg from
M5) is preserved on every PR; on-device captures show 0 bcn_timeout,
0 wifi disconnects, 0 panics, and exact 5 s telemetry cadence after
each flash.

- **`-O2` per-component (PR #65, commit `86c04d3`).** Override the
  global `CONFIG_COMPILER_OPTIMIZATION_DEBUG=y` (`-Og`) for the
  perf-critical components only via
  `target_compile_options(${COMPONENT_LIB} PRIVATE -O2)`:
  `components/tinylink` (WG transport, ChaCha20-Poly1305, Curve25519,
  BLAKE2s, HKDF, DISCO/STUN/DERP codecs, netif fast path),
  `main` (app_main + app_wifi + app_nvs), and the IDF `mbedcrypto`
  library target (mbedtls's symmetric/asymmetric primitives;
  `mbedtls` + `mbedx509` left at default — bulk of their code is
  parsing/validation on cold TLS paths, and HW SHA/AES/MPI paths are
  already enabled separately in sdkconfig.defaults). Everything else
  (lwIP, esp_wifi, esp_phy, bootloader) stays at the global default,
  which scopes the documented toolchain hangs around certain lwIP
  files at -O2 out of the build. Drive-by fix in
  `main/app_wifi.c`: -O2 enables `-Wstringop-truncation` which trips
  on `strncpy(dst, src, sizeof(dst))` for the SSID/password load even
  though `app_nvs_read_str()` guarantees a NUL-terminated src.
  Replaced with `memcpy + strnlen` (bounded copy, zero-padded tail
  from the `{0}` initializer). Cost: +2.3 KiB flash from more
  aggressive inlining/unrolling.

- **`FREERTOS_HZ` 1000 → 100 (PR #64, commit `e19ccb3`).** The IDF
  default 1 ms tick is overkill for tinylink — no code path uses
  sub-100 ms delays. Lower tick-ISR overhead and deeper tickless idle
  entries. Audited before flipping: every `pdMS_TO_TICKS(N)` callsite
  in `components/tinylink/src` + `main/` uses N ≥ 100 ms (TMP117
  probe 500, TELEMETRY_PERIOD 5000, REGISTER_RETRY 30000,
  STUN_REPROBE 300000, derp-supervised backoff base, `step_ms=100`,
  plus literals 100/500/2000/8000/30000), 0 raw integer tick
  arguments to `vTaskDelay` / `xQueue*` / `xSemaphoreTake` in our
  code, 0 references to `configTICK_RATE_HZ` / `portTICK_PERIOD_MS`.
  Cost: +128 B flash (symbol-table variance only).

- **Flash mode `QIO@80MHz` (PR #63, commit `28cb49b`).** Flip
  `CONFIG_ESPTOOLPY_FLASHMODE_DIO`+`FLASHFREQ_40M` to
  `_QIO`+`FLASHFREQ_80M`. Per the WROOM-32E datasheet Table 17
  (Espressif v2.0 oct-2025), the integrated flash is guaranteed at
  80 MHz FC "through design and/or characterization" — pre-
  characterized by Espressif for this configuration, so no soak
  required for this specific module. Boot log on this device
  (rev v3.1) confirms `qio_mode: Enabling default flash chip QIO` +
  `SPI Speed: 80MHz` + `SPI Mode: QIO`; the "default flash chip QIO"
  path means the bootloader matched the chip via the fallback entry
  in IDF's `bootloader_flash_qe_support_list_default`
  (`flash_qio_mode.c:48` in v5.5.4), known-good for GigaDevice /
  FM25Q32 / BY25Q32. Effective flash-read bandwidth goes from
  ~40 Mbit/s (DIO@40, quad SPI lanes idle) to ~320 Mbit/s peak
  (QIO@80, all 4 lanes saturated for reads). Cost: −144 B flash
  (header bits change, no code change).

- **`esp_pm_configure` + `WIFI_PS_MIN_MODEM` (PR #62, commit
  `c63ce2c`).** Enable runtime light-sleep tickless idle by calling
  `esp_pm_configure(.light_sleep_enable=true, max=240, min=80)`
  AFTER `app_wifi_wait_connected()`, plus
  `esp_wifi_set_ps(WIFI_PS_MIN_MODEM)` in `app_wifi_start()`. IDF
  source review (`esp_pm/pm_impl.c:561, :829`) proved that
  `CONFIG_PM_ENABLE=y` + `CONFIG_FREERTOS_USE_TICKLESS_IDLE=y` alone
  were inert: without `esp_pm_configure(light_sleep_enable=true)`,
  `s_light_sleep_en` stays false, `pick_mode()` never returns
  `PM_MODE_LIGHT_SLEEP`, and `vApplicationSleep` short-circuits via
  `should_skip_light_sleep()`. The post-wait_connected ordering is
  critical — calling `esp_pm_configure` before assoc reproduces the
  disconnect-retry-loop seen in the previous perf round (the AP
  kicks the client because tickless idle puts the chip to sleep
  mid-AUTH/ASSOC, which the AP reads as missed beacons). Also
  confirmed empirically that `CONFIG_ESP_WIFI_SLP_IRAM_OPT`
  (auto-selects `PM_SLP_DEFAULT_PARAMS_OPT`) breaks initial
  association on WPA2-PSK+PMF AP regardless of any
  `esp_pm_configure` call — flag stays disabled in
  `sdkconfig.defaults` until A/B on a less strict AP. Cost:
  +2.2 KiB flash (esp_pm + sleep_modem infrastructure).

- **Constant-time `curve25519-donna` (PR #61, commit `dd6427a`).**
  Swap TweetNaCl-derived X25519 reference impl for
  `agl/curve25519-donna` (BSD-3, Google, ~860 LoC 1:1 upstream).
  Donna is the canonical constant-time 32-bit X25519 and is the
  right fit for Xtensa LX6. Motivation: the long-term MachineKey
  private key feeds every ts2021 Noise IK handshake (DH e/s and s/s)
  and every WG `handshake_init` (DH e/s, s/s). TweetNaCl's
  Montgomery ladder uses `sel25519` (constant-time cmov), but its
  M/S limb arithmetic has data-dependent timing in the carry path
  that has not been audited against the modern timing-channel
  literature. `curve25519.c` becomes a 70-line shim that delegates
  `scalarmult` to `curve25519_donna()` and keeps clamping +
  low-order rejection + keypair + derive_pub helpers; API
  unchanged. RFC 7748 §5.2 (two single-scalarmult vectors) + §6.1
  (DH round-trip Alice↔Bob) pass in `test_curve25519`; full host
  KAT battery 452 OK / 0 FAIL (matches post-#58 baseline). Cost:
  +8.6 KiB flash (~+0.7 %), constant-time MachineKey scalarmult on
  every Noise IK / WG handshake. The mbedTLS HW-MPI alternative was
  rejected after IDF source review: only `MBEDTLS_MPI_MUL_MPI_ALT`
  applies on ESP32 (`ESP_MPI_USE_MONT_EXP` keeps `exp_mod` in SW
  because IDF docs the ESP32 RSA peripheral as "slow for public key
  ops"), and no `_MXZ_ALT` hooks for the Montgomery-curve operations
  are defined in `port/mbedtls/esp_config.h` — the win vs donna
  pure-C would be small and would cost `MBEDTLS_ECP_C` + `_ECDH_C`
  flash.

### Security
- **DISCO replay window — fixes WireGuard endpoint hijack DoS.** NaCl
  box (XSalsa20-Poly1305) is a stateless AEAD: `nacl_box_open(peer_pub,
  my_priv, nonce, ct)` is deterministic. `wg_netif::handle_disco_direct`
  used a successful `disco_open` plus a DiscoKey match as sufficient
  authorisation to roam `g.peer.peer_endpoint_*` to the source AddrPort
  of the inbound frame, applying both to PING (line ~471) and PONG
  (line ~502) branches under the same `roam_allowed` gate. An attacker
  who passively captured one DISCO PING or PONG (peer→tinylink) could
  replay the bytes from a spoofed/owned source AddrPort and force the
  WireGuard transport target to that AddrPort — black-holing outbound
  WG transport, while the rx_task source filter (`wg_netif.c:556-561`)
  silently dropped legit peer's WG packets from the original AddrPort.
  Capture surface includes both peer-initiated PINGs AND peer-side
  PONGs answering tinylink's own prepunch/CMM PINGs (which fire on
  every netmap arrival), so capture windows recur ~1-2/min in steady
  state. Fix: new `disco_replay.{c,h}` module — sliding window of last
  128 nonces seen on inbound DISCO frames (~3 KiB BSS).
  `handle_disco_direct` consults it post-decrypt, before any side-effect
  (no roam, no Pong emit on replay). Host KAT in
  `tools/test/test_disco_replay.c` covers first-arrival, immediate
  replay, distinct-non-collide, ring-buffer eviction, and reset
  semantics. On-device verified with 30 s of normal traffic
  (peer 191.89.194.5:3176 + 192.168.1.38:41641 LAN endpoint,
  ~2-3 PING→Pong/s, all unique txids → all unique nonces → zero false
  positives).
- **`parse_keyed_hex` partial-write hardening (mapreq.c).** On a
  malformed hex nibble at position `k>0`, the parser previously wrote
  bytes `0..k-1` to the output buffer before returning
  `ESP_ERR_INVALID_ARG`. The "Key" → `peer->node_pub` call site at
  `parse_one_peer` ignores the return value, so a malformed control-
  plane MapResponse could land attacker-hex-prefix bytes into the
  WireGuard static peer pubkey. (Mitigated upstream by Noise IK auth
  to the control plane, but defense-in-depth costs nothing.) Now
  decodes into a scratch buffer and `memcpy`s into the caller-provided
  output only on full success.
- **`auth_key` memzero hardened (tinylink.c).** Replaced the post-use
  `memset(auth_key, 0, sizeof(auth_key))` with
  `mbedtls_platform_zeroize` so the compiler cannot eliminate the zero
  as a dead store on a no-longer-read buffer.
- **`register_emit` refuses truncated responses (register.c).** The
  `h2_drive_request` path silently latches
  `conn->h2_resp_overflow=true` when `/machine/register` answers with
  more than `RESPONSE_BUF-1` bytes (`h2_client.c:163-171`). The
  previous code parsed the truncated JSON, where attacker-shaped
  truncation could yield a misleading `MachineAuthorized` verdict.
  Now the overflow flag is checked before `cJSON_Parse` and the
  request is failed with `ESP_ERR_INVALID_RESPONSE`.

### Added
- **RX-stale watchdog + indefinite handshake-burst backoff.** Closes the
  "peer restart silent black-hole" gap that the existing age-based
  proactive rekey at session_age=110 s did NOT cover, plus the
  follow-on "permanent FAILED state" that a long peer outage triggered.
  - `wg_netif.c::handle_transport` now stamps
    `g.last_transport_recv_us` on every successful WG transport decrypt
    (including zero-length keepalives — the watchdog cares about
    session liveness, not payload direction). Initialized at
    `session up` and `session rekeyed` so a fresh session has a 30 s
    grace before the watchdog can fire.
  - rx_task tick: if state == UP and no transport decrypt in
    `WG_RX_STALE_THRESHOLD_MS = 30000`, force a rekey via the same
    make-before-break path as the proactive rekey. Catches "peer
    restarted, our transport keys are now garbage to the peer's fresh
    process" scenarios that the age-based rekey would only notice up
    to 110 s late.
  - **`WG_NETIF_FAILED` is no longer terminal.** Pre-fix, after the
    handshake retry budget (12 × 5 s = 60 s) exhausted, the firmware
    transitioned to `WG_NETIF_FAILED` permanently — required an ESP32
    reboot to recover from a peer outage longer than 60 s. Now,
    exhaustion logs `W handshake budget exhausted ... backing off Ns
    before next burst (peer may be rebooting)`, sleeps
    `WG_HANDSHAKE_BACKOFF_MS = 30000`, and starts a fresh burst.
    Repeats indefinitely. Recovery is fully autonomous regardless of
    peer outage length. The `WG_NETIF_FAILED` enum value is retained
    for forward compat / external-API stability but is unreachable in
    current code.
  - Empirical validation, `sudo reboot` of Servidor1 (~216 s downtime
    incl. BIOS+kernel+services):
      - Pre-fix (E.1): watchdog detected, rekey budget exhausted,
        cold-handshake budget exhausted, state = FAILED, telemetry
        `sendto failed errno=-1` continuous. Required ESP32 power-cycle.
      - Post-fix (E.2): proactive rekey exhausted at firmware time
        t=275 s → backoff 30 s → new burst at t=307 s → `session up`
        at t=335 s (attempt 6 of new burst). 27 telemetry packets lost
        during ~130 s observable outage; cadence resumed at seq=63
        within 4.3 s of `session up`. Zero ESP32 intervention.

### Added
- **Pre-punch on netmap-receive + WG endpoint roaming via DISCO.** Two
  coupled changes that together close the cold-start "direct connection
  not established" QoL gap (the first 3-DERP-rounds-then-direct
  observation in `docs/ROADMAP.md`).
  - On every non-KeepAlive netmap arrival,
    `prepunch_pings_to_peer_endpoints` (in `tinylink.c`) sends a sealed
    DISCO ping to every v4 endpoint advertised for every peer. This
    opens or refreshes our NAT mapping proactively, so the very first
    inbound packet from any peer finds an open path instead of the
    closed one that was the symptom previously. Boot evidence: 11 pings
    fan-out across 3 peers ~1.5 s after `netmap (initial)`; Servidor1
    starts replying with direct DISCO pongs ~9 s after that.
  - `handle_disco_direct` (in `wg_netif.c`) now promotes the *src*
    AddrPort of any DISCO ping/pong sealed by the WG peer's DiscoKey to
    `g.peer.peer_endpoint_v4_be`+`peer_endpoint_port`. Prior code only
    accepted `wg_netif_update_peer_endpoint` from netmap-driven
    `pick_peer_endpoint` — the netmap-picked address is often a stale
    public NAT mapping, so peer-side ICMP echo requests came in via
    direct UDP but our echo replies went to the netmap endpoint and got
    dropped or DERP-relayed. The roam migrates WG transport to the
    verified-working AddrPort. Gated by DiscoKey: only frames from the
    WG peer's DiscoKey trigger roaming, so other Tailscale peers in the
    netmap (e.g. a laptop with its own NodeKey) cannot flap our WG
    transport target.
  - To enable the gate, `struct wg_netif_peer_config` gained
    `peer_disco_pub[WG_KEY_LEN]` + `has_peer_disco_pub`; sourced from
    `tl_peer_t::disco_pub` in `wg_dataplane.c`.
  - Empirical results (Servidor1 → ESP32 ICMP, 38-min mega-ping
    n=2301): 4.95 % loss, 23 ms min RTT, 147 ms avg, 2071 ms max,
    170 ms mdev. Compare to prior IS_PPP+no-prepunch baseline: 4.2 %
    loss, 156 ms avg, 60 ms mdev (n=71, ~1 min). Compare to no-IS_PPP
    without prepunch (C.9, n=3445, 60 min): 3.86 % loss, 154 ms avg,
    243 ms mdev, 4847 ms max. Net effect: avg RTT slightly lower
    (direct UDP latency vs DERP+) and max RTT cut by 57 % vs the
    pre-prepunch 60-min run.
  - 30-min firmware-side capture during the mega-ping shows: 0 panics,
    0 `tx queue full`, 0 `sendto failed` (steady state), 0 `endpoint
    roam` events after boot lock-on (gate keeps the endpoint stable),
    667 successful DISCO direct pong exchanges with Servidor1, 16
    successful proactive rekeys, 360 telemetry tx (5 s cadence
    preserved across all rekey cycles).

### Changed
- **WG netif no longer fakes PPP** (already on this branch since commit
  `4a915df`, called out here for completeness). Replaced
  `ESP_NETIF_FLAG_IS_PPP` + `ESP_NETIF_NETSTACK_DEFAULT_PPP` with a
  custom static `s_wg_netstack_config` whose `init_fn` performs the
  full netif setup (mtu / output / linkoutput) inside the
  `netif_add()` callback rather than in `wg_lwip_attach()` (which
  would have its work zeroed by `netif_add()` line 321-339 before
  `init_fn` runs). `netif_set_up()` / `netif_set_link_up()` are
  intentionally NOT called from `init_fn` — they are deferred to
  post-`esp_netif_action_start()` because firing
  `LWIP_NSC_STATUS_CHANGED` on a netif not yet linked into
  `netif_list` (line 437-438 of `lwip/.../netif.c`) caused 23 % ICMP
  loss and 1760 ms avg RTT in earlier iterations.
  - **Requires** the two patches in `idf-patches/` applied to ESP-IDF
    (whitelist+null-guard for `dhcp_ip_addr_store` against non-DHCP
    custom netifs). Building against stock IDF panics in
    `dhcp_state.c:52` from the lwIP task at WG bring-up.
  - Net runtime improvements: -3 KiB binary (PPP/LCP/FSM linker-
    dropped), +4.4 KiB heap free at boot (no `ppp_pcb`),
    `stun_reprobe` task spawn succeeds first try (vs failure +
    30 s retry under IS_PPP heap pressure pre-`#34`).

### Fixed
- **`CONFIG_TINYLINK_TELEMETRY_DEST` default points at a real tailnet
  peer.** The Kconfig default was `100.64.0.1:9000`, a placeholder IP
  in the `100.64.0.0/10` CGNAT range that wasn't assigned to any
  device — telemetry datagrams were dropped at the tailnet routing
  layer (no peer claimed the address) before reaching anyone, so a
  fresh build would silently emit into a black hole. Updated to
  `100.88.250.54:27821`, the actual tailnet IP of the receiving host
  in the reference deployment. Port moved off `9000` (already in use
  on the receiver) to `27821`: `> 9000` and below the Linux ephemeral
  range (`32768-60999`), so the receiver's bind survives daemon
  restarts without colliding with a transient outbound socket. Also
  fixed an internal comment in `long_poll_handler` that referenced
  `100.64.0.1` as a stand-in for "the telemetry destination" —
  replaced with generic "tailnet IP" since the comment was about WG
  route ordering, not the specific destination. Verified end-to-end
  on hardware: serial log shows `telemetry → 100.88.250.54:27821
  every 5000 ms` followed by `tx seq=N temp=...°C (47 B)` lines from
  `seq=2` onwards (`seq=0/1` fail with `errno=-1` while the WG
  dataplane is still coming up — known boot transient covered by the
  surrounding `s_dataplane_started` gate). On the receiver,
  `tcpdump -ni tailscale0 udp port 27821` captures
  `100.67.60.92.<port> > 100.88.250.54.27821: UDP, length 47` with
  the same JSON `{"host":"sensor-cali","seq":N,"temp_c":29.250}`
  emitted by the firmware, at exactly 5 s cadence. Downstream
  consumers of the UDP path (e.g. `sensor_app` running with
  `PRIMARY_TRANSPORT=udp`) must align `UDP_BIND_HOST=100.88.250.54`
  and `UDP_BIND_PORT=27821` in their `.env` to match.

### Changed
- **STUN re-probe now runs via the live WG socket** (was: ephemeral
  socket). Pre-fix `stun_probe_run` opened its own UDP socket whose
  source port differed from `g.sock`'s; the public AddrPort the STUN
  server learned therefore couldn't be advertised to peers (their
  DISCO punches would land on a closed port). Symptom on hardware:
  `tailscale ping` reverted to `via DERP(...)` after a NAT rebind even
  though ICMP kept working (Servidor1 learns the live port from the
  source of `HANDSHAKE_INIT`, refreshed every 110 s by the proactive
  rekey). Fix splits send/recv across the existing tasks: the reprobe
  task `sendto`s the STUN binding request directly on `g.sock` (lwIP
  `sendto` is thread-safe, no ownership transfer); `rx_task` already
  classifies `WG_DEMUX_STUN`, now dispatches the response to a
  callback registered via the new `wg_netif_set_stun_callback()`. The
  callback parses, matches the in-flight txid, and signals a
  semaphore. Zero packet loss in the dispatch path (RX task keeps
  decoding DISCO + WG transport normally), no race (only one
  recvfrom-er still). On endpoint change, a one-shot
  `tinylink_ep_push` task (24 KiB stack) opens its own ts2021
  channel, fires `mapreq_push_endpoints`, and exits — keeps the
  long-poll's `s_conn` untouched. Also: `wg_demux_classify` upgraded
  to detect STUN by the magic cookie at offset 4 (RFC 5389 §6),
  catching both binding requests and responses (the prior shape only
  caught requests; a STUN response with byte 0 = 0x01 collided with
  WG `MSG_RESPONSE` and got DISCARDed). Verified on hardware: 7-min
  capture shows `stun re-probe ok via wg socket: 190.109.12.37:53174`
  (the WG socket's actual port), 3 clean rekey cycles, 80 telemetry
  packets uninterrupted, 0 crashes. Removes the *"followup PR
  re-probes via wg socket"* TODO from `tinylink.c`.

### Security
- **Constant-time disassembly review of crypto primitives.** Walked
  the post-#51 compiled `.o` for `chacha20`, `chacha20poly1305`,
  `blake2s`, `curve25519`, `poly1305_donna` with
  `xtensa-esp-elf-objdump -d -S`. All hot paths — including the
  high-risk `poly1305_finish` mask select (`g[i] &= mask; h[i] = (h[i]
  & ~mask) | g[i]`) and `sel25519` — confirmed branch-free at the ASM
  level: the optimizer respected the constant-time idioms in source.
  One residual finding, low severity: `poly1305_finish`'s 64-bit
  add-with-carry compiles to four `bgeu` carry-detect branches on
  Xtensa LX6 because the ISA has no add-with-carry instruction. Leak:
  ~4 bits per MAC; the WG key rotates every 110 s (initiator-side
  proactive rekey from PR #46), so the attack window per key is
  small. Documented in `docs/SECURITY-MODEL.md` § "Constant-time
  review (M7-6, post-AEAD-perf-sprint)" with the branch-free carry
  idiom that would close it if a future deployment needs a stricter
  side-channel posture. Closes M7 within the in-scope items; eFuse-
  NVS-encryption and Secure-Boot V2 are intentionally out of scope
  for this project (irreversible per-device operations) — see
  `docs/ROADMAP.md` § "M7 — Hardening".

### Added
- **TAI64N handshake-timestamp persistence across reboots.**
  `wg_proto.c::wg_tai64n_now` previously fell back to
  `monotonic_seconds()` whenever wall-clock was unset (no SNTP yet);
  every reboot rewound that to 0, so the next handshake's TAI64N
  timestamp could be lower than the value the responder saw before
  the reboot, and the responder rejected the handshake as
  out-of-order. New shape: `wg_tai64n_init(floor, reservation,
  persist_fn)` installs a persisted seconds floor at boot;
  `wg_tai64n_now` clamps emitted seconds to `floor + 1` minimum and
  asks the orchestration layer to extend the reservation forward by
  `WG_TAI64N_RESERVE_CHUNK_SECS` (1 day) when needed. New
  `tinylink_tai64n_floor_init()` (public API) reads the floor from
  NVS namespace `tl_state` key `tai_floor`, pre-reserves a chunk
  forward, and persists it so a subsequent reboot reads it back.
  `main.c::bringup` invokes it between `tinylink_init` and the first
  WG handshake. NVS write cost: one per boot (the pre-reserve);
  inline extends from `wg_tai64n_now` only fire if a single boot
  session emits past 1 day of seconds. Verified on hardware across
  three sequential resets: NVS chained 86400 → 172800 → 259200 →
  345600 (Δ = chunk exact every time). Fail-soft: NVS errors fall
  back to legacy unprotected behavior so a transient NVS issue
  doesn't brick boot. Fourth M7 hardening item.

### Fixed
- **`stun_reprobe` task spawn now retries on `ESP_ERR_NO_MEM`.**
  Previously, if the boot-time `xTaskCreate(stun_reprobe_task)` failed
  due to a low largest-contiguous-heap-block at boot (typical: ~3.5 KiB
  free during the supervisor TLS handshake transient, below the
  4 KiB+TCB requirement), `tinylink_stun_reprobe_start` logged
  `"continuing static"` and silently dropped the re-probe. The
  endpoint pushed at boot then stayed stale forever, and any later NAT
  rebind broke the direct-UDP path with no recovery — observed on
  hardware as `tailscale ping` reverting to `via DERP(...)` after
  router-side port rotation. Fix: schedule an `esp_timer` one-shot at
  +30 s on spawn failure; the callback retries `xTaskCreate` and
  reprograms itself if still failing. Verified on hardware: failed at
  t=18 s with `largest_block=3456 B`, succeeded at t=48 s with
  `largest_block=12800 B` once the TLS-handshake transient freed.
  Third M7 hardening item.

### Added
- **Compile-in fallback control plane pubkey
  (`CONFIG_TINYLINK_CONTROL_PUB_FALLBACK_HEX`).** New optional Kconfig
  string (64 hex chars or empty). When set, `control_key_get()` installs
  the fallback as the NVS pin on first boot without contacting the
  network — eliminating the TOFU window where a MITM during the initial
  `GET /key?v=100` could substitute the pin. `control_key_refresh()`
  also refuses any fetched key that disagrees with the fallback, closing
  the malicious-refresh vector after first boot. Resolution order is
  now: NVS pin (operator-accepted) → compile-in fallback (production
  pin) → TOFU via `/key` (legacy, logs a loud WARN). Empty fallback
  preserves the previous TOFU behavior so existing development
  `sdkconfig` files keep working unchanged. Second M7 hardening item.

### Changed
- **DERP supervisor reconnect backoff is now exponential, capped at 30 s.**
  `tinylink.c::derp_supervised_task` previously slept a fixed
  `CONFIG_TINYLINK_DERP_SUPERVISED_BACKOFF_MS` (default 15 s) between
  every connect failure, hammering a downed server at the same rate
  whether it was the first failure or the hundredth. New behavior: the
  Kconfig value is the *base* delay; the supervisor doubles it on every
  consecutive failure up to a hardcoded 30 s cap, and resets to base on
  a successful login. The Kconfig help text is updated to reflect the
  new shape; the symbol name is unchanged so existing
  `sdkconfig.defaults` overrides keep working. First M7 hardening item
  (see `docs/ROADMAP.md` § "M7 — Hardening").

### Fixed
- **WG session expiry at exactly 180 s of inactivity.** Symptoms: ICMP
  from a peer to the device's CGNAT IP started failing 100 % at
  `icmp_seq=181`; `tailscale ping` reactivated the path because DISCO
  forced new outbound traffic; ping then worked again until the next
  180 s window. Root cause: the device is initiator-only by design
  (incoming `HANDSHAKE_INIT` is dropped — `wg_handshake.h:5-7`), so
  when the responder hits `REKEY_AFTER_TIME = 120 s` and tries to
  rotate, its INIT goes nowhere; at `REJECT_AFTER_TIME = 180 s` the
  responder invalidates our transport keys and our outbound enters a
  silent black hole (`g.state` is still `UP`, but the responder
  drops every encrypted packet). Fix: proactive rekey on the
  initiator side. A new timer in `wg_netif.c::rx_task` fires
  `start_rekey()` once session age exceeds `WG_REKEY_AFTER_MS`
  (110 s, slightly before the responder's 120 s mark). The rekey is
  make-before-break — `g.state` stays `UP` and the existing
  `g.transport` keeps serving traffic until
  `handle_handshake_response` swaps in the new keys via
  `wg_transport_session_init`. If the rekey exhausts its 12-attempt
  retry budget (60 s) we fall back to a cold handshake before the
  180 s mark so we never silently zombie. Verified on hardware:
  6 consecutive 110 s rekey cycles, 0 retries, 0 fallbacks, telemetry
  cadence unbroken across each rekey (tx seq deltas held at 5003 ms).
  Responder-mode is no longer needed for steady-state operation; it
  remains a follow-up for peer-roaming corner cases where the peer
  endpoint changes mid-session and only the peer can re-initiate.

### Added
- **M3 first cut: TMP117 telemetry over UDP-through-WG.**
  - New `tmp117.{c,h}`: I²C driver using IDF v5.5
    `driver/i2c_master.h`. Reset-default CONFIG (continuous, AVG=8) is
    fine, so we only read TEMP_RESULT (and DEVICE_ID at init for a
    fast-fail wiring check). Result is reported in milli-°C using the
    documented 7.8125 m°C/LSB scale.
  - New `telemetry.{c,h}`: 4 KiB-stack FreeRTOS task `tinylink_tlm`
    that periodically reads the sensor and emits a JSON datagram
    `{"host","seq","temp_c"}` to `CONFIG_TINYLINK_TELEMETRY_DEST`
    over UDP. The socket binds to the default route, which is the WG
    netif once `tinylink_dataplane_start()` has run, so packets reach
    the home peer end-to-end.
  - New Kconfig submenu `Telemetry (M3)` exposes I²C pin selection,
    sensor address, sample period, destination IP:port, and a
    compile-time enable/disable so boards without a TMP117 still
    build and run.
  - New public API `tinylink_telemetry_start()`; `main.c` calls it
    after the long-poll task is up.
  - Build size: `tinylink.bin` 0x118d10 → 0x11e890 (+22 KiB).

- **M2 long-poll MapRequest stream.**
  - `h2_client` now exposes `h2_post_json_stream(...)` that invokes a
    per-chunk callback; the one-shot `h2_post_json` and the streaming
    variant share an internal driver.
  - `mapreq_run_stream()` POSTs `/machine/map` with `Stream:true` and
    walks the upstream `LE32 size || body` framing
    (`tailscale/control/controlclient/direct.go:~1248`). KeepAlive
    messages are absorbed; non-KeepAlive messages are parsed into a
    `tl_netmap_t` and dispatched to a caller-supplied handler.
  - `wg_dataplane_update_peer()` compares the new endpoint against the
    currently-configured one and reconnects WG only if it changed.
  - New public API `tinylink_long_poll_start()` spawns an 8 KiB-stack
    FreeRTOS task `tinylink_lp` that drives the loop indefinitely and
    reconnects (with the existing `CONFIG_TINYLINK_REGISTER_RETRY_MS`
    backoff) on stream EOF or transport error. `main.c` invokes it
    after the data plane is up.
  - Build size: `tinylink.bin` 0x1182e0 → 0x118d10 (+2.6 KiB).

- **M2 first-cut data plane: WireGuard via `trombik/esp_wireguard`.**
  - Added `trombik/esp_wireguard@0.9.0` (BSD-3) as a managed component
    in `main/idf_component.yml`.
  - New `wg_dataplane.{c,h}` shim translates `tl_netmap_t` →
    `wireguard_config_t`: base64-encodes the device NodePrivate and the
    peer's NodePublic, splits `Node.Addresses[0]` into local IP +
    netmask, splits `Peers[0].Endpoints[0]` into host + port, then
    drives `esp_wireguard_init` + `esp_wireguard_connect`. 25-second
    persistent keepalive is enabled until DISCO takes over keepalive
    duty in M3.
  - New public API `tinylink_dataplane_start()` opens a fresh ts2021
    channel, calls `mapreq_fetch_once()`, and brings up the WG netif
    against the first peer announced. `main.c` invokes it after
    `tinylink_register()` succeeds.
  - The `wireguardif.c` UDP-socket-sharing patch (so DISCO/STUN can
    multiplex on the WG socket) is intentionally deferred to M3 — until
    DISCO actually needs the same socket, the upstream
    `udp_bind(IP_ADDR_ANY, port)` is fine.
  - Build size: `tinylink.bin` 0x111a50 → 0x1182e0 (+25 KiB).

- **M2 scaffolding: `MapRequest` + `MapResponse` parser.**
  - Vendored `jsmn` (single-header zero-alloc tokenizer, MIT, ~350 LoC)
    at `components/tinylink/src/jsmn.h`.
  - `tl_netmap_t` (`netmap.h`) holds the M2 working set: self addresses,
    up to 4 peers (`{ID, NodeKey, DiscoKey, Addresses, Endpoints,
    HomeDERP}`), and up to 4 DERP regions. v6 entries are dropped at
    parse time since the lwIP netif is v4-only.
  - `mapreq_fetch_once()` POSTs `/machine/map` with `Stream:false` and
    `Compress:""`; the server replies with a single `MapResponse` and
    closes the stream. The `Stream:true` long-poll form lands alongside
    the WireGuard bringup.
  - `mapresp_parse()` is platform-independent and runs under a host KAT
    (`tools/test/test_mapresp.c`) that exercises a one-peer +
    one-DERP-region stub.

### Performance
- **ChaCha20-Poly1305 AEAD: ~10% faster encrypt and ~12% faster decrypt
  on 1500 B payloads on ESP32 LX6.** Three changes in
  `components/tinylink/src/crypto/`:
  1. `chacha20.c`: keystream/plaintext XOR loop in `chacha20()` and the
     16 keystream stores in `chacha20_block()` now go through
     `__builtin_memcpy` of `uint32_t` chunks instead of byte-by-byte.
     `output[CHACHA20_BLOCK_SIZE]` is `__attribute__((aligned(4)))` so
     the compiler folds these to single `l32i`/`s32i` on Xtensa.
  2. `poly1305_donna_32.h`: `U8TO32` rewritten as `__builtin_memcpy`.
     Compiler emits `l32i` when alignment is provable (the
     leftover-completing call always passes `st->buffer`, which is
     4-aligned) and falls back to the original byte path otherwise.
     Strict-aliasing-safe by construction.
  3. `chacha20.c`: `U8TO32_LITTLE` / `U32TO8_LITTLE` macros switched to
     `__builtin_memcpy`; `chacha20_init` now bulk-copies the 32-byte
     key into `state[4..11]` so GCC schedules the loads/stores
     interleaved instead of expanding 8 separate macro instances.
- **Bench harness.** New `CONFIG_TINYLINK_BENCH_AEAD` (off by default)
  builds an opt-in micro-bench (`components/tinylink/src/tinylink_bench.c`)
  that times encrypt + decrypt over 64 B and 1500 B payloads with
  `esp_timer_get_time()` and verifies a round-trip before reporting
  numbers. Used to measure the changes above; left in place as the
  reference for future crypto work.
- Measured on Freenove ESP32-WROOM-32E, ESP-IDF v5.5.4, `-Os`:
  enc 739→659 µs, dec 740→654 µs at 1500 B. Variance run-to-run is
  ~1-2 % on MTU; treat sub-3 % deltas as noise.

### Fixed
- **ts2021 wire format corrected against upstream.** Initial implementation
  put the Noise IK msg1 in the HTTP body and used a 4-byte invented frame
  header. After cross-checking `tailscale/control/controlbase/messages.go`,
  `controlhttp/client.go`, and `control/ts2021/conn.go`:
  - The 101-byte initiation frame now travels base64-encoded in
    `X-Tailscale-Handshake`, with `Content-Length: 0` on the upgrade.
  - Initiation header is 5 bytes (`BE16 version || type(1) || BE16 len`);
    all subsequent records are 3 bytes (`type(1) || BE16 len`).
  - Frame types pinned to `1=initiation / 2=response / 3=error / 4=record`.
  - Noise prologue is the **string** `"Tailscale Control Protocol v1"`,
    not the byte `0x01` (that byte appears only in the cleartext header).
  - Optional EarlyPayload sentinel (`"\xff\xff\xffTS"` + BE32 len + JSON)
    is drained and discarded; upstream never acts on it either.
- **`/machine/register` body fixes.** `Version` changed from `100` to `1`
  (the Noise transport `CapabilityVersion`, not a marketing version);
  `NLKey` added as required `"nlpub:" + 64 zeros` (TKA disabled);
  `NodeKeySignature` removed (only set for TKA pre-auth flows upstream).

### Changed
- **Milestone 1 redefined.** The original M1 was "static WireGuard against a
  fixed peer + TMP117 telemetry over UDP." It is now "ts2021 control plane:
  the device registers with `controlplane.tailscale.com` and shows up in the
  Tailscale admin panel as an online node." There is no data plane in the
  new M1 — that returns in M2 alongside MapResponse.
- Roadmap shifted: M2 = MapRequest streaming + WireGuard data plane,
  M3 = DISCO + TMP117 telemetry, M4 = STUN, M5 = DERP, M6 = hardening.

### Added
- `tinylink` core component now contains the real M1 implementation:
  - Vendored crypto: BLAKE2s (RFC 7693), HMAC-BLAKE2s + HKDF, Curve25519
    (TweetNaCl-derived placeholder, swap with constant-time donna for
    production), Salsa20/HSalsa20/XSalsa20, NaCl-box.
  - Noise IK state machine (`Noise_IK_25519_ChaChaPoly_BLAKE2s`).
  - ts2021 client: TLS to control plane, HTTP/1.1 Upgrade with the
    initiation frame in `X-Tailscale-Handshake`, controlbase 5/3-byte
    framing, post-handshake EarlyPayload drain.
  - HTTP/2 client over the Noise channel via nghttp2
    (`espressif/nghttp`), with HPACK dynamic-table disabled.
  - Control plane public key bootstrap with NVS pinning.
  - `RegisterRequest` builder + response parser.
- `tools/credentials.csv.example` simplified to the M1 set
  (`wifi_ssid`, `wifi_pass`, `auth_key`).

### Removed
- `main/app_wireguard.{c,h}`, `main/app_sensor.{c,h}`,
  `main/app_telemetry.{c,h}`. These return in M2/M3.
- WireGuard-specific entries in `sdkconfig.defaults`.
- `examples/milestone1_static_wg/`, `examples/milestone1_tailscale_peer/`.
  Replaced by `examples/milestone1_register/`.

[Unreleased]: https://github.com/bryamzxz/tinylink/commits/main
