# Roadmap / Hoja de ruta

> Bilingual (EN / ES). Other docs are English-only.

The detailed protocol map and memory/flash budgets that drive the
milestone breakdown below come from a maintainer-private research
artifact (not in the repository and not required to build or contribute).
Citations of the form `[research §X]` point at that document; everything
normative it contained has since been folded into `docs/PROTOCOL.md` and
the `TS2021_VERIFY` comments in the source. Line citations of the form
`tailscale/path/file.go:start-end` point at the upstream Tailscale Go
implementation, which is the authoritative reference for wire format.

## Milestones (high level)

| #  | Name                                          | Status                              | Targeted release | Estimate |
|----|-----------------------------------------------|-------------------------------------|------------------|----------|
| M1 | ts2021 control plane (register only)          | done                                | v0.1             | 2-3 wk   |
| M2 | MapRequest streaming + WireGuard data plane   | done                                | v0.2             | 2-3 wk   |
| M3 | DISCO P2P discovery + TMP117 telemetry        | done — direct UDP + DERP            | v0.3             | 1-2 wk   |
| M4 | STUN minimal binding                          | done — runs on WG socket            | v0.4             | 0.5 wk   |
| M5 | DERP relay + direct-UDP NAT traversal         | done — DISCO punch via CallMeMaybe  | v0.5             | 1-2 wk   |
| M6 | ICMP-over-WG end-to-end                       | done — verified on hardware         | v0.6             | <1 wk    |
| M7 | Production hardening                          | done — within scope (eFuse + secure-boot intentionally out of scope) | v0.7 | landed |
| M8 | Perf + power round (2026-05-10)               | done — PRs #61–#65                   | v0.7             | landed   |
| M9 | Protocol + crypto follow-ups                  | done — PRs #85–#87                   | v0.7             | landed   |
| M10| Perf-trim + footprint round                   | done — PRs #88–#104 (net −68.1 KiB)  | v0.7             | landed   |
| M11| Security round                                | done — PR #105 (WGN-1 writer + 4 hardenings) | v0.7    | landed   |
| M12| Audit-fix round (2026-06-10)                  | done — 6 fixes, HW-validated vs tailscale.com | v0.7   | landed   |
| M13| Control-plane reconnect hardening (2026-07-16)| done — stream idle budget, patch-driven refetch, in-place re-register, wedge restart. Boot smoke + 20-min stream check passed on the deployed sensor 2026-09-04 (checklist items 3–5 still open) | v0.8   | landed   |
| M14| Audit + optimization round (2026-09-04)       | done — endpoint-push stack overflow fixed (task removed, −12.6 KiB BSS), headscale `/key` capver gate, TSMP drop, DERP close race, Xtensa-tuned AEAD, backoff consolidation, provisioning contract, ASan CI. See "M14" + "Improvement list" below | v0.8   | landed   |
| M15| Road-to-100 round (2026-09-04, part 2)        | done — netmap parsed one value at a time (−30 KiB BSS, no tailnet-size ceiling), task WDT for app tasks, capver 142, connect-path stack diet, DERP live relay switch, IP-change recycle + WiFi backoff, conn kept after register, flash trims, 3 new KAT suites, firmware 1.2.0 | v1.2   | landed   |
| —  | Next rounds                                   | queued — see "Execution queue" below (M13 checklist 3–5 → task WDT → SNTP → buffer diet → /stats → OTA; eFuse encryption explicitly out) | —      | queued   |

End-to-end verification on hardware (sensor-cali next to router,
Servidor1 WG peer with public IP):

```
$ tailscale ping sensor-cali        # from Servidor1
pong from sensor-cali (100.67.60.92) via 190.109.12.37:50582 in 403ms
$ ping -c 10 100.67.60.92            # from Servidor1
10 packets transmitted, 10 received, 0% packet loss, time 9008ms
rtt min/avg/max/mdev = 48.916/93.805/141.008/28.296 ms
```

Total realistic timeline to land all of M1–M6 (one engineer
full-time): **8–12 weeks** [research §K]. M7 hardening is
project-lifetime ongoing.

Remaining quality-of-life follow-ups (none blocking the
established direct-UDP + ICMP path):

- ~~**Pre-punch on netmap-receive**~~ — *landed*.
  `prepunch_pings_to_peer_endpoints` (`tinylink.c`) now fires sealed
  DISCO pings to every v4 endpoint of every peer on every non-KeepAlive
  netmap arrival. Combined with WG endpoint roaming via DISCO
  direct-path observation in `handle_disco_direct` (gated by the WG
  peer's DiscoKey so other Tailscale peers in the netmap don't flap
  our transport target), the cold-start `direct connection not
  established` window is closed: 38-min mega-ping from Servidor1
  (n=2301) measured 4.95 % loss / 147 ms avg / 23 ms min RTT, vs the
  prior 100 % DERP fallback observation that motivated this item.
  Empirically Servidor1 starts replying with direct DISCO pongs ~9 s
  after `netmap (initial)` lands at WG bring-up. See `CHANGELOG.md`
  § "[Unreleased] / Added" for the full evidence.
- **WG handshake init delay**: handshake retries 2–5× at boot before
  `session up`, because we fire the init at t≈15s while the peer's
  netmap may not yet contain our current AddrPort. Delaying init
  until the first inbound DISCO observation cuts the retry cost.
- ~~**stun_reprobe → fetch_once trigger**~~ — *landed (initial M5),
  hardened 2026-05-11*. The periodic re-probe runs over the live WG
  socket (`stun_reprobe_via_wg_socket` in `tinylink.c`, dispatched
  through `wg_netif_set_stun_callback()`), so the port it learns is
  the one peers can actually reach. The endpoint push to the control
  plane is now handled by a **persistent** `tinylink_ep_up` task
  (replaces the one-shot pattern that died on a fragmented heap after
  hours of operation — see `CHANGELOG.md` § "Recovery after peer NAT
  rebind"). The persistent worker sleeps on a semaphore, coalesces
  rapid signals via a monotonic gen counter, and uses
  `xTaskCreateStatic` (BSS-backed stack) so it can never fail to
  spawn at boot. Mirrors upstream tailscale's
  `controlclient.Auto.updateRoutine`. See `wg_demux.c` for the
  STUN-response classification fix (magic cookie at offset 4).
- ~~**DISCO-driven path probe on RX-stale**~~ — *landed 2026-05-11*.
  When WG transport stays silent >30 s, `wg_netif`'s rx_task fires a
  registered callback that sends sealed DISCO pings to every known
  peer endpoint. If the peer responds from a different AddrPort
  (post-reboot with a fresh NAT mapping is the common case), the
  existing roaming in `handle_disco_direct` swaps the WG transport
  target to the live address BEFORE the next handshake INIT goes
  out. Cuts recovery-after-peer-NAT-rebind from ~9 min (hammer the
  stale endpoint until a netmap update arrives + prepunch fires) to
  <10 s (one probe burst → pong → roam → INIT lands). Modeled on
  upstream `wgengine/magicsock/endpoint.go::setBestAddrLocked`:
  DISCO pong is the canonical path-liveness signal. Cooldown
  `WG_PATH_PROBE_COOLDOWN_MS = 10 s` bounds the rate during a long
  outage.
- ~~**DERP outbound queue**~~ — *landed (PR #83, 2026-05-12)*. Needed
  only for peers behind shared CGNAT (where direct UDP can never
  punch) or while a direct path is stale. `wg_netif.c` now relays WG
  transport frames out through the supervised DERP session as a
  lossless fallback, mirroring the inbound `wg_netif_inject_packet`
  path. For peers with public IPs the direct UDP path still carries
  all steady-state traffic; the relay only engages on path-stale.
  Forced-flap exercise of this RX-stale branch (iptables-DROP on
  Servidor1) is still pending — see GAP below.
- **Responder-mode handshake**: steady-state session expiry is already
  fixed by initiator-side proactive rekey at session_age=110 s (see
  `ARCHITECTURE.md` § "WireGuard handshake lifecycle"). Responder
  mode is only needed for the peer-roaming corner case where the
  peer endpoint changes mid-session and we cannot reach it to
  re-initiate; in practice peer NAT rebindings are observed
  end-to-end via DISCO and handled by `wg_netif_update_peer_endpoint`,
  so this is a long-tail item rather than a blocker.
- ~~**Peer-restart silent black-hole + permanent-FAILED recovery**~~ —
  *landed*. Pre-fix scenarios that broke the firmware until ESP32
  reboot:
  (a) peer's tailscaled restarts mid-session → its session keys are
  gone but the firmware's age-based proactive rekey only fires at
  110 s, leaving up to 110 s of silent loss;
  (b) peer offline longer than the 60 s handshake retry budget
  (e.g. full OS reboot ~150-180 s) → state went to `WG_NETIF_FAILED`
  permanently. Both fixed in `wg_netif.c`: an RX-stale watchdog
  (`WG_RX_STALE_THRESHOLD_MS = 30 s`) detects "no transport decrypt
  recently" and forces a rekey via the same make-before-break path,
  closing (a). Handshake-burst exhaustion now backs off
  `WG_HANDSHAKE_BACKOFF_MS = 30 s` and starts a fresh burst,
  indefinitely, instead of transitioning to `WG_NETIF_FAILED`,
  closing (b). Empirically: `sudo reboot` of Servidor1 with ~216 s
  of downtime now recovers in ~130 s of observable telemetry outage,
  fully autonomous. See `CHANGELOG.md` § "[Unreleased] / Added" for
  full evidence.

## Future directions

These are bigger-than-QoL extensions that would meaningfully expand
what tinylink can do. They are **not commitments** — they are listed
here so contributors and downstream deployers know where the obvious
extension points are, what dependencies they would need, and what
each one would unlock. None block the current
sensor-→-collector use case; the firmware on `main` is empirically
stable for that workload (see `CHANGELOG.md` for the validation
runs).

Effort is rated as *small* (1-3 days), *medium* (1-2 weeks), or
*large* (≥ 1 month) for one engineer working part-time. Dependencies
are flagged because some items unblock others.

### Streaming JSON parser to eliminate `RESPONSE_BUF_SZ`

**What**: Replace the current `jsmn`-based parser in `mapreq.c` (which
needs the entire MapResponse JSON in a single contiguous buffer
`RESPONSE_BUF_SZ = 32 KiB`) with a streaming parser (yajl, sajson,
or a hand-rolled jsmn-streaming variant). The parser would emit
events as bytes arrive on the long-poll socket, accumulating only the
small fields we actually need (`tl_netmap_t` is ~8 KiB).

**Unlocks**: tailnets larger than ~30 peers / 4 DERP regions without
DRAM pressure. Today the `RESPONSE_BUF_SZ` ceiling caps how large a
MapResponse can be parsed, which indirectly caps `TL_MAX_PEERS = 4`
and `TL_MAX_DERP_REGIONS = 28` — the BSS for those structs is what
lets us allocate `RESPONSE_BUF_SZ` from the heap. Removing the body
buffer frees ~32 KiB of contiguous heap that other paths
(supervisor=y TLS handshake transient, multi-peer tables) currently
contend for.

**Effort**: medium. The parser swap is mechanical; the hard part is
field-by-field re-validation against the host KAT corpus
(`tools/test/test_mapresp.c`), which currently asserts on a fully-
parsed `tl_netmap_t`.

**Dependency**: none — can land standalone. **Unblocks**: Multi-peer
support (below) and PSRAM-free larger tailnets.

### Multi-peer support

**What**: Generalize `wg_netif.c::g.peer` (single struct) to a peer
table indexed by NodeKey. Each entry needs its own
`wg_transport_session`, replay window, last_transport_recv_us,
peer_endpoint, and DiscoKey. The netmap-driven update path
(`wg_dataplane_update_peer`) becomes a peer-set diff.

**Unlocks**: any topology beyond sensor-→-single-collector. Notably:
mesh of devices, sensor groups talking to each other for
store-and-forward, or a single device serving multiple downstream
collectors.

**Effort**: large. Touches `wg_netif.c`, `wg_demux.c`,
`wg_dataplane.c`, `wg_lwip.c`, the replay window scheme (would need
RFC 6479 2000-entry sliding windows per peer), the WG endpoint
roaming gate (DiscoKey-keyed lookup instead of single comparison),
and every memory budget decision in `sdkconfig.defaults`. The
streaming JSON parser above is a soft prerequisite — without it the
peer table is BSS-bound to TL_MAX_PEERS = 4.

**Dependency**: streaming JSON parser (soft).
**Unblocks**: Mesh of devices, diagnostics web endpoint serving multiple
viewers, downstream sensor topologies.

### PSRAM support

**What**: Move the heap-heavy components — lwIP pools (`MEMP_*`),
mbedtls handshake transients, WG demux scratch, telemetry queue —
from internal DRAM to PSRAM. ESP-IDF supports `MALLOC_CAP_SPIRAM`
allocation hints; the work is identifying which components benefit
and reconfiguring their alloc policies via Kconfig.

**Unlocks**: `CONFIG_TINYLINK_DERP_SUPERVISED=y` works on every board
regardless of DRAM headroom (today it's gated by the supervisor's
TLS handshake transient holding the largest contiguous block). Also
unlocks the larger BSS budget multi-peer would need.

**Effort**: small (config-level changes) for the easy wins, medium
for the ones requiring code changes (some lwIP pools assume
internal-DRAM access patterns).

**Dependency**: PSRAM-equipped board. **Unblocks**: large tailnets,
multi-peer.

### OTA firmware updates over the tailnet

**What**: Fetch a signed firmware image from a tailnet peer (HTTPS to
a known peer, or DERP-relayed for peers behind CGNAT) using the
existing `esp_ota_*` IDF APIs. Signature verification with a
build-time-burned public key (RSA or ECDSA). On success, swap the OTA
slot and reboot into the new image.

**Unlocks**: closes the "auth-key rotation needs a remote trigger"
gap that currently blocks PR #49's pre-known-control-pubkey provision
mechanism from also rotating the WG/Disco/auth keys. With a signed-
update path, key rotation becomes an OTA-triggered NVS rewrite. Also
unlocks operator-controlled feature toggles without UART access.

**Effort**: medium (esp_ota_* is well-trodden, but the peer-side
signed-image distribution and key management are their own design
problems).

**Dependency**: none for the fetch path; requires operator decision on
how to host signed images.
**Unblocks**: Auth-key rotation API (currently out-of-scope).

### Power management with WG session preservation

**What**: Light-sleep / deep-sleep modes that preserve enough WG
session state across wake to skip the full handshake. Today every
boot pays ~30 s for WiFi associate + ts2021 handshake + first
MapRequest + WG handshake; deep-sleeping for telemetry-idle windows
would reset all of that. The fix: serialize `g.transport` (sender
index, receiver index, send/recv counters, send/recv keys) to NVS
before sleep, restore on wake, and send a "ping" transport packet to
verify the session is still accepted by the peer (handshake fallback
on rejection).

**Unlocks**: battery-powered sensor deployments with multi-day life
on a 2000 mAh cell at 1-minute telemetry cadence. Today the WiFi-up
duration dominates power draw; deep-sleep with preserved session
would cut active time per telemetry cycle from ~30 s to ~200 ms.

**Effort**: medium. Foundation pieces in place: TAI64N persistence
(PR #51) handles the monotonicity invariant across reboots; the
RX-stale watchdog (PR #56) handles peer-side session loss. The new
work is the serialize/restore + verify-ping path in `wg_netif.c`.

**Dependency**: TAI64N persistence (✓ landed in #51), RX-stale
watchdog (✓ landed in #56).
**Unblocks**: battery-powered remote sensors.

### Sensor driver framework

**What**: Refactor `tmp117.c` from a single hard-wired driver into a
small driver framework (init, sample, scale, report) that supports
adding BME280, SCD30, ADS1115, etc. without touching the WG/control-
plane layers. Per-sensor Kconfig + a registry pattern in `main.c`.

**Unlocks**: same firmware base for environmental monitoring, air
quality, soil moisture, etc. Today every new sensor type requires a
firmware fork.

**Effort**: small (driver framework) + per-sensor work (which is
sensor-specific, not tinylink-specific).

**Dependency**: none. **Unblocks**: domain expansion.

### Mesh of devices (sensor ↔ sensor)

**What**: Once multi-peer lands, devices can talk to each other over
their tailnet IPs. Useful patterns: store-and-forward (sensor A
buffers when collector is offline, sensor B picks up when it sees
the collector); voting (3 sensors agree on a measurement before
emitting); local aggregation (5-minute averages computed on device).

**Unlocks**: deployments where collector connectivity is intermittent
(remote sites, mobile collectors) or where local quorum matters
(safety-critical readings).

**Effort**: small once multi-peer is in (the WG plumbing is the same;
the topology logic is a few hundred lines of `tinylink.c`).

**Dependency**: multi-peer support.
**Unblocks**: degraded-mode deployments.

### Diagnostics web endpoint

**What**: A tiny HTTP server on the WG netif (e.g. `mongoose` or
hand-rolled, running at `100.x.y.z:80` on the tailnet IP) exposing
read-only endpoints: `/stats` (heap, rekey count, RX-stale events,
endpoint roam history, telemetry tx counter), `/log/recent` (last N
log lines), `/peer` (current peer endpoint, session age, last
transport recv timestamp). HTML rendering for browser viewing,
`?format=json` for scripts.

**Unlocks**: production debugging without a serial cable. Today
diagnosing a misbehaving deployment requires UART access; a tailnet-
local web endpoint means anyone with `tailscale ssh` to the device's
LAN can see what's going on.

**Effort**: small. Most of the data is already in `wg_netif_*` getters
(rekey count, etc.); the work is HTTP server scaffolding + JSON
serialization.

**Dependency**: none for read-only stats. A write endpoint (toggle
log level, force rekey, etc.) needs auth — would benefit from the OTA
signed-update infrastructure above.
**Unblocks**: production observability.

---

## M1 — ts2021 control plane

EN: The device:
1. Generates Curve25519 identities (MachineKey, NodeKey, DiscoKey) on first
   boot, after WiFi is up so `esp_random()` is a true TRNG, and persists
   them in NVS namespace `tl_keys` [research §L].
2. Bootstraps the control plane public key via `GET /key?v=<capver>`
   (a fixed `v=100` until M14), pins it
   in NVS namespace `tl_pin`. Compile-in fallback pin recommended for
   production (M7).
3. Opens TLS to `controlplane.tailscale.com:443`, sends `POST /ts2021`
   with `Upgrade: tailscale-control-protocol`, `Connection: upgrade`,
   `Content-Length: 0`, and the 101-byte Noise IK initiation frame
   base64-encoded in `X-Tailscale-Handshake`. The Noise prologue is the
   string `"Tailscale Control Protocol v1"` (per
   `tailscale/control/controlbase/handshake.go`).
4. Reads the 101 Switching Protocols response and the controlbase
   `type=2` response frame containing Noise IK msg2, completing the
   handshake.
5. Drains the optional EarlyPayload sentinel (`"\xff\xff\xffTS"` + BE32
   length + JSON of `tailcfg.EarlyNoise`). Its only field is
   `NodeKeyChallenge`, but the upstream Tailscale client never responds
   to it in production (`SealToChallenge` from `types/key/chal.go` is
   only referenced from tests), so tinylink discards it as well.
6. Sends `POST /machine/register` (HTTP/2 inside the Noise channel via
   nghttp2) with the auth key from NVS. `Version` on the wire is `1`
   (the Noise transport `CapabilityVersion`); `NLKey` is sent as
   `"nlpub:" + 64 zeros` until M7 hardening adds real Ed25519
   NLPrivate generation.
7. Reads the response. On `MachineAuthorized=true` the device is registered
   and idle; on `false` it retries on a slow cadence.

ES: Idem traducido. Definitions of done iguales que en EN.

**Done when:** the device shows up in
`https://login.tailscale.com/admin/machines` with hostname `sensor-cali`,
status online, an assigned `100.x.y.z`. Pings to it will not work yet —
M1 has no data plane.

**Known gaps in the current scaffolding** (see follow-up tasks):
- `NodeKeyChallenge` is intentionally not implemented. The upstream
  Tailscale client defines `SealToChallenge` / `ChallengePrivate.OpenFrom`
  in `types/key/chal.go` but never calls them outside tests, so the
  EarlyPayload reaches no caller in production. tinylink mirrors that
  behavior by draining and discarding the sentinel.
- `NLKey` is sent as 32 zero bytes until M7 hardening lands real
  Ed25519 NLPrivate generation; this is tolerated because TKA is off.
- The vendored crypto only has host-side KATs for BLAKE2s and X25519
  today (commit `358297f`). ChaCha20-Poly1305 / Salsa20 / Poly1305 KATs
  are still pending.

## M2 — MapRequest + WireGuard data plane

EN: After register, the same Noise channel transitions into a long-lived
`POST /machine/map` with `Stream: true`. The server streams
newline-delimited `tailcfg.MapResponse` JSON objects [research §I].
Parse with **jsmn** (zero-alloc tokenizer, ~350 LoC), not cJSON DOM —
budget 20 KB SRAM during parse, 4 KB for retained peer state. Disable
zstd by not advertising support (saves ~30 KB flash).

**Step 1 (landed in `feat(m2): scaffolding`):**
- jsmn vendored at `components/tinylink/src/jsmn.h`.
- `tl_netmap_t` defined in `components/tinylink/src/netmap.h` with a
  4-peer / 4-DERP-region budget.
- `mapreq_fetch_once()` does a one-shot `POST /machine/map` with
  `Stream:false` and `Compress:""`; the server responds with a single
  `MapResponse` and closes. Sufficient for bootstrapping the netmap
  while the data plane is being wired up; long-poll `Stream:true`
  follows in step 3.
- `mapresp_parse()` extracts `Node.Addresses`, `Peers[].{ID,Key,
  DiscoKey,Addresses,Endpoints,HomeDERP}`, and `DERPMap.Regions`.
  v6 endpoints/addresses are dropped during parse — the lwIP build is
  v4-only at the netif layer.
- Host-side KAT in `tools/test/test_mapresp.c` parses a stub modeled
  on a real one-peer MapResponse and checks each extracted field.

**Step 2 (landed in `feat(m2): WireGuard data plane via trombik`):**
- Lifted `trombik/esp_wireguard@0.9.0` (BSD-3) as a managed component.
- `components/tinylink/src/wg_dataplane.{c,h}` is a thin shim that
  translates the parsed netmap into the `wireguard_config_t` the
  upstream component expects. Single-peer (`peers[0]`), v4-only,
  25-second persistent keepalive until DISCO takes over.
- New public API `tinylink_dataplane_start()` opens a fresh ts2021
  channel, drives one `mapreq_fetch_once()`, and brings up the WG
  netif. `main.c` calls it after register succeeds.

**Step 3 (landed in `feat(m2): long-poll MapRequest stream`):**
- `h2_client` grew a streaming variant (`h2_post_json_stream`) that
  invokes a per-DATA-frame callback instead of buffering the whole
  body. Common request setup is shared with the one-shot variant.
- `mapreq_run_stream()` POSTs `/machine/map` with `Stream:true`. The
  reply is a sequence of `LE32 size || body` frames (verified against
  `tailscale/control/controlclient/direct.go:~1248`); the chunk
  callback feeds bytes into a tiny state machine that emits one
  parsed `tl_netmap_t` per non-KeepAlive message.
- New public API `tinylink_long_poll_start()` spawns a dedicated
  8 KiB-stack FreeRTOS task (`tinylink_lp`) that runs the long-poll
  loop and reconnects on stream EOF or transport error. Each
  MapResponse fires `wg_dataplane_update_peer()`, which compares the
  new endpoint to the active one and reconnects WG only if it
  changed.

**Deferred to M3 (alongside DISCO):**
- Patch ~50 lines in upstream `wireguardif.c` to accept packets
  injected from a demuxer task rather than via `udp_bind(IP_ADDR_ANY,
  port)`, so DISCO/STUN can share the WG UDP socket. Until DISCO
  actually arrives, the bare bind is fine.

Cookie reply (WG message type 3, XChaCha20-Poly1305) is intentionally
**dropped on receive** and `mac2 = 0^16` always on send — saves ~1-2 KB
flash and removes XChaCha20/HChaCha20 from the binary. This is
spec-compliant.

ES: Mismo contenido, en español a futuro.

## M3 — DISCO + TMP117 telemetry

**Step 1 (landed in `feat(m3): TMP117 driver + UDP telemetry`):**
- TMP117 driver under `components/tinylink/src/tmp117.{c,h}` using
  IDF v5.5's `driver/i2c_master.h`. Reset-default config (continuous,
  AVG=8, ~1 s conversion) is left as-is, so we never write
  CONFIGURATION; we read TEMP_RESULT and convert via the documented
  7.8125 m°C/LSB scale.
- DEVICE_ID probe at `tmp117_init` — wrong wiring or address fails
  fast.
- `telemetry.c` spawns a 4 KiB-stack FreeRTOS task `tinylink_tlm` that
  reads the TMP117 every `CONFIG_TINYLINK_TELEMETRY_PERIOD_MS` and
  pushes a JSON datagram to `CONFIG_TINYLINK_TELEMETRY_DEST` over
  UDP. The destination is expected to be a 100.x.y.z tailnet address
  reachable through the WG netif.
- Public API `tinylink_telemetry_start()`; main.c invokes it after
  the long-poll task is running. Compile-time disable
  `CONFIG_TINYLINK_TELEMETRY_ENABLE=n` collapses the call to a no-op
  for boards without a TMP117.

**Step 2 (landed in PR #42 `feat: direct UDP path end-to-end`):**
NaCl-box DISCO ping/pong on the same UDP socket as WG (multiplexed
by first byte in `wg_demux_classify`: WG types 1-4, DISCO magic
`0x54 0x53 0xF0 0x9F 0x92 0xAC` = "TS💬", STUN `0x00 0x01`). The
RX task in `wg_netif.c` handles WG_DEMUX_DISCO inline via
`handle_disco_direct` — decrypts the NaCl box with the local
DiscoKey, builds a sealed Pong, and `sendto`s it back to the source
AddrPort. Drops `Pong` (we don't track outbound probers) and
`CallMeMaybe` (handled below).

CallMeMaybe handling lives in `tinylink.c::send_disco_pings_to_cmm_endpoints`:
when the DERP supervisor receives a CMM, the device emits a fresh
sealed DISCO Ping via the WG socket to each v4-mapped peer
endpoint advertised in the CMM. Each outbound ping opens the
device-side NAT mapping for that destination so the peer's
simultaneous probe can land on us — that's the NAT-punching pair
that makes the path go "direct" instead of "DERP" in
`tailscale ping`.

Five interlocking conditions had to land together for direct UDP
to work end-to-end (see PR #42 commit message + `reference_tinylink_direct_udp.md`):

1. STUN runs on the WG socket so the advertised port matches the
   WG NAT mapping that keepalives keep pinned.
2. WG_DEMUX_DISCO classified before the peer-source filter so DISCO
   from a non-WG-peer src isn't dropped.
3. MapRequest is `Stream=false && OmitPeers=true` (lite update —
   the only shape modern Tailscale.com persists).
4. `NetInfo.WorkingUDP=true` accompanies the lite update — server
   refuses to propagate Endpoints without this signal.
5. CMM punch handler emits outbound DISCO pings on receive.

Requires no `wireguardif.c` patch; the data plane is in-tree
(`wg_netif.c`) and owns the socket.

## M4 — STUN

EN: 20-byte RFC 5389 binding request to the STUN port of the home DERP
region (3478) at startup. Decode XOR-MAPPED-ADDRESS, stuff the result
into MapRequest.Endpoints. ~50 LoC C. **Skip** all `netcheck` NAT-type
classification, MTU discovery, and DERP latency ranking [research §E].
Re-do only when the UDP 5-tuple changes (~"never" for a stationary
sensor unless the router reboots).

ES: idem.

## M5 — DERP relay + direct-UDP NAT traversal

EN: Minimal DERP client over TLS (HTTP Upgrade), framed as
`type(1) || BE32 length || payload`. Constants in `derp/derp.go`
upstream. Required frames: `FrameServerKey(0x01)`, `FrameClientInfo(0x02)`,
`FrameSendPacket(0x04)`, `FrameRecvPacket(0x05)`, `FrameKeepAlive(0x06)`,
`FramePing(0x0D)`, `FramePong(0x0E)` [research §D]. **Skipped**:
WatchConns / ForwardPacket / ClosePeer (mesh / admin only),
`FrameHealth` (log-only), `CanAckPings` negotiation (always respond).

`tinylink.c::derp_supervised_task` keeps a long-lived TLS upgrade
to the `PreferredDERP` region's first node (selected from the netmap
on initial bringup; `update_derp_host_from_netmap` switches if the
control plane reroutes). On `DERP_EVT_RECV_PACKET` the task hands
the relayed frame to `handle_disco_relayed`, which:

- DISCO Ping → sealed Pong via the same DERP route.
- DISCO CallMeMaybe → outbound DISCO ping per advertised v4-mapped
  endpoint via the WG socket (`send_disco_pings_to_cmm_endpoints` —
  the NAT-punching pair to peer's simultaneous probe).
- Anything else (WG transport, handshake response over relay) →
  `wg_netif_inject_packet` so it traverses the same demux + handler
  chain a UDP recv would.

The DERP connection stays open for the device's lifetime (not
"on demand") because the supervisor doubles as a netmap-update
listener and the cost of keeping one TLS session is small relative
to the round-trip latency of re-handshaking on demand.

Direct UDP NAT traversal is the M5 step that flips the data plane
off DERP. See M3 step 2 above for the five conditions; together they
make `tailscale ping` show `via 190.x.x.x:port` instead of
`via DERP(mia)` after one CMM round-trip.

Outbound DERP queue (relayed WG transport for end-to-end ICMP via
DERP for CGNAT-trapped peers) landed in PR #83 (2026-05-12):
`wg_netif.c` relays transport frames out through the supervised DERP
session when the direct path is stale, mirroring the inbound inject
path. For peers with public IPs the direct path still covers
everything; the relay only engages on path-stale. The one remaining
open task here is a forced-flap soak that actually exercises the
RX-stale branch (iptables-DROP on Servidor1) — see GAPS below.

ES: idem.

## M6 — ICMP-over-WG end-to-end

`tailscale ping` uses DISCO and bypasses lwIP entirely. Real ICMP
(`ping <our-tailnet-ip>`) needs the WG netif to actually carry IP
packets through lwIP both directions — which the original
PPP-flagged `esp_netif` did NOT do.

Four problems were chained (PR #43 commit message has the full
forensic trail):

1. `esp_netif_action_start` with `ESP_NETIF_FLAG_IS_PPP` dispatches
   to `esp_netif_start_ppp` and returns before the AUTOUP block, so
   `netif_set_up` and `netif_set_link_up` never fire — `lwn->flags`
   keeps both bits at 0 and `ip4_input_accept` drops every inbound.
2. The same path skips `netif_set_addr`, so `lwn->ip_addr.addr` is
   0.0.0.0 even though `esp_netif_get_ip_info` returns the right
   address — `ip4_input` finds no matching local netif for
   inbound dst=100.x.y.z and drops before ICMP echo can reply.
3. `ESP_NETIF_NETSTACK_DEFAULT_PPP` registers `input_fn =
   esp_netif_lwip_ppp_input` which calls `pppos_input_tcpip_as_ram_pbuf`,
   an HDLC-framed-PPP parser. Raw IP (`0x45 0x00 ...`) gets
   silently discarded at the framer.
4. The egress side wraps each outbound packet in HDLC + PPP
   protocol headers (`0xff 0x03 0x00 0x21 ...`); peer's WireGuard
   decrypts cleanly but the inner bytes aren't a valid IP header.

Fix in `wg_lwip.c::wg_lwip_attach`:

- Cache `s_lwn = esp_netif_get_netif_impl(s_netif)`.
- `netif_set_addr` + `netif_set_up` + `netif_set_link_up` explicitly.
- Override `lwn->output` and `lwn->linkoutput` with raw-IP
  passthroughs that hand the pbuf payload straight to
  `wg_netif_send_plaintext`.
- `wg_rx_inject` now calls `tcpip_input(pbuf, lwn)` directly instead
  of `esp_netif_receive`, bypassing the PPP `input_fn`.

The PPP flag is kept because removing it triggers an IDF v5.5
`dhcpc_cb` panic from the trombik baseline. After the four
overrides above, the netif behaves as a true raw-IP carrier.

Verified on hardware: 10/10 ICMP echo packets, 0% packet loss,
~93 ms RTT through the tunnel from the active WG peer.

## M7 — Hardening

Production-readiness checklist. Items land one PR at a time so each
change has its own verification trail. Status as of HEAD:

- [x] **Exponential reconnect backoff (cap 30 s).** DERP supervisor
  doubles `CONFIG_TINYLINK_DERP_SUPERVISED_BACKOFF_MS` on every
  consecutive connect failure up to 30 s, resets to base on a
  successful login. See `tinylink.c::derp_supervised_task`.
- [x] **Constant-time Curve25519.** PR #61 swapped the TweetNaCl-
  derived reference for `agl/curve25519-donna` (BSD-3, ~860 LoC 1:1
  upstream — see `components/tinylink/src/crypto/curve25519_donna.c`).
  `curve25519.c` is now a 70-line shim that delegates `scalarmult`
  to `curve25519_donna()` and keeps clamping + low-order rejection +
  keypair + derive_pub. Donna is the canonical constant-time 32-bit
  X25519 implementation. RFC 7748 §5.2 + §6.1 vectors verified in
  `tools/test/test_curve25519.c`. The earlier inline review of
  `sel25519` (`c = ~(b - 1)` mask + XOR) is also preserved in the
  shim's low-order zero check.
- [x] **Compile-in fallback control plane pubkey.** Optional
  `CONFIG_TINYLINK_CONTROL_PUB_FALLBACK_HEX` (64 hex chars). When
  set, `control_key_get()` installs the fallback as the NVS pin on
  first boot without any network round-trip. Empty preserves legacy
  TOFU (with a loud WARN). See
  `components/tinylink/src/control_key.{c,h}`. (The companion
  `control_key_refresh()` re-fetch-and-compare primitive was removed
  in `22969c4` — it had no caller and unconditionally overwrote the
  TOFU pin, a dead primitive that was net-negative for the pin's
  integrity.)
- [x] **TAI64N monotonicity across reboots.** `wg_tai64n_init()`
  installs a persisted seconds floor at boot;
  `tinylink_tai64n_floor_init()` reads it from NVS namespace
  `tl_state` key `tai_floor`, pre-reserves
  `WG_TAI64N_RESERVE_CHUNK_SECS` (1 day) forward, and writes it back
  so the next reboot reads the new floor. `wg_tai64n_now` clamps
  emitted seconds to `floor + 1` minimum and extends the reservation
  inline if a single boot session ever exhausts the chunk. Verified
  across three sequential resets: 86400 → 172800 → 259200 → 345600.
  See `components/tinylink/src/wg_proto.{c,h}` and
  `tinylink.c::tinylink_tai64n_floor_init`.
- [x] **`stun_reprobe` task spawn resilience.** Boot-time
  `xTaskCreate(stun_reprobe_task)` could fail with `ESP_ERR_NO_MEM`
  while the supervisor TLS handshake transient was still holding the
  largest contiguous heap block. The handler now schedules an
  `esp_timer` one-shot at +30 s and retries until spawn succeeds,
  reprogramming itself on each still-failed attempt. Verified on
  hardware: failed at boot with `largest_block=3456 B`, succeeded
  30 s later at `largest_block=12800 B`. See
  `tinylink.c::tinylink_stun_reprobe_start`.
- [x] **Disassembly review of crypto.** Walked the post-#51
  compiled `.o` for `chacha20`, `chacha20poly1305`, `blake2s`,
  `curve25519`, `poly1305_donna` (`xtensa-esp-elf-objdump -d -S`).
  All hot paths — including the high-risk targets `poly1305_finish`
  mask select and `sel25519` — are branch-free at the ASM level.
  One residual finding (low severity): `poly1305_finish`'s 64-bit
  add-with-carry compiles to four `bgeu` carry-detect branches on
  Xtensa LX6 because the ISA has no add-with-carry. ~4 bits leak per
  MAC; key rotates every 110 s. Documented in `SECURITY-MODEL.md` §
  "Constant-time review (M7-6, post-AEAD-perf-sprint)".

**Out of scope for this project — irreversible per-device
operations**, intentionally not executed:

- ~~**Auth-key rotation path.**~~ The storage-side primitive is small
  (one NVS write), but without a remote *trigger* mechanism
  (control-plane delivery or OTA) it would be unreachable code, and
  the trigger is its own design problem. Re-provisioning via UART
  remains the only supported rotation path on this firmware.
- ~~**NVS encryption with HMAC key in eFuses.**~~ Burning the eFuse
  for the HMAC key is **irreversible per device**. The current
  threat model accepts plaintext-on-flash NVS for NodeKey /
  DiscoKey / auth_key (physical-access attacker is out of scope, see
  `SECURITY-MODEL.md` § "Adversary").
- ~~**Secure boot V2 + flash encryption.**~~ Same irreversibility
  argument. Would lock down the boot chain at the cost of preventing
  any further development flashing on the same device. Not
  appropriate while the project is still iterating on the firmware.

If a downstream deployment later needs production-grade
key-at-rest protection, those three items can be picked up as a
forked hardening sprint with operator-authorized eFuse burns. The
checklist above marks where each one would slot in.

[research §L] for the underlying threat model.

ES: idem.

## M8 — Perf + power round (2026-05-10)

Five consecutive PRs after M7-close took the firmware from `-Og`
DIO@40 / no-light-sleep to the current `-O2` QIO@80 / light-sleep
build. Each landed independently with its own on-device verification.
The `CHANGELOG.md` "Performance + power round" section has the full
per-PR write-up; this is the milestone-view tracking entry.

- [x] **PR #61 — `curve25519-donna`** (constant-time scalarmult).
  Eliminates the timing channel against MachineKey/NodeKey on every
  Noise IK and WG handshake. +8.6 KiB flash.
- [x] **PR #62 — `esp_pm_configure` + `WIFI_PS_MIN_MODEM`**
  (tickless idle actually enters light sleep). IDF source review of
  `pm_impl.c:561` + `:829` confirmed the pre-PR `PM_ENABLE=y` +
  `USE_TICKLESS_IDLE=y` were inert without the runtime
  `esp_pm_configure(.light_sleep_enable=true)` call. Critical
  ordering caught: call must run AFTER `app_wifi_wait_connected()`
  or the AP kicks the client mid-AUTH/ASSOC. +2.2 KiB flash.
- [x] **PR #63 — Flash mode `QIO@80MHz`** (was DIO@40).
  WROOM-32E datasheet Table 17 guarantees the spec for the
  integrated flash. Boot log confirms `mode:QIO, clock div:1`.
  ~8× effective flash-read bandwidth on cold-cache / boot paths.
  −144 B flash.
- [x] **PR #64 — `FREERTOS_HZ` 1000 → 100** (10 ms tick).
  Pre-audit: every `pdMS_TO_TICKS(N)` callsite in our code uses
  N ≥ 100 ms, 0 raw integer tick arguments to `vTaskDelay` /
  `xQueue*`, 0 references to `configTICK_RATE_HZ` /
  `portTICK_PERIOD_MS`. Lower tick-ISR overhead + deeper tickless
  sleeps. +128 B flash.
- [x] **PR #65 — `-O2` per-component** (`tinylink` + `main` +
  `mbedcrypto` via `target_compile_options`). Global stays at
  `-Og` to scope the documented toolchain hangs around certain
  lwIP files out of the build. Drive-by `memcpy + strnlen`
  refactor in `app_wifi.c` to satisfy `-Wstringop-truncation`.
  +2.3 KiB flash.

Aggregate cost: ~+13 KiB flash on top of the M7-close baseline.
26 % of the app partition still free. RAM unchanged.

Regression gate (preserved on every PR): on-device 60-min mega-ping
baseline of 3.86 % loss / 154 ms avg from M5 → no regression at any
intermediate state; on-device boot captures show 0 `bcn_timeout`,
0 wifi disconnects, 0 panics, exact 5 s telemetry cadence.

ES: idem.

## M9 — Protocol + crypto follow-ups (PRs #85–#87)

Three small landed items that the milestone view had not yet
absorbed; the `CHANGELOG.md` entries are authoritative.

- [x] **PR #85 — `429` / `Retry-After` handling.** The control-plane
  HTTP clients now parse a `429 Too Many Requests` with its
  `Retry-After` header (delta-seconds or HTTP-date) and back off for
  the advertised interval instead of hammering. +15 host assertions
  in the 429/Retry-After parser test.
- [x] **PR #86 — branch-free Poly1305 carry.** Replaced the
  `poly1305_finish` add-with-carry's data-dependent `bgeu` branches
  (the residual finding from M7-6) with a branch-free carry, closing
  the documented ~4-bit-per-MAC timing leak (LX6 has no ISA
  add-with-carry). Tags are bit-identical to the prior baseline —
  20-min ICMP-over-WG soak (5.29 % loss / 109 ms avg) confirmed no
  functional regression. See `SECURITY-MODEL.md`.
- [x] **PR #87 — IPN `1.0.0-tinylink`.** Bumped the IPN bus version
  and flipped the `tsReleaseTrack` panel `unstable → stable`. The
  macro is derivable from a single source of truth in `tinylink.h`.

ES: idem.

## M10 — Perf-trim + footprint round (PRs #88–#104)

A 17-PR aggressive footprint round (the `perf-audit` skill's
verified-against-real-code output). Main HEAD after the round was
`8062847`. The `CHANGELOG.md` "perf-audit round" section has the
full per-PR forensic trail; this is the milestone-view tracking
entry.

Net result: **−68.1 KiB flash** and **+2.6 KiB largest contiguous
heap block** (6 656 → 9 216 B — the block the supervised-TLS handshake
transient contends for). Highlights:

- [x] **PPP component fully off** (−21.4 KiB). The WG netif is a
  raw-IP carrier with a no-op netstack now that `IS_PPP` is gone (see
  `ARCHITECTURE.md` § WG netif); nothing in the build needs PPP.
- [x] **`NEWLIB_NANO` formatted I/O** (−30.3 KiB). The firmware logs
  no floats and no wide format specifiers, so the nano printf is a
  free win.
- [x] **mbedTLS 4-stage prune** (−13.6 KiB). Curve set trimmed to the
  ones the live `controlplane.tailscale.com` + DERP cert chains
  actually present (P-256 leaf + P-384 chain to ISRG Root X2, plus a
  Curve25519 TLS-1.3 hedge); 8 unused `MBEDTLS_ECP_DP_*` curves
  disabled. Each TLS endpoint was `openssl s_client -showcerts`-checked
  before any curve was dropped.
- [x] **5 stack trims — 2 reverted.** LP-task and `ep_up` trims were
  caught and reverted (PR #99 → #103, PR #102 → #104): a 100 s
  post-boot smoke is insufficient for tasks with TLS-reconnect /
  retry loops, whose lifetime stack peak only shows up minutes into a
  soak (#99's real LP peak was 20 KiB at 18 min uptime, not the 11
  KiB boot peak it was trimmed against; #102's `ep_up` peak surfaced
  under a NAT-rebind + heap-frag panic in a 30-min stress soak). PR
  #104 also bumped `CONFIG_LWIP_TCPIP_TASK_STACK_SIZE` 3 K → 4.5 K
  (the `tiT` task was a latent 95.5 % steady-state, overflowing under
  `ENOMEM` `sendto` pressure). Lesson recorded: reconnect-loop stack
  trims need a multi-hour soak with 60 s diag dumps before landing;
  single-shot deterministic paths (DERP / `stun_r` / `ep_up` spawn)
  are fine on a short smoke.

Final 30-min stress soak after the round: 0 panics, 361 telemetry
datagrams, heap stable.

ES: idem.

## M11 — Security round (PR #105)

The first dedicated security-audit PR after the perf round, on top of
HEAD `8062847`.

- [x] **WGN-1 (HIGH) writer-side close.** The unlocked WG-session swap
  in the `session_init` writer could expose a `(key, nonce)` reuse
  window; the swap now happens under `g.lock`. HW-verified rekey at
  session_age ≈ 110 s. (The companion rx-path lock landed in M12 —
  see below — together they fully close WGN-1.)
- [x] **ROAM-3 — DISCO pong source binding.** Outbound DISCO probes
  now record their tx-id (the `disco_prober.c` table that replaced the
  deleted `disco_replay.{c,h}` in `31de72d`), so an unsolicited pong
  from an attacker-chosen source can no longer drive an endpoint roam.
- [x] **`secure_zero` introduction + ROAM-2 + RC-2.** First
  `tl_secure_zero` scrub primitive; `GOT_IP → reprobe` (ROAM-2) so a
  WiFi reassociation re-runs STUN; exponential backoff on a class of
  reconnect (RC-2). The full `secure_zero` sweep across all key
  material landed in M12.

WGN-2 was skipped (dead primitive without a consumer — landing a
primitive without its trigger is a maintenance burden).

ES: idem.

## M12 — Audit-fix round (2026-06-10)

Six audit fixes, all landed on branch `fix/audit-cluster-1-protocol-wg`
and **hardware-validated against `tailscale.com`**. Host suite is now
**531 assertions across 20 binaries** in `tools/test`
(`test_keys_regen` +9, `test_skip_value` +9 over the prior 513 / 18).

- [x] **(`971419c`) capver 138 at the Noise layer + stream
  early-payload.** `TINYLINK_CAPVER = 138` (= Tailscale v1.98) in
  `components/tinylink/include/tinylink.h:61` is now the single source
  of truth that derives the ts2021 Noise initiation header + prologue
  (`"Tailscale Control Protocol v138"`, was hardcoded `1` in
  `ts2021_client.h`), `RegisterRequest.Version`, and
  `MapRequest.Version`. This clears headscale's `earlyNoise`
  `MinSupportedCapabilityVersion` floor of **113** (= v1.80) — the
  prior advertised `1` was rejected by current headscale.
  Upstream `CurrentCapabilityVersion` is **141** for reference; the
  `GET /key?v=100` bootstrap was a deliberately separate, lower floor
  (`control_key.c`) — *superseded in M14*: headscale now gates `/key`
  on the same floor as `/ts2021`, so it sends `TINYLINK_CAPVER` too. `consume_early_payload` was rewritten to read the
  9-byte EarlyNoise header (`magic[5] || BE32 len || JSON`) as a byte
  **stream** spanning Noise records (the server flushes the 5-byte
  magic as its own record); the `NodeKeyChallenge` is drained and
  discarded.
- [x] **(`e8997d7`) WGN-1 rx-path close + relayed-DISCO gate.**
  `g.lock` now wraps `wg_transport_decrypt` in `handle_transport`
  (previously unlocked across the `wg_rx` + `tinylink_derp` tasks;
  PR #105 had locked only the writer). Combined with M11's writer
  lock, the WGN-1 replay-window / `recv_key` race is fully closed.
  Plus a **relayed-DISCO gate**: `handle_disco_relayed` now drops a
  relayed PING/CallMeMaybe whose decrypted sender DiscoKey ≠ the
  active WG peer's (new `wg_netif_get_peer_disco_pub` accessor),
  mirroring the direct-UDP path's `knownPeerDiscoKey` gate — closes
  the CallMeMaybe-triggered UDP ping-flood to attacker-chosen
  endpoints (`tinylink.c:714`).
- [x] **(`573312f`) atomic machine+node identity regen.** `keys.c`
  now regenerates the MachineKey and NodeKey as one unit (headscale's
  new 1:1 `NodeKey ↔ MachineKey` binding, upstream `eb57a3a6` +
  `4914f9f2`): if either is absent or corrupt, **both** regenerate;
  DiscoKey stays independent. The policy lives in the pure header
  `keys_regen.h` and is host-tested across 8 combinations.
- [x] **(`0d5ec30`) depth-bounded `skip_value`.** `jsmn_skip.h`
  enforces `JSMN_SKIP_MAX_DEPTH = 64`, so an adversarial
  deeply-nested MapResponse can no longer overflow the long-poll
  task stack. Legit netmaps are unchanged. Host-tested.
- [x] **(`df7b6bd`) complete `secure_zero` sweep.** `tl_secure_zero`
  now scrubs **all** secret key material — **39 call sites** across
  `wg_netif.c` (WG session keys), `wg_handshake.c` (DH / chaining /
  tau / derived keys + `wg_handshake_scrub`), `salsa20.c`,
  `hkdf_blake2s.c`, `chacha20poly1305.c`. WG session/handshake keys
  are no longer scrubbed with a plain `memset` (which the optimizer
  can elide). Public values (nonces / timestamps / wire messages)
  keep `memset`.
- [x] **(`22969c4`) hygiene.** `esp_wifi_connect()` return is now
  logged on failure (`app_wifi.c`); the dead `control_key_refresh()`
  primitive was removed (it had no caller and overwrote the TOFU
  pin); the dead `CONFIG_TINYLINK_LOG_LEVEL` Kconfig was removed; the
  `derp_client.c` DERPPort comment was fixed; `.gitignore` now
  self-maintains the `test_*` pattern + ignores `.claude/`; the
  orphan `test_disco_replay` binary was removed.

ES: idem.

## M13 — Control-plane reconnect hardening (2026-07-16)

Four fixes on branch `fix/control-reconnect-hardening`, driven by the
production symptom "after a control-plane change the node sometimes
never reconnects until power-cycle" plus a fresh two-sided upstream
audit (tailscale `632293de7..71b90de0d`, headscale
`f585f8a9..04830851` — zero wire drift, capver 138 still clears the
unchanged headscale floor of 113; upstream current is 142). Host suite
**546/0** (`OK|PASS` metric; +15 over M12's 531). Δ flash +1 488 B.
Commit-level detail in `CHANGELOG.md`; threat-model view in
`SECURITY-MODEL.md`.

- [x] **Stream idle budget.** `tls_io_read_full`/`tls_io_write_full`
  take a `max_idle` bound on consecutive zero-progress
  `WANT_READ`/`WANT_WRITE` polls; breach returns the new
  `TLS_IO_ERR_IDLE_TIMEOUT`. Wired through ts2021, both 101-upgrade
  readers, `derp_run_loop`, and the DERP send paths.
  `CONFIG_TINYLINK_STREAM_IDLE_TIMEOUT_S` (default 120 s) mirrors
  upstream's `watchdogTimeout` (`direct.go`). Kills the half-open-conn
  infinite hang — the root cause of the symptom.
- [x] **`PeersChangedPatch` identity refetch.** Patches carrying a
  peer `Key`/`DiscoKey` change (how headscale ≥0.29.2 and
  tailscale.com deliver peer re-login) now recycle the stream so the
  reconnect's guaranteed-full first netmap refreshes the keys within
  seconds. Endpoint-only patches stay ignored (DISCO's job). +4 KATs.
- [x] **In-place re-register on persistent map 4xx.** ≥2 consecutive
  non-429 4xx map rejections re-run `tinylink_register()` with the NVS
  authkey (power-of-two schedule) + push endpoints on success. Heals
  server-side node-state loss (headscale 404 on unknown node) without
  a reboot.
- [x] **Wedge-restart last resort.**
  `CONFIG_TINYLINK_CONTROL_WEDGE_RESTART_S` (default 3600 s, 0=off):
  zero control-plane bytes for the window → diag dump + `esp_restart()`.
  Same option arms a 60-s-delay restart on failed `bringup()` (was:
  park in diagnostics mode forever).
- [ ] **HW smoke** — device was not attached this round. Checklist in
  `CHANGELOG.md` (boot smoke, ≥15-min stream stability, forced
  half-open, ≥60-min wedge restart, admin-panel node delete).

## M14 — Audit + optimization round (2026-09-04)

Inputs: upstream drift audit (tailscale `71b90de0d..31d8badb3`,
headscale `04830851..89fa72e0`), a core-code review, an ISA/memory pass
over the compiled binary, and the first hardware run since M13. Per-item
detail in `CHANGELOG.md`; this is the milestone view plus the
improvement inventory the round produced.

- [x] **Endpoint-push stack overflow (HIGH).** `tinylink_ep_up` needed
  ≈ 28 KiB on its 12 KiB static stack (stack-local `ts2021_conn_t`
  8 648 B + `ts2021_connect` 9 888 B + record read 4 176 B + TLS). It
  overflowed into BSS on every real push; the PR #102 "NAT-rebind
  panic" was this. Task removed; the push runs on the long-poll after a
  cooperative stream recycle (`ts2021_abort_reads`). −12.6 KiB BSS.
- [x] **headscale `/key` gate.** `/key?v=` now carries `TINYLINK_CAPVER`
  (headscale `5b6e1e17`; floor 115).
- [x] **TSMP proto 99 drop** (capver 144 disco-key adverts no longer
  answered with ICMP).
- [x] **DERP client close race** (use-after-free / deleted mutex vs the
  wg_tx relay) + `MBEDTLS_SSL_RENEGOTIATION=n`.
- [x] **Xtensa AEAD fast paths**: ChaCha20 XOR 19 → 7 instructions per
  word (0 byte ops on the aligned path), rounds inlined under one
  zero-overhead loop (22 → 2 calls), Poly1305 block loads 4× `l32i`.
- [x] **Backoff consolidation** (DERP supervisor → `tl_backoff_ms`;
  with the ep_up task gone there is one implementation).
- [x] **Provisioning contract** (namespace/partition/tool/docs matched
  to the firmware, with a legacy fallback so the deployed sensor keeps
  booting).
- [x] **Noise state scrub on close; dead per-frame diag scan removed;
  inert `CONFIG_NVS_ENCRYPTION` line removed.**
- [x] **Tests/CI**: `-Werror`, ASan+UBSan target and job, pipefail + OK
  floor, idf-patches dry-run, size summary, dependabot.
- [x] **Hardware**: full-flash backup; app flashed to the deployed
  sensor; 150-s boot smoke clean; largest free block +60 s 21.5 KiB
  (was 9–11 KiB); 20-min stream stability — see CHANGELOG.

## M15 — Road-to-100 round (2026-09-04, part 2)

Same day as M14, working down the improvement list below on the
connected sensor. Per-item detail in `CHANGELOG.md`.

- [x] **#5 netmap parse memory** — `jsmn_split.h` + per-value jsmn:
  token table 40 KiB → 10 KiB, no document-size ceiling.
- [x] **#3 task WDT** for `wg_rx`/`wg_tx`/telemetry/DERP/long-poll
  (`tl_wdt.h`, tls_io poll hook, 90 s, panic → reboot).
- [x] **#2 capver 138 → 142** (HW A/B on tailscale.com).
- [◐] **#4 connect-path diet** — −8 KiB of `ts2021_connect` frame
  (h2_rx reuse); the LP stack trim itself waits for the multi-hour soak.
- [x] **#7 DERP live switch** + parsed port + fallback host in the
  preferred region.
- [x] **#11 mark-alive on Noise connect.**
- [x] **#12 WiFi reconnect backoff + `ip_changed` → recycle both conns**
  + `set_storage` before `set_config`.
- [x] **#13 per-packet logs → DEBUG.**
- [◐] **#15 KATs** — `tai64n`, `nacl_box` (libsodium vectors),
  `jsmn_split`; `noise_ik` / `register` parsing still open.
- [◐] **#17 flash trims** — TLS client-only, no RSA kx / PEM write /
  WPA-Enterprise (−8.2 KiB); the cert-bundle trim stays a CA-risk
  decision.
- [x] **#19 conn kept after register.**  [x] **#20 dead code.**
- Firmware version **1.2.0** (even minor: Tailscale shows odd minors as the *unstable* release track).

### Improvement list (2026-09-04) — what remains, in priority order

Owner-facing inventory. "Gate" is what each item waits on.

| # | Item | Why | Effort | Gate |
|---|------|-----|--------|------|
| 1 | ⏳ **M13 checklist items 3–5** (forced half-open, ≥ 60-min drop → wedge restart, admin-panel node delete → re-register) | the reconnect ladder has only seen the healthy path on hardware | small | router/admin access |
| 2 | ✅ (M15: 142) **CapabilityVersion bump** (138 → ≥ 142) before headscale's floor passes 138 | floor moved 113 → 115 in two months; below it both `/key` and `/ts2021` reject us | small | HW A/B smoke (prologue changes) |
| 3 | ✅ (M15) **Task WDT for app tasks** (`wg_rx`, `wg_tx`, telemetry, DERP, long-poll via a `tls_io` idle hook; `TIMEOUT_S`≈90, `PANIC=y`) | a wedge in one of those still bricks its function | small | multi-hour soak |
| 4 | ◐ (M15: −8 KiB frames; LP stack trim pending soak) **ts2021 connect-path buffer diet** (`resp_buf`→`h2_rx`, `rec`→`rx_residual`, in-place record decrypt) | −8…12 KiB of long-poll stack (24 → ~14 KiB), −4 KiB per conn | medium | soak with stack-diag dumps |
| 5 | ✅ (M15: toks 40 → 10 KiB; region filter not needed) **Netmap parse memory**: shallow top-level/region splitter feeding jsmn per value (toks 40 KiB → ~8 KiB), DERP regions filtered to {preferred, peer home} at parse (−5.5 KiB) | the two largest BSS objects; lifts the "largest block" ceiling for good | medium | host KATs (`test_mapresp`) + smoke |
| 6 | ⏳ **SNTP + `MBEDTLS_HAVE_TIME_DATE`** with a persisted/build-epoch floor and `BADCERT_FUTURE/EXPIRED` tolerated until first sync | certs are never date-checked today | medium | re-smoke all TLS clients |
| 7 | ✅ (M15) **DERP region change on a live conn** (generation counter → supervisor exits the stream; honour `restart_reconnect_ms`; dial parsed `DERPPort`; default fallback host in the preferred region) | a region reroute is ignored until the stream happens to die | small | smoke |
| 8 | ⏳ **WG handshake/roam state under a lock** (rx_task vs DERP-inject vs long-poll writers of `g.handshake`/`g.peer_addr`) | rare torn writes / wasted handshake rounds | medium | soak |
| 9 | ⏳ **Pre-auth source filter vs roaming**: verify first, then roam `peer_addr` on an authenticated packet from a new source | today a peer NAT rebind blackholes inbound until the 30-s RX-stale probe | medium | forced-flap soak |
| 10 | ⏳ **`PeersRemoved` / delta merge** keyed by NodeKey | a delta carrying another peer overwrites `s_last_peers` | medium | multi-peer tailnet |
| 11 | ✅ (M15) **Mark control alive on a completed Noise handshake** | a deleted/expired node reboots hourly despite a reachable control plane | trivial | owner decision (semantics of the wedge restart) |
| 12 | ✅ (M15) **WiFi reconnect backoff + `ip_changed` → stream recycle** (`app_wifi.c` reconnects instantly; `set_storage(RAM)` runs after `set_config`) | tight reconnect loop on AP loss; half-open control conn after a DHCP change | small | smoke |
| 13 | ✅ (M15) **Per-packet INFO logs → DEBUG** (DISCO ping/pong, relayed DERP packets, telemetry samples) | UART at 115200 blocks the RX/DERP tasks for ms per line | trivial | owner's grep-based smoke recipes |
| 14 | ⏳ **Coredump to flash** (`ESP_COREDUMP_ENABLE_TO_FLASH`, partition in the free tail) | panics currently leave no post-mortem | small | partition-table reflash |
| 15 | ◐ (M15: TAI64N + NaCl box done) **Host KATs for `noise_ik.c`, `register.c` parsing, `wg_proto.c` TAI64N, Salsa20/NaCl vectors** | highest-value untested modules | small each | none |
| 16 | ⏳ **IRAM placement of the AEAD hot path** (~4 KiB of the 56 KiB free IRAM) | a flash-cache miss costs ≈ 225 CPU cycles per 32-B line; after eviction by TLS/WiFi code a packet re-fetches ~4 KiB | small | on-device AEAD bench |
| 17 | ◐ (M15: client-only TLS, no RSA kx/PEM write/EAP) **Flash trims for the production profile**: custom cert bundle (−~50 KiB), `MBEDTLS_TLS_CLIENT_ONLY`, `ESP_WIFI_ENTERPRISE_SUPPORT=n`, `esp_http_client` only when TOFU is compiled in | 40 % free today; matters for OTA slot headroom | small | CA-change risk assessment |
| 18 | ⏳ **`/stats` over UDP on the tunnel** (reuse the telemetry socket) and **OTA over the tunnel** (plain HTTP over WG + detached ECDSA signature) | observability / remote update | small / medium | per the Execution queue |
| 19 | ✅ (M15) Drop the `s_conn` teardown after register (stale rationale; costs one extra Noise+TLS handshake per boot) | ~5 s boot, one heap peak | trivial | smoke |
| 20 | ✅ (M15, dead code; helper de-duplication still open) Dead code: `mapreq_fetch_once`, `stun_probe_run`, `tinylink_telemetry_start` stub, `WG_NETIF_FAILED`; duplicated 101-upgrade readers / hex helpers / host:port splitters | maintenance | small | none |

### Completion estimate by area (2026-09-04, after M15)

Maintainer-style estimate of "% of the declared single-peer scope that is
done and optimized". Not a metric — a planning aid. The M14 column is
what the morning round left; M15 is the state on `main` after part 2.

| Area | after M14 | after M15 | What the remainder is |
|------|----------:|----------:|-----------------------|
| Control-plane protocol compatibility (tailscale.com + headscale) | 95 % | 97 % | `PeersRemoved` (#10); capver has ~8 headscale releases of headroom now |
| Data plane (WG / DISCO / DERP / STUN) | 90 % | 92 % | handshake-state lock (#8), auth-then-roam (#9), forced-flap relay soak |
| Self-healing / robustness | 85 % | 93 % | M13 checklist 3–5 (#1), multi-hour WDT soak, SNTP (#6) |
| Static + dynamic memory (DRAM) | 70 % | 88 % | body_buf 32 KiB (needs a streaming parser), LP stack 24 → ~14 KiB after a soak |
| CPU / ISA hot path | 80 % | 80 % | IRAM placement (#16) pending a bench |
| Flash footprint | 85 % | 90 % | cert-bundle trim (CA-change risk decision) |
| Power | 80 % | 80 % | deep-sleep with WG state is a future direction |
| Security within the threat model | 90 % | 94 % | coredump (#14); plaintext NVS accepted by decision |
| Tests / CI | 80 % | 88 % | `noise_ik` / `register` KATs, size-regression gate, formatter job, HIL |
| Provisioning / tooling | 90 % | 90 % | `examples/` is a README, not a project |
| Documentation | 85 % | 92 % | — |
| **Overall (declared scope)** | **≈ 85 %** | **≈ 90 %** | the rest is gated on router/admin access, a multi-hour soak, or owner decisions |

ES: idem — inventario de mejoras y estimación de avance por área tras la
ronda 2026-09-04; el detalle por ítem está en `CHANGELOG.md`.

## Execution queue — next rounds (agreed 2026-07-16)

Owner-approved order for closing the remaining gaps toward ~100 % of
the declared scope. Each item waits on its stated gate; none blocks
the current deployment. Items get their M-number when their round
lands.

**Gate: a test ESP32 attached** (never reflash the deployed sensor for
experiments):

1. **M13 hardware smoke** — run the 5-step checklist in the CHANGELOG
   M13 entry. **Items 1–2 done 2026-09-04** on the deployed sensor
   (boot smoke, 20-min stream stability). Still open: forced half-open
   (expect reconnect ≤ ~2.5 min, no reboot), ≥60-min drop (expect wedge
   restart + recovery), admin-panel node delete (expect self
   re-register — this path now also exercises the long-poll-side
   endpoint push).
2. ~~**Task WDT for application tasks**~~ — *landed in M15* (`tl_wdt.h`,
   90 s, panic → reboot). The multi-hour validation soak is still owed:
   the stack-trim lesson applies (short post-boot smokes are
   insufficient for tasks with reconnect/retry loops).
3. **SNTP + `MBEDTLS_HAVE_TIME_DATE`** — TLS certificate
   `notBefore`/`notAfter` validation with a boot fallback when NTP is
   unreachable (an offline boot must not brick). Re-smoke all three
   TLS clients (control, DERP, future OTA) + flash-budget check.
4. **`/stats` diagnostics endpoint** on the WG netif — heap, rekey
   count, RX-stale events, endpoint roams (see Future directions).
5. **OTA over the tailnet** — signed image fetch from a tailnet peer;
   the partition table is already OTA-shaped. Also provides the
   remote trigger that auth-key rotation lacked.

**Gate: Servidor1 (peer-side) access:**

- Forced-flap relay soak (see Open backlog below). If Servidor1 runs
  headscale, upgrade it to ≥ 0.29.2 first — the issue-#3346 cluster
  fixed three server-side "client retries forever after a control
  change" bugs (2026-07 upstream audit).

**Gate: an extended soak window:**

- ~~Backoff consolidation~~ — landed in M14 (2026-09-04).

**Explicitly out — owner decision (2026-07-16), reaffirming the M7
call:** NVS/flash encryption via eFuse. Burning eFuses is irreversible
and recovery from any provisioning mishap would depend on a control
plane the project does not operate (tailscale.com) — an unrecoverable
failure mode for a remote sensor. Plaintext NVS stays an accepted,
documented risk (physical-access attackers are out of scope per
`SECURITY-MODEL.md`); this item must not be re-proposed as roadmap
work.

## Open backlog (roadmap — NOT done)

These are the genuinely remaining protocol/data-plane follow-ups, kept
separate from the accepted-risk GAPS below. None block the current
sensor-→-collector workload.

- **Netmap `PeersChanged` / `PeersRemoved` delta-merge.** The
  long-poll currently treats each MapResponse as a fresh snapshot;
  proper incremental delta application needs a multi-peer tailnet to
  validate, which we don't have. Upstream evidence got stronger in the
  2026-07 audit (headscale now delivers peer re-login as
  `PeersChangedPatch`); M13's identity-refetch covers the
  key-rotation case by recycling the stream, so the remaining exposure
  is efficiency (full refetch instead of merge) plus `PeersRemoved`,
  not correctness for single-peer.
- ~~**Backoff consolidation.**~~ *Closed 2026-09-04 (M14)*: the DERP
  supervisor uses `tl_backoff_ms` and the endpoint-push task — whose
  "regression sensitivity" (PRs #102/#104) turned out to be a stack
  overflow — is gone. One implementation, host-tested.
- **Everything in "Improvement list (2026-09-04)" above**, in that
  priority order; the buffer diet (#4/#5) is the memory item, the
  M13 checklist (#1) and the capver bump (#2) are the compatibility
  items.
- **Forced-flap relay soak.** PR #83's DERP-relay WG-transport
  fallback (the RX-stale branch) has only been exercised on the
  healthy path. Exercising it for real needs an iptables-DROP on
  Servidor1 (root on the peer), per `CHANGELOG.md`'s recipe.

## GAPS — accepted-risk / next-round (NOT fixed)

Surfaced honestly so downstream deployers know exactly what is and
isn't covered. Each is a conscious deferral, not an oversight.

- **No general task watchdog.** M13 closed this for the control path
  (stream idle budget + wedge `esp_restart`, see above) and for failed
  bringup; what remains open is the general case — no application task
  (`wg_rx`, telemetry, DERP supervisor) is subscribed to the task WDT,
  so a wedge in one of *those* still bricks its function (though the
  control-path watchdog now reboots the whole device if the wedge also
  starves the control stream for an hour).
- **NVS private keys are PLAINTEXT.** `CONFIG_SECURE_FLASH_ENC_ENABLED`
  is off and `keys.c` uses the default plain NVS partition. The
  MachineKey / NodeKey / DiscoKey / auth_key sit in cleartext on
  flash. At-rest / eFuse encryption **will not be implemented — owner
  decision 2026-07-16** (see the Execution queue above for the
  rationale); accepted risk, physical-access attacker out of scope per
  `SECURITY-MODEL.md`.
- **No SNTP-backed TLS time validation.** `MBEDTLS_HAVE_TIME_DATE` is
  off, so all three TLS clients (controlplane, DERP, OTA-to-be) never
  check certificate `notBefore` / `notAfter`. The pinned-control-key
  TOFU + the published cert chain are the only trust anchors.
- ~~CI runs `idf.py build` only, not `make test`~~ **Closed 2026-07-16**:
  `build.yml` now runs the 546-assertion host suite as its own job and
  pins the exact `v5.5.4` the project freezes on (was the floating
  `v5.5`). Remaining CI wish: hardware-in-the-loop, tracked under
  Future directions.
- **Telemetry / TMP117 path unaudited.** The partition table is
  OTA-shaped, but there is no `esp_ota` path and no coredump capture
  wired up yet; OTA firmware update (above, Future directions) is the
  vehicle that would close this.
