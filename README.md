# tinylink

A minimalist Tailscale-compatible client for **ESP32-WROOM-32E (no PSRAM)**,
written in pure C on **ESP-IDF v5.5.x**.

## Status

**Stable — direct UDP + ICMP-over-WG live end-to-end on real hardware,
M1–M7 all landed, perf round 2026-05-10 closed, sdkconfig perf-trim
round 2026-05-12 PM merged (5 PRs), DERP outbound round 2026-05-12
evening merged (PR-D0 + PR-D1: lossless transport during peer NAT
flap).**

| Layer                          | State                                  |
|--------------------------------|----------------------------------------|
| ts2021 control plane (M1)      | done                                   |
| MapRequest + WireGuard (M2)    | done                                   |
| TMP117 telemetry (M3)          | done                                   |
| DISCO ping/pong (M3)           | done — direct + DERP                   |
| STUN binding probe (M4)        | done — runs over WG socket             |
| DERP supervised recv (M5)      | done                                   |
| Direct UDP NAT punching (M5)   | done                                   |
| ICMP over WG transport         | **done** — `ping <our-tailnet-ip>` flows |
| Production hardening (M7)      | done — within scope                    |
| Perf + power round (2026-05-10)| done — constant-time crypto, light-sleep PM, QIO@80, -O2 |
| sdkconfig perf-trim (2026-05-12 PM) | 5 PRs merged: −158.7 KiB flash · DRAM −2.9 KiB · IRAM −30.5 KiB (80%→56%) |
| DERP outbound round (2026-05-12 evening) | 2 PRs merged: derp supervisor finally spawns + WG transport relay fallback (lossless on path-stale or sendto errno) |

What works today, verified on real hardware:

- A peer running upstream `tailscaled` runs `tailscale ping sensor-cali`
  and gets pongs `via 190.x.x.x:<port>` (direct UDP, no DERP relay).
- The same peer runs `ping -c 10 100.67.60.92` (sensor-cali's tailnet IP)
  and gets `0% packet loss, ~93ms RTT` over the WireGuard tunnel —
  ICMP encapsulated, encrypted, decrypted, replied, end-to-end.
- TMP117 telemetry frames flow out over the same tunnel every 5 s.
- The Tailscale admin panel shows `Endpoints: 190.x.x.x:<port>` and
  `Client connectivity → UDP: Yes`.

What's still pending:

- DERP outbound queue (only relevant for peers behind shared CGNAT
  where direct UDP can never work — for peers with public IPs the
  direct path covers everything).
- Multi-peer (single-peer today).

## Performance + power round (2026-05-10)

Five consecutive PRs took the firmware from the M7-close baseline to
a constant-time, power-managed, QIO@80, -O2 build. The CHANGELOG has
the per-PR detail; one-liner summary:

| PR  | Change                          | Flash Δ  | What it unlocks                                                  |
|-----|---------------------------------|----------|------------------------------------------------------------------|
| #61 | `curve25519-donna` swap         | +8.6 KiB | Constant-time MachineKey scalarmult (eliminates timing channel) |
| #62 | `esp_pm_configure` + `WIFI_PS_MIN_MODEM` | +2.2 KiB | Tickless idle actually enters light sleep; DTIM-paced modem sleep |
| #63 | Flash `QIO@80` (was DIO@40)     | −0.1 KiB | ~8× effective flash-read bandwidth (boot + cold-cache paths)    |
| #64 | `FREERTOS_HZ` 1000 → 100        | +0.1 KiB | Lower tick-ISR overhead, deeper tickless sleeps                  |
| #65 | `-O2` per-component (`tinylink` + `main` + `mbedcrypto`) | +2.3 KiB | Aggressive inlining/unrolling on the hot crypto + WG paths      |

Total cost: ~+13 KiB flash on top of the M7-close baseline.
26 % of the app partition is still free.
RAM unchanged.

The 60-min mega-ping regression gate (3.86 % loss / 154 ms avg from
the M5 baseline) is preserved across every PR; on-device captures
show 0 `bcn_timeout`, 0 disconnects, 0 panics, and exact 5 s
telemetry cadence on every flash.

## sdkconfig perf-trim round (2026-05-12 afternoon)

Five `feat/perf-*` branches pushed to GitHub the same day as the
audit-driven round closed. **sdkconfig only — no `.c`/`.h` changes,
no API surface change.** Each PR validated by a 60-120 s smoke
(boot + register + initial netmap + ≥5 telemetry @ 5 s + 0 panic).
The CHANGELOG `[Unreleased]` section has the per-PR detail;
one-liner summary:

| PR (branch)                                | Δ flash app | Δ DRAM | Δ IRAM   |
|--------------------------------------------|------------:|-------:|---------:|
| `feat/perf-error-strings-and-assertions`   | −75.6 KiB   | −2.6 KiB | −3.4 KiB |
| `feat/perf-vfs-trim`                       | −9.4 KiB    | 0      | −1.1 KiB |
| `feat/perf-bootloader-log-none`            | 0 (bootloader.bin −8 KiB) | 0 | 0 |
| `feat/perf-wifi-station-only-no-wpa3`      | −74.6 KiB   | −0.3 KiB | −0.1 KiB |
| `feat/perf-iram-to-flash-moves`            | +0.9 KiB    | 0      | **−25.9 KiB** |
| **Combined (projected)**                   | **−158.7 KiB** | **−2.9 KiB** | **−30.5 KiB** |

The IRAM relief is the headline: 79.64 % → ~56.4 % unlocks future
work that needs IRAM (a second persistent TLS connection, selective
IRAM_ATTR on hot WG paths, multi-peer state) without crowding wifi/
rtos/lwip.

Skipped after measurement (research-suggested but no-op on this
target):
- `COMPILER_SAVE_RESTORE_LIBCALLS` — Kconfig does not exist for
  Xtensa LX6 in IDF v5.5.4 (it's a GCC RISC-V flag, ESP32-C3/C6
  only).
- `MBEDTLS_PEM_WRITE_C off` — section GC already strips it (cert
  bundle path needs only PEM_PARSE). Δ = 8 B.
- `MBEDTLS_ERROR_STRINGS off` — `nm tinylink.elf` shows zero
  references to `mbedtls_strerror`; the table is already dead-
  stripped. Δ = 0.
- `LOG_MAXIMUM_LEVEL=WARN` — Kconfig clamps `MAXIMUM ≥ DEFAULT`
  (`depends on LOG_DEFAULT_LEVEL < N`), so the only real win is
  dropping DEFAULT to WARN. That strips every `ESP_LOGI` call site
  and breaks the serial-grep smoke (no more "tinylink up",
  "telemetry tx seq", "netmap (initial)"). Deferred until the
  smoke can verify operation via tcpdump on the sensor_app
  receiver instead of UART logs.

A 4-hour soak with the COMBINED set is the remaining validation
gate before declaring the round closed.

Intentionally out of scope (irreversible per-device operations —
see `docs/ROADMAP.md` § "M7 — Hardening"):

- NVS encryption with HMAC key in eFuses.
- Secure boot V2 + flash encryption.
- Auth-key rotation API (no remote trigger mechanism without
  control-plane / OTA delivery).

## DERP outbound round (2026-05-12 evening)

Two PRs that unlock the full DERP-mediated fallback path. Motivated
by a 2026-05-12 PM incident where Servidor1's WAN endpoint changed
(HA-failover ISP setup), the ESP32's cached endpoints went stale,
and direct UDP went into a 35-minute blackhole because the ESP32
had no fallback channel to learn the peer's new endpoints.

| PR (branch)                                            | Function                                                                            |
|--------------------------------------------------------|--------------------------------------------------------------------------------------|
| `feat/derp-supervisor-spawn-pre-tls` (**PR-D0**)       | Move derp supervisor xTaskCreate to pre-TLS bringup (heap pristine, 12 KiB contig OK); wait-for-netmap moves into the task body. Closes the chronic `xTaskCreate(derp supervisor) failed` that fired on every boot. |
| `feat/derp-outbound-wg-transport-fallback` (**PR-D1**) | Lossless WG transport via DERP relay when direct UDP looks broken (path-stale watchdog OR sendto errno). Adds `wg_netif_relay_fn` callback + `tinylink_relay_via_derp` glue. |

Combined size impact: flash **+0.39 KiB**, DRAM **+32 B**, IRAM 0.

Architectural insight: most of the recovery machinery (CMM ingestion
via DERP, `send_disco_pings_to_cmm_endpoints`, the disco_prober that
matches txids on response pongs) already existed in source from
prior PRs. PR-D0 was the unblocker — the supervisor was the missing
piece because its xTaskCreate kept failing. Once the supervisor
spawned, the existing flow lit up:

```
peer NAT changes → peer's tailscaled detects new endpoint
   → CMM via DERP to our supervisor       ← PR-D0 enables this
      → handle_disco_relayed (CMM case)   ← existed
         → send_disco_pings_to_cmm_endpoints(new endpoints)
            → disco_prober tracks new txids
               → peer responds → prober matches → endpoint roam
                  → direct UDP resumes (recovery time: seconds)
```

PR-D1 then closes the "telemetry during recovery window" gap:
while the prober is still matching the new endpoint, the TX worker
ships any outbound packets through DERP instead of letting them
blackhole at the stale endpoint. The TX path checks
`last_transport_recv_us > WG_RX_STALE_THRESHOLD_MS` preemptively;
on a match it routes via `g.relay_cb` and skips direct sendto
entirely. Three new stats (`relayed_stale`, `relayed_errno`,
`relay_errors`) for soak observability.

Smoke validated (30-min capture, INTELCOM-CARDONA WPA2+PMF):
- 0 panics / xTaskCreate fails / WDT
- derp supervisor task spawned t=5.9 s + login OK at t=16.9 s
- **9 CMMs processed via DERP** (peer Servidor1 sending them as
  part of its NAT-punch routine; observable evidence the supervisor
  recv loop is actually delivering frames)
- 361 telemetry packets at 5 s cadence, single WG session whole
  window (`remote_idx=0x049221a7` constant)
- Relay paths dormant — direct UDP stayed healthy throughout, no
  path-stale event fired. The relay is in place; whether it fires
  under a forced flap is a follow-up soak.
- External validation: peer-side `ping 100.67.60.92` for 2755
  packets returned 95.83 % delivery / RTT avg 137 ms — matches
  pre-DERP-round baseline (no regression).

The combined recovery time for a real Servidor1 WAN flap is now
estimated **~30 s** (path-stale watchdog) instead of **35 min**
(waiting for `PeersChangedPatch[]` via long-poll), with zero
packets lost during the recovery window when PR-D1's relay path
activates.

## Possible future directions

These are not commitments — they are bigger-than-QoL extensions that
would meaningfully expand what tinylink can do. None are blocking the
current sensor-→-collector use case. See
[`docs/ROADMAP.md` § "Future directions"](docs/ROADMAP.md#future-directions)
for the rationale and rough effort sketch for each.

- **Streaming JSON parser** (yajl/jsmn-streaming style) to eliminate
  the `RESPONSE_BUF_SZ` body buffer entirely — would unlock larger
  tailnets without DRAM pressure and remove the BSS ceiling that
  currently caps `TL_MAX_PEERS = 4` and `TL_MAX_DERP_REGIONS = 28`.
- **Multi-peer support** — generalize the single-peer assumption in
  `wg_netif.c` (one `g.peer`, one `g.transport` session) to a peer
  table. Touches the replay window scheme (would need RFC 6479 2000-
  entry windows per peer) and the netmap-driven peer add/remove path.
- **PSRAM support** — moving lwIP pools, mbedtls handshake transients,
  and the WG demux scratch out of internal DRAM into PSRAM would lift
  the heap budget that today gates `CONFIG_TINYLINK_DERP_SUPERVISED`
  on some boards.
- **OTA over the tailnet** — fetch a signed firmware image from a
  tailnet peer (HTTPS or DERP-relayed) without touching WiFi
  credentials. Would close the "auth-key rotation needs a trigger
  mechanism" gap by giving us a signed-update path.
- **Power management with WG state preservation** — deep-sleep with
  WG session checkpoint to NVS so the device wakes back into an
  established tunnel without a fresh handshake. The TAI64N persistence
  in PR #51 is the foundation; would need session-key serialization
  + a re-establish-on-wake handshake budget.
- **Other sensor families** — current TMP117 driver is single-purpose.
  An I²C/SPI driver framework would let the same firmware base support
  BME280, SCD30, ADS1115, etc. without rebuilding the WG stack.
- **Mesh of devices** — once multi-peer lands, a sensor↔sensor topology
  (rather than star → collector) becomes possible. Useful for
  store-and-forward when the collector is offline.
- **Diagnostics web endpoint** — a tiny HTTP server on the WG netif
  that exposes `/stats` (heap, rekey count, RX-stale events,
  endpoint roams) for inspection from any tailnet peer with a
  browser.

Each item below has a longer write-up in `docs/ROADMAP.md` with
expected effort, dependencies, and what the firmware would unlock.

Not production-ready. Not affiliated with Tailscale Inc. The Tailscale
name and logo are trademarks of Tailscale Inc.; this project is a
clean-room reimplementation of the documented wire protocols.

## Scope (what tinylink IS)

- Single-peer Tailscale client targeted at sensor telemetry use cases.
- ESP32-WROOM-32E target. No PSRAM required.
- USB-powered, always-on devices (no deep-sleep workloads).
- Pure C, ESP-IDF native (no Arduino, no ESPHome, no C++).

## Non-goals (what tinylink is NOT)

- Multi-peer mesh.
- MagicDNS, Tailnet Lock, ACL/PacketFilter enforcement on-device.
- Subnet routing or exit nodes.
- Taildrop, Funnel, Serve, Services.
- Tailscale SSH.
- IPv6 (v4-only at the netif layer).
- Battery-powered deep-sleep workloads.
- A drop-in replacement for `tailscaled`.

## Why

The official Tailscale client is ~23 MB (~4.5 MB with `extra-small` + UPX),
which does not fit a 4 MiB flash budget. MicroLink is the closest existing
reference (~950 KiB flash, **requires PSRAM** in any realistic configuration).
tinylink targets the gap below MicroLink: bare ESP32 with no PSRAM,
single-peer, ~600 KiB flash.

## Hardware

- Freenove ESP32-WROOM-32E DevKit (CH340 USB-UART).
- TMP117 high-accuracy temperature sensor on I²C. Default wiring per
  the Freenove DevKit pinout: SDA=GPIO21, SCL=GPIO22, ADD0 tied to
  GND for I²C address `0x48`. All three are overridable in
  `idf.py menuconfig` → *tinylink application* → *Telemetry*.

## Architecture

End-state component layout. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
for the full call graphs and threading model.

```
control plane (one Noise+HTTP/2 channel reused for everything):
  ts2021_client.c  Noise IK over TLS Upgrade → controlplane.tailscale.com
   ├── register.c       POST /machine/register (boot)
   ├── mapreq.c         POST /machine/map  (Stream=false lite push, then Stream=true poll)
   └── (long-poll task lives in tinylink.c::long_poll_task)

data plane (single UDP socket, demuxed):
  wg_netif.c       UDP socket + handshake + transport state machine
   ├── wg_demux.c       classify first byte: WG / DISCO / STUN
   ├── wg_handshake.c   Noise_IK_25519_ChaChaPoly_BLAKE2s
   ├── wg_transport.c   ChaCha20-Poly1305 + counter
   └── handle_disco_direct  inbound DISCO ping → sealed pong via same socket

  wg_lwip.c        lwIP integration (custom no-op netstack with init_fn
                   that installs raw-IP output/linkoutput; AUTOUP flag
                   instead of IS_PPP — see "WG netif as raw-IP carrier"
                   in ARCHITECTURE.md). REQUIRES idf-patches/ applied to
                   ESP-IDF — see BUILDING.md.

  stun_probe.c     RFC 5389 binding probe; runs ON the wg_netif socket
                   so the public AddrPort matches the WG NAT mapping

  derp_client.c    Long-lived TLS upgrade to PreferredDERP region
   tinylink.c::derp_supervised_task
   ├── handle_disco_relayed       relayed DISCO via DERP
   │    └── send_disco_pings_to_cmm_endpoints  CallMeMaybe → outbound
   │                                            DISCO ping (NAT punch)
   └── wg_netif_inject_packet     relayed WG transport → demux + handler

application:
  tmp117.c         I²C driver (continuous mode, ~1 s conversion)
  telemetry.c      JSON datagram → CONFIG_TINYLINK_TELEMETRY_DEST
                   (routed through wg_netif, so the dest is a tailnet IP)
```

Three properties that are non-obvious from a casual read of the code:

1. **One UDP socket carries everything**: WG transport, DISCO direct,
   STUN. The RX task classifies the first byte and dispatches; STUN
   piggy-backs on the WG socket at boot so the public AddrPort the
   control plane advertises lines up with the NAT mapping that WG
   keepalives keep pinned.

2. **The WG netif is a raw-IP carrier with no PPP/Ethernet baggage.**
   The IDF-v5.5 `dhcpc_cb` panic that historically forced an
   `ESP_NETIF_FLAG_IS_PPP` workaround is now patched at the source —
   the firmware ships two minimal patches in `idf-patches/` (a
   DHCP_CLIENT whitelist in `esp_netif_lwip.c` plus a NULL-guard in
   `dhcp_state.c`). With those applied, the netif uses
   `ESP_NETIF_FLAG_AUTOUP` and a custom no-op netstack whose `init_fn`
   installs WG-aware `output`/`linkoutput` directly into the lwIP
   netif. End result: raw IP both directions, no PPP allocations, no
   LCP retry storm at boot, ~4.4 KiB more heap free. See
   `BUILDING.md` for the patch-apply step.

3. **Endpoints are pushed via a "lite" MapRequest** (Stream=false +
   OmitPeers=true), the only shape modern Tailscale.com persists at
   CapVer ≥ 68. The long-poll Stream=true is read-only — it streams
   netmap updates but ignores any Hostinfo/Endpoints in the request.

## Roadmap

| # | Milestone                                       | Status                |
|---|-------------------------------------------------|-----------------------|
| 1 | ts2021 control plane (register only)            | done                  |
| 2 | MapRequest streaming + WireGuard data plane     | done                  |
| 3 | DISCO P2P discovery + TMP117 telemetry          | done                  |
| 4 | STUN minimal binding                            | done                  |
| 5 | DERP relay fallback + direct-UDP NAT traversal  | done                  |
| 6 | ICMP-over-WG end-to-end                         | done                  |
| 7 | Production hardening                            | done — within scope   |
| 8 | Perf + power round (2026-05-10)                 | done                  |
| 9 | sdkconfig perf-trim round (2026-05-12 PM)       | done — 5 PRs merged (#76-#80) |
| 10 | DERP outbound round (2026-05-12 evening)       | done — PR-D0 + PR-D1 merged (#82, #83), 30-min smoke OK, relay dormant pending forced flap test |

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the per-milestone breakdown.

## Building

See [`docs/BUILDING.md`](docs/BUILDING.md). TL;DR:

```bash
source ~/entorno_investigación/bin/activate
. ~/esp/esp-idf-v5.5.4/export.sh
idf.py set-target esp32
idf.py build
```

Host-side codec tests:

```bash
cd tools/test
make
for t in test_*; do ./$t; done   # 15 KAT binaries, all should report ALL OK
```

On-device AEAD micro-bench (opt-in via `CONFIG_TINYLINK_BENCH_AEAD`,
off by default — see [`docs/BUILDING.md`](docs/BUILDING.md#benchmarking-aead)).
Used to measure the ChaCha20-Poly1305 hot path. The pre-perf-round
baseline on ESP32 LX6 was ~660 µs/encrypt and ~654 µs/decrypt at
1500 B; the post-`-O2` build (PR #65) ships the same code with
component-scoped `-O2` and donna-backed curve25519 — re-measure with
`CONFIG_TINYLINK_BENCH_AEAD=y` if you need hard numbers for your
build. `CHANGELOG.md` has the full change log including the perf
round detail.

## Provisioning

Credentials (WiFi + Tailscale auth key) are stored in an encrypted NVS
partition. The Curve25519 node identities are generated on first boot
and persisted automatically. See [`docs/PROVISIONING.md`](docs/PROVISIONING.md).

## Examples

- [`examples/milestone1_register/`](examples/milestone1_register/) —
  register the device with the Tailscale control plane and watch it
  appear in the admin panel.

## License

MIT — see [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md) for the disclosure policy and
[`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) for the threat model.
