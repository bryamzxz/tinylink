# tinylink

A minimalist Tailscale-compatible client for **ESP32-WROOM-32E (no PSRAM)**,
written in pure C on **ESP-IDF v5.5.x**. It registers with the Tailscale
control plane over ts2021 (Noise IK over TLS), brings up a WireGuard data
plane on a single UDP socket, NAT-punches to a direct path with DISCO + STUN,
falls back to DERP when it must, and ships TMP117 sensor telemetry over the
tunnel.

> **Not affiliated with Tailscale Inc.** The Tailscale name and logo are
> trademarks of Tailscale Inc.; this project is a clean-room
> reimplementation of the documented wire protocols.

## Why

The official Tailscale client is ~23 MB (~4.5 MB with `extra-small` + UPX),
which does not fit a 4 MiB flash budget. MicroLink is the closest existing
reference (~950 KiB flash, **requires PSRAM** in any realistic
configuration). tinylink targets the gap below MicroLink: a bare ESP32 with
**no PSRAM** and 520 KiB of internal SRAM, made possible by cutting scope to
a single peer. The current app image is ~925 KiB (2026-06 build) and fits
one of the two 1.5 MiB OTA slots of a stock 4 MB module.

## Status

**Production-ready — stable within the single-peer scope.** The firmware
runs 24/7 in its intended sensor-→-collector deployment. Milestones M1–M12
are all done and hardware-validated; the latest round (2026-06-10 audit
fix, PR #106) was validated end-to-end against tailscale.com. Per-milestone breakdown in
[`docs/ROADMAP.md`](docs/ROADMAP.md), per-PR history in
[`CHANGELOG.md`](CHANGELOG.md).

What works today, verified on real hardware:

- A peer running upstream `tailscaled` runs `tailscale ping sensor-cali`
  and gets pongs `via 190.x.x.x:<port>` (direct UDP, no DERP relay).
- The same peer runs `ping -c 10 100.67.60.92` (sensor-cali's tailnet IP)
  and gets `0% packet loss, ~93ms RTT` over the WireGuard tunnel —
  ICMP encapsulated, encrypted, decrypted, replied, end-to-end.
- TMP117 telemetry frames flow out over the same tunnel every 5 s.
- The Tailscale admin panel shows `Endpoints: 190.x.x.x:<port>` and
  `Client connectivity → UDP: Yes`.

| #  | Milestone                                      | Status |
|----|------------------------------------------------|--------|
| 1  | ts2021 control plane                           | done |
| 2  | MapRequest + WireGuard data plane              | done |
| 3  | DISCO P2P discovery + TMP117 telemetry         | done |
| 4  | STUN minimal binding                           | done |
| 5  | DERP relay fallback + direct-UDP NAT traversal | done |
| 6  | ICMP-over-WG end-to-end                        | done |
| 7  | Production hardening                           | done — within scope |
| 8  | Perf + power round (2026-05-10, #61–#65)       | done — constant-time crypto, light-sleep PM, QIO@80, -O2 |
| 9  | Protocol + crypto follow-ups (#85–#87)         | done |
| 10 | Perf-trim + footprint round (#88–#104)         | done — net −68.1 KiB flash, largest-contig heap 6656 → 9216 B |
| 11 | Security round (#105)                          | done — WGN-1 nonce-reuse race closed + 4 hardenings |
| 12 | Audit-fix round (2026-06-10, #106)             | done — capver 138 at the Noise layer, WG rx-path lock + relayed-DISCO peer gate, atomic key regen, depth-bounded MapResponse skip, secure_zero sweep |

Two further 2026-05-12 rounds — sdkconfig perf-trim (#76–#80) and DERP
outbound (#82–#83: supervisor spawn + lossless relay fallback during peer
NAT flap) — are documented in the CHANGELOG.

### Known limitations

None of these block the current sensor-→-collector path:

- **Single-peer only** — the netmap `PeersChanged`/`PeersRemoved`
  delta-merge is stubbed pending a multi-peer tailnet to validate against.
- **No task watchdog / `esp_restart` self-recovery** — a wedged task is a
  brick until physical reset.
- **NVS private keys are stored in PLAINTEXT** — there is no
  `CONFIG_SECURE_FLASH_ENC_ENABLED` and `keys.c` uses the default plain
  partition. At-rest/eFuse key encryption is aspirational (see
  *Provisioning*).
- **No SNTP / wall-clock** — `MBEDTLS_HAVE_TIME_DATE` is off, so the three
  TLS clients never validate cert `notBefore`/`notAfter`.
- **Three divergent backoffs** (DERP supervisor + `endpoint_push`, the
  latter two without jitter) want folding into a single `tl_backoff_ms`;
  deferred pending an extended soak (`endpoint_push` is
  regression-sensitive).
- **DERP relay TX path validated only dormant** — the PR-D1 relay fallback
  is in place but has not yet fired under a real forced flap; that soak
  needs peer-side (Servidor1) access.

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

## Hardware

- Freenove ESP32-WROOM-32E DevKit (CH340 USB-UART).
- TMP117 high-accuracy temperature sensor on I²C. Default wiring per the
  Freenove DevKit pinout: SDA=GPIO21, SCL=GPIO22, ADD0 tied to GND for I²C
  address `0x48`. All three are overridable in `idf.py menuconfig` →
  *tinylink application* → *Telemetry*.

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
   the firmware ships two minimal patches in [`idf-patches/`](idf-patches/)
   (a DHCP_CLIENT whitelist in `esp_netif_lwip.c` plus a NULL-guard in
   `dhcp_state.c`). With those applied, the netif uses
   `ESP_NETIF_FLAG_AUTOUP` and a custom no-op netstack whose `init_fn`
   installs WG-aware `output`/`linkoutput` directly into the lwIP
   netif. End result: raw IP both directions, no PPP allocations, no
   LCP retry storm at boot, ~4.4 KiB more heap free. See
   [`docs/BUILDING.md`](docs/BUILDING.md) for the patch-apply step.

3. **Endpoints are pushed via a "lite" MapRequest** (Stream=false +
   OmitPeers=true), the only shape modern Tailscale.com persists at
   CapVer ≥ 68. The long-poll Stream=true is read-only — it streams
   netmap updates but ignores any Hostinfo/Endpoints in the request.
   The advertised CapabilityVersion is `TINYLINK_CAPVER = 138`
   (= Tailscale v1.98), set once in `components/tinylink/include/
   tinylink.h` and derived into the Noise prologue, RegisterRequest,
   and MapRequest. It clears headscale's earlyNoise
   `MinSupportedCapabilityVersion` floor of 113 (= Tailscale v1.80),
   which the server enforces before any JSON is read. The separate
   `/key?v=100` floor in `control_key.c` is a deliberately lower,
   independent value for the legacy TOFU control-key fetch.

## Building

See [`docs/BUILDING.md`](docs/BUILDING.md) for the full walkthrough
(prerequisites, flash, monitor, serial capture). TL;DR:

```bash
source ~/entorno_investigación/bin/activate   # your IDF python venv
. ~/esp/esp-idf-v5.5.4/export.sh
idf.py set-target esp32
idf.py build
```

**Before the first flash**: apply the two **required** ESP-IDF patches in
[`idf-patches/`](idf-patches/) (see
[`docs/BUILDING.md`](docs/BUILDING.md#required-apply-idf-patches)).
Without them the firmware compiles cleanly but panics with
`LoadProhibited` at `dhcp_state.c:52` the first time the WG netif comes up.

### Tests

Host-side codec + crypto + state-machine tests — stock gcc, no ESP-IDF
needed:

```bash
cd tools/test
make test          # 20 binaries · 531 assertions, all should report PASS
```

CI ([`.github/workflows/build.yml`](.github/workflows/build.yml)) builds
the firmware against ESP-IDF v5.5 on every push/PR; the host suite runs
locally.

On-device AEAD micro-bench: opt-in via `CONFIG_TINYLINK_BENCH_AEAD=y`
(off by default — see
[`docs/BUILDING.md`](docs/BUILDING.md#benchmarking-aead)). The
pre-perf-round baseline on the ESP32 LX6 was ~660 µs/encrypt and
~654 µs/decrypt at 1500 B; re-measure on your build if you need hard
numbers.

## Provisioning

Credentials (WiFi + Tailscale auth key) are stored in NVS. The Curve25519
node identities are generated on first boot and persisted automatically.
**NVS is currently a plaintext partition** —
`CONFIG_SECURE_FLASH_ENC_ENABLED` is not set, so at-rest/eFuse key
encryption is aspirational, not enabled (tracked under *Known
limitations*). See [`docs/PROVISIONING.md`](docs/PROVISIONING.md).

## Examples

- [`examples/milestone1_register/`](examples/milestone1_register/) —
  register the device with the Tailscale control plane and watch it
  appear in the admin panel.

## Repository layout & documentation

```
components/tinylink/   protocol implementation: control plane, data plane, vendored crypto
main/                  app entry: WiFi bring-up, tinylink start, telemetry app
docs/                  the documents indexed below
idf-patches/           two REQUIRED patches to ESP-IDF v5.5 (see Building)
tools/                 NVS provisioning + serial-capture helpers
tools/test/            host-side test suite (make test)
examples/              minimal register-only example
```

| Document | Contents |
|----------|----------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Component call graphs, task model, the WG-netif raw-IP design |
| [`docs/PROTOCOL.md`](docs/PROTOCOL.md) | Clean-room wire-protocol map (ts2021, MapRequest, WG, DISCO, DERP, STUN) with upstream citations |
| [`docs/BUILDING.md`](docs/BUILDING.md) | Environment setup, required IDF patches, build/flash/monitor, AEAD bench |
| [`docs/PROVISIONING.md`](docs/PROVISIONING.md) | NVS credential provisioning (WiFi + auth key) |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Per-milestone breakdown M1–M12, open backlog, future directions |
| [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) | Threat model + audit history |
| [`CHANGELOG.md`](CHANGELOG.md) | Per-PR history of every round |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contribution guidelines |
| [`SECURITY.md`](SECURITY.md) | Disclosure policy |

## Possible future directions

Not commitments — bigger-than-QoL extensions, none blocking the current
sensor-→-collector use case. Rationale and effort sketches in
[`docs/ROADMAP.md` § "Future directions"](docs/ROADMAP.md#future-directions).

- **Streaming JSON parser** — eliminate the `RESPONSE_BUF_SZ` body buffer;
  lifts the BSS ceiling behind `TL_MAX_PEERS = 4`.
- **Multi-peer support** — peer table in `wg_netif.c`, per-peer RFC 6479
  replay windows, netmap-driven peer add/remove.
- **PSRAM support** — move lwIP pools, mbedTLS transients, and the WG
  demux scratch out of internal DRAM.
- **OTA over the tailnet** — signed image fetch from a tailnet peer; also
  gives auth-key rotation the trigger mechanism it lacks.
- **Deep-sleep with WG state preservation** — session checkpoint to NVS so
  the device wakes into an established tunnel (the TAI64N persistence from
  PR #51 is the foundation).
- **Other sensor families** — an I²C/SPI driver framework beyond TMP117
  (BME280, SCD30, ADS1115, …).
- **Mesh of devices** — sensor↔sensor store-and-forward once multi-peer
  lands.
- **Diagnostics web endpoint** — tiny HTTP `/stats` on the WG netif (heap,
  rekey count, RX-stale events, endpoint roams).

## Security

See [`SECURITY.md`](SECURITY.md) for the disclosure policy and
[`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) for the threat model.

## License

MIT — see [LICENSE](LICENSE).
