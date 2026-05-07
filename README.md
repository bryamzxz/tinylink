# tinylink

A minimalist Tailscale-compatible client for **ESP32-WROOM-32E (no PSRAM)**,
written in pure C on **ESP-IDF v5.5.x**.

## Status

**Pre-alpha — DERP relay path live.** M1 lands the ts2021 control
plane (Noise IK + register). M2 lands the `MapRequest` emitter
(`jsmn` parser, top-level `Endpoints` + `NetInfo`, `Stream:false`
push so the server actually persists state) and the in-tree
WireGuard data plane (`wg_netif`, `wg_lwip` over a PPP-flagged
esp_netif). M3 lands TMP117 telemetry. M4 lands a minimal STUN
binding probe. **M5 first cut**: the DERP supervisor task
connects to the `PreferredDERP` region pulled from the netmap,
maintains the long-lived TLS upgrade against `derpNN.tailscale.com`,
and answers DISCO Pings with sealed Pongs over the relay —
`tailscale ping sensor-cali` from another tailnet node returns
pongs via DERP reliably across multi-minute sessions.

**The remaining gap**: real ICMP over the WG transport. Outbound
packets routed via the WG netif from the lwIP TCPIP task are
guarded against re-entering the lwIP socket API (which would
deadlock the data plane); a follow-up queue model that posts
encrypted bytes to a worker task running outside TCPIP context is
the proper fix and unlocks ICMP end-to-end.

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

- **ts2021 control protocol** (Milestone 1, current): Noise IK
  (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) inside TLS to
  `controlplane.tailscale.com`. The device generates Curve25519 identities
  on first boot, fetches and pins the control plane public key, and
  registers via `POST /machine/register`.
- **MapRequest + WireGuard data plane** (Milestone 2, landed): the
  Noise channel already runs HTTP/2 via nghttp2 from M1, so M2
  reuses it for `POST /machine/map`. A jsmn-based parser extracts
  only the fields the data plane needs (self/peer addresses, peer
  endpoints, DERP map). The data plane is in-tree under
  `components/tinylink/src/wg_netif.{c,h}` and `wg_lwip.c`: a UDP
  socket for the wire transport, an esp_netif with PPP-flagged
  netstack as the lwIP integration point, ChaCha20-Poly1305
  transport via the in-tree `wg_transport.c`, and a single-peer
  selector (`select_target_peer`) that prefers cross-NAT-reachable
  endpoints over hairpin-blocked ones.
- **DISCO** (Milestone 3, partial): NaCl-box ping/pong implemented
  in `disco_handler.c`. Today it answers Pings relayed via DERP
  (the supervisor task hands frames to the handler, which seals a
  Pong and ships it back over the relay). Direct-UDP DISCO
  multiplexed on the WG socket lands alongside the queue-based
  outbound rework.
- **STUN** (Milestone 4, landed): minimal RFC 5389 binding probe at
  boot, result re-advertised on every MapRequest's `Endpoints`.
  Re-probe runs on a slow timer to track NAT port rotation.
- **DERP** (Milestone 5, first cut landed): supervisor task in
  `tinylink.c::derp_supervised_task` keeps a long-lived TLS upgrade
  to the `PreferredDERP` region's first node and dispatches relayed
  frames either to the DISCO handler or back into `wg_netif` via
  `wg_netif_inject_packet`. Outbound DERP send (relayed WG transport
  for end-to-end ICMP) lands in the same queue-based PR as the
  outbound WG fix.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
[`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the full protocol map.

## Roadmap

| # | Milestone                                       | Status                |
|---|-------------------------------------------------|-----------------------|
| 1 | ts2021 control plane (register only)            | done                  |
| 2 | MapRequest streaming + WireGuard data plane     | done                  |
| 3 | DISCO P2P discovery + TMP117 telemetry          | partial — DISCO via DERP works; direct UDP demux pending |
| 4 | STUN minimal binding                            | done                  |
| 5 | DERP relay fallback + reconnection              | first cut — recv path live; outbound queue pending |
| 6 | Production hardening (NVS, secure boot, OTA)    | pending               |

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for details.

## Building

See [`docs/BUILDING.md`](docs/BUILDING.md). TL;DR:

```bash
source ~/entorno_investigación/bin/activate
. ~/esp/esp-idf-v5.5.4/export.sh
idf.py set-target esp32
idf.py build
```

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
