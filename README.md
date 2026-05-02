# tinylink

A minimalist Tailscale-compatible client for **ESP32-WROOM-32E (no PSRAM)**,
written in pure C on **ESP-IDF v5.5.x**.

## Status

**Pre-alpha — Milestone 1 complete, Milestone 2 in progress.** M1 lands
the ts2021 control plane (Noise IK + register, wire format verified
against upstream in commit `2717ab7`). M2 is starting on the data
plane: a `MapRequest` emitter and `jsmn`-based `MapResponse` parser
have landed; the WireGuard component (lift of `trombik/esp_wireguard`
+ demuxer patch) is the next piece.

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
- TMP117 high-accuracy temperature sensor on I²C — re-enabled in M3.

## Architecture

- **ts2021 control protocol** (Milestone 1, current): Noise IK
  (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) inside TLS to
  `controlplane.tailscale.com`. The device generates Curve25519 identities
  on first boot, fetches and pins the control plane public key, and
  registers via `POST /machine/register`.
- **MapRequest + WireGuard data plane** (Milestone 2, in progress): the
  Noise channel already runs HTTP/2 via nghttp2 from M1, so M2 reuses
  it for `POST /machine/map`. A jsmn-based parser extracts only the
  fields the data plane needs (self/peer addresses, peer endpoints,
  DERP map). The data plane lifts `trombik/esp_wireguard` with a
  ~50-line patch to `wireguardif.c` so packets are injected from a
  demuxer task instead of via `udp_bind` — that lets the same UDP
  socket multiplex DISCO/STUN later.
- **DISCO** (Milestone 3): NaCl-box over the same UDP socket as WireGuard,
  alongside the TMP117 driver and UDP telemetry task.
- **DERP** (Milestone 5): TLS relay fallback.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
[`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the full protocol map.

## Roadmap

| # | Milestone                                       | Status   |
|---|-------------------------------------------------|----------|
| 1 | ts2021 control plane (register only)            | done     |
| 2 | MapRequest streaming + WireGuard data plane     | current  |
| 3 | DISCO P2P discovery + TMP117 telemetry          | pending  |
| 4 | STUN minimal binding                            | pending  |
| 5 | DERP relay fallback + reconnection              | pending  |
| 6 | Production hardening (NVS, secure boot, OTA)    | pending  |

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
