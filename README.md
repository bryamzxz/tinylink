# tinylink

A minimalist Tailscale-compatible client for **ESP32-WROOM-32E (no PSRAM)**,
written in pure C on **ESP-IDF v5.5.x**.

## Status

**Pre-alpha — Milestone 1 in progress.** Not production-ready. Not affiliated
with Tailscale Inc. The Tailscale name and logo are trademarks of Tailscale Inc.;
this project is a clean-room reimplementation of the documented wire protocols.

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
tinylink targets the gap below MicroLink: bare ESP32 with no PSRAM, single-peer,
~600 KiB flash.

## Hardware

- Freenove ESP32-WROOM-32E DevKit (CH340 USB-UART).
- TMP117 high-accuracy temperature sensor on I²C (default GPIO 21/22, addr 0x48).

## Architecture

- **WireGuard data plane** via [`droscy/esp_wireguard`](https://github.com/droscy/esp_wireguard) v0.4.4.
  The original `trombik/esp_wireguard` is abandoned and breaks on IDF ≥ 5.3
  because of the default `CONFIG_LWIP_TCPIP_CORE_LOCKING=y`. We pin droscy's fork.
- **ts2021 control protocol** (Milestone 2+): Noise IK + HTTP/2 inside TLS to
  `controlplane.tailscale.com`.
- **DISCO** (Milestone 4+): NaCl-box over the same UDP socket as WireGuard.
- **DERP** (Milestone 5+): TLS relay fallback.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
[`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the full protocol map.

## Roadmap

| # | Milestone                                | Status   |
|---|------------------------------------------|----------|
| 1 | WireGuard standalone (static peer)       | scaffold |
| 2 | ts2021 Noise IK handshake                | pending  |
| 3 | MapResponse parsing                      | pending  |
| 4 | DISCO P2P discovery                      | pending  |
| 5 | DERP relay fallback                      | pending  |
| 6 | Production hardening                     | pending  |

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for details.

## Building

See [`docs/BUILDING.md`](docs/BUILDING.md). TL;DR:

```bash
. $HOME/esp/esp-idf-v5.5.4/export.sh
idf.py set-target esp32
idf.py build
```

## Provisioning

Credentials (WiFi + WireGuard keys + peer config) are stored in an encrypted
NVS partition. See [`docs/PROVISIONING.md`](docs/PROVISIONING.md).

## License

MIT — see [LICENSE](LICENSE).

## Security

See [SECURITY.md](SECURITY.md) for the disclosure policy and
[`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) for the threat model.
