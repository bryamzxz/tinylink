# tinylink

A minimalist Tailscale-compatible client for **ESP32-WROOM-32E (no PSRAM)**,
written in pure C on **ESP-IDF v5.5.x**.

## Status

**Pre-alpha — direct UDP + ICMP-over-WG live end-to-end.**

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
| Production hardening (M6)      | pending                                |

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

- M6 hardening (real Ed25519 NLKey, secure boot, OTA, NVS encryption).
- Pre-punch on netmap-receive (cuts the first `tailscale ping` from
  3-DERP-rounds-then-direct down to direct-from-attempt-1).
- DERP outbound queue (only relevant for peers behind shared CGNAT
  where direct UDP can never work — for peers with public IPs the
  direct path covers everything).
- Multi-peer (single-peer today).

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

  wg_lwip.c        lwIP integration (PPP-flagged esp_netif, but with
                   linkoutput / output / input bypassed so it carries
                   raw IP — see "WG netif as raw-IP carrier" in ARCHITECTURE.md)

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

2. **The WG netif is PPP-flagged but is NOT a PPP link.** The flag
   tells esp_netif "no DHCP, no ARP, point-to-point" and sidesteps an
   IDF-v5.5 `dhcpc_cb` panic; we then override the netif's
   `input` / `output` / `linkoutput` so that ingress doesn't get
   eaten by the PPP HDLC framer and egress doesn't get wrapped in PPP
   protocol headers. End result: the netif carries raw IP both
   directions, which is what WireGuard needs.

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
| 7 | Production hardening (NVS, secure boot, OTA)    | pending               |

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
Used to measure the ChaCha20-Poly1305 hot path; current numbers on
ESP32 LX6 are ~660 µs/encrypt and ~654 µs/decrypt at 1500 B
(`CHANGELOG.md` has the full change log).

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
