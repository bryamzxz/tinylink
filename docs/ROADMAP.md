# Roadmap / Hoja de ruta

> Bilingual (EN / ES). Other docs are English-only.

The detailed protocol map and memory/flash budgets that drive the
milestone breakdown below come from a research artifact maintained
out-of-tree by the maintainer (referenced in
`/home/bryam/Descargas/compass_artifact_*.md`). All section citations of
the form `[research §X]` point at that document; line citations of the
form `tailscale/path/file.go:start-end` point at the upstream Tailscale
Go implementation, which is the authoritative reference for wire format.

## Milestones (high level)

| #  | Name                                          | Status   | Targeted release | Estimate |
|----|-----------------------------------------------|----------|------------------|----------|
| M1 | ts2021 control plane (register only)          | current  | v0.1             | 2-3 wk   |
| M2 | MapRequest streaming + WireGuard data plane   | pending  | v0.2             | 2-3 wk   |
| M3 | DISCO P2P discovery + TMP117 telemetry        | pending  | v0.3             | 1-2 wk   |
| M4 | STUN minimal binding                          | pending  | v0.4             | 0.5 wk   |
| M5 | DERP relay fallback + reconnection            | pending  | v0.5             | 1-2 wk   |
| M6 | Production hardening (NVS, secure boot, OTA)  | pending  | v0.6             | ongoing  |

Total realistic timeline (one engineer full-time): **8–12 weeks**
[research §K].

## M1 — ts2021 control plane (current)

EN: The device:
1. Generates Curve25519 identities (MachineKey, NodeKey, DiscoKey) on first
   boot, after WiFi is up so `esp_random()` is a true TRNG, and persists
   them in NVS namespace `tl_keys` [research §L].
2. Bootstraps the control plane public key via `GET /key?v=100`, pins it
   in NVS namespace `tl_pin`. Compile-in fallback pin recommended for
   production (M6).
3. Opens TLS to `controlplane.tailscale.com:443`, sends an HTTP Upgrade
   request (`Upgrade: tailscale-control-protocol`) whose body carries
   Noise IK message 1. Prologue is the single byte `0x01` (protocol
   version) per upstream commit `1b7380a`.
4. Reads the 101 Switching Protocols response and Noise IK message 2,
   completing the handshake.
5. Consumes the EarlyNoise frame containing a NodeKeyChallenge,
   opens it with NodeKey priv via NaCl-box, and re-encrypts the response
   per `tailscale/control/controlclient/direct.go:1159-1239`.
6. Sends `POST /machine/register` (HTTP/2 inside the Noise channel via
   nghttp2) with the auth key from NVS and the NodeKeySignature.
7. Reads the response. On `MachineAuthorized=true` the device is registered
   and idle; on `false` it retries on a slow cadence.

ES: Idem traducido. Definitions of done iguales que en EN.

**Done when:** the device shows up in
`https://login.tailscale.com/admin/machines` with hostname `sensor-cali`,
status online, an assigned `100.x.y.z`. Pings to it will not work yet —
M1 has no data plane.

**Known gaps in the current scaffolding** (see follow-up tasks):
- nghttp2 is not yet wired; `register.c` sends HTTP/1.1 which the
  production server rejects.
- The NodeKeyChallenge response in `ts2021_client.c:process_early_noise`
  signs the base64 challenge string; the correct flow is open-then-
  re-encrypt against the control plane DiscoKey.
- All vendored crypto is unvalidated against test vectors.

## M2 — MapRequest + WireGuard data plane

EN: After register, the same Noise channel transitions into a long-lived
`POST /machine/map` with `Stream: true`. The server streams
newline-delimited `tailcfg.MapResponse` JSON objects [research §I].
Parse with **jsmn** (zero-alloc tokenizer, ~350 LoC), not cJSON DOM —
budget 20 KB SRAM during parse, 4 KB for retained peer state. Disable
zstd by not advertising support (saves ~30 KB flash).

Lift `trombik/esp_wireguard` (active port of `smartalock/wireguard-lwip`,
~3500 LoC C, BSD-3) as the data-plane component [research §B]. Patch
~50 lines in `wireguardif.c` to accept packets injected from a demuxer
task rather than `udp_bind(IP_ADDR_ANY, port)` so the same UDP socket
can multiplex DISCO/STUN later.

Cookie reply (WG message type 3, XChaCha20-Poly1305) is intentionally
**dropped on receive** and `mac2 = 0^16` always on send — saves ~1-2 KB
flash and removes XChaCha20/HChaCha20 from the binary. This is
spec-compliant.

ES: Mismo contenido, en español a futuro.

## M3 — DISCO + TMP117 telemetry

EN: NaCl-box DISCO ping/pong on the WG UDP socket (multiplexed by first
byte: WG types 1-4, DISCO `0x54 0x53 0xF0 0x9F 0x92 0xAC` = "TS💬",
STUN `0x00 0x01`). Only message types 0x01 (Ping), 0x02 (Pong),
0x03 (CallMeMaybe) are required. Drop 0x04-0x09 (peer-relay) on receive,
never emit [research §C].

Path probing collapses to one address: send Ping to last-known endpoint
on startup, mark "up" on first valid Pong, heartbeat every 2 s. ~150 LoC
versus ~1500 in the real implementation.

Re-introduce the TMP117 driver (continuous mode, 8-sample averaging) and
the FreeRTOS telemetry task that the original M1 sketched.

ES: idem.

## M4 — STUN

EN: 20-byte RFC 5389 binding request to the STUN port of the home DERP
region (3478) at startup. Decode XOR-MAPPED-ADDRESS, stuff the result
into MapRequest.Endpoints. ~50 LoC C. **Skip** all `netcheck` NAT-type
classification, MTU discovery, and DERP latency ranking [research §E].
Re-do only when the UDP 5-tuple changes (~"never" for a stationary
sensor unless the router reboots).

ES: idem.

## M5 — DERP

EN: Minimal DERP client over TLS (HTTP Upgrade), framed as
`type(1) || BE32 length || payload`. Constants in `derp/derp.go`
upstream. Required frames: `FrameServerKey(0x01)`, `FrameClientInfo(0x02)`,
`FrameSendPacket(0x04)`, `FrameRecvPacket(0x05)`, `FrameKeepAlive(0x06)`,
`FramePing(0x0D)`, `FramePong(0x0E)` [research §D]. **Skip**
WatchConns/ForwardPacket/ClosePeer (mesh / admin only),
`FrameHealth` (log-only), `CanAckPings` negotiation (always respond).

DERP is opened on demand: keep alive only when direct UDP fails 3× in
30 s; close as soon as direct path recovers. Saves ~14 KB SRAM task
stack + 8 KB mbedtls context for the steady state.

ES: idem.

## M6 — Hardening

EN: TAI64N monotonicity tests across reboot scenarios (NVS-persisted
epoch counter). NVS encryption with HMAC key in eFuses. Watchdog +
reconnection with exponential backoff (cap 30 s). Auth-key rotation
path. Compile-in fallback control plane pubkey. Constant-time
Curve25519 swap (`trombik/esp_wireguard/src/crypto/x25519.c`). Disassembly
review of all crypto functions to verify no secret-dependent branches
[research §L].

ES: idem.
