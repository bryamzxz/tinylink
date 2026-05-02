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
| M1 | ts2021 control plane (register only)          | done     | v0.1             | 2-3 wk   |
| M2 | MapRequest streaming + WireGuard data plane   | current  | v0.2             | 2-3 wk   |
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
   `"nlpub:" + 64 zeros` until M6 hardening adds real Ed25519
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
- `NLKey` is sent as 32 zero bytes until M6 hardening lands real
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

**Step 3 (deferred to M3, alongside DISCO):**
- Swap `Stream:false` for `Stream:true`; run the parser in a long-poll
  loop driven by an `app_task` FreeRTOS task; update the WG peer
  endpoint in place when MapResponse churns.
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
