# Protocol map

tinylink rides on a small subset of the protocols `tailscaled` speaks. This
document is the *cleanroom* reference we use to keep our implementation
honest. None of it is official Tailscale documentation — see the published
`tailscale/tailscale` repo for ground truth.

## Authoritative references

- Tailscale upstream Go source — the wire-format ground truth. Specific
  files cited throughout this doc and inline in the C source via
  `TS2021_VERIFY` comments.
- Out-of-tree research artifact maintained by the project owner at
  `/home/bryam/Descargas/compass_artifact_*.md`, which indexes the
  upstream files, gives memory/flash budgets, and lists the
  minimum-viable subset for a single-peer ESP32. Cited as
  `[research §X]`.

## Layered view (M1 + later)

```
   App: TMP117 telemetry (UDP, JSON)         ← M3
   ────────────────────────────────────────
   MapResponse: protobuf (long-lived stream) ← M2
   HTTP/2 inside Noise (nghttp2)             ← M2
   ────────────────────────────────────────
   /machine/register: HTTP/1.1 inside Noise  ← M1 (current)
   ts2021: Noise IK + HTTP Upgrade in TLS    ← M1
   ────────────────────────────────────────
   DISCO: NaCl-box on WG UDP socket          ← M3
   WireGuard data plane (droscy/esp_wireguard)← M2
   UDP / IPv4
   WiFi STA
```

## Cryptographic primitive table

| Primitive           | Used by             | Source              | Why                                |
|---------------------|---------------------|---------------------|------------------------------------|
| ChaCha20-Poly1305   | Noise IK, WG, DERP  | mbedTLS (HW-accel)  | ESP32 has accelerator; same impl   |
| Curve25519 (X25519) | Noise IK, WG        | vendored placeholder | constant-time required (see below) |
| BLAKE2s             | Noise IK            | vendored RFC 7693   | small, simple, no IDF builtin      |
| HMAC-BLAKE2s + HKDF | Noise IK            | vendored            | Noise §4.3 KDF                     |
| TLS 1.2/1.3         | ts2021, DERP        | mbedTLS             | already linked                     |
| Salsa20 / XSalsa20  | NaCl-box (DISCO)    | vendored            | tiny dep                           |
| Poly1305            | NaCl-box auth tag   | mbedTLS             | already linked                     |

> The `curve25519.c` shipped today is **TweetNaCl-derived, not constant-time
> donna**. It is *designed* to be constant-time but is not as carefully
> audited as the canonical donna implementation. For production use, swap
> with `trombik/esp_wireguard`'s `src/crypto/x25519.c`. See
> [`SECURITY-MODEL.md`](SECURITY-MODEL.md).

## ts2021 (M1)

The control connection is TLS to `controlplane.tailscale.com`. The HTTP
request is a `POST /ts2021` with `Upgrade: tailscale-control-protocol`
(token confirmed in `control/ts2021/server.go` upstream — the shorter
"ts2021" form is the URL path, not the upgrade token). The request body
is a single ts2021 frame
(`version(1) || type=HANDSHAKE(1) || BE16 length || Noise IK msg1`).
The server replies `101 Switching Protocols` and switches to the same
framing for all subsequent traffic.

The Noise IK prologue is a single byte `0x01` (the protocol version),
MixHash'd before message 1 — see upstream commit `1b7380a`
"control/noise: include the protocol version in the Noise prologue".

After the upgrade and the EarlyNoise message, **the inner protocol is
HTTP/2** (per `tailscale/control/ts2021/`). tinylink wraps
`ts2021_send` / `ts2021_recv` with nghttp2 (espressif/nghttp managed
component) in `components/tinylink/src/h2_client.c`. SETTINGS sent by
the client disable HPACK dynamic-table indexing
(`SETTINGS_HEADER_TABLE_SIZE = 0`) and server push
(`SETTINGS_ENABLE_PUSH = 0`) for one-shot request semantics.

After the upgrade the connection carries:

- `version(1) || type=HANDSHAKE(1) || BE16 length || Noise IK msg2`
  (responder's reply).
- Optional EarlyNoise frame: `version(1) || type=RECORD(2) || BE16 length
  || ChaChaPoly(noise_recv_key, JSON)`. JSON has a `NodeKeyChallenge`
  field; we sign it with the NodeKey via NaCl-box and stash the result
  for `RegisterRequest`.
- All further traffic is HTTP/1.1 (M1) or HTTP/2 (M2+) wrapped in
  `type=RECORD(2)` frames.

`TS2021_VERIFY` markers in `components/tinylink/src/ts2021_client.c` flag
the spots where the exact wire format needs to be cross-checked against
`tailscale/control/ts2021/types.go`,
`tailscale/control/ts2021/server.go`, and
`tailscale/control/controlclient/direct.go`.

## /machine/register (M1)

JSON body, fields used today:

| Field               | Notes                                              |
|---------------------|----------------------------------------------------|
| `Version`           | `100` — our IPN/MapRequest schema version.         |
| `NodeKey`           | `"nodekey:" + 64-hex` of NodeKey public.           |
| `OldNodeKey`        | `"nodekey:" + 64 zeros` on first registration.     |
| `Hostinfo.OS`       | `"esp32"`.                                         |
| `Hostinfo.Hostname` | from `CONFIG_TINYLINK_DEVICE_HOSTNAME`.            |
| `Hostinfo.IPNVersion` | `"0.1.0-tinylink"`.                              |
| `Auth.AuthKey`      | `tskey-auth-...` from NVS `tl_creds/auth_key`.     |
| `Timestamp`         | RFC3339 from the device clock.                     |
| `Expiry`            | `"0001-01-01T00:00:00Z"` (no expiry).              |
| `Ephemeral`         | `false`.                                           |
| `NodeKeySignature`  | base64 of the NaCl-box-signed NodeKeyChallenge.    |

Response fields used today:

| Field                | Notes                                              |
|----------------------|----------------------------------------------------|
| `MachineAuthorized`  | `true` → registered. `false` → operator must approve. |
| `Error`              | non-empty on hard failure.                         |

## MapResponse (M2)

Protobuf-framed, length-delimited, streamed over a long-lived HTTP/2
stream. tinylink will decode only the fields it needs (peer list, derp
map, self-node info). Packet-filter / ACL fields are **not** enforced
on-device.

## DISCO (M3)

UDP datagrams piggy-back on the same socket WireGuard uses. Each datagram
is a NaCl-box with the static DISCO key. The first valid pong upgrades a
peer from "DERP-relayed" to "direct".

## DERP (M5)

A WebSocket-like framing over TLS to a regional DERP node. tinylink uses
DERP only as a fallback for DISCO failures, not as a primary path.
