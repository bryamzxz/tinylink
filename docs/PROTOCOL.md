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
request is `POST /ts2021` with `Upgrade: tailscale-control-protocol`,
`Connection: upgrade`, and `Content-Length: 0`. The Noise IK initiation
bytes do **not** travel in the request body — they ride in an
`X-Tailscale-Handshake: <base64>` header, per
`tailscale/control/controlhttp/client.go` and
`controlhttpcommon.HandshakeHeaderName`. The server replies
`101 Switching Protocols`, after which the same TLS connection carries
controlbase frames.

Two distinct frame layouts (see `tailscale/control/controlbase/messages.go`):

- **Initiation frame** (5-byte header + 96-byte Noise msg1):
  `BE16 protocolVersion || type(1) || BE16 payloadLen`. The base64 of
  the full 101 bytes is what goes in `X-Tailscale-Handshake`.
- **All later frames** (3-byte header):
  `type(1) || BE16 payloadLen`.

Frame types: `1=initiation`, `2=response`, `3=error`, `4=record`. The
post-handshake records (`type=4`) carry ChaCha20-Poly1305 ciphertext
authenticated under the Noise transport keys. `maxMessageSize=4096`,
giving a plaintext cap of `4096 − 3 − 16 = 4077`.

The Noise IK prologue is the **string**
`"Tailscale Control Protocol v1"` (prefix `"Tailscale Control Protocol v"`
+ decimal protocol version, per `controlbase/handshake.go:protocolVersionPrologue`).
The earlier note in this doc that called the prologue "the single byte
`0x01`" was wrong; that byte appears in the cleartext init header, not
in the Noise prologue.

After the upgrade and the optional EarlyPayload, the inner protocol is
**HTTP/2** (per `tailscale/control/ts2021/`). tinylink wraps
`ts2021_send` / `ts2021_recv` with nghttp2 (espressif/nghttp managed
component) in `components/tinylink/src/h2_client.c`. SETTINGS sent by
the client disable HPACK dynamic-table indexing
(`SETTINGS_HEADER_TABLE_SIZE = 0`) and server push
(`SETTINGS_ENABLE_PUSH = 0`) for one-shot request semantics.

After `read_msg2` the connection optionally carries an EarlyPayload
sentinel — `"\xff\xff\xffTS"` (5 B) + `BE32 length` + JSON-encoded
`tailcfg.EarlyNoise` (per `tailscale/control/ts2021/conn.go`,
`hdrLen=9`). Its only field is `NodeKeyChallenge`. The current upstream
client reads it but no caller of `GetEarlyPayload` exists in production
(`SealToChallenge` / `OpenFrom` from `types/key/chal.go` are referenced
only in tests). tinylink therefore **drains and discards** the
EarlyPayload bytes and starts the HTTP/2 stream from whatever follows.

## /machine/register (M1)

JSON body, fields used today:

| Field               | Notes                                              |
|---------------------|----------------------------------------------------|
| `Version`           | `1` — Noise transport `CapabilityVersion` (upstream pins this on the wire; feature gating is keyed on `Hostinfo`, not `Version`). |
| `NodeKey`           | `"nodekey:" + 64-hex` of NodeKey public.           |
| `OldNodeKey`        | `"nodekey:" + 64 zeros` on first registration.     |
| `NLKey`             | `"nlpub:" + 64 zeros` for M1 (TKA disabled). Real Ed25519 NLPrivate generation lands in M6 hardening. The field has no `omitempty` upstream, so it must be present. |
| `Hostinfo.OS`       | `"esp32"`.                                         |
| `Hostinfo.Hostname` | from `CONFIG_TINYLINK_DEVICE_HOSTNAME`.            |
| `Hostinfo.IPNVersion` | `"0.1.0-tinylink"`.                              |
| `Auth.AuthKey`      | `tskey-auth-...` from NVS `tl_creds/auth_key`.     |
| `Timestamp`         | RFC3339 from the device clock.                     |
| `Expiry`            | `"0001-01-01T00:00:00Z"` (no expiry).              |
| `Ephemeral`         | `false`.                                           |

`NodeKeySignature` is intentionally omitted: upstream only sets it for
TKA-wrapped pre-auth flows, which tinylink does not implement. The
EarlyPayload `NodeKeyChallenge` is also ignored — the Tailscale client
itself never responds to it in production code.

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
