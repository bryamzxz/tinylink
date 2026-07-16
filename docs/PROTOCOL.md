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
   MapResponse: JSON, LE32-framed stream     ← M2
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
`"Tailscale Control Protocol v138"` (prefix `"Tailscale Control Protocol v"`
+ decimal protocol version, per `controlbase/handshake.go:protocolVersionPrologue`).
The decimal suffix is `TINYLINK_CAPVER` (the single source of truth in
`components/tinylink/include/tinylink.h`, currently `138`); `ts2021_client.c`
builds the prologue with `snprintf(prologue, …, TS2021_PROLOGUE_PREFIX,
TS2021_PROTOCOL_VERSION)` where `TS2021_PROTOCOL_VERSION = TINYLINK_CAPVER`,
and writes the same value into the cleartext BE16 header of the initiation
frame so the server can reconstruct the prologue. (It was hardcoded `1` in M1;
that broke headscale's `earlyNoise` floor of 113 — see below.) The earlier
note in this doc that called the prologue "the single byte `0x01`" was wrong;
that byte appears in the cleartext init header, not in the Noise prologue.

After the upgrade and the optional EarlyPayload, the inner protocol is
**HTTP/2** (per `tailscale/control/ts2021/`). tinylink wraps
`ts2021_send` / `ts2021_recv` with nghttp2 (espressif/nghttp managed
component) in `components/tinylink/src/h2_client.c`. SETTINGS sent by
the client disable HPACK dynamic-table indexing
(`SETTINGS_HEADER_TABLE_SIZE = 0`) and server push
(`SETTINGS_ENABLE_PUSH = 0`) for one-shot request semantics.

After `read_msg2` the connection optionally carries an EarlyPayload
sentinel — `"\xff\xff\xffTS"` (5 B magic) + `BE32 length` + JSON-encoded
`tailcfg.EarlyNoise` (per `tailscale/control/ts2021/conn.go`, `hdrLen=9`).
Its only field is `NodeKeyChallenge`.

The header crosses Noise record boundaries and must be read as a byte
**stream**, not record-by-record. The control plane does *not* pack the
9-byte header into one Noise record: observed in vivo against
`controlplane.tailscale.com` for a capver ≥ 113 client, the **5-byte magic
arrives as its own record**, with the `BE32` length and the JSON in later
records. So `consume_early_payload` (`ts2021_client.c`) decrypts records
into a buffer and consumes them byte-wise until it has all 9 header bytes —
mirroring upstream `readHeader`, which does `io.ReadFull(c.Conn, hdr[:9])`
over the decrypted stream (`control/ts2021/conn.go`). An earlier
record-aligned version assumed the whole header fit in the first record and
mis-stashed the short 5-byte magic record as HTTP/2 data, desyncing the
stream so the server closed the connection (`h2_session_init` → EOF).

The current upstream client reads the payload but no caller of
`GetEarlyPayload` exists in production (`SealToChallenge` / `OpenFrom` from
`types/key/chal.go` are referenced only in tests). tinylink therefore
**drains and discards** the EarlyPayload — it skips the magic, the `BE32`
length, and that many JSON bytes (which themselves may span further
records), leaving whatever follows as the HTTP/2 residual replayed to
nghttp2. The `NodeKeyChallenge` is dropped on the floor.

## /machine/register (M1)

JSON body, fields used today:

| Field               | Notes                                              |
|---------------------|----------------------------------------------------|
| `Version`           | `TINYLINK_CAPVER` (currently `138` = Tailscale v1.98) — the Tailscale `CapabilityVersion`, same value as the ts2021 Noise prologue/header (`register.c` adds `cJSON_AddNumberToObject(root, "Version", TINYLINK_CAPVER)`). M1 hardcoded `1`, which sits below headscale's `earlyNoise` floor `MinSupportedCapabilityVersion = 113` (`hscontrol/capver/capver_generated.go`) and aborts the `/ts2021` upgrade before any JSON is read. Feature gating is keyed on `Hostinfo`, not `Version`. |
| `NodeKey`           | `"nodekey:" + 64-hex` of NodeKey public.           |
| `OldNodeKey`        | `"nodekey:" + 64 zeros` on first registration.     |
| `NLKey`             | `"nlpub:" + 64 zeros` for M1 (TKA disabled). Real Ed25519 NLPrivate generation lands in M7 hardening. The field has no `omitempty` upstream, so it must be present. |
| `Hostinfo.OS`       | `"esp32"`.                                         |
| `Hostinfo.Hostname` | from `CONFIG_TINYLINK_DEVICE_HOSTNAME`.            |
| `Hostinfo.IPNVersion` | `TINYLINK_IPN_VERSION` (currently `"1.0.0-tinylink"`; derived from `TINYLINK_VERSION_{MAJOR,MINOR,PATCH}` in `components/tinylink/include/tinylink.h`). Tailscale parses the `MAJOR.MINOR.PATCH` prefix and labels the node `tsReleaseTrack=stable` when MINOR is even, `unstable` when odd (see `tailscale/version/prop.go::IsUnstableBuild`). |
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

## MapResponse (M2, liveness semantics M13)

**JSON, not protobuf** (an early revision of this doc said protobuf —
wrong; verified on-wire 2026-05-02). Each MapResponse on the
`Stream:true` long-poll is framed `LE32 length || JSON body`, matching
upstream `control/controlclient/direct.go`'s read loop; the same
framing applies to `Stream:false` one-shot responses. tinylink sends
`Compress:""` (no zstd linked) and decodes only the fields it needs
(self node, peer list, DERP map). Packet-filter / ACL fields are
**not** enforced on-device.

Request-side semantics that took real debugging to learn (upstream
`tailcfg.go:1408+1436`, verified against `controlplane.tailscale.com`):

- `Stream:true` requests are **read-only** at `Version ≥ 68` — the
  server silently discards their `Hostinfo` and top-level `Endpoints`.
- The only combination that persists endpoints is
  `Stream:false && OmitPeers:true` (the "lite" update;
  `mapreq_push_endpoints`).
- `KeepAlive:true` in the request asks the server for periodic
  `{"KeepAlive":true}` frames: cadence ~60 s on tailscale.com
  (`direct.go:1051`), 50 s + 0–9 s jitter on headscale (`poll.go:24`).
- Endpoint-propagation caveat (headscale `a5ef3aff`, 2026-07 audit):
  endpoint-only updates whose `EndpointTypes` are all STUN are stored
  but **not eagerly broadcast** to peers — peers learn endpoint churn
  via DISCO/CMM, which is also how upstream behaves. tinylink labels
  its single pushed endpoint `EndpointTypes:[2]` (STUN) honestly and
  relies on the DISCO path for propagation.

Stream-frame handling (`mapreq.c`):

- Full frames (`Node` / `Peers` / `PeersChanged`) replace the whole
  in-memory netmap — no delta merge (single-peer deployments; see
  ROADMAP).
- `{"KeepAlive":true}` frames reset the liveness clocks and are
  otherwise ignored.
- `PeersChangedPatch` (M13): entries touching a peer's `Key` or
  `DiscoKey` — how headscale ≥0.29.2 and tailscale.com deliver a peer
  re-login — force a **stream recycle**: the client stops the stream
  and reconnects, because the first frame of every new stream is
  guaranteed to be a full netmap (headscale `f4eeb94b`). Patches
  touching only `Endpoints`/`DERPRegion`/`Online` are ignored (DISCO
  owns endpoint discovery). `PeersRemoved` is still not honored.

Client liveness (M13, mirrors upstream `direct.go`
`watchdogTimeout = 120 s`): every blocking read/write on the control
conn tolerates at most `CONFIG_TINYLINK_STREAM_IDLE_TIMEOUT_S`
(default 120 s ≈ two missed KeepAlives) of consecutive silence, then
the stream is declared dead and the long-poll reconnects with a **full
fresh Noise handshake** (never resumed), exponential-backoff-capped at
30 s — same recovery shape as upstream `mapRoutine`. Persistent HTTP
4xx (non-429) rejections additionally trigger an in-place re-register
with the stored authkey (tinylink-specific: the headless equivalent of
upstream's `NeedsLogin`), and one hour of *total* control silence is a
wedge → `esp_restart()` (see `SECURITY-MODEL.md`).

## DISCO (M3)

UDP datagrams piggy-back on the same socket WireGuard uses. Each datagram
is a NaCl-box with the static DISCO key. The first valid pong upgrades a
peer from "DERP-relayed" to "direct".

## DERP (M5)

A WebSocket-like framing over TLS to a regional DERP node. tinylink uses
DERP only as a fallback for DISCO failures, not as a primary path.
