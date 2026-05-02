# Protocol map

tinylink rides on a small subset of the protocols `tailscaled` speaks. This
document is the *cleanroom* reference we use to keep our implementation
honest. None of it is official Tailscale documentation — see the published
`tailscale/tailscale` repo for ground truth.

## Layered view

```
   App: TMP117 telemetry (UDP, JSON)         ← M1
   ────────────────────────────────────────
   ts2021: Noise IK + HTTP/2 inside TLS       ← M2 (control plane)
   MapResponse: protobuf                      ← M3
   DISCO: NaCl-box on WG UDP socket           ← M4
   DERP: TLS relay                            ← M5
   ────────────────────────────────────────
   WireGuard data plane (droscy/esp_wireguard) ← M1 baseline
   UDP / IPv4
   WiFi STA
```

## Cryptographic primitive table

| Primitive           | Used by         | Source              | Why                                |
|---------------------|-----------------|---------------------|------------------------------------|
| ChaCha20-Poly1305   | WG, Noise, DERP | mbedTLS (HW-accel)  | ESP32 has accelerator; same impl   |
| Curve25519 (X25519) | WG, Noise IK    | vendored donna      | constant-time scalarmult required  |
| BLAKE2s             | Noise IK        | vendored            | small, simple, no IDF builtin      |
| HKDF                | Noise IK, WG    | mbedTLS             | already linked for TLS             |
| NaCl-box            | DISCO           | vendored            | tiny dep; DISCO is exactly nacl-box|
| TLS 1.2/1.3         | ts2021, DERP    | mbedTLS             | already linked                     |

The vendored `donna` is mandatory: mbedTLS's Curve25519 path is variable-time
in the relevant code paths and we do not want long-term keys to leak through
timing channels on a sensor sitting on an LAN. See `SECURITY-MODEL.md`.

## ts2021 (M2)

The control connection is HTTP/2 over TLS to `controlplane.tailscale.com`,
and inside that, a Noise_IK_25519_ChaChaPoly_BLAKE2s session frames the
control-plane RPCs. Our implementation only needs the IK initiator role —
we never act as the responder.

## MapResponse (M3)

Protobuf-framed, length-delimited, streamed over the open HTTP/2 stream.
We will decode only the fields we strictly need (peer list, derp map,
self-node info). Packet-filter / ACL fields are **not** enforced on-device.

## DISCO (M4)

UDP datagrams piggy-back on the same socket WireGuard uses. Each datagram
is a NaCl-box with the static DISCO key derived during ts2021. The first
valid pong upgrades a peer from "DERP-relayed" to "direct".

## DERP (M5)

A WebSocket-like framing over TLS to a regional DERP node. tinylink uses
DERP only as a fallback for DISCO failures, not as a primary path.
