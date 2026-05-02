# Roadmap / Hoja de ruta

> Bilingual (EN / ES). Other docs are English-only.

## Milestones (high level)

| #  | Name                              | Status   | Targeted release |
|----|-----------------------------------|----------|------------------|
| M1 | WireGuard standalone (static peer)| current  | v0.1             |
| M2 | ts2021 Noise IK handshake         | pending  | v0.2             |
| M3 | MapResponse parsing               | pending  | v0.3             |
| M4 | DISCO P2P discovery               | pending  | v0.4             |
| M5 | DERP relay fallback               | pending  | v0.5             |
| M6 | Production hardening              | pending  | v0.6             |

## M1 — WireGuard standalone (current)

EN: A static-peer WireGuard tunnel that survives WiFi reconnects and pushes
TMP117 readings to a single peer. **Out of scope:** ts2021, DISCO, DERP, any
control-plane traffic. The peer's pubkey/endpoint/allowed-ip live in the
encrypted NVS — there is no key exchange.

ES: Túnel WireGuard con un único par estático que sobrevive reconexiones de
WiFi y envía lecturas del TMP117 al par. **Fuera de alcance:** ts2021, DISCO,
DERP y todo el plano de control. La clave pública / endpoint / allowed-ip del
par viven en NVS cifrado — no hay intercambio de claves.

**Done when:**
- `idf.py build` produces a binary that fits ota_0 (1.5 MiB).
- Booting on a WROOM-32E with a provisioned NVS connects WiFi, brings up WG,
  and emits one JSON datagram to the peer every `TELEMETRY_INTERVAL_MS`.
- The bringup recovers from WiFi disconnect without a reboot.

## M2 — ts2021 handshake

EN: Implement the tailscaled ts2021 handshake (Noise IK over HTTP/2 inside
TLS to `controlplane.tailscale.com`) up to a registered node identity and a
`MapRequest` round-trip. Re-uses mbedTLS for ChaCha20-Poly1305 only;
Curve25519 comes from vendored constant-time `donna`; BLAKE2s vendored.

ES: Implementar el handshake ts2021 (Noise IK sobre HTTP/2 dentro de TLS al
plano de control) hasta obtener identidad registrada y un round-trip de
`MapRequest`. mbedTLS solo para ChaCha20-Poly1305; Curve25519 vendido desde
`donna` (tiempo constante); BLAKE2s vendido.

## M3 — MapResponse

EN: Parse `MapResponse` payloads (peer list, derp map, packet filter is
ignored on-device). No multi-peer routing yet — first matching peer wins.

ES: Parsear `MapResponse` (lista de peers, derp map; filter se ignora). Sin
ruteo multi-peer todavía; gana el primer peer que coincida.

## M4 — DISCO

EN: NaCl-box DISCO ping/pong on the same UDP socket WireGuard already owns.
Promote a peer from "DERP-relayed" to "direct" on the first valid pong.

ES: Ping/pong DISCO con NaCl-box sobre el mismo socket UDP de WireGuard.
Ascender un peer de "vía DERP" a "directo" con el primer pong válido.

## M5 — DERP

EN: TLS client to a regional DERP node, fallback when DISCO can't punch
through NAT. Reuses the mbedTLS session from M2.

ES: Cliente TLS a un DERP regional como fallback cuando DISCO no atraviesa
NAT. Reutiliza la sesión mbedTLS de M2.

## M6 — Hardening

EN: Replay window, rate-limit on the control socket, key rotation hooks,
secure-element guidance for the WG private key, watchdog wiring.

ES: Ventana antirreplay, rate-limit en el socket de control, ganchos para
rotar claves, guía para mover la clave WG a elemento seguro, watchdog.
