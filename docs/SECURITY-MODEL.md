# Security model

This document captures the threat model and the rationale behind the
cryptographic choices that the README and `PROTOCOL.md` summarize.

## Adversary

We assume an attacker who:

- Controls the local WiFi network (passive sniffing, active MITM, DHCP
  spoofing, ARP poisoning).
- Can reach the device's WAN-facing UDP port (the WireGuard endpoint).
- Cannot mount physical attacks beyond casual inspection: no decapping, no
  laser fault injection, no nanoprobing. Side channels at the level of
  electromagnetic emissions are out of scope.
- May know that a tinylink device exists at a given IP (no obscurity).

We **do not** defend against:

- Physical attackers with persistent access to the board (e.g. an adversary
  who can clip onto the I²C lines or read flash with a programmer). Anyone
  with that level of access can also dump the encrypted NVS partition and
  recover the eFuse key from the bootrom; that is an ESP32 platform-level
  decision, not something tinylink can paper over.
- Compromise of `controlplane.tailscale.com` itself (M2+).

## Why constant-time Curve25519 from `donna`, not mbedTLS

The WireGuard handshake uses the device's **long-term** Curve25519 private
key on every initial handshake. mbedTLS's Curve25519 implementation has not
historically been written with the same constant-time discipline as
`curve25519-donna` (the reference compact constant-time C implementation by
Adam Langley). On a sensor sitting on a LAN, an adversary who can co-locate
on the same physical machine or watch fine-grained timing on the local
network can plausibly mount timing attacks against variable-time scalar
multiplication.

We therefore pin the long-term-key code paths to a constant-time
implementation. ChaCha20-Poly1305 stays on mbedTLS because the ESP32's
hardware AES accelerator is irrelevant to ChaCha and the mbedTLS C path is
already constant-time. BLAKE2s is small enough that vendoring is cheaper
than dragging in another dependency.

## Long-term key storage

- WireGuard private key: 32 B raw blob in NVS namespace `tinylink`, key
  `wg_priv_key`. The NVS partition is encrypted (`CONFIG_NVS_ENCRYPTION=y`),
  with the key sealed by the eFuse-derived flash-encryption key.
- WiFi password: in the same encrypted NVS, key `wifi_pass`.
- M2+ node identity (Noise IK static key): same NVS namespace, key TBD.

There is no on-device UI for entering keys; provisioning happens at flash
time via `tools/nvs_provision.py`.

## What we explicitly do not enforce on-device

- ACLs / packet filter from `MapResponse`. The device assumes the upstream
  peer or the broader Tailscale ACL system enforces who is allowed to
  connect to it. This matches MicroLink's posture and avoids shipping a
  filter engine on a 4 MiB-flash device.
- MagicDNS resolution. We use raw `100.x.y.z` peer IPs.
- Tailnet Lock. tinylink does not verify the tailnet-lock signature on
  `NodeKey` updates. If you need this, do not use tinylink.
