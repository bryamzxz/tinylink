# Security model

This document captures the threat model and the rationale behind the
cryptographic choices that the README and `PROTOCOL.md` summarize.

## Adversary

We assume an attacker who:

- Controls the local WiFi network (passive sniffing, active MITM, DHCP
  spoofing, ARP poisoning).
- Can reach `controlplane.tailscale.com` from the same internet path the
  device uses.
- Cannot mount physical attacks beyond casual inspection: no decapping,
  no laser fault injection, no nanoprobing. Side channels at the level
  of electromagnetic emissions are out of scope.
- May know that a tinylink device exists at a given IP.

We **do not** defend against:

- Physical attackers with persistent access to the board (e.g. an attacker
  who can clip onto the I²C lines, read flash with a programmer, or burn
  fresh eFuses). Anyone with that level of access can also dump the
  encrypted NVS partition and recover the eFuse-derived key from the
  bootrom; that is an ESP32 platform decision, not something tinylink can
  paper over.
- Compromise of `controlplane.tailscale.com` itself.

## Long-term keys

| Key             | Purpose                       | Storage                        |
|-----------------|-------------------------------|--------------------------------|
| MachineKey      | Noise IK static (ts2021)      | NVS `tl_keys/machine` (32 B)   |
| NodeKey         | WireGuard static (M2+)        | NVS `tl_keys/node` (32 B)      |
| DiscoKey        | NaCl-box (DISCO, M3+)         | NVS `tl_keys/disco` (32 B)     |
| NLKey           | TKA / network-lock signing    | currently sent as 32 zero bytes (`"nlpub:" + 64 zeros`) — TKA is disabled in M1 and the server tolerates a zero NLKey. M6 hardening swaps in real Ed25519 NLPrivate generation and NVS persistence. |
| Tailscale auth key (`tskey-auth-…`) | one-time register | NVS `tl_creds/auth_key` (str)  |
| WiFi PSK        | local network association     | NVS `tl_creds/wifi_pass` (str) |
| Pinned control plane pub | TOFU pin               | NVS `tl_pin/control_pub` (32 B)|

All NVS data sits in an `nvs_creds` partition with
`CONFIG_NVS_ENCRYPTION=y` set on top of the eFuse-derived flash-encryption
key. The Curve25519 identities are generated on first boot using
`esp_fill_random()` (RF-derived entropy) and never leave the chip in
plaintext.

The Tailscale auth key is **single-use by convention** — once
`MachineAuthorized=true` returns, the auth key has done its job and
should be revoked from the admin panel. Because the device persists its
NodeKey, future re-registrations would require a new auth key flashed
into NVS.

## Why the curve25519.c shipped today is not enough for production

The X25519 implementation in `components/tinylink/src/crypto/curve25519.c`
is TweetNaCl-derived. TweetNaCl was designed to be constant-time, but it
is small, less audited, and historically has been subject to compiler
re-ordering caveats. The MachineKey and NodeKey private keys are exercised
on every Noise IK handshake — an attacker who can co-locate or watch
fine-grained timing on the local network can plausibly mount timing
attacks against variable-time scalar multiplication.

For production, replace the file with the constant-time `curve25519-donna`
implementation that ships in `trombik/esp_wireguard` at
`src/crypto/x25519.c` (~600 LoC, BSD-3, MIT-compatible). Keep the public
symbols (`curve25519_scalarmult`, `curve25519_keypair`,
`curve25519_dh`, `curve25519_derive_pub`) so call sites compile unchanged.

## Why constant-time Curve25519 from `donna`, not mbedTLS

The same argument applies even more strongly to mbedTLS: mbedTLS's
Curve25519 path has not historically been written with the same
constant-time discipline as donna. ChaCha20-Poly1305 stays on mbedTLS
because the ESP32's hardware AES accelerator is irrelevant to ChaCha and
the mbedTLS C path is already constant-time. BLAKE2s is small enough that
vendoring is cheaper than dragging in another dependency.

## What we explicitly do not enforce on-device

- **ACLs / packet filter from MapResponse.** The device assumes the
  upstream peer or the broader Tailscale ACL system enforces who is
  allowed to connect to it. This matches MicroLink's posture and avoids
  shipping a filter engine on a 4 MiB-flash device.
- **MagicDNS resolution.** We use raw `100.x.y.z` peer IPs.
- **Tailnet Lock.** tinylink does not verify the tailnet-lock signature
  on `NodeKey` updates. If you need this, do not use tinylink.

## Verification still TODO before any production use

- Run RFC 7693 BLAKE2s test vectors through `blake2s_init`/`update`/`final`.
- Run RFC 7748 X25519 test vectors through `curve25519_scalarmult`.
- Run RFC 8439 ChaCha20-Poly1305 round-trips through Noise's
  `EncryptAndHash` to confirm the AAD layout matches the Noise spec.
- Cross-check `TS2021_VERIFY` markers in
  `components/tinylink/src/ts2021_client.c` against the live Tailscale
  control plane source (see `PROTOCOL.md` for the exact files).

## Cross-cutting security warnings

Distilled from the protocol research artifact §L.

- **Validate peer public keys.** RFC 7748 §5 lists low-order points that,
  if accepted, leak your private key. The `curve25519_scalarmult` call
  rejects all-zero outputs in constant time; do not bypass that check.
- **Nonce uniqueness across two AEAD contexts.** ts2021 (LE64 counter)
  and DISCO (24-byte random) have different nonce schemes. Force a
  rekey on every boot by zeroing all transport keys at startup; never
  reuse a counter across reboots.
- **Hardware RNG.** `esp_random()` is only a true TRNG *after*
  `esp_wifi_start()`. Generate Curve25519 long-term identities only
  after WiFi is up — `tinylink_init()` is called from `app_main()`
  exactly for this reason.
- **Toolchain pinning.** Build with the default ESP-IDF
  `xtensa-esp32-elf-gcc`. LLVM's `select-optimize` pass has been known
  to transform mbedTLS's constant-time-select macros into branchy code.
  Do not switch to Clang without disassembling the crypto primitives.
- **Compile-in fallback control pub.** TLS-only TOFU on first
  `/key?v=100` fetch is the weakest link in ts2021 (man-in-the-middle
  via a corporate TLS root). For production firmware, hardcode the
  known control plane public key as a second pin and refuse to accept
  a `/key` response that disagrees. Tracked in M6.
- **Replay window.** A 64-bit single-word bitmap is fine for single-peer
  single-flow. If tinylink ever extends to multi-peer, switch to the
  RFC 6479 2000-entry scheme or accept replay risk.
- **Do not invent.** Noise IK, WG `Noise_IKpsk2`, and NaCl-box all have
  subtle state-transition rules (e.g., responder cannot send WG
  transport data until it receives one from initiator — §5.4.5 of the
  WG paper). Follow the papers verbatim.
