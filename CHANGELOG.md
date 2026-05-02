# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **M3 first cut: TMP117 telemetry over UDP-through-WG.**
  - New `tmp117.{c,h}`: I²C driver using IDF v5.5
    `driver/i2c_master.h`. Reset-default CONFIG (continuous, AVG=8) is
    fine, so we only read TEMP_RESULT (and DEVICE_ID at init for a
    fast-fail wiring check). Result is reported in milli-°C using the
    documented 7.8125 m°C/LSB scale.
  - New `telemetry.{c,h}`: 4 KiB-stack FreeRTOS task `tinylink_tlm`
    that periodically reads the sensor and emits a JSON datagram
    `{"host","seq","temp_c"}` to `CONFIG_TINYLINK_TELEMETRY_DEST`
    over UDP. The socket binds to the default route, which is the WG
    netif once `tinylink_dataplane_start()` has run, so packets reach
    the home peer end-to-end.
  - New Kconfig submenu `Telemetry (M3)` exposes I²C pin selection,
    sensor address, sample period, destination IP:port, and a
    compile-time enable/disable so boards without a TMP117 still
    build and run.
  - New public API `tinylink_telemetry_start()`; `main.c` calls it
    after the long-poll task is up.
  - Build size: `tinylink.bin` 0x118d10 → 0x11e890 (+22 KiB).

- **M2 long-poll MapRequest stream.**
  - `h2_client` now exposes `h2_post_json_stream(...)` that invokes a
    per-chunk callback; the one-shot `h2_post_json` and the streaming
    variant share an internal driver.
  - `mapreq_run_stream()` POSTs `/machine/map` with `Stream:true` and
    walks the upstream `LE32 size || body` framing
    (`tailscale/control/controlclient/direct.go:~1248`). KeepAlive
    messages are absorbed; non-KeepAlive messages are parsed into a
    `tl_netmap_t` and dispatched to a caller-supplied handler.
  - `wg_dataplane_update_peer()` compares the new endpoint against the
    currently-configured one and reconnects WG only if it changed.
  - New public API `tinylink_long_poll_start()` spawns an 8 KiB-stack
    FreeRTOS task `tinylink_lp` that drives the loop indefinitely and
    reconnects (with the existing `CONFIG_TINYLINK_REGISTER_RETRY_MS`
    backoff) on stream EOF or transport error. `main.c` invokes it
    after the data plane is up.
  - Build size: `tinylink.bin` 0x1182e0 → 0x118d10 (+2.6 KiB).

- **M2 first-cut data plane: WireGuard via `trombik/esp_wireguard`.**
  - Added `trombik/esp_wireguard@0.9.0` (BSD-3) as a managed component
    in `main/idf_component.yml`.
  - New `wg_dataplane.{c,h}` shim translates `tl_netmap_t` →
    `wireguard_config_t`: base64-encodes the device NodePrivate and the
    peer's NodePublic, splits `Node.Addresses[0]` into local IP +
    netmask, splits `Peers[0].Endpoints[0]` into host + port, then
    drives `esp_wireguard_init` + `esp_wireguard_connect`. 25-second
    persistent keepalive is enabled until DISCO takes over keepalive
    duty in M3.
  - New public API `tinylink_dataplane_start()` opens a fresh ts2021
    channel, calls `mapreq_fetch_once()`, and brings up the WG netif
    against the first peer announced. `main.c` invokes it after
    `tinylink_register()` succeeds.
  - The `wireguardif.c` UDP-socket-sharing patch (so DISCO/STUN can
    multiplex on the WG socket) is intentionally deferred to M3 — until
    DISCO actually needs the same socket, the upstream
    `udp_bind(IP_ADDR_ANY, port)` is fine.
  - Build size: `tinylink.bin` 0x111a50 → 0x1182e0 (+25 KiB).

- **M2 scaffolding: `MapRequest` + `MapResponse` parser.**
  - Vendored `jsmn` (single-header zero-alloc tokenizer, MIT, ~350 LoC)
    at `components/tinylink/src/jsmn.h`.
  - `tl_netmap_t` (`netmap.h`) holds the M2 working set: self addresses,
    up to 4 peers (`{ID, NodeKey, DiscoKey, Addresses, Endpoints,
    HomeDERP}`), and up to 4 DERP regions. v6 entries are dropped at
    parse time since the lwIP netif is v4-only.
  - `mapreq_fetch_once()` POSTs `/machine/map` with `Stream:false` and
    `Compress:""`; the server replies with a single `MapResponse` and
    closes the stream. The `Stream:true` long-poll form lands alongside
    the WireGuard bringup.
  - `mapresp_parse()` is platform-independent and runs under a host KAT
    (`tools/test/test_mapresp.c`) that exercises a one-peer +
    one-DERP-region stub.

### Fixed
- **ts2021 wire format corrected against upstream.** Initial implementation
  put the Noise IK msg1 in the HTTP body and used a 4-byte invented frame
  header. After cross-checking `tailscale/control/controlbase/messages.go`,
  `controlhttp/client.go`, and `control/ts2021/conn.go`:
  - The 101-byte initiation frame now travels base64-encoded in
    `X-Tailscale-Handshake`, with `Content-Length: 0` on the upgrade.
  - Initiation header is 5 bytes (`BE16 version || type(1) || BE16 len`);
    all subsequent records are 3 bytes (`type(1) || BE16 len`).
  - Frame types pinned to `1=initiation / 2=response / 3=error / 4=record`.
  - Noise prologue is the **string** `"Tailscale Control Protocol v1"`,
    not the byte `0x01` (that byte appears only in the cleartext header).
  - Optional EarlyPayload sentinel (`"\xff\xff\xffTS"` + BE32 len + JSON)
    is drained and discarded; upstream never acts on it either.
- **`/machine/register` body fixes.** `Version` changed from `100` to `1`
  (the Noise transport `CapabilityVersion`, not a marketing version);
  `NLKey` added as required `"nlpub:" + 64 zeros` (TKA disabled);
  `NodeKeySignature` removed (only set for TKA pre-auth flows upstream).

### Changed
- **Milestone 1 redefined.** The original M1 was "static WireGuard against a
  fixed peer + TMP117 telemetry over UDP." It is now "ts2021 control plane:
  the device registers with `controlplane.tailscale.com` and shows up in the
  Tailscale admin panel as an online node." There is no data plane in the
  new M1 — that returns in M2 alongside MapResponse.
- Roadmap shifted: M2 = MapRequest streaming + WireGuard data plane,
  M3 = DISCO + TMP117 telemetry, M4 = STUN, M5 = DERP, M6 = hardening.

### Added
- `tinylink` core component now contains the real M1 implementation:
  - Vendored crypto: BLAKE2s (RFC 7693), HMAC-BLAKE2s + HKDF, Curve25519
    (TweetNaCl-derived placeholder, swap with constant-time donna for
    production), Salsa20/HSalsa20/XSalsa20, NaCl-box.
  - Noise IK state machine (`Noise_IK_25519_ChaChaPoly_BLAKE2s`).
  - ts2021 client: TLS to control plane, HTTP/1.1 Upgrade with the
    initiation frame in `X-Tailscale-Handshake`, controlbase 5/3-byte
    framing, post-handshake EarlyPayload drain.
  - HTTP/2 client over the Noise channel via nghttp2
    (`espressif/nghttp`), with HPACK dynamic-table disabled.
  - Control plane public key bootstrap with NVS pinning.
  - `RegisterRequest` builder + response parser.
- `tools/credentials.csv.example` simplified to the M1 set
  (`wifi_ssid`, `wifi_pass`, `auth_key`).

### Removed
- `main/app_wireguard.{c,h}`, `main/app_sensor.{c,h}`,
  `main/app_telemetry.{c,h}`. These return in M2/M3.
- WireGuard-specific entries in `sdkconfig.defaults`.
- `examples/milestone1_static_wg/`, `examples/milestone1_tailscale_peer/`.
  Replaced by `examples/milestone1_register/`.

[Unreleased]: https://github.com/bryamzxz/tinylink/commits/main
