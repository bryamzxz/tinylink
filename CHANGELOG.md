# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **TAI64N handshake-timestamp persistence across reboots.**
  `wg_proto.c::wg_tai64n_now` previously fell back to
  `monotonic_seconds()` whenever wall-clock was unset (no SNTP yet);
  every reboot rewound that to 0, so the next handshake's TAI64N
  timestamp could be lower than the value the responder saw before
  the reboot, and the responder rejected the handshake as
  out-of-order. New shape: `wg_tai64n_init(floor, reservation,
  persist_fn)` installs a persisted seconds floor at boot;
  `wg_tai64n_now` clamps emitted seconds to `floor + 1` minimum and
  asks the orchestration layer to extend the reservation forward by
  `WG_TAI64N_RESERVE_CHUNK_SECS` (1 day) when needed. New
  `tinylink_tai64n_floor_init()` (public API) reads the floor from
  NVS namespace `tl_state` key `tai_floor`, pre-reserves a chunk
  forward, and persists it so a subsequent reboot reads it back.
  `main.c::bringup` invokes it between `tinylink_init` and the first
  WG handshake. NVS write cost: one per boot (the pre-reserve);
  inline extends from `wg_tai64n_now` only fire if a single boot
  session emits past 1 day of seconds. Verified on hardware across
  three sequential resets: NVS chained 86400 → 172800 → 259200 →
  345600 (Δ = chunk exact every time). Fail-soft: NVS errors fall
  back to legacy unprotected behavior so a transient NVS issue
  doesn't brick boot. Fourth M7 hardening item.

### Fixed
- **`stun_reprobe` task spawn now retries on `ESP_ERR_NO_MEM`.**
  Previously, if the boot-time `xTaskCreate(stun_reprobe_task)` failed
  due to a low largest-contiguous-heap-block at boot (typical: ~3.5 KiB
  free during the supervisor TLS handshake transient, below the
  4 KiB+TCB requirement), `tinylink_stun_reprobe_start` logged
  `"continuing static"` and silently dropped the re-probe. The
  endpoint pushed at boot then stayed stale forever, and any later NAT
  rebind broke the direct-UDP path with no recovery — observed on
  hardware as `tailscale ping` reverting to `via DERP(...)` after
  router-side port rotation. Fix: schedule an `esp_timer` one-shot at
  +30 s on spawn failure; the callback retries `xTaskCreate` and
  reprograms itself if still failing. Verified on hardware: failed at
  t=18 s with `largest_block=3456 B`, succeeded at t=48 s with
  `largest_block=12800 B` once the TLS-handshake transient freed.
  Third M7 hardening item.

### Added
- **Compile-in fallback control plane pubkey
  (`CONFIG_TINYLINK_CONTROL_PUB_FALLBACK_HEX`).** New optional Kconfig
  string (64 hex chars or empty). When set, `control_key_get()` installs
  the fallback as the NVS pin on first boot without contacting the
  network — eliminating the TOFU window where a MITM during the initial
  `GET /key?v=100` could substitute the pin. `control_key_refresh()`
  also refuses any fetched key that disagrees with the fallback, closing
  the malicious-refresh vector after first boot. Resolution order is
  now: NVS pin (operator-accepted) → compile-in fallback (production
  pin) → TOFU via `/key` (legacy, logs a loud WARN). Empty fallback
  preserves the previous TOFU behavior so existing development
  `sdkconfig` files keep working unchanged. Second M7 hardening item.

### Changed
- **DERP supervisor reconnect backoff is now exponential, capped at 30 s.**
  `tinylink.c::derp_supervised_task` previously slept a fixed
  `CONFIG_TINYLINK_DERP_SUPERVISED_BACKOFF_MS` (default 15 s) between
  every connect failure, hammering a downed server at the same rate
  whether it was the first failure or the hundredth. New behavior: the
  Kconfig value is the *base* delay; the supervisor doubles it on every
  consecutive failure up to a hardcoded 30 s cap, and resets to base on
  a successful login. The Kconfig help text is updated to reflect the
  new shape; the symbol name is unchanged so existing
  `sdkconfig.defaults` overrides keep working. First M7 hardening item
  (see `docs/ROADMAP.md` § "M7 — Hardening").

### Fixed
- **WG session expiry at exactly 180 s of inactivity.** Symptoms: ICMP
  from a peer to the device's CGNAT IP started failing 100 % at
  `icmp_seq=181`; `tailscale ping` reactivated the path because DISCO
  forced new outbound traffic; ping then worked again until the next
  180 s window. Root cause: the device is initiator-only by design
  (incoming `HANDSHAKE_INIT` is dropped — `wg_handshake.h:5-7`), so
  when the responder hits `REKEY_AFTER_TIME = 120 s` and tries to
  rotate, its INIT goes nowhere; at `REJECT_AFTER_TIME = 180 s` the
  responder invalidates our transport keys and our outbound enters a
  silent black hole (`g.state` is still `UP`, but the responder
  drops every encrypted packet). Fix: proactive rekey on the
  initiator side. A new timer in `wg_netif.c::rx_task` fires
  `start_rekey()` once session age exceeds `WG_REKEY_AFTER_MS`
  (110 s, slightly before the responder's 120 s mark). The rekey is
  make-before-break — `g.state` stays `UP` and the existing
  `g.transport` keeps serving traffic until
  `handle_handshake_response` swaps in the new keys via
  `wg_transport_session_init`. If the rekey exhausts its 12-attempt
  retry budget (60 s) we fall back to a cold handshake before the
  180 s mark so we never silently zombie. Verified on hardware:
  6 consecutive 110 s rekey cycles, 0 retries, 0 fallbacks, telemetry
  cadence unbroken across each rekey (tx seq deltas held at 5003 ms).
  Responder-mode is no longer needed for steady-state operation; it
  remains a follow-up for peer-roaming corner cases where the peer
  endpoint changes mid-session and only the peer can re-initiate.

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

### Performance
- **ChaCha20-Poly1305 AEAD: ~10% faster encrypt and ~12% faster decrypt
  on 1500 B payloads on ESP32 LX6.** Three changes in
  `components/tinylink/src/crypto/`:
  1. `chacha20.c`: keystream/plaintext XOR loop in `chacha20()` and the
     16 keystream stores in `chacha20_block()` now go through
     `__builtin_memcpy` of `uint32_t` chunks instead of byte-by-byte.
     `output[CHACHA20_BLOCK_SIZE]` is `__attribute__((aligned(4)))` so
     the compiler folds these to single `l32i`/`s32i` on Xtensa.
  2. `poly1305_donna_32.h`: `U8TO32` rewritten as `__builtin_memcpy`.
     Compiler emits `l32i` when alignment is provable (the
     leftover-completing call always passes `st->buffer`, which is
     4-aligned) and falls back to the original byte path otherwise.
     Strict-aliasing-safe by construction.
  3. `chacha20.c`: `U8TO32_LITTLE` / `U32TO8_LITTLE` macros switched to
     `__builtin_memcpy`; `chacha20_init` now bulk-copies the 32-byte
     key into `state[4..11]` so GCC schedules the loads/stores
     interleaved instead of expanding 8 separate macro instances.
- **Bench harness.** New `CONFIG_TINYLINK_BENCH_AEAD` (off by default)
  builds an opt-in micro-bench (`components/tinylink/src/tinylink_bench.c`)
  that times encrypt + decrypt over 64 B and 1500 B payloads with
  `esp_timer_get_time()` and verifies a round-trip before reporting
  numbers. Used to measure the changes above; left in place as the
  reference for future crypto work.
- Measured on Freenove ESP32-WROOM-32E, ESP-IDF v5.5.4, `-Os`:
  enc 739→659 µs, dec 740→654 µs at 1500 B. Variance run-to-run is
  ~1-2 % on MTU; treat sub-3 % deltas as noise.

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
