# Round 1.3.0 — upstream sync (2026-10-28) — working report

Living notes for branch `feat/upstream-sync-2026-10`. Distilled into
`CHANGELOG.md` at the end of the round; this file keeps every finding,
decision and design constraint so nothing is lost between sessions.

## Owner decisions (2026-10-28)

- **Goal 1**: bring tinylink up to current upstream — tailscale
  `f7c1b8e52` (2026-10-28, v1.105.0-pre, capver 149) and headscale
  `2d220b2e` (2026-10-24, 0.29.6). Previous audit stopped at tailscale
  `31d8badb3` / headscale `89fa72e0` (2026-09-03).
- **Goal 2**: "optimization to the absurd" for the ESP32 v1 — first a
  prioritized list (analysis agents running), implementation later.
- **Capver target = 148** (= v1.104, even minor = Tailscale *stable*
  track). Never 149 (sentinel on the odd 1.105-pre line). Owner rule:
  claim only capvers that map to an even-minor release.
- **Version line**: 1.3.x is the work line (this round = **1.3.0**, the
  optimization rounds = 1.3.x; the admin panel showing "unstable" on the
  sensor meanwhile is accepted); **1.4.0** = the stable release once
  everything is measured and soaked.
- **ESP-IDF**: stay on the 5.5 line, move **v5.5.4 → v5.5.6**
  (2026-10-16; Wi-Fi supplicant security fixes). Installed side by side
  at `/home/bryam/ESP32/esp-idf-v5.5.6`, both `idf-patches/` applied as
  commits (`0dc28b56`, `17ad4d0e`; 0001 applies with a 21-line offset,
  neither is upstreamed yet). Same toolchain `esp-14.2.0_20260121`.
  v6.x rejected for now: mbedTLS 4/PSA removes `mbedtls_chachapoly_*`
  (used by `noise_ik.c`), +27–41 KB flash and +800 B stack per HTTPS
  conn, deprecated CAs dropped from the bundle, FreeRTOS/ringbuf forced
  into flash (hot-path latency), picolibc default, cJSON moved out, our
  two patches need re-validation. Revisit in 2027 as its own round.
- **ESP32 docs folder**: `docs/esp32/` (README with exact identity,
  `fetch-docs.sh`, `REFERENCE.md` digest with page citations). PDFs in
  `docs/esp32/pdf/` are git-ignored (Espressif/Cadence copyright).

## Hardware identity (read 2026-10-28, read-only esptool/espefuse)

ESP32-WROOM-32E-N4 · ESP32-D0WD-V3 **rev v3.1** · dual LX6 240 MHz ·
40 MHz XTAL · flash **XMC** (JEDEC 0x46, D series) 4 MB · VDD_SDIO 3.3 V ·
no security eFuses burned · CH340. Sensor rebooted once for the read and
came back: register 200 @ +8.5 s, netmap @ +11 s, WG up @ +16.5 s.

## Tailscale audit (`31d8badb3..f7c1b8e52`, 329 commits) — summary

No wire drift in disco/, controlhttp, derp.go; controlbase/stun only
fuzz tests. Capver 143–148 claimability:

| v | meaning | tinylink |
|---|---|---|
| 143 | control stops sending conn25 attrs below 143 | ok (CapMap/DNSConfig skipped) |
| 144 | client SENDS TSMPDiscoKeyAdvertisement per new keypair | **implemented this round (T1)** |
| 145 | macOS quad-100 DNS scoping | ok |
| 146 | `debug-conn-reject` attr + c2n /debug/rejects (local aggregator only) | ok, nothing to enforce |
| 147 | Retry-After on /machine/register + /machine/map | **exact semantics this round (T2)** |
| 148 | `Node.StableTailnetID` (self only) | ok (unknown key skipped) |
| 149 | sentinel: cache-network-maps default | not claimed |

Peers never gate on the remote's capver ≥ 144 (only `capVerIsRelayCapable`
≥ 121 and `peerCanProxyDNS` ≥ 26). headscale capver use = floor only.

## Headscale audit (`89fa72e0..2d220b2e`, 330 commits) — summary

- `62714564` ts2021 via net/http h2c: **tolerant** (same SETTINGS:
  MAX_FRAME 1 MiB, MCS 250, IWS 1 MiB, NO_RFC7540_PRIORITIES; no idle
  timeout / server PING / idle GOAWAY; server now waits for the client
  preface before SETTINGS — nghttp2 sends preface first, fine).
- Floor `MinSupportedCapabilityVersion` = **116** (v1.84) on main (113 on
  0.29.x releases); capver table maps up to 148 (v1.104); no upper bound.
- Real tinylink bugs exposed (H1–H7 below). Not one hardware run against
  headscale exists yet — see test plan.

## Work items — status

Legend: [x] done in tree · [~] in progress · [ ] pending

### Tailscale side
- [x] **T1 TSMP disco-key advert (capver 144).** `src/tsmp.h` (header-
  only builder, 53-byte IPv4 proto-99 packet `'a'`+disco key, RFC 1071
  checksum; golden vector independently re-derived in Python), sent from
  `wg_netif.c::send_disco_advert()` after every accepted handshake
  response (cold/rekey, direct/DERP-relayed), after `hs_lock` release,
  via `wg_netif_send_plaintext` (g.lock-protected, safe from rx/derp
  tasks). Skipped if peer has no DiscoKey or either tailnet IPv4 unknown.
  `wg_netif_peer_config` gained `self_tailnet_v4_be`/`peer_tailnet_v4_be`
  (set in `wg_dataplane_start` via `first_host_v4()` = first /32 v4).
  `/stats` gained `wg.disco_adverts`; stats buffer 640 → 768 B (worst
  case with 63-char hostname exceeded 640 → reply silently not sent).
  Host KAT `tools/test/test_tsmp.c` (9 asserts) wired into Makefile.
  Side benefit: first transport packet under new keys → peer confirms
  the keypair immediately after rekey.
- [x] **T2 Retry-After exact (capver 147)** — upstream direct.go
  `isRateLimitedResponse` + `parseRateLimitError`, auto.go
  `waitRetryAfter`: rate-limited iff 429, or 503 with NON-EMPTY
  Retry-After; value = Atoi (optional sign, whole string) seconds, else
  HTTP-date − now; ≤0 / >3600 s / unparsable → uniform 5–10 s; then cap
  300 s; backoff counter neither advanced nor reset while waiting;
  scope = register + map (lite + stream), not /key. Plan:
  `h2_retry_after.h` → `h2_parse_retry_after_seconds(v,len,now)` (valid
  1..3600 else 0) + `h2_rate_limit_wait_ms(status,present,secs,rnd)`;
  conn gets `h2_retry_after_present`; h2_client passes `time(NULL)` only
  when `tl_time_synced()`; tinylink.c long-poll + in-loop re-register +
  boot loop (`main.c`, public API `tinylink_last_retry_after_s` →
  wait-ms variant) use it. `src/tl_date.h` (written) has
  `tl_parse_imf_fixdate` + `tl_parse_rfc3339` + `tl_days_from_civil`.
- [x] **T3 capver 142 → 148** (code + docs; HW A/B smoke still pending): `tinylink.h` macro + rewrite the long
  comment (143–148 honoured, 149 not, upstream 149, headscale floor 116,
  table max 148), `docs/PROTOCOL.md:132`, README capver/floor lines,
  `ARCHITECTURE.md:52`. Needs HW A/B smoke (Noise prologue changes).
- [ ] T4 self-node token headroom: during smoke read `mapresp peak:
  tokens=` on the initial netmap (conn25 CapMap entries may grow self).
- [ ] T5 (may) home-DERP fallback when PreferredDERP region disappears
  from DERPMap (upstream `508d654dd`); `update_derp_host_from_netmap`.
- [ ] T6 (may, deferred) inbound TSMP: apply received `'a'` adverts /
  answer TSMP ping. **Deferred**: X25519 for the new shared K cannot run
  inside wg_rx's handle_transport (frames: rx_task 0x740, handle_transport
  0x630, curve25519_donna **0xa70 = 2 672 B**; wg_rx stack 8 KiB with
  ~2.1 KiB free at HWM). Netmap patches deliver the key within seconds.

### Headscale side
- [x] **H1 (HIGH) deleted/expired node never recovers.** headscale
  ≥0.29.4 `noise.go:738-765`: unknown NodeKey + Stream=true → HTTP 200 +
  one frame `{"Node":{"Key","KeyExpiry":"1970-01-01T00:00:01Z",
  "Expired":true},"Debug":{…}}` then stream end (404 only for
  Stream=false). Expired nodes: stream stays open with `Expired:true`.
  tinylink ignored `Expired`, status 200 → no 4xx re-register, every byte
  feeds `tinylink_control_mark_alive` → wedge restart never fires →
  reconnect loop forever. Plan: netmap `self_expired` + `self_key_expiry`
  (done in netmap.h); `parse_node_obj` reads both; long_poll_handler:
  expired = Expired || (0 < key_expiry ≤ time(NULL)) [time(NULL) is a
  lower bound of real time even unsynced → never false-positive] →
  return `MAPREQ_STREAM_RECYCLE`; long_poll_task re-registers at
  consec = 1, 2, 4, 8… (4xx keeps ≥ 2). If after re-register the self
  /32 changes (deleted node → new IP) → `esp_restart()` (boot path is the
  tested one; wg_lwip has the old local IP). Caveat for docs: re-register
  after delete/expire needs a *valid* (reusable/tagged) pre-auth key.
- [x] **H2 (HIGH) peer key changes never reach the data plane.**
  `wg_dataplane_update_peers` matched only `s_peer_node_pub`; wg_netif
  had no key setter; DISCO pre-filter + relayed-DISCO gate keep the boot
  DiscoKey forever → after every peer tailscaled restart (new disco key
  each start) DISCO is dropped until reboot; a peer re-login (new
  NodeKey) leaves WG dead. Plan: merge table by **NodeID** (fallback
  NodeKey if ID 0) in upstream order (Peers → replace & stop; else
  Removed → Changed → Patch); apply patches (Key, DiscoKey, Endpoints,
  DERPRegion) in place; `wg_dataplane` tracks peer by NodeID + last
  disco; new `wg_netif_update_peer_keys(static, disco)` — computes the
  NaCl shared K in the caller (long-poll task, 24 KiB stack) BEFORE
  locking, then under hs_lock+g.lock swaps peer static/disco/K; static
  change → reset rekey state + `kick_off_handshake()` (old session is for
  a dead identity). DISCO readers (`handle_disco_direct`,
  `wg_netif_get_peer_disco_pub`) snapshot key/K under g.lock.
  Drop the old "recycle stream on Key/DiscoKey patch" path; keep recycle
  only for `patches_overflow` / `removed_overflow`.
- [x] **H3 (MED)** removal-only / DERPMap-only frames were treated as
  KeepAlive (`!have_self && n_peers==0`). Dispatch when have_self ||
  n_peers || n_removed || n_patches || have_derp_map. Start the data
  plane from the merged table (needs `wg_dataplane_start` to take
  self addrs + peer table, not a frame).
- [x] **H4 (MED)** combined frame (PeersChanged A + patch B) ignored B's
  key patch (`n_peers == 0` gate) — solved by H2's in-place patches.
- [x] **H5 (MED)** endpoint/DERP changes arrive only as patches (59f3ff12)
  — solved by H2.
- [x] **H6 (MED)** `tools/nvs_provision.py:35,66` requires `tskey-`;
  headscale keys are `hskey-auth-<12>-<64>`. Fix tool +
  `docs/PROVISIONING.md:43,90` + `tools/credentials.csv.example`.
- [x] **H7 (LOW)** TL_MAX_PEERS_REMOVED overflow (now a flag → recycle);
  refresh floor/table mentions (`tinylink.h:53-65`, README:320-325,
  PROTOCOL.md:132,196-198, ARCHITECTURE.md:52,396 "404 on unknown node"),
  stale "http2.Server.ServeConn" comments (`ts2021_client.h:12`,
  `h2_client.h:30`).
- [ ] H8 (optional) consume the early-Noise payload lazily on first read
  (today we wait for server bytes before sending the h2 preface; a
  front-end that skips early payload would stall 30 s).

### Cross-cutting
- [x] Version 1.2.0 → **1.3.0** (`TINYLINK_IPN_VERSION`, component
  `idf_component.yml`, README badge, PROJECT_VER if any).
- [x] IDF pin v5.5.4 → v5.5.6: `.github/workflows/build.yml:79,96`,
  `.github/dependabot.yml:3`, README:204,237, `docs/BUILDING.md:5,56,100,192`,
  `docs/ARCHITECTURE.md:212`, `docs/SECURITY-MODEL.md:101`,
  `idf-patches/README.md`, `components/tinylink/src/tl_time.c:40`
  comment, `sdkconfig.defaults:106` comment, `dependencies.lock` (regen
  with `idf.py reconfigure`). Memory file `esp32-toolchain-location`.
- [x] Remove dead `wg_dataplane_update_peer()` (no callers).
- [x] Host tests: test_retry_after rewrite, test_tl_date (new),
  test_mapresp (+expired frame, patches incl. combined frame, removal-
  only, DERPMap-only, overflow flags, StableTailnetID ignored), CI floor.
- [x] Firmware build on v5.5.6: size delta vs 5.5.4 baseline
  (`build_sync/` = 5.5.4 baseline of HEAD 5de412b).
- [x] CHANGELOG entry + ROADMAP M17 + docs.
- [ ] **Owner approval before any flash.** Smoke plan: tailscale.com
  boot smoke (capver 148 A/B), `/stats` disco_adverts increments per
  rekey (~110 s), peer `tailscale ping` direct; then headscale tests:
  boot vs main ≥62714564, `nodes delete` + `nodes expire` while
  connected, restart peer tailscaled (disco rotation), peer
  `--force-reauth`, peer roam, delete non-WG peer, embedded DERP with
  `verify_clients`.

## Results so far (2026-10-28)

Commits on the branch: `09f5f1a` docs(esp32), `c60cfe7` feat (all
firmware code + tests), `c2676dd` build (IDF 5.5.6), `51d4b71` tools
(hskey), then docs/CHANGELOG. Host suite **623 strict OK / 0 FAIL**
(CI-style count), ASan+UBSan clean, 0 compiler warnings.

| build | image B | .bss B | .data B | IRAM .text B |
|---|---:|---:|---:|---:|
| HEAD 5de412b on IDF 5.5.4 (`build_sync/`) | 946 037 | 93 048 | 14 648 | 77 639 |
| HEAD 5de412b on IDF 5.5.6 (`/tmp/tl-head556`) | 952 125 | 93 176 | 14 632 | 77 739 |
| round 1.3.0 on IDF 5.5.6 (`build_v556/`) | 958 013 | 94 320 | 14 632 | 77 739 |

IDF 5.5.6 itself: +6 088 B flash (lwIP + mbedTLS submodule moves),
+128 B BSS. Round code: +5 888 B flash, +1 144 B BSS (4 patch slots in
the static netmap ≈ 850 B, /stats buffer +128 B, self-address cache).

Post-commit: `69caeb5` — the advert was queued before `roam_to` on a
handshake response from a new source (went to the old endpoint); both
callers now roam first, then `send_disco_advert()`. Independent review
agent running on `5de412b..HEAD` (concurrency, stack, merge/expiry
loops, parser bounds, upstream parity) — results to be folded in here.

### Security fixes found by the optimization audit (pre-existing)

- [x] **S1** `f810686` — replay window updated before the AEAD
  (`wg_transport.c`): one forged high-counter packet blocked all inbound
  until rekey (≤110 s), repeatable. Now check → AEAD → update.
- [x] **S2** `f810686` — forged handshake response mutated
  `chain_key`/`hash` before the tag check (5-s stall per attempt) and
  mac1 was never verified. Now local copies + mac1 (keyed with our pub,
  wireguard-go `cookieGenerator.Init(pk)`/`AddMacs`, `CheckMAC1`) first.
- [x] Log bugs `002465e`: DERP stats labels shifted; `%zu` under nano.
- [ ] S3 (crypto hardening, optimization round): donna has ~342k
  secret-dependent branches per scalarmult; some secret scrubs use
  plain memset → fiat32-style constant-time field code (also −30 %).
Host suite now **631 OK / 0 FAIL**, CI floor 631.

## Optimization track (Goal 2)

Agents running (CPU/crypto/data-plane; memory/footprint/boot/power;
`docs/esp32/REFERENCE.md` digest). Told mid-run to stop using IDF 5.5.4
and resume on 5.5.6 in fresh /tmp build dirs. Output = prioritized list
for the owner; nothing implemented until the owner picks.

`docs/esp32/REFERENCE.md` (460 lines, cited) is done. Reliability /
optimization facts it surfaced:
- **RTC-126 erratum applies**: auto light-sleep powers down RTC periph →
  RTC register reads may be wrong after wake; IDF has no workaround;
  fix = `esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_PERIPH, ESP_PD_OPTION_ON)`.
- Cache live-lock erratum (WDT-3.15) affects v3.1 dual core; IDF's fix is
  only compiled with PSRAM → only the interrupt WDT catches it.
- IDF's XMC safeguards (bootloader flow, brownout flash reset) key on
  vendor 0x20; ours is **0x46** → neither runs. Brownout detector at the
  lowest level (2.43 V) while the flash needs ≥ 2.7 V → raise BOD level.
- ESP32 cannot suspend flash ops: every NVS/OTA write stalls both CPUs'
  caches (4 KB erase up to 500 ms, 64 KB up to 3 s) → audit NVS write
  cadence (time floor hourly, TAI64N reservations).
- REV_MIN_3 removes the peripheral-read workaround (cheaper accelerator
  access); CPU-3.16 speculative read still applies → keep `volatile`.
- RSA/MPI accelerator min operand 512 bit, 2 rounds/modmul → useless for
  X25519. No HW for ChaCha20/Poly1305/BLAKE2s/Salsa20.
- REV_MIN 3.1 vs 3.0 changes nothing in IDF 5.5 beyond the boot check.
- Global `CONFIG_COMPILER_OPTIMIZATION_DEBUG=y` (-Og); only the tinylink
  component is -O2.

CPU / crypto / data-plane agent: DONE (summary — full list will be in
`docs/rounds/2026-10-optimization-list.md`). Measured on IDF 5.5.6
scratch builds, nothing timed on device:
- P0: global -O2 (`COMPILER_OPTIMIZATION_PERF`: −25.5 KB flash, −3.6 KB
  IRAM; all lwIP compiles at -O2 — the "-O2 hangs" note is stale; lwIP
  checksum 21→9 µs/1500 B); DHCP ARP check still ON (`sdkconfig.defaults:329`
  sets a choice member that is ignored → select
  `CONFIG_LWIP_DHCP_DOES_NOT_CHECK_OFFERED_IP`, −1.0 s/boot); first WG INIT
  lost every boot (−2.5…3.5 s: INIT on DERP login/pong/CMM, deadline-
  based RX timeout); TCP_NODELAY + one TLS record per DERP packet (3
  records today → +1 RTT per relayed packet), Noise record = 1 TLS
  record; WIFI_PS_NONE until session up (−0.6…1.5 s); ECP fixed-point
  optim (+5.6 KB, −0.45…0.6 s/handshake); don't wait SETTINGS ACK (−1 RTT);
  UART 921600 + no log colors; DISCO pong seal does a full X25519 even
  with cached K (−20 ms/ping); precompute static-static DH + mac1 key
  (wg_handshake_init redoes them, −20 ms/INIT); finish crypto-in-IRAM
  (chacha20_init, zeros[], mbedtls_platform_zeroize in flash); TX queue
  item 1 556 B copied twice → ring index; wg_lwip_linkoutput 1.5 KB
  stack frame (static scratch).
- P1: IRAM for lwIP/FreeRTOS/WiFi RX/WG glue (+43 KB IRAM, 12 KB left);
  lwIP raw-API WG endpoint (TX copies 6→3, RX 4→1, kills wg_tx task);
  split g.lock (RX/TX AEAD never run in parallel today); ChaCha20 C
  rewrite (−18 % instr); Poly1305 pre-shifted r; constant-time fiat32
  X25519 (−30 %); precompute next INIT off wg_rx; X25519 reuse (DISCO
  relayed cache, DERP, Noise ss); control plane: plain HTTP :80 for
  ts2021, DERP before netmap, TLS session tickets, bigger TCP wnd,
  pipelined push+stream; task priorities/pinning; SO_NO_CHECK.
- P2/P3: WG AEAD entry w/o memcpy/memset, now_us once per loop, WDT
  feed 1/s, deadline wakeups, RUN_TIME_STATS off, demux switch on
  buf[0], word-wise ct_memeq, BLAKE2s/Salsa20 SAR-once, HKDF −17
  compressions, nacl_box on in-tree Poly1305, unity build, misc control
  items. Projected WG-up ≈ 5.2 s (3.8 s with :80) vs 14.6–25 s today.
- Stale sdkconfig.defaults comments: "TLS 1.3" (not compiled in), E8
  chain (now YE1/YE2 → Root YE → X2 → X1), "ECDHE-RSA" (actually
  ECDHE-ECDSA-AES128-GCM-SHA256), line 329 no effect.
- Scratch artifacts: /tmp/tlopt-556/keep/*.map, /tmp/tlopt/cc/,
  /tmp/tlopt-asym/, /tmp/tlopt-tls-556/.

Ideas captured so far (to merge into the list):
- `noise_ik.c` still uses mbedTLS `mbedtls_chachapoly_*` → switch to the
  in-tree IRAM AEAD (also removes the v6 blocker).
- Inbound TSMP advert apply (T6) once there is a stack-safe context.
- `wg_netif.h` doc comment of `wg_netif_get_peer_disco_pub` had drifted
  from its declaration (fixed).
