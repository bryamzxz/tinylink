# Optimization list for the ESP32 v1 — "optimization to the absurd" (2026-10-28)

Input for the 1.3.x rounds. Nothing here is implemented yet; the owner
picks. Sources: two analysis agents (CPU / crypto / data plane;
memory / footprint / boot / power) working on ESP-IDF **v5.5.6** scratch
builds of `5de412b` (27 + 4 measured variants, nothing flashed), plus
`docs/esp32/REFERENCE.md` (vendor docs, page-cited). Part: ESP32-WROOM-32E-N4,
ESP32-D0WD-V3 rev v3.1 (`docs/esp32/README.md`).

**Measured** = built and sized (flash / static RAM) or stack frames read
from the compiled objects. **Est.** = static instruction counts or
arithmetic; needs an on-device number ("measure on v5.5.6"). Baseline
(HEAD `5de412b` on 5.5.6): image 952 093 B, static DRAM 107 808 B, static
IRAM 78 767 B. Round 1.3.0 adds +5.9 KB flash / +1.1 KB BSS on top.

Headline numbers:

| scenario | image | Δ |
|---|---:|---:|
| Kconfig-only set (A1–A9) | 813 459 B | **−135 KiB** |
| + code items that link (B1–B6) | 742 123 B | **−205 KiB (−22 %)** |
| + single-core (D3) | 733 705 B | −213 KiB |
| boot → WG up (today 14.6–25 s) | ≈ 5.2 s est. | (≈ 3.8 s with ts2021 on :80) |

Compiler level — the two agents disagreed: global -O2 is −25 KB vs
today's -Og and fastest; global **-Os is −62 KB** and still faster than
-Og. Recommendation: **-Os globally + -O2 islands** (tinylink hot files,
mbedTLS bignum/ecp, lwIP's checksum/pbuf/udp/ip4, FreeRTOS queue) — the
islands keep the hot-path gains (lwIP checksum 21 → 9 µs per 1 500 B).

---

## Round A — Kconfig / one-liners (biggest win, lowest risk) → 1.3.1

**Status (2026-10-28, branch `feat/opt-1.3.1`): implemented, hardware
smoke clean (boot to WG 16.6 → 13.6 s), 6-h soak running.** Image 959 249 → 826 768 B (−132 481 B, −13.8 %),
static IRAM 78 767 → 73 867 B, static DRAM 108 952 → 108 220 B. Host
suite 633/0, 0 warnings, partition table byte-identical (app-only
flash). Deviations from the table below, each verified against IDF
5.5.6 source:
- A1 islands as listed (tinylink, main, mbedcrypto + lwIP inet_chksum /
  pbuf / udp / ip4 + FreeRTOS queue.c via `set_property(SOURCE …
  TARGET_DIRECTORY)`); -Os also drops FreeRTOS's task-return wrapper —
  no task returns.
- A3: Log V2's call chain is ≈ 150–200 B deeper → `tinylink_tlm`
  4 096 → 4 608 B and the Wi-Fi task +512 B (M16 soak lows: 452 / 584 B
  free).
- A7 **dropped**: IDF's hidden `ESP_SLEEP_RTC_BUS_ISO_WORKAROUND` (y on
  ESP32) already keeps RTC_PERIPH on in every light sleep
  (`sleep_modes.c:2895`); REFERENCE.md corrected.
- A8 at **level 6** (2.77 V ±0.05), not 7: lowest level whose band stays
  above the flash's 2.7 V minimum, 30 mV more nuisance headroom than L7.
  Reset reason now in the boot log and `/stats` to count BOD resets.
- A11 as an `esp_timer` in `app_wifi.c` (PS_NONE → MIN_MODEM at WG
  session up, ≤ 60 s after Wi-Fi start), not a wait in `bringup()` —
  `app_main` must return to free its 24 KiB stack before the DERP TLS
  handshake.
- A12 at **500 000 baud**, not 921 600: with PM_ENABLE the console UART
  runs from REF_TICK (1 MHz) and 921 600 comes out ≈ 941 k; only
  settable on the CUSTOM console choice.
- A13: dynamic log levels off via `LOG_TAG_LEVEL_IMPL_NONE`; nothing
  calls `esp_log_level_set` except IDF debug drivers.
- A14 also fixed: CAMELLIA claim (it is gone; only ARIA is linked), RSA
  "fallback" note, the no-op `MBEDTLS_SSL_MAX_CONTENT_LEN` line, chain
  now YE1/YE2 → Root YE → X2 → X1, 43 (not 44) CMN roots.
- New guard: CMake warns when an `sdkconfig` predates 1.3.1 (an
  existing sdkconfig keeps its old choice selections over the defaults).

| # | item | evidence | gain | risk |
|---|---|---|---|---|
| A1 | **-Os global + -O2 islands** (see above); drop the stale "toolchain hangs at -O2" note — all 92 lwIP files build at -O2 | `CONFIG_COMPILER_OPTIMIZATION_DEBUG=y` today | −62 KB flash, −6.6 KB IRAM (measured -Os); islands keep hot paths | M: 155 frames grow / 107 shrink (net +480 B) → soak |
| A2 | **Cert bundle FULL → common (CMN)**: 43 roots incl. ISRG X1/X2, GTS R1–R4, DigiCert, GlobalSign, Amazon, USERTrust | `x509_crt_bundle.S.obj` 68 988 B | **−51 064 B** measured | L: exotic-CA servers fail closed; closes most of owner item G |
| A3 | **Log V2** (+ `LOG_COLORS=n`, which alone is −6.6 KB) | measured | −19 368 B flash, +1.9 KB IRAM | L: re-check soak grep patterns |
| A4 | `ESP_NGHTTP2_INBOUND_BUFFER_LENGTH` 4096 → 512 | `nghttp2_session_recv` frame 4 128 → 544 B | −3.6 KB long-poll stack | L |
| A5 | **DHCP ARP check really off**: select `CONFIG_LWIP_DHCP_DOES_NOT_CHECK_OFFERED_IP=y` (`sdkconfig.defaults:329` sets a choice member → ignored) | `acd_dhcp_check.c` 2 × 500 ms probes | **−0.5…1.0 s every boot + re-assoc**, −704 B | L |
| A6 | `FREERTOS_USE_TIMERS=n` (timer task unused) | links clean | −1 348 B flash, −328 B DRAM, −2.5 KB heap | L |
| A7 | **RTC-126 erratum**: `esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_PERIPH, ESP_PD_OPTION_ON)` at boot (auto light-sleep powers it down; rev v3.1 affected; no power cost per errata) | Errata v3.1 §3.18 p.22 | correctness | L |
| A8 | **Brown-out level 0 (2.43 V) → LVL 7 (2.80 V)**: flash min 2.7 V, module 3.0 V; IDF's XMC BOD safeguard keys on 0x20, ours is 0x46 | WROOM-32E Table 17 p.30 | correctness | L: count BOD resets in /stats |
| A9 | mbedTLS trims `PK_PARSE_EC_EXTENDED/COMPRESSED=n`, `PEM_PARSE_C=n` (DER bundle, no client key) | measured | −4 360 B | L |
| A10 | `ECP_FIXED_POINT_OPTIM=y` | measured +5.6 KB | **−0.45…0.6 s per full TLS handshake** (2 per boot) | L (flash cost) |
| A11 | `WIFI_PS_NONE` until "session up", then MIN_MODEM | `app_wifi.c:171` | −0.6…1.5 s boot | L: +70 mA for ~10 s/boot |
| A12 | Console UART 921 600 (no driver = busy-wait on 128-B FIFO; stack-diag burst spins 85 ms/60 s) | log stats | −0.3…0.5 s boot, fewer stalls | L: monitor baud |
| A13 | `FREERTOS_GENERATE_RUN_TIME_STATS=n`, dynamic log levels off — first add the missing `esp_timer` REQUIRES (build breaks otherwise) | measured | esp_timer read per context switch saved | L |
| A14 | Stale `sdkconfig.defaults` comments: "TLS 1.3" (not compiled in), E8 chain (now YE1/YE2 → Root YE → X2 → X1), "ECDHE-RSA" (is ECDHE-ECDSA-AES128-GCM-SHA256), ARIA "removed" (still linked), "%f unsupported under nano" (IDF forces `_printf_float`), `partitions.csv` free-space note | — | hygiene | — |

## Round B — small code changes, big wins → 1.3.2

**Status (2026-10-28, branch `feat/opt-1.3.2`): implemented except B18,
hardware smoke pending.** Four parallel branches (ctl / crypto / dp /
sys), merged and reviewed as a whole. Image 826 768 → 762 535 B
(−64 233 B), static DRAM 108 220 → 95 884 B, host suite 881/0. Measured
vs plan: B1 −21.9 KB (plan −33.5, measured at -Og), B2 −5.0, B3 −15.4,
B4 −5.5, B5 −8.8, B6 −10.6, B15 −5.1 KB static (the stream request
needs its own 1 KiB), B16 −6.0 KB BSS, B14 needs 4 slots (not 3) for
the old capacity. Corrections found on the way: the Noise nonce counter
is big-endian; 1.3.1's TLS suite was ChaCha20-Poly1305 (now AES-GCM);
the /stats worst case is 862 B (buffer 896); the pong "fast INIT"
broke one-INIT-per-REKEY_TIMEOUT. Per-item details in the CHANGELOG.

| # | item | gain | risk |
|---|---|---|---|
| B1 | **Drop esp_http_client** — only the TOFU `GET /key` uses it (`control_key.c:119`); ~40 lines on esp_tls like ts2021/DERP | **−33.5 KB** (−34 KB with ALPN off) | L |
| B2 | **Drop cJSON** (`register.c`, `control_key.c`) → snprintf + jsmn | −6.8 KB, −40…60 heap allocs per register | L |
| B3 | **Float printf/scanf stubs** (enabled by B2) | B1+B2+B3 = **−57.5 KB** measured | L |
| B4 | **Noise + NaCl box on the in-tree IRAM AEAD** (`noise_ik.c` mbedtls chachapoly; `nacl_box.c`), then mbedTLS CHACHA/POLY off — also removes the IDF v6 blocker | −5.7 KB, Noise records from IRAM | L |
| B5 | mbedTLS user config: undef ARIA, CFB/OFB, 3 paddings, PKCS12 (XTS + PKCS5 must stay) | −9.2 KB | L |
| B6 | -O2 islands tuned (mbedcrypto only ecp/bignum at -O2; tinylink cold files at -Os) | −12.5 KB | L |
| B7 | **First WG INIT lost on every boot** (WG-up − netmap = 5.2–6.2 s = REKEY_TIMEOUT + 1-s tick): INIT on DERP login / pong / CMM while pending, also via DERP; deadline-based RX timeout | **−2.5…3.5 s to tunnel up** | L |
| B8 | **TCP_NODELAY** on control + DERP sockets; DERP send = 1 TLS record (3 today: hdr, key, pkt → Nagle waits an RTT); Noise record = 1 TLS record | −0.9…1.3 s to netmap; −1 RTT per relayed packet | L |
| B9 | Don't wait for the h2 SETTINGS ACK before the first request (`h2_client.c:306`) | −1 RTT per control connect | L |
| B10 | **DISCO pong seal reuses the cached shared K** (`disco_handler.c:83` does a full X25519 even on the cached path) | ~20 ms → 50 µs per ping, no 20-ms wg_rx stall | L |
| B11 | Precompute static-static DH + mac1 key once per peer (`wg_handshake_init` redoes them every INIT) | −20 ms per INIT/rekey | L |
| B12 | Finish crypto in IRAM: `chacha20_init`, `zeros[]` (flash .rodata), in-tree IRAM secure-zero instead of `mbedtls_platform_zeroize` | ~5–6 µs per cold packet | L |
| B13 | **`wg_lwip_linkoutput` 1 568-B frame on every TX** (chained-pbuf scratch) → noinline slow path / static under core lock; likely root cause of the 2026-05 lwIP-task overflow | −1.5 KB stack on tiT/telemetry/wg_rx | L |
| B14 | **TX queue of 1 556-B items copied twice** → 3-slot ring of indices | −2 memcpy/packet (≈9 µs), −1.5 KB static, −1.5 KB stack | L |
| B15 | One shared control buffer (register `resp[4096]`, mapreq `body[2048]`, stack bodies) carved from `body_buf`; cap frames 30 KB (peak 25 838 B) | −6 KB static, −2…3 KB stack | L |
| B16 | Keep only DERP regions in use (by ID, not order — region-16 lesson) | −5.2 KB static | L |
| B17 | Fold the STUN re-probe task into telemetry | −3.4 KB heap | L |
| B18 | Stack trims from soak data: esp_timer 6 → 3.5 KB, DERP 10 → 8 KB, diag `snap[32]` → 20 | −5 KB heap | M: soak |
| B19 | `/stats`: min-ever free heap, largest block, reset reason, BOD/WDT counters in RTC memory | observability for every item | L |
| B20 | NVS time floor daily (or on >1-day move) instead of hourly: every 4 KB erase stalls both CPUs 70 ms typ / 500 ms max (ESP32 cannot suspend flash ops) | fewer stalls | L |
| B21 | Small: `now_us()` once per loop (12 esp_timer reads), WDT feed 1/s, deadline wakeups (wg_rx 1 s, wg_tx 500 ms → 3 wakes/s from light sleep), demux switch on `buf[0]`, word-wise `ct_memeq`, WG AEAD entry without memcpy/memset of a public nonce | µs each | L |

## Round C — data-plane & crypto engineering → 1.3.3+

| # | item | gain (est.) | risk |
|---|---|---|---|
| C1 | **lwIP raw-API WireGuard endpoint**: `udp_recv` in tiT decrypts in place and `ip4_input`; TX `udp_sendto` from linkoutput encrypting into the outer pbuf; handshake/DISCO/STUN to a worker | TX copies 6 → 3, RX 4 → 1, task hops halved, **wg_tx task gone (−7 KB stack, −4.7 KB queue)** | M: needs unaligned-capable AEAD; intermediate steps (decrypt into pbuf, `LOCK_TCPIP_CORE`+`ip4_input`) are S |
| C2 | **Split `g.lock`**: verify+decrypt outside, replay update under a short lock — today RX and TX AEAD (~400 µs/MTU) can never run on both cores | parallel crypto | M |
| C3 | IRAM for the rest of the hot path: `LWIP_IRAM_OPTIMIZATION` (+9.9 KB), FreeRTOS out of flash (+10.1 KB), `WIFI_RX_IRAM_OPT` (+14.2 KB), `WIFI_EXTRA_IRAM_OPT` (+4.4 KB), WG glue (+4.4 KB) → IRAM 75 → 119 KB (12 KB left; IRAM is not counted in heap_free) | no flash misses per packet | M: measure sparse vs flood first |
| C4 | ChaCha20 C rewrite (pair-wise QR, fused add+XOR; −18 % instr, spills 35 → 19; bit-identical over 5 000 trials) | AEAD −14 % with C5 (≈385 → 330 µs/MTU) | L |
| C5 | Poly1305 "pre-shifted r" (−25 mask pairs/block; needs asm to beat GCC's spills) | see C4 | M |
| C6 | **Constant-time X25519, fiat32 structure** (products split at bit 28): 3.58 M → 2.51 M instr (−30 %, ~13 ms vs 20) and removes ~342 k secret-dependent branches per scalarmult (S3) | security + speed | M: RFC 7748 + 3 000 cross-checks pass on host |
| C7 | Precompute the next INIT / move handshake crypto off wg_rx (INIT 60 ms + response 40 ms every 110 s block a 6-packet mailbox) | INIT latency ~0.1 ms | M |
| C8 | X25519 reuse: relayed-DISCO per-peer K cache + pre-AEAD sender gate (any node can make us burn 40 ms/relayed ping), DERP keypair reuse, Noise IK ss cache | −20…260 ms bursts | L |
| C9 | BLAKE2s / Salsa20 SAR-once (1 995 → 1 826 instr/compression), HKDF −17 compressions/handshake, nacl_box on in-tree Poly1305 (mbedTLS one has 30 `bgeu`/block) | small | L |
| C10 | Task layout: wg_rx (IDLE+3) is below long-poll (IDLE+4) — netmap parsing preempts the data plane; pin wg_rx/wg_tx/TLS tasks to CPU1 (each core has its own 32 KB cache) | latency | M: rate-limit floods |
| C11 | `SO_NO_CHECK` on the outer WG socket (outer UDP checksum, ~9 µs/1500 B at -O2) | small | M: some middleboxes drop |

## Round D — big engineering (memory) → 1.3.x late

| # | item | gain | risk |
|---|---|---|---|
| D1 | **In-tree HTTP/2 client** (frame codec, HPACK literal encoder, compact Huffman) instead of nghttp2 (71 457 B incl. a 16 KB Huffman table) | **−66…70 KB flash, −18 KB heap** | M: host tests with captured traces |
| D2 | **Streaming MapResponse splitter**: 32 KB `body_buf` → 8 KB per element | **−24 KB static** | M |
| D3 | **Single-core** (`FREERTOS_UNICORE`): −2.7 KB DRAM, −3.9 KB IRAM, −9.8 KB flash measured; frees RTC FAST 8 KB + 2nd cache 32 KB as heap; removes the WDT-3.15 live-lock precondition | +14 KB byte heap, +32 KB IRAM heap | M: wg_rx priority above TLS; soak |
| D4 | Long-poll stack diet then 24 → 12 KB (A4 + in-place Noise decrypt in `h2_rx`, drop `ct[4096]`, 2 KB send chunks, B15); main task 24 → 12 KB | −12…24 KB heap | M: 6-h soak gate (M10 lesson) |
| D5 | Remove `rx_residual[4077]` (`ts2021_client.h:89`) — offsets into `h2_rx` | −4 KB static | M |
| D6 | jsmn token table (10 KB, all 32-bit accesses) in free IRAM via `MALLOC_CAP_32BIT|EXEC` | −10 KB DRAM | M: a byte access traps |
| D7 | nghttp2 send buffer 16 394 B chunk → ~4 KB (vendored) | −12 KB contiguous heap per reconnect | M |
| D8 | mbedTLS direct instead of esp_tls (static SSL contexts reset on reconnect) | −6.2 KB flash, less fragmentation | M |
| D9 | TLS session tickets (both servers issue them): skip chain verify + ECDHE on reconnect | −1.5…1.8 s per reconnect | M: re-test old DYNAMIC_BUFFER suspicion |
| D10 | ts2021 over plain HTTP :80 with :443 fallback (Noise authenticates via the pinned key); DERP without waiting for the netmap; pipeline lite push + stream as two h2 streams; TCP wnd 5 760 → 11 520–16 384; A/B `HARDWARE_MPI=n` (256/384-bit ops padded to 512) | −1.9…3.5 s boot | M |
| D11 | Warm-boot cache in RTC slow memory (unused today: Wi-Fi channel/BSSID, last IP, DERP host, STUN endpoint, crash counters); cold-boot channel/BSSID in NVS on change; STUN probe off the boot critical path | −0.3…3 s | L–M |
| D12 | Coredump partition (owner item F): +15 KB flash, +2 KB DRAM; 64 KB at 0x330000 fits the free tail | debuggability | needs full-flash authorization |
| D13 | Wi-Fi static RX buffers 8 → 5 (+ BA window 5), dynamic RX ≤ 10 | −4.8 KB heap | M: 25 KB netmap burst retransmits |

## Round E — extreme / low value (only if everything else is done)

Single-core + `IRAM_AS_8BIT_ACCESSIBLE` to put `body_buf` in freed cache
IRAM (−32 KB DRAM, ~70 ms per full netmap); RTC slow for cold buffers
(−2.4 KB); custom 2–4-root bundle (−15 KB more, CA-rotation risk);
production WARN log overlay (−18 KB, loses soak greps); TX power 13–15 dBm
(TX 239 → 183 mA avg, less self-heating next to the TMP117); max CPU 160 MHz;
`PM_SLP_IRAM_OPT` / `PM_RTOS_IDLE_OPT`; AMPDU RX off (4 static RX
buffers); unity build for crypto (LTO breaks ldgen placement).

## Already optimal / rejected (do not re-propose)

REV_MIN 3 already set (DPORT workaround out, ECO3 ROM); BT excluded and
its region already in use; QIO@80; 240 MHz with PM holding max while
busy; `-mlongcalls` relaxed to `call8` in IRAM; ROM memcpy already
`ssa8l`/`src`; zero-overhead loops on the XOR paths, no `l32r` in crypto
loops; the ChaCha20 double round is too big for `loop`; MAC16,
radix-2^32, the RSA/MPI accelerator (min 512-bit operands) and mbedTLS
X25519 rejected for Curve25519; fusing ChaCha20+Poly1305 (SRAM is
uncached — ~0.25 instr/B); splitting keystream across cores; AES-GCM on
HW AES (~3 ms/netmap), HW SHA; JSON parse ~4 ms; RNG not per packet;
`LOGD` compiled out; RX IP/UDP checksum checks already off; lwIP core
locking on; heap poisoning off; lwIP pools on demand; earlier mbedTLS
prunes sound (CMAC for PMF, SHA1, SHA512, RSA must stay); ~12 KB Wi-Fi
blob static data fixed; LTO unavailable (IDF links -fno-lto).

## Security / correctness found on the way (fixed in round 1.3.0)

S1 replay window before AEAD, S2 handshake-response state mutation +
missing mac1 (`f810686`); DERP stats labels and `%zu` (`002465e`).
Open: S3 secret-dependent branches in donna (→ C6), secret scrubs with
plain memset (→ B12's in-tree secure-zero).

## Suggested order

1.3.1 = Round A (Kconfig, one soak); 1.3.2 = Round B (code, host tests
+ soak); 1.3.3 = C1–C2 + C4/C6 (data plane + crypto, bench + soak);
1.3.4 = D1/D2/D4 (memory, long soak); then 1.4.0 after a clean
multi-day run. Every round: size report vs the previous one, the 6-h
soak with stack-diag dumps, `/stats` deltas.

Scratch artifacts (copied out of /tmp, git-ignored, local only):
`work/artifacts/` (was `build_opt-artifacts-2026-10/`) — `maps-mem/` + `maps-cpu/` (linker maps /
size reports per measured variant), `tlopt_cc/` (ChaCha20 / Poly1305
variants + host equivalence tests), `tlopt-asym/` (fiat32 X25519,
handshake PoC, BLAKE2s), `tlopt_replay/t.c` (S1 PoC), `tlopt-tls-556/`,
`tl-scripts/` (variant build + patch scripts).
