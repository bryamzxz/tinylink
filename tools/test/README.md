# Host-side known-answer tests

Codec, crypto and state-machine tests for the tinylink component. They
compile with stock gcc — no ESP-IDF needed — and run on whatever host you
build on. The on-target build still has to be verified independently
(compilers and architectures can introduce subtle differences; the
Xtensa-specific fast paths in `chacha20.c` / `poly1305_donna_32.h` are
dispatched on buffer alignment, which UBSan checks on the host).

## Run

```bash
cd tools/test
make test                    # build + run all binaries
make asan                    # same, under ASan + UBSan (clean rebuild)
make test RUNNER='valgrind -q --error-exitcode=9'
make test_stun.run           # one binary
```

Every case prints `[name] OK`; every binary ends with `ALL OK` or
`[PASS] …` and exits non-zero on the first failed assertion, which
`make` propagates. CI (`.github/workflows/build.yml`) requires zero
`FAIL` lines and a floor on the number of `OK` lines
(`HOST_TESTS_MIN_OK`) — bump the floor when you add cases.

`CFLAGS` carries `-Werror`; `EXTRA_CFLAGS` is appended for sanitizers or
coverage without restating the base flags.

The HTTP/2 interop pair (`test_h2_interop`, `test_h2_ref`) needs nghttp2
on the host: the `espressif__nghttp` component the firmware used until
1.3.4 (`make test NGHTTP2_COMPONENT=/path/to/espressif__nghttp`, compiled
here, with the sanitizers under `make asan`), or the system library
(`libnghttp2-dev` / `pkg-config libnghttp2`). Without either, `make
test` prints a skip notice and runs everything else (53 fewer OK lines).

## Coverage

| Binary                   | Exercises                                             | Vectors / oracle |
|--------------------------|-------------------------------------------------------|------------------|
| `test_blake2s`           | `crypto/blake2s.c`                                    | RFC 7693 §A + KATs |
| `test_curve25519`        | `crypto/curve25519.c`, `curve25519_fiat32.c`          | RFC 7748 §5.2, §6.1 |
| `test_x25519`            | `curve25519_fiat32.c` field ops at their bounds + X25519 (C fallback on the host; the asm runs in `tools/qemu_crypto`) | RFC 7748 iterated 1 / 1 000 (1 000 000 with `X25519_MILLION=1`), 4 000 pairs vs donna (`ref/`), `__int128` mod-p oracle |
| `test_chacha20`          | `crypto/chacha20.c` fused + keystream paths, all 16 alignments, in place | RFC 8439 §2.3.2, A.1 #1–5, A.2 #1–3, HChaCha20, 5 000 trials vs 1.3.2 (`ref/chacha20_132.c`) |
| `test_poly1305`          | `crypto/poly1305_donna.c`                             | RFC 8439 §2.5.2 + A.3 #1–#11 |
| `test_chacha20poly1305`  | AEAD glue (`chacha20poly1305.c`)                      | RFC 8439 §2.8.2 (114 B: exercises the tail path) + A.5 |
| `test_noise_ik`          | `noise_ik.c` ts2021 Noise IK handshake + transport records (BE64 nonce, tamper / replay / in-place) | OpenSSL-based `gen_noise_vectors.py` + in-file responder |
| `test_ts2021`            | `ts2021_client.c` record layer after the handshake, over a fake esp_tls: the EarlyPayload skip and the HTTP/2 start kept in the record ring by offset (D5), magic bytes put back across records, rejects; records decrypted / sealed in place in the ring, ≤ 2 048-B sends in one esp_tls write, ≤ 64-B control records off the ring (D4) | synthetic + 2 000-case record-segmentation fuzz |
| `test_hpack`             | `hpack.c` (D1): streaming decoder, canonical Huffman, dynamic table bounded by the advertised size, literal encoder | RFC 7541 C.1–C.6 (block / byte-by-byte / random splits, table sizes), every symbol vs an independent Appendix B table, §5.2 padding / EOS, malformed blocks, device table 0, round-trip fuzz vs an in-test encoder + table model, 200 000-block garbage fuzz |
| `test_h2_core`           | `h2_core.c` (D1) against a scripted peer: exact preface / SETTINGS / request bytes, padding, CONTINUATION + its limit, WINDOW_UPDATE at half the window, window violations, request bodies held by small / negative server windows, PING / GOAWAY / RST_STREAM, nghttp2's response checks, every connection-error code | synthetic, every stream fed whole / byte by byte / at random splits; structured + garbage frame fuzz |
| `test_h2_interop` / `test_h2_ref` | the firmware HTTP/2 stack (h2_client → h2_core → ts2021 records over Noise) / the 1.3.4 nghttp2 client (`ref/h2_134/`), same scenarios | **nghttp2's server** in memory: POST JSON, 429 / 503 + Retry-After, overflow latch, 100 KB stream through WINDOW_UPDATEs, server PING, GOAWAY mid-stream / refusing, RST, register → push → stream, tiny server window, a 4 000-B body in ≤ 2 048-B records, padding, CONTINUATION, trailers, 1xx, EOF, callback stop. Needs nghttp2 (`NGHTTP2_COMPONENT=<espressif__nghttp dir>` or `pkg-config libnghttp2`), else skipped |
| `test_hkdf_noise`        | `crypto/hkdf_blake2s.c` (HKDF, Noise §4.3 KDFs)       | cross-consistency |
| `test_wg_handshake`      | `wg_proto.c`, `wg_handshake.c` (Noise IKpsk2 initiator) | upstream-derived transcript |
| `test_wg_transport`      | `wg_transport.c` (RFC 6479 replay window, AEAD framing; 1.3.3 reserve / begin / open / commit split, every rekey / duplicate interleaving, pthread race test with the races forced) | synthetic + fuzz vs the old bit-wise window |
| `test_wg_demux`          | `wg_demux.c` first-byte classification                | synthetic |
| `test_wg_timers`         | `wg_timers.h` RX-task deadline wait (never 0 / early / past the cap) | FreeRTOS tick model |
| `test_disco`             | `disco.c` codec + NaCl box (`salsa20.c`, `nacl_box.c`) | upstream `disco_test.go` + round-trip |
| `test_disco_handler`     | `disco_handler.c` ping → sealed pong                  | synthetic |
| `test_disco_prober`      | `disco_prober.c` tx-id table (ROAM-3)                 | synthetic |
| `test_stun`              | `stun.c` RFC 5389 binding codec                       | upstream `stun_test.go` |
| `test_derp`              | `derp.c` frame codec, ServerInfo/ClientInfo           | upstream `derp_test.go` |
| `test_tls_io`            | `tls_io.c` WANT_READ retry + idle budget (M13)        | fake reader |
| `test_retry_after`       | `h2_retry_after.h` 429/503 parsing                    | synthetic |
| `test_mapresp`           | `mapreq.c` MapResponse parser (netmap, DERPMap kept by RegionID, patches, Peers vs PeersChanged vs PeersRemoved, oversized element); since 1.3.4 (D2) the streaming splitter + `LE32` framing: random chunkings from 1 B, two-chunk cuts at every byte incl. inside the length prefix, every truncation + resync, elements over the 8 KiB buffer, frame cap | real one-peer stub, real-shaped 25.5 KB initial netmap + deltas; **the whole-body parser** (`ref/mapresp_133.c`) as oracle, 40 000 random edits |
| `test_skip_value`        | `jsmn_skip.h` depth bound; `jsmn_tree_ok` (1.3.4: a pair walk that stays inside the tokens jsmn wrote) | synthetic + 300 000 random vs a bounds-checked walk |
| `test_backoff`           | `backoff.h` ladder + jitter                           | synthetic |
| `test_keys_regen`        | `keys_regen.h` identity regeneration policy           | 8 combinations |
| `test_jsmn_split`        | `jsmn_split.h` shallow object/array splitter; `tl_jsplit_scan_*` (its byte-at-a-time form, 1.3.4) | synthetic incl. depth bound; 200 000 random strings scan vs `tl_jsplit_value` |
| `test_tai64n`            | `wg_proto.c` TAI64N floor / reservation / persist     | synthetic |
| `test_stats`             | `tl_bootstat.h` RTC boot counters, `stats_json.h` /stats worst case vs buffer | synthetic + jsmn validity |
| `test_nacl_box`          | `nacl_box.c` seal/open/precomputed-shared/tamper      | **libsodium** vectors (PyNaCl, `gen_nacl_vectors.py`) |

## On the target: `tools/qemu_crypto` (Espressif QEMU, esp32 machine)

The host binaries above only ever run the C fallbacks. The Xtensa paths
— the inline asm in `curve25519_fiat32.c` (MULL / MULUH / SRC under one
`ssai 28`), `chacha20.c`, `blake2s.c`, `salsa20.c`, Poly1305 — depend on
SAR, which GCC cannot be told about, so only running the compiled LX6
code checks them. `tools/qemu_crypto/run.sh` builds the crypto suites
(`test_chacha20`, `test_chacha20poly1305`, `test_poly1305`,
`test_blake2s`, `test_hkdf_noise`, `test_nacl_box`) for the ESP32 with
the firmware's -O2 islands, plus `x25519_qemu.c`: the field operations,
asm vs the C fallback compiled for the same target, bit for bit on
200 000 inputs at the loose bounds; X25519 asm vs C vs donna on 3 000
pairs (u ≥ p, u = p, small u, all-ones scalars); RFC 7748 iterated
1 / 1 000. It runs them on `qemu-system-xtensa -machine esp32` — an ISA
implementation nobody on this project wrote — and exits non-zero on any
failure (~2 min in QEMU). Needs an exported ESP-IDF and
`python $IDF_PATH/tools/idf_tools.py install qemu-xtensa`; CI runs it
(`qemu-crypto` job). The upstream QEMU tree has no ESP32 machine or LX6
core config — use Espressif's build.

## Optional: mbedTLS reference (`make mbedtls-ref IDF_PATH=…`)

Not in `make test` (CI has no ESP-IDF). Links IDF's mbedTLS sources and
runs `test_aead_mbedtls` (in-tree ChaCha20-Poly1305 / Poly1305 vs
`mbedtls_chachapoly_*` / `mbedtls_poly1305_mac`, fixed-seed fuzz over
WG / ts2021 / arbitrary nonces, alignments, in place) and
`test_noise_ik_mbedtls` (`test_noise_ik.c` against `noise_ik.c` as of
`NOISE_OLD_REV`, i.e. the pre-1.3.2 mbedTLS path). Round 1.3.2 moved
Noise and the NaCl box off mbedTLS; these prove no byte changed.

## Not covered on the host (needs a seam or a fixture)

- `register.c` RegisterResponse parsing (cJSON-based), `control_key.c`
  `/key` parsing, `stun_probe.c` — all platform-bound today
  (`telemetry.c`'s /stats line moved to `stats_json.h`, covered).
