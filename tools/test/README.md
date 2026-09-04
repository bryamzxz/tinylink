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
make test                    # build + run all 23 binaries
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

## Coverage

| Binary                   | Exercises                                             | Vectors / oracle |
|--------------------------|-------------------------------------------------------|------------------|
| `test_blake2s`           | `crypto/blake2s.c`                                    | RFC 7693 §A + KATs |
| `test_curve25519`        | `crypto/curve25519.c`, `curve25519_donna.c`           | RFC 7748 §5.2, §6.1 |
| `test_chacha20`          | `crypto/chacha20.c` (incl. aligned/unaligned XOR paths) | RFC 8439 §2.4.2 |
| `test_poly1305`          | `crypto/poly1305_donna.c`                             | RFC 8439 §2.5.2 |
| `test_chacha20poly1305`  | AEAD glue (`chacha20poly1305.c`)                      | RFC 8439 §2.8.2 (114 B: exercises the tail path) |
| `test_hkdf_noise`        | `crypto/hkdf_blake2s.c` (HKDF, Noise §4.3 KDFs)       | cross-consistency |
| `test_wg_handshake`      | `wg_proto.c`, `wg_handshake.c` (Noise IKpsk2 initiator) | upstream-derived transcript |
| `test_wg_transport`      | `wg_transport.c` (RFC 6479 replay window, AEAD framing) | synthetic |
| `test_wg_demux`          | `wg_demux.c` first-byte classification                | synthetic |
| `test_disco`             | `disco.c` codec + NaCl box (`salsa20.c`, `nacl_box.c`) | upstream `disco_test.go` + round-trip |
| `test_disco_handler`     | `disco_handler.c` ping → sealed pong                  | synthetic |
| `test_disco_prober`      | `disco_prober.c` tx-id table (ROAM-3)                 | synthetic |
| `test_stun`              | `stun.c` RFC 5389 binding codec                       | upstream `stun_test.go` |
| `test_derp`              | `derp.c` frame codec, ServerInfo/ClientInfo           | upstream `derp_test.go` |
| `test_tls_io`            | `tls_io.c` WANT_READ retry + idle budget (M13)        | fake reader |
| `test_retry_after`       | `h2_retry_after.h` 429/503 parsing                    | synthetic |
| `test_mapresp`           | `mapreq.c::mapresp_parse` (netmap, DERPMap, patches, Peers vs PeersChanged vs PeersRemoved, oversized element) | real one-peer MapResponse stub + synthetic |
| `test_skip_value`        | `jsmn_skip.h` depth bound                             | synthetic |
| `test_backoff`           | `backoff.h` ladder + jitter                           | synthetic |
| `test_keys_regen`        | `keys_regen.h` identity regeneration policy           | 8 combinations |
| `test_jsmn_split`        | `jsmn_split.h` shallow object/array splitter (MapResponse) | synthetic incl. depth bound |
| `test_tai64n`            | `wg_proto.c` TAI64N floor / reservation / persist     | synthetic |
| `test_nacl_box`          | `nacl_box.c` seal/open/precomputed-shared/tamper      | **libsodium** vectors (PyNaCl, `gen_nacl_vectors.py`) |

## Not covered on the host (needs a seam or a fixture)

- `noise_ik.c` — the ts2021 Noise IK transcript (needs an mbedtls
  chachapoly shim over `chacha20poly1305.c`; `host_mbedtls_shim.c` shows
  the pattern).
- `register.c` RegisterResponse parsing (cJSON-based), `control_key.c`
  `/key` parsing, `stun_probe.c`, `telemetry.c` JSON formatting — all
  platform-bound today.
