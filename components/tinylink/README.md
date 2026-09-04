# tinylink component

The protocol implementation: control plane (ts2021 Noise IK over TLS,
HTTP/2 via nghttp2, register + MapRequest long-poll), data plane
(WireGuard on a single UDP socket, DISCO, STUN, DERP), the vendored
constant-time crypto (`src/crypto/`), the lwIP raw-IP netif carrier and
the TMP117 telemetry app.

| Area                          | Files                                              | Status |
|-------------------------------|----------------------------------------------------|--------|
| ts2021 Noise IK + HTTP/2      | `ts2021_client.c`, `noise_ik.c`, `h2_client.c`, `tls_io.c` | done (M1, hardened M12–M13) |
| register / MapRequest / netmap| `register.c`, `mapreq.c`, `netmap.h`, `jsmn*.h`    | done (M1–M2, patch-refetch M13) |
| WireGuard                     | `wg_proto.c`, `wg_handshake.c`, `wg_transport.c`, `wg_netif.c`, `wg_demux.c`, `wg_lwip.c` | done (M2, M6) |
| DISCO / STUN / DERP           | `disco*.c`, `stun*.c`, `derp*.c`                   | done (M3–M5) |
| crypto (BLAKE2s, ChaCha20-Poly1305, X25519-donna, Salsa20/NaCl box, HKDF) | `src/crypto/` | done, host-KAT'd |
| telemetry (TMP117 → JSON/UDP) | `tmp117.c`, `telemetry.c`                          | done (M3) |

The public header is [`include/tinylink.h`](include/tinylink.h); the
protocol map with upstream citations is in
[`docs/PROTOCOL.md`](../../docs/PROTOCOL.md), the task/threading model in
[`docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md). Host tests for the
codecs, crypto and state machines live in
[`tools/test/`](../../tools/test/) (`make test`).
