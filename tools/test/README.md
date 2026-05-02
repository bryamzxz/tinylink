# Host-side known-answer tests

Smoke tests for the vendored crypto primitives. They compile with stock
gcc — no ESP-IDF needed — and run on whatever host you build on. The
on-target build still has to be verified independently because compilers
and architectures can introduce subtle differences in 64-bit math.

## Run

```bash
cd tools/test
make test
```

Expected output ends in `ALL OK` for both binaries:

```
[rfc7693-abc] OK
[kat-empty-nokey] OK
[kat-empty-key32] OK
[kat-1byte-nokey] OK

ALL OK

[rfc7748-5.2-a] OK
[rfc7748-5.2-b] OK
[rfc7748-6.1-alice-to-bob] OK
[rfc7748-6.1-bob-to-alice] OK

ALL OK
```

## Coverage

| Test                  | Algorithm     | Vectors                                |
|-----------------------|---------------|----------------------------------------|
| `test_blake2s.c`      | BLAKE2s-256   | RFC 7693 §A "abc"; 3 KAT vectors       |
| `test_curve25519.c`   | X25519        | RFC 7748 §5.2 (×2); §6.1 DH round-trip |

## Not yet covered

- HMAC-BLAKE2s (RFC 4231 doesn't cover BLAKE2s; need a reference impl
  to derive vectors).
- Noise §4.3 HKDF (`noise_hkdf2`, `noise_hkdf3`) — derive from a known
  Noise implementation.
- Salsa20 / HSalsa20 / XSalsa20 — DJB's original test suite vectors.
- NaCl-box — RFC-style vectors don't exist; use libsodium's KAT.
- The Noise IK handshake as a whole — best validated against a known-
  good responder (e.g. a local `noise-c` test program acting as the
  control plane).
