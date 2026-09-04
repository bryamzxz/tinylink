# Security Policy

## Supported versions

tinylink versions as `1.1.x` (`TINYLINK_IPN_VERSION` in
`components/tinylink/include/tinylink.h`), but there are no release tags or
branches yet: development happens on `main` and only `main` receives fixes.

| Version       | Supported |
|---------------|-----------|
| `main`        | yes       |
| anything else | no        |

## Reporting a vulnerability

**Please do not file public GitHub issues for security bugs.**

Email: `security@bryamzxz.dev` (or open a [GitHub private vulnerability report](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository).

Please include:

1. A description of the issue and the affected component.
2. Reproduction steps, including IDF version and target.
3. Impact assessment (what an attacker can do with this).
4. Suggested mitigation, if any.

I will acknowledge receipt within **72 hours** and aim to ship a fix or a
public advisory within **90 days** of the report. If you need a faster
disclosure timeline (e.g. active exploitation), say so in the report.

## Scope

In scope:

- Memory-safety bugs in tinylink C code (this repository).
- Cryptographic protocol mistakes (Noise IK transcript, DISCO box, WireGuard
  message handling, KDF chain).
- Provisioning / NVS handling that leaks long-term keys.
- Defaults that downgrade security (e.g. accepting unauthenticated peers).

Out of scope:

- Bugs in upstream dependencies (`espressif/nghttp` (nghttp2), `mbedtls`,
  ESP-IDF). Please report those upstream; we will track and pull in fixes.
- Side-channel attacks requiring physical access beyond what the threat model
  in [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) covers.
- Recovery of key material by reading the flash: NVS is stored in
  **plaintext by decision** (no flash/NVS encryption — eFuse burns are
  irreversible and were declined, see `docs/ROADMAP.md` § Execution queue);
  physical-access attackers are outside the threat model in
  [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md).

## Cryptographic primitives

See [`docs/SECURITY-MODEL.md`](docs/SECURITY-MODEL.md) for the rationale behind
the primitive choices, including why Curve25519 is vendored from constant-time
"donna" rather than taken from mbedTLS.
