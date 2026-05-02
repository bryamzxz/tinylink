# Contributing to tinylink

Thanks for your interest. tinylink is a small, focused project — keeping it
small **is** the project. Please read this document before opening a PR.

## Ground rules

1. **Stay in scope.** The README's *non-goals* list is binding. Pull requests
   that add MagicDNS, exit-node routing, multi-peer mesh, etc. will be closed.
   If you need those, use `tailscaled` or MicroLink — both already exist.
2. **Pure C, ESP-IDF native.** No Arduino, no ESPHome, no C++.
3. **No new heap allocations on the hot path.** WireGuard packet handling and
   DISCO/STUN parsing must be allocation-free per packet.
4. **Constant-time crypto for long-term keys.** See `docs/SECURITY-MODEL.md`.
5. **No silent fallbacks.** Failures must surface in `esp_log` at WARN/ERROR.

## Workflow

1. Open an issue first for anything bigger than a typo or a one-line bug fix.
   Describe the milestone you are targeting (1–6, see `docs/ROADMAP.md`).
2. Branch from `main`. Branch names: `m1/wifi-init`, `m2/ts2021-handshake`,
   `fix/short-description`.
3. Run `idf.py build` for `esp32` before pushing. CI will reject builds that
   warn (we treat warnings as errors).
4. Commit messages: subject ≤ 72 chars, imperative mood. Body explains *why*,
   not *what*.
5. PR description must reference the milestone and link the issue.

## Code style

- 4-space indentation, no tabs.
- `snake_case` for functions and variables. `UPPER_SNAKE_CASE` for macros.
- Public symbols prefixed `tinylink_` (component) or `app_` (main).
- Every `.c`/`.h` file starts with `// SPDX-License-Identifier: MIT` and the
  copyright line.
- Headers use `#pragma once`.
- Comments and log messages in English.

## Testing

Milestone 1 has no automated tests yet (we test on real hardware against a
known-good WireGuard peer). From Milestone 3 onward we will add Unity tests
for protocol parsers (decoupled from any radio).

## Code of conduct

This project adopts the [Contributor Covenant 2.1](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions will be licensed under MIT,
matching the repository.
