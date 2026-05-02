# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Project scaffolding (top-level CMake, partition table, sdkconfig defaults).
- Skeleton for Milestone 1 application: WiFi STA, WireGuard via
  `droscy/esp_wireguard`, TMP117 driver, UDP telemetry task.
- `tinylink` core component with version API and milestone stubs.
- Documentation set: `ARCHITECTURE`, `ROADMAP`, `PROTOCOL`, `SECURITY-MODEL`,
  `BUILDING`, `PROVISIONING`.
- `tools/nvs_provision.py` for generating an encrypted NVS partition with
  WiFi + WireGuard credentials.
- GitHub Actions CI: matrix build for `esp32` against ESP-IDF v5.5.

[Unreleased]: https://github.com/bryamzxz/tinylink/commits/main
