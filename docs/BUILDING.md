# Building

## Prerequisites

- ESP-IDF **v5.5.4** installed (the project is frozen on this exact
  release — see "CI" below). `$IDF_PATH` below is its checkout.
- A Python virtualenv with the project tooling installed (the helper scripts
  in `tools/` use `pyserial` and the IDF Python deps).
- A Freenove ESP32-WROOM-32E DevKit on `/dev/ttyUSB0` (CH340).

## One-time setup

```bash
# Activate the Python venv ESP-IDF's install.sh populated.
source "$VENV/bin/activate"

# Source ESP-IDF (export.sh sets IDF_PATH and the toolchain PATH).
. "$IDF_PATH/export.sh"

# Set the target. Only required once; rerun if you change targets.
cd /path/to/tinylink
idf.py set-target esp32
```

### REQUIRED: apply IDF patches

The firmware uses `ESP_NETIF_FLAG_AUTOUP` + a custom netstack on the WG
netif (no `IS_PPP` workaround). That triggers an IDF v5.5 panic in
`esp_netif_internal_dhcpc_cb` → `dhcp_ip_addr_store(NULL)` at WG
bring-up unless the two patches in `idf-patches/` are applied to
ESP-IDF. **Without these patches the firmware compiles cleanly but
panics with `LoadProhibited` at `dhcp_state.c:52` from the lwIP task
the first time `wg_lwip_attach()` calls `netif_set_addr()`.**

```bash
cd "$IDF_PATH"
git apply --check /path/to/tinylink/idf-patches/0001-*.patch /path/to/tinylink/idf-patches/0002-*.patch
git am          /path/to/tinylink/idf-patches/0001-*.patch /path/to/tinylink/idf-patches/0002-*.patch
```

(CI runs the same `git apply --check` against the pinned release on
every push, so a patch that stops applying is caught early.)

If `git am` fails on whitespace, fall back to:

```bash
cd "$IDF_PATH"
git apply /path/to/tinylink/idf-patches/0001-*.patch /path/to/tinylink/idf-patches/0002-*.patch
git add -A && git commit -m "tinylink: apply DHCP_CLIENT whitelist patches"
```

To revert (e.g. to test against stock IDF — expect the panic):

```bash
cd "$IDF_PATH"
git reset --hard v5.5.4
```

See [`idf-patches/README.md`](../idf-patches/README.md) for the full
diagnostic history (esp-protocols#800, commit `c8c10214f8`, and the
2018→2022 regression that introduced the bug).

## Build / flash / monitor

```bash
idf.py build
idf.py -p /dev/ttyUSB0 flash
idf.py -p /dev/ttyUSB0 monitor   # Ctrl-] to exit
```

## Benchmarking AEAD

The ChaCha20-Poly1305 hot path has an opt-in micro-benchmark that runs
once on boot, prints µs/call + ns/B + MB/s for 64 B and 1500 B payloads
(encrypt and decrypt), and verifies a round-trip before reporting any
numbers.

Enable, build, flash, capture:

```bash
idf.py menuconfig             # tinylink core → Run ChaCha20-Poly1305 AEAD
                              # micro-benchmark on boot → y
idf.py build
idf.py -p /dev/ttyUSB0 flash
python tools/serial_capture.py --port /dev/ttyUSB0 --duration 30 \
    --out /tmp/bench.log
grep "bench-aead" /tmp/bench.log
```

The bench fires after `tinylink_init()` returns and before
`tinylink_register()`, so the heap is still pristine and the timer
numbers aren't confounded by background TLS/long-poll work. Run-to-run
variance is roughly 1-2 % on the 1500 B path — treat smaller deltas as
noise. Disable the flag for production builds (`# CONFIG_TINYLINK_BENCH_AEAD
is not set`); the bench code drops out of the binary entirely.

## Size budget snapshot

Reference `idf.py size` numbers for the ESP32-WROOM-32E (no PSRAM)
target on ESP-IDF v5.5.4:

| Region        | Post-η baseline (`4bd5b0f`) | M13 (`c383e49`)     | M14 (`8f353c5`)       | M15 (`8a18425`)       | **M16**                       |
|---------------|----------------------------:|--------------------:|----------------------:|----------------------:|------------------------------:|
| Flash app     | 1 173 717 B (74.6 %)        | 948 624 B (60.2 %)  | 946 293 B (60.1 %)    | 938 421 B (59.6 %)    | **946 209 B (60.1 %)**        |
| DRAM static   | 151 412 B (83.78 %)         | 149 312 B (82.6 %)  | 136 656 B (75.6 %)    | 106 880 B (59.1 %)    | **107 696 B (59.6 %)**        |
| IRAM          | 104 383 B (79.64 %)         | 75 079 B (57.28 %)  | 75 079 B (57.28 %)    | 75 079 B (57.28 %)    | **76 787 B (58.6 %)**         |
| Bootloader    | 27 808 B                    | 18 176 B            | 18 176 B              | 18 176 B              | 18 176 B                      |
| RTC SLOW      | 56 B                        | 56 B                | 56 B                  | 56 B                  | 56 B                          |

M14's DRAM drop is the removal of the endpoint-push task's 12 KiB static
stack; M15's is the MapResponse token table (40 → 10 KiB); M16 adds SNTP
+ the `/stats` responder (+7.8 KiB flash, +0.8 KiB BSS) and moves the
AEAD hot path into IRAM (+1.7 KiB, measured −17 % cold per MTU packet).
Largest contiguous heap block 60 s after boot: 9–11 KiB before M14,
21 504 B after M14, 49–51 KiB after M15/M16 — see `CHANGELOG.md`.

Headline of the cumulative work from baseline to post-DERP-round:
**flash −154.6 KiB, DRAM −2.9 KiB, IRAM −29.3 KiB (80 % → 57 %),
bootloader −9.4 KiB**. The IRAM relief is what enables the DERP
outbound work to land without crowding the 128 KiB IRAM budget.

The DERP-round adds only +0.39 KiB flash + 32 B DRAM on top of
post-perf-trim, but unlocks an entirely new transport path
(WG-over-DERP relay) plus inbound CMM ingestion that was wired in
source but dormant before PR-D0 made the supervisor actually
spawn.

## Compiler optimization scope

The firmware **does not** flip the global
`CONFIG_COMPILER_OPTIMIZATION_PERF` Kconfig. The global stays at
`CONFIG_COMPILER_OPTIMIZATION_DEBUG=y` (`-Og`), and per-component
`-O2` is opted-in via `target_compile_options(${COMPONENT_LIB}
PRIVATE -O2)` after `idf_component_register(...)` in:

- `components/tinylink/CMakeLists.txt` (the entire tinylink component)
- `main/CMakeLists.txt` (app_main + app_wifi + app_nvs)
- `CMakeLists.txt` at the project root, for the IDF `mbedcrypto`
  library target only — `mbedtls` + `mbedx509` are left at the
  default

This scopes the documented toolchain hangs around certain lwIP files
at -O2 out of the build. If you add a new component to the perf-
critical set, follow the same pattern (do not flip the global). If a
toolchain upgrade ever resolves the lwIP hangs we can revisit and
collapse to the global flip.

-O2 also enables `-Wstringop-truncation` and a few related warnings
that `-Og` doesn't trigger. `idf.py build` is configured with
`-Werror` for the project, so an inadvertent `strncpy(dst, src,
sizeof(dst))` will break the build. Use `memcpy + strnlen` (see
`main/app_wifi.c` for the pattern).

## Common gotchas

- **`CONFIG_LWIP_TCPIP_CORE_LOCKING` must stay `y`.** It is the IDF default
  on v5.3+ and `droscy/esp_wireguard` requires it. The original
  `trombik/esp_wireguard` is incompatible with this and is **not** what we
  pin.
- **NVS encryption.** A virgin board must be flashed with `idf.py
  encrypted-flash` and the resulting eFuse key burned the **first time**
  only. After that, regular `flash` works because flash encryption is a
  one-way switch.
- **No PSRAM.** `sdkconfig.defaults.esp32` does not enable PSRAM; do not
  enable it through `menuconfig` — we keep the budget at zero PSRAM.
- **IPv4-only build.** `CONFIG_LWIP_IPV6=n` and `CONFIG_LWIP_IP4_FRAG=n`
  /`IP4_REASSEMBLY=n` are pinned in `sdkconfig.defaults`. Every socket
  in the firmware (WG UDP, esp_tls to controlplane.tailscale.com, DERP,
  STUN, telemetry) opens `AF_INET`. Flipping `LWIP_IPV6=y` back on
  silently widens the surface and costs ~7 KiB RAM + ~36 KiB flash for
  nothing — leave it off until a real IPv6 path lands. The IP-frag
  flags stay off because WG sets its tunnel MTU to fit inside the
  outer link without fragmenting, and inbound IP reassembly is a
  classic teardrop / overlap DoS surface that nothing benign needs.

## Provisioning credentials

Before the firmware can do anything useful you need the WiFi credentials
and a Tailscale auth key in NVS (namespace `tl_creds`, either in the
dedicated `nvs_creds` partition or the default `nvs` one). See
[`PROVISIONING.md`](PROVISIONING.md).

## CI

GitHub Actions (`.github/workflows/build.yml`) runs, on every push and PR:

1. the host KAT suite (`make -C tools/test test`, with a floor on the
   number of `OK` cases) and the same suite under ASan + UBSan;
2. a dry-run of the two `idf-patches/` against the pinned ESP-IDF, so a
   patch that stops applying is caught before a device panics;
3. `idf.py build` for `esp32` against the pinned ESP-IDF **v5.5.4**, plus
   `idf.py size` / `size-components` (posted to the run summary) and a
   check that `dependencies.lock` was not rewritten.

Artefacts include the ELF, BIN, MAP, size reports and partition table —
useful for diffing flash/DRAM between PRs.
