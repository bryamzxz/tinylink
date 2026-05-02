# Building

## Prerequisites

- ESP-IDF **v5.5.x** installed (e.g. `~/esp/esp-idf-v5.5.4`).
- A Python virtualenv with the project tooling installed (the helper scripts
  in `tools/` use `pyserial` and the IDF Python deps).
- A Freenove ESP32-WROOM-32E DevKit on `/dev/ttyUSB0` (CH340).

## One-time setup

```bash
# Activate your project Python venv.
source ~/entorno_investigación/bin/activate

# Source ESP-IDF.
. ~/esp/esp-idf-v5.5.4/export.sh

# Set the target. Only required once; rerun if you change targets.
cd ~/dev/tinylink
idf.py set-target esp32
```

## Build / flash / monitor

```bash
idf.py build
idf.py -p /dev/ttyUSB0 flash
idf.py -p /dev/ttyUSB0 monitor   # Ctrl-] to exit
```

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

## Provisioning credentials

Before the firmware can do anything useful you need an `nvs_creds` partition
populated with WiFi + WireGuard data. See [`PROVISIONING.md`](PROVISIONING.md).

## CI

GitHub Actions (`.github/workflows/build.yml`) runs `idf.py build` against
`esp32` with ESP-IDF v5.5 on every push and PR. CI artefacts include the
ELF, BIN, MAP and partition table — useful for diffing flash size between
PRs.
