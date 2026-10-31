# ESP32 hardware reference — the exact part tinylink runs on

Vendor documentation for the silicon the deployed sensor actually uses,
so every optimization in this repo can cite a datasheet page instead of
folklore. The PDFs themselves are **not committed** (Espressif and
Cadence copyright); `fetch-docs.sh` downloads them into `pdf/` (git-ignored)
and checks them against the hashes below. The digest that the
optimization work cites — memory map, cache, accelerators, pipeline,
errata, power — is [`REFERENCE.md`](REFERENCE.md).

## Identity of the deployed unit (`sensor-cali`)

Read from the device with `esptool.py chip_id` / `flash_id` and
`espefuse.py summary` (read-only) on 2026-10-28.

| Field | Value |
|---|---|
| Module | **ESP32-WROOM-32E-N4** — 4 MB flash, no PSRAM, PCB antenna (ordering code inferred from flash size + no PSRAM; the 105 °C `-H4` variant is indistinguishable from software) |
| SoC | **ESP32-D0WD-V3**, chip revision **v3.1** (`WAFER_VERSION_MAJOR=3`, `WAFER_VERSION_MINOR=1`, `PKG_VERSION=1`) |
| CPU | Dual-core Xtensa® 32-bit **LX6**, rated 240 MHz (`CHIP_CPU_FREQ_RATED=1`, `CHIP_CPU_FREQ_LOW=0`) |
| Features (eFuse) | Wi-Fi, BT (not disabled in eFuse; unused by firmware), dual core, ADC Vref calibration (1121 mV) |
| Crystal | 40 MHz |
| Flash | JEDEC manufacturer `0x46` = **XMC** (D series — IDF `spi_flash_chip_generic.c` gives it suspend + 32-bit addressing caps), device `0x4016` = 32 Mbit / **4 MB** |
| Flash voltage | VDD_SDIO 3.3 V, set by strapping (GPIO12 low; `XPD_SDIO_FORCE=0`) |
| PSRAM | none |
| USB-UART | CH340 (`1a86:7523`) — loses bytes at 921 600 baud, use 460 800 |
| eFuse coding scheme | None (BLK1–3 = 256 bit) |
| Security eFuses | flash encryption off (`FLASH_CRYPT_CNT=0`), secure boot v1/v2 off, JTAG enabled, UART download enabled, `WR_DIS=0` — nothing burned |
| Firmware build target | `CONFIG_ESP32_REV_MIN_3=y` (min rev v3.0), QIO @ 80 MHz, CPU 240 MHz |

The MAC address and the key blocks are deliberately not recorded here.

## Documents

| File (in `pdf/`) | Document | Version | sha256 |
|---|---|---|---|
| `esp32_technical_reference_manual_en.pdf` | ESP32 Technical Reference Manual (791 pp) | v5.9 | `1007b90e6fafc16541d693d7444b63e1c5b01e46e60cce9b6810e02340a64b82` |
| `esp32_datasheet_en.pdf` | ESP32 Series Datasheet (78 pp) | v5.3 | `a7917e6b47528c9dcab06837a49d452e582751335797db879f1cf2d17cd29adf` |
| `esp32-wroom-32e_esp32-wroom-32ue_datasheet_en.pdf` | ESP32-WROOM-32E / -32UE module datasheet (52 pp) | v2.1 | `4c7a345d1c1bfec34c38665639e39a7f43b79a35a12f6adcc2c7c0f83850f8b8` |
| `esp32_errata_en.pdf` | ESP32 Series SoC Errata (36 pp) | v3.1 | `a31e6a35d6ebccd54d49493cf8fe4befe754eeea0dc744c3db06cd62b587fd44` |
| `esp32_chip_revision_v3_0_user_guide_en.pdf` | ESP32 Chip Revision v3.0 User Guide (8 pp) | — | `7fa403d962987837c516a3b7c2769c06ca33a2b74db76d4e8eedbae28745a9d1` |
| `xtensa_isa_reference_manual_RB-2010.1.pdf` | Xtensa Instruction Set Architecture (ISA) Reference Manual, Tensilica | RB-2010.1 | `52c28fa26c5287825953c12bb69e4cd7683f46f2f0efa0994d1a78e6318dbd46` |

The Espressif URLs are stable but the files are revised in place, so a
hash mismatch after a re-fetch usually means a newer revision — re-check
the pages `REFERENCE.md` cites when that happens. The Xtensa ISA manual
is not on a stable public URL; `fetch-docs.sh` takes a local copy via
`XTENSA_ISA_PDF=/path/to/xtensa.pdf`.

```bash
docs/esp32/fetch-docs.sh                    # Espressif PDFs
XTENSA_ISA_PDF=~/Descargas/xtensa.pdf docs/esp32/fetch-docs.sh
pdftotext -f 30 -l 34 docs/esp32/pdf/esp32_technical_reference_manual_en.pdf -
```
