# ESP32 vendor-documentation digest for tinylink

Scope: a dense, citation-backed extract of the Espressif and Cadence/Tensilica
documents listed in [`README.md`](README.md), restricted to what matters when
optimizing tinylink (pure-C single-peer Tailscale/WireGuard node: ChaCha20-Poly1305,
Curve25519, BLAKE2s, XSalsa20, mbedTLS TLS 1.3/1.2, lwIP, Wi-Fi STA always on,
FreeRTOS dual core, no PSRAM) on the deployed part: ESP32-WROOM-32E-N4,
ESP32-D0WD-V3 rev v3.1, 40 MHz crystal, XMC (JEDEC 0x46) 4 MB flash QIO @ 80 MHz,
CPU 240 MHz, ESP-IDF v5.5.4 with `CONFIG_ESP32_REV_MIN_3=y`. Every row carries a
citation. **Page numbers are PDF page indices** (1-based, what `pdftotext -f N`
takes). They equal the printed footer for TRM, DS and MOD; for ERR the printed
number is PDF−3, for ISA printed = PDF−24, REV3 prints "n/5". "**Derived**" marks a
value computed from cited facts, not stated in a document. "**Not in docs**" marks
a gap: measure it, don't assume it.

## Sources

| Prefix | File (`docs/esp32/pdf/`) | Document / version |
|---|---|---|
| `TRM` | `esp32_technical_reference_manual_en.pdf` | ESP32 Technical Reference Manual v5.9 (791 pp) |
| `DS` | `esp32_datasheet_en.pdf` | ESP32 Series Datasheet v5.3 (78 pp) |
| `MOD` | `esp32-wroom-32e_esp32-wroom-32ue_datasheet_en.pdf` | ESP32-WROOM-32E/32UE Datasheet v2.1 (52 pp) |
| `ERR` | `esp32_errata_en.pdf` | ESP32 Series SoC Errata v3.1 (36 pp) |
| `REV3` | `esp32_chip_revision_v3_0_user_guide_en.pdf` | ESP32 Chip Revision v3.0 User Guide v1.3 (8 pp) |
| `ISA` | `xtensa_isa_reference_manual_RB-2010.1.pdf` | Xtensa ISA Reference Manual RB-2010.1 (662 pp) |
| `IDF` | `/home/bryam/ESP32/esp-idf-v5.5.4/` | ESP-IDF v5.5.4 source, cited `file:line` (aliases below) |
| `TL` | `/home/bryam/dev/tinylink/sdkconfig` | tinylink's checked-in sdkconfig |

IDF file aliases (paths relative to the IDF root):

| Alias | Path |
|---|---|
| `core-isa.h` / `tie.h` | `components/xtensa/esp32/include/xtensa/config/{core-isa.h,tie.h}` |
| `soc.h` / `soc_caps.h` | `components/soc/esp32/include/soc/{soc.h,soc_caps.h}` |
| `soc/dport_access.h` | `components/soc/esp32/include/soc/dport_access.h` |
| `hw/dport_access.h` | `components/esp_hw_support/include/dport_access.h` |
| `Kconfig.hw_support`, `Kconfig.rtc` | `components/esp_hw_support/port/esp32/` |
| `Kconfig.system`, `Kconfig.memory` | `components/esp_system/port/soc/esp32/` |
| `Kconfig.power` | `components/esp_hw_support/power_supply/port/esp32/Kconfig.power` |
| `Kconfig.spiram` | `components/esp_psram/esp32/Kconfig.spiram` |
| `bl/Kconfig.projbuild` | `components/bootloader/Kconfig.projbuild` |
| `spi_flash/Kconfig`, `cache_utils.c`, `esp_flash_api.c`, `spi_flash_chip_generic.c`, `flash_brownout_hook.c` | `components/spi_flash/` |
| `bootloader_flash.c`, `bootloader_flash_config_esp32.c` | `components/bootloader_support/bootloader_flash/src/` |
| `bootloader_clock_init.c`, `bootloader_common_loader.c` | `components/bootloader_support/src/` |
| `bootloader_random.h` | `components/bootloader_support/include/bootloader_random.h` |
| `rom/spi_flash.h` | `components/esp_rom/esp32/include/esp32/rom/spi_flash.h` |
| `esp_rom/CMakeLists.txt`, `rom.libc-funcs.ld`, `rom.eco3.ld` | `components/esp_rom/` (`esp32/ld/esp32.rom.*.ld`) |
| `memory.ld.in` | `components/esp_system/ld/esp32/memory.ld.in` |
| `memory_layout.c` | `components/heap/port/esp32/memory_layout.c` |
| `esp_bt.h` / `bt/Kconfig.in` | `components/bt/include/esp32/include/esp_bt.h` / `components/bt/controller/esp32/Kconfig.in` |
| `mpi_ll.h`, `uart_ll.h` | `components/hal/esp32/include/hal/` |
| `esp_sha256.c` | `components/mbedtls/port/sha/parallel_engine/esp_sha256.c` |
| `hw_random.c`, `sleep_modes.c` | `components/esp_hw_support/` |
| `chip_info.c`, `rtc_clk.c` | `components/esp_hw_support/port/esp32/` |
| `int_wdt.c` | `components/esp_system/int_wdt.c` |
| `xtensa_vectors.S` | `components/xtensa/xtensa_vectors.S` |
| `wifi_types.h` | `components/esp_wifi/include/esp_wifi_types_generic.h` |

---

## 1. Memory map & sizes

### 1.1 Embedded memories

| Region | Size | Data-bus alias | Instruction-bus alias | Notes | Cite |
|---|---|---|---|---|---|
| Internal ROM 0 | 384 KiB | — | `0x4000_0000–0x4005_FFFF` | first 32 KiB can be remapped (per CPU) to SRAM1 `0x400B_0000–0x400B_7FFF` | [TRM §3.3.2.1 p.68] |
| Internal ROM 1 | 64 KiB | `0x3FF9_0000–0x3FF9_FFFF` | — | read-only data | [TRM §3.3.2.2 p.68] |
| Internal SRAM 0 | 192 KiB | — | `0x4007_0000–0x4009_FFFF` | first 64 KiB usable as flash/PSRAM cache; when used as cache it is not available to the I-bus | [TRM §3.3.2.3 p.68–69], [TRM §3.3.4 p.71–72] |
| Internal SRAM 1 | 128 KiB | `0x3FFE_0000–0x3FFF_FFFF` | `0x400A_0000–0x400B_FFFF` | I-bus alias is **word-reversed** (`0x3FFE_0000` ≡ `0x400B_FFFC`), bytes within a word not reversed | [TRM §3.3.2.4 p.69] |
| Internal SRAM 2 | 200 KiB | `0x3FFA_E000–0x3FFD_FFFF` | — | data only | [TRM §3.3.2.5 p.69] |
| RTC FAST | 8 KiB | `0x3FF8_0000–0x3FF8_1FFF` | `0x400C_0000–0x400C_1FFF` | **PRO_CPU only**; APP_CPU sees nothing at these addresses; both aliases same word order | [TRM §3.3.2.7 p.70] |
| RTC SLOW | 8 KiB | `0x5000_0000–0x5000_1FFF` | same range (shared D/I) | both CPUs; ULP-accessible in deep sleep | [TRM §3.3.2.8 p.70], [DS §4.1.2 p.26] |
| Totals | 448 KiB ROM, 520 KiB SRAM, 8+8 KiB RTC | | | 1296 KiB embedded address space, 328 KiB DMA address space | [TRM §3.2 p.63] |

### 1.2 Bus and access rules

| Rule | Cite |
|---|---|
| `< 0x4000_0000` = data bus; `0x4000_0000–0x4FFF_FFFF` = instruction bus; `≥ 0x5000_0000` shared. Both buses little-endian. | [TRM §3.3.1 p.66] |
| D-bus: aligned or non-aligned byte/half-word/word reads and writes. | [TRM §3.3.1 p.66] |
| I-bus data access (IRAM, IROM, SRAM1 I-alias): **word-aligned only**, otherwise CPU exception. | [TRM §3.3.1 p.66] |
| ISA view: InstRAM is data-accessible only via `L32I`/`L32I.N`/`L32R`/`S32I`/`S32I.N`; other loads/stores undefined; L32R/L32I from InstRAM/ROM have "reduced performance on some Xtensa implementations". | [ISA §4.5.8 p.147–148] |
| Core has hardware unaligned load/store (no alignment exception). | [IDF core-isa.h:171–174] |
| Hardware Alignment Option still raises `LoadStoreAlignment` for unaligned `L32AI`/`S32RI`/`S32C1I` and for unaligned access to XLMI, IRAM or IROM; unaligned is slower than aligned. | [ISA §4.5.14 p.152] |
| IDF can emulate 8-bit IRAM access via `LoadStoreError`/`LoadStoreAlignmentError` handlers (`ESP32_IRAM_AS_8BIT_ACCESSIBLE_MEMORY`), **single-core only**, ≤ 167 CPU cycles per access. | [IDF Kconfig.memory:34–42] |
| IDF byte-accessible range `0x3FF9_0000–0x4000_0000`; internal range `0x3FF9_0000–0x400C_2000`. | [IDF soc.h:208–214] |
| ROM and SRAM run on CPU_CLK, **single-cycle**; RTC FAST runs on APB_CLK, RTC SLOW on FAST_CLOCK ("may be slower"); DMA accesses memory on APB_CLK. | [TRM §3.3.5.3 p.74] |
| SRAM is banked in 32 KiB; each CPU and each DMA channel run at full speed simultaneously if they hit different banks. | [TRM §3.3.5.3 p.74] |
| Peripherals `0x3FF4_0000–0x3FF7_FFFF` (DPORT alias) are also at `0x6000_0000–0x6003_FFFF` (AHB alias). DPORT is faster but reads are **speculative** and may reorder r/w; AHB must not be used for FIFO reads. | [TRM §3.3.5 p.73] |
| Root cause of the speculation: `0x3FF0_0000`+512 KiB is the core's XLMI port; XLMI loads may be speculative, stores never. | [IDF core-isa.h:329–331], [ISA §4.5.13 p.151] |

### 1.3 How IDF v5.5.4 lays it out (this build: dual core, no BT, no PSRAM)

| Address range | Physical | IDF use | Cite |
|---|---|---|---|
| `0x4007_0000–0x4007_7FFF` | SRAM0 pool 0 | PRO_CPU cache | [IDF soc.h:178–179], [TRM Table 3.3-5 p.71] |
| `0x4007_8000–0x4007_FFFF` | SRAM0 pool 1 | APP_CPU cache (usable as RAM if APP cache off) | [IDF soc.h:180–181], [TRM §4.3.2.2 p.86] |
| `0x4008_0000–0x4009_FFFF` | SRAM0 | `iram0_0_seg` (128 KiB): vectors, `IRAM_ATTR` code; unused tail becomes IRAM-only heap | [IDF memory.ld.in:55], [IDF memory_layout.c:100–115,178–179] |
| `0x400A_0000–0x400A_9FFF` | SRAM1 (I-alias) | +40 KiB IRAM only with `ESP_SYSTEM_ESP32_SRAM1_REGION_AS_IRAM` | [IDF memory.ld.in:40–43,55], [IDF Kconfig.memory:46] |
| `0x3FFA_E000–0x3FFA_E6DF` | SRAM2 | reserved: ROM data | [IDF memory_layout.c:154] |
| `0x3FFB_0000–0x3FFD_C1FF` | SRAM2 | `dram0_0_seg` .data/.bss, max `0x2C200` (176.5 KiB) static because ROM uses static RAM at the 176 KiB mark; rest is heap | [IDF memory.ld.in:38,72–82] |
| `0x3FFE_0000–0x3FFF_FFFF` | SRAM1 (D-alias, "DIRAM") | heap; ROM PRO data `0x3FFE_0000–0x3FFE_0440` and ROM APP data `0x3FFE_3F20–0x3FFE_4350` reserved; top 16/32 KiB only if TRAX trace memory enabled | [IDF memory_layout.c:92–97,149–160] |
| `0x3FF8_0000` / `0x400C_0000` | RTC FAST | `rtc_data_seg` / `rtc_iram_seg` (deep-sleep stub, `RTC_FAST_ATTR`) | [IDF memory.ld.in:92–95] |
| `0x5000_0000` | RTC SLOW | `rtc_slow_seg` (`RTC_DATA_ATTR`; ULP reserve first) | [IDF memory.ld.in:110–113] |
| `0x400D_0020–0x403F_FFFF` | flash via I-cache | `.text` (`iram0_2_seg`) | [IDF soc.h:174–175], [IDF memory.ld.in:60] |
| `0x3F40_0020–0x3F7F_FFFF` | flash via D-cache | `.rodata` (`drom0_0_seg`) | [IDF soc.h:170–171], [IDF memory.ld.in:86] |
| RTC FAST as data under dual core | — | `ESP32_RTCDATA_IN_FAST_MEM` requires single-core because APP_CPU can't reach RTC FAST | [IDF Kconfig.memory:3–11] |

### 1.4 Bluetooth controller reservation (not active in tinylink)

| Item | Value | Cite |
|---|---|---|
| Static DRAM shift when `CONFIG_BT_ENABLED` | `BTDM_RESERVE_DRAM = 0xDB5C` (56 156 B); `dram0_0_seg` origin moves to `0x3FFB_DB5C`; 0 when BT is off | [IDF bt/Kconfig.in:542–545], [IDF memory.ld.in:81] |
| Controller regions | `.data 0x3FFA_E6E0–0x3FFA_FF10`, EM `0x3FFB_0000–0x3FFB_7CD8`, BSS `0x3FFB_8000–0x3FFB_9A20`, misc `0x3FFB_DB28–0x3FFB_DB5C` | [IDF esp_bt.h:24–46] |
| Heap pools 14/15 (`0x3FFB_0000–0x3FFB_FFFF`, 64 KiB) | annotated "BT HW shared memory / BT ROM data" if BT enabled | [IDF memory_layout.c:74–75] |
| tinylink | `CONFIG_BT_ENABLED` is not set → nothing reserved | [TL sdkconfig] |

### 1.5 DMA-capable memory

| Fact | Cite |
|---|---|
| DMA uses the D-bus addresses of **SRAM1 and SRAM2 only** (`0x3FFA_E000–0x3FFF_FFFF`); SRAM0, RTC, flash are not DMA-reachable. | [TRM §3.3.2.6 p.70], [IDF soc.h:204–205] |
| 13 DMA-capable modules: UART0–2, SPI1–3, I2S0–1, SDIO slave, SDMMC, EMAC, **BT, WIFI**. AES/SHA/RSA are not on the list. | [TRM Table 3.3-3 p.70] |
| DMA engine sits on AHB; descriptors are 3 words (owner, eof, 12-bit length, 12-bit size, buffer ptr, next ptr); buffer address and size must be word-aligned. | [TRM §2.3.1–2.3.2 p.57–58] |

---

## 2. Cache & flash

### 2.1 Cache and MMU

| Parameter | Value | Cite |
|---|---|---|
| Cache per CPU | 32 KiB, **2-way set associative, 32-byte block** | [TRM §3.3.4 p.71], [DS §4.1.5 p.29] |
| I/D | one cache per core serves both instruction and data accesses to external memory | [IDF soc_caps.h:154–155] |
| Backing SRAM | SRAM0 POOL0/POOL1 chosen by `CACHE_MUX_MODE` (mode 0: PRO→POOL0, APP→POOL1) | [TRM Table 3.3-5 p.71] |
| Inside the Xtensa core | **no caches, no prefetch**; the Espressif cache sits behind the core's InstRAM/DataROM/DataRAM local-memory ports | [IDF core-isa.h:215–216,221,290–326] |
| MMU page size | **64 KiB** (flash), 32 KiB (PSRAM); entry bits[7:0] = physical page, bit 8 = invalid → max 256 × 64 KiB = 16 MB | [TRM §4.3.2.2 p.83,85] |
| Virtual windows | VAddr0 `0x3F40_0000` 4 MB (D, read-only); VAddr1–3 `0x4000_0000–0x40BF_FFFF` (I; `0x4000_0000–0x400C_1FFF` is on-chip) | [TRM Table 4.3-9 p.84] |
| Mapping limits | I-space up to 11 MB + 248 KB; **> 3 MB + 248 KB mapped reduces cache performance (CPU speculative reads)**; D-space 4 MB, 8/16/32-bit reads | [DS §4.1.3 p.27] |
| Invalid-entry hazard | with more than one unmasked I-bus, bit 8 of all MMU entries should be 0, otherwise an access hitting an invalid entry stalls the cache | [TRM §4.3.2.1 note p.83] |
| Flush | `x_CACHE_FLUSH_ENA` discards (no write-back) | [TRM §3.3.4 p.72] |
| Image alignment | IDF keeps `paddr % 64 KiB == vaddr % 64 KiB` (0x20 header offset) | [IDF memory.ld.in:60–68] |
| Hit latency, miss stall behaviour | **Not in docs.** The core is in-order with no core-side cache, so a miss stalls the issuing CPU until the line arrives (inference). ERR describes CPUs "stuck in the state of memory access" during cache contention. | [ERR §3.19 p.23] |

### 2.2 Flash access cost at QIO 80 MHz

| Item | Value | Cite |
|---|---|---|
| Controller | SPI0 serves the caches; SPI1 shares the same signal bus through an arbiter | [TRM §20.1 p.354] |
| Wiring | module flash on GPIO6–11, not led out | [MOD p.12] |
| Flash max clock | 80 MHz | [MOD Table 17 p.30] |
| QIO cache-read format | address phase 32 bits (`SPI0_R_QIO_ADDR_BITSLEN = 31`), dummy `SPI0_R_QIO_DUMMY_CYCLELEN (3) + ESP_ROM_SPIFLASH_DUMMY_LEN_PLUS_80M (2)` written to `SPI_USR_DUMMY_CYCLELEN` (= cycles − 1) | [IDF rom/spi_flash.h:68–69,97–98], [IDF bootloader_flash_config_esp32.c:135–169], [TRM §20.8 p.372] |
| **Derived** line-fill time | 8 (cmd, 1 line) + 8 (32 addr/mode bits on 4 lines) + 6 (dummy) + 64 (256 data bits on 4 lines) = **≈ 86 SPI clocks ≈ 1.08 µs ≈ 258 CPU cycles at 240 MHz** per 32-B miss, before arbitration and controller overhead (assumes the command byte is sent on each miss) | derived from the rows above |
| **Derived** peak streaming rate | ≤ 40 MB/s raw (4 bit × 80 MHz); ≈ 30 MB/s for back-to-back line fills | derived |
| Shared path | both CPUs' caches use the single SPI0 → misses from the two cores serialize (inference from the single controller) | [TRM §20.1 p.354] |

### 2.3 What happens during flash program/erase

| Fact | Cite |
|---|---|
| IDF suspends the scheduler, parks the other CPU in an IPC spin loop (`spi_flash_op_block_func`), disables all non-IRAM interrupts and **disables both CPUs' caches** for the operation; only IRAM/DRAM/ROM code and IRAM-safe ISRs run. | [IDF cache_utils.c:100–192] |
| Erase is issued sector-by-sector (or 64 KiB block); caches are disabled for each command and re-enabled between commands; `SPI_FLASH_YIELD_DURING_ERASE` (tinylink: y) yields between them. | [IDF esp_flash_api.c:713–756], [IDF spi_flash/Kconfig:318–326], [TL sdkconfig:1716] |
| Flash timing (module flash): page program 0.8 ms typ / 5 ms max; 4 KB sector erase 70 / 500 ms; 32 KB block 0.2 / 2 s; 64 KB block 0.3 / 3 s; 100 000 P/E cycles; 20 years retention. | [MOD Table 17 p.30] |
| **No flash suspend on ESP32**: `soc_caps.h` has no `SOC_SPI_MEM_SUPPORT_AUTO_SUSPEND`, so `SPI_FLASH_AUTO_SUSPEND` cannot be enabled. The generic chip driver tags vendor 0x46 (XMC-D) with `SUSPEND` and 32-bit-address caps, but the ESP32 host can't use it. | [IDF soc_caps.h:365–366], [IDF spi_flash/Kconfig:85–88], [IDF spi_flash_chip_generic.c:674–678] |

### 2.4 XMC-specific notes (vendor 0x46 on this unit)

| Fact | Cite |
|---|---|
| Bootloader "XM25QHxxC startup flow" (DPD → UDPD → exit → 2 ms → release) runs only for vendor ID **0x20**; a 0x46 part passes the RDID check as "not XMC" and only runs the flow if its SFDP manufacturer byte reads 0x20. `BOOTLOADER_FLASH_XMC_SUPPORT=y` in tinylink. | [IDF bootloader_flash.c:905–980], [IDF bl/Kconfig.projbuild:81–88], [TL sdkconfig:333] |
| Brownout flash reset (`SPI_FLASH_BROWNOUT_RESET_XMC`, y in tinylink) sends a reset only when the vendor ID is **0x20** and an erase is in progress, so it does not trigger for 0x46. It still selects `ESP_BROWNOUT_USE_INTR`. | [IDF flash_brownout_hook.c:19–36], [IDF spi_flash/Kconfig:6–22], [TL sdkconfig:1687–1688] |
| Brownout detector levels: L0 2.43 V … L7 2.80 V (±0.05); tinylink uses **L0**. The TRM's detector is "calibrated around 2.5 V". | [IDF Kconfig.power:25–40], [TL sdkconfig:919], [TRM §9.3.5 p.184] |
| Module flash VCC (3.3 V part) 2.7–3.6 V; VDD_SDIO in 3.3 V mode is VDD3P3_RTC through ≈ 6 Ω. | [MOD Table 17 p.30], [DS §5.2 note 1 p.51] |
| ERR v3.1 has no XMC-specific erratum; the flash start-up-time reset (RES-3.8) is fixed in v3.0. | [ERR §3.15 p.20–21] |

---

## 3. CPU: Xtensa LX6 as configured in ESP32

### 3.1 Configured options (authoritative: `core-isa.h`)

| Option | ESP32 | Cite |
|---|---|---|
| Core | LX6.0.3, config `esp32_v3_49_prod`; 7-stage pipeline (`XCHAL_DATA_PIPE_DELAY 2`), ≤ 240 MHz | [IDF core-isa.h:166,178,189], [DS §4.1.1 p.26] |
| Byte order | little-endian | [IDF core-isa.h:49] |
| Windowed registers | yes; **64 physical AR**, 16 visible | [IDF core-isa.h:50–51] |
| Instruction size | 16/24-bit (density), max 3 bytes; fetch width 4 B | [IDF core-isa.h:53,55,164] |
| Zero-overhead loops | `LOOPS 1`, loop buffer 256 | [IDF core-isa.h:56–57] |
| NSA/NSAU, MIN/MAX/MINU/MAXU, SEXT, CLAMPS | all present | [IDF core-isa.h:58–62] |
| DEPBITS, CONST16, LITBASE (extended L32R) | **absent** | [IDF core-isa.h:61,68–69] |
| MUL16 (`MUL16S/U`) | present | [IDF core-isa.h:63] |
| MUL32 (`MULL`) | present | [IDF core-isa.h:64] |
| MUL32_HIGH (`MULUH/MULSH`) | present | [IDF core-isa.h:65] |
| DIV32 (`QUOS/QUOU/REMS/REMU`) | present; divide by zero → exception cause 6 | [IDF core-isa.h:66], [ISA Table 4-35 p.84] |
| MAC16 | present: 40-bit ACC, 4 × MR, 72 instructions incl. `MULA.DD.*.LDINC/LDDEC` (MAC + load) | [IDF core-isa.h:96], [ISA §4.3.7 p.84–86] |
| ADDX/SUBX, ABS | present | [IDF core-isa.h:70,74] |
| Wide / predicted branches | absent | [IDF core-isa.h:71–72] |
| `L32AI/S32RI`, `S32C1I` | present | [IDF core-isa.h:77–78] |
| Speculation option | absent | [IDF core-isa.h:79] |
| THREADPTR, BOOLEANS | present | [IDF core-isa.h:92–93] |
| FPU | single precision (+DIV/RECIP/SQRT/RSQRT), coprocessor 0, 72-byte save area; no double precision (DFP accel ops only) | [IDF core-isa.h:122–132], [IDF tie.h:35–43] |
| Load/store units, write buffer | 1 LSU, 4-entry write buffer | [IDF core-isa.h:162–163] |
| Unaligned access | no exception, handled in hardware | [IDF core-isa.h:171–174] |
| I/D cache in core | none (size 0), no prefetch | [IDF core-isa.h:215–216,221] |
| Local memory ports | InstRAM0 `0x4000_0000`, InstRAM1 `0x4040_0000`, InstROM0 `0x4080_0000` (4 MB each); DataRAM0 `0x3FF8_0000` (512 KB); DataRAM1 `0x3F80_0000`; DataROM0 `0x3F40_0000`; XLMI0 `0x3FF0_0000` (512 KB); load/store to IRAM/IROM allowed | [IDF core-isa.h:290–334] |
| Interrupts | 32 (26 external), **6 levels + NMI (7)**, `EXCM_LEVEL 3`, debug level 6; XEA2 | [IDF core-isa.h:341–351,405–407,541] |
| Timers | `CCOUNT` + 3 `CCOMPARE` | [IDF core-isa.h:344–345] |
| Debug / profiling | 2 IBREAK, 2 DBREAK, TRAX 16 KB, 2 perf counters | [IDF core-isa.h:613–626] |
| MMU | region protection only, identity mapped, no page-table MMU | [IDF core-isa.h:635–649] |
| SoC interrupt matrix | 71 sources → 26 peripheral interrupts per CPU; 32 CPU interrupts each | [TRM §8.2 p.174], [TRM §8.3.2 p.178] |
| Vendor benchmark | CoreMark 539.98 (1 core, 240 MHz, 2.25/MHz); 1079.96 (2 cores) | [DS p.3–4] |

### 3.2 Pipeline facts for hand-tuning (from the ISA RM)

| Topic | Fact | Cite |
|---|---|---|
| Disclaimer | the ISA RM "is not the reference for performance"; stage tables are in the processor data book (**not among these docs**) | [ISA §8.4 p.629], [ISA §8.4.2 p.633] |
| Issue model | dependent instruction issues `max(SA − SB + 1, 0)` cycles after the producer; interlock in R stage, a bubble goes to E | [ISA §8.4.1 p.629–630], [ISA §8.4.2 p.632] |
| ALU → use | 0 extra cycles (result end of E, needed start of E) | [ISA §8.4.2 p.632] |
| Load → use | 5-stage reference: dependent must issue **2 cycles after the load** (1 bubble); put an independent instruction in between | [ISA §8.4.2 p.632] |
| Load → use on ESP32 | **Not in docs.** ESP32 has d-side delay 2 vs 1 for 5-stage (`XCHAL_DATA_PIPE_DELAY`), so expect at least one more bubble than the reference (inference) → measure with `CCOUNT` | [IDF core-isa.h:166] |
| Taken branch | branch resolves in E; **2 fall-through instructions killed**; +1 cycle if the target crosses a 32-bit fetch boundary | [ISA §8.4.2 p.632–633] |
| Branch target alignment | 24-bit targets at 0/1 mod 4, 16-bit at 0/1/2 mod 4 | [ISA §4.3.1.2 p.78], [ISA §8.4.2 p.633] |
| Store throughput | R-stage interlock when the write buffer is (or may become) full (4 entries on ESP32) | [ISA §8.4.2 p.633], [IDF core-isa.h:163] |
| MULL / MULUH / MULSH latency | **Not in docs.** `MulAlgorithm` is implementation-dependent; "some hardware implementations may be slower than the software implementations for some operand values". No constant-time guarantee is stated. Same wording for divide. | [ISA §4.3.5 p.82–83], [ISA §4.3.6 p.83] |
| 64-bit product | `MULL` (low 32) + `MULUH`/`MULSH` (high 32) = 2 instructions per 32×32→64 | [ISA Table 4-33 p.83], [ISA p.474,480] |
| `LOOP`/`LOOPNEZ`/`LOOPGTZ` | set LBEG/LEND/LCOUNT; `LCOUNT = as − 1` (`LOOP` with 0 iterates 2³²; `LOOPNEZ` skips on 0; `LOOPGTZ` skips on ≤ 0); body ≤ 256 B (8-bit offset); should not incur a taken-branch penalty | [ISA Table 4-29 p.79], [ISA p.416] |
| Loop restrictions | not nestable (single LBEG/LEND/LCOUNT); calls inside discouraged; first instruction must fit in a naturally aligned 4-byte unit (24-bit at 0/1 mod 4); last instruction must not be a call, `ISYNC`, `WAITI`, `RSR.LCOUNT`; taken branch as last → LCOUNT undefined; branch to LEND exits | [ISA §4.3.2.2 p.79–80], [ISA p.416–417] |
| Loops and exceptions | loop-back disabled while `PS.EXCM` is set (exception/window handlers) | [ISA §4.3.2.3 p.80] |
| Loop overhead | "some implementations" take an extra clock on the first loop-back; `ISYNC`/LEND writes add a cycle | [ISA p.417] |
| `L32R` | PC-relative, reach −262 141 … −4 bytes (~256 KiB **below** PC); no LITBASE on ESP32 | [ISA p.406], [IDF core-isa.h:68] |
| **Derived:** literal placement | DRAM ends at `0x3FFF_FFFF`; IRAM starts `0x4008_0000` (512 KiB above) and flash text at `0x400D_0000`, so literals for IRAM or flash code must live in I-space next to the code, i.e. IRAM literal loads go through the InstRAM data path that the ISA calls potentially slower | [ISA §4.5.8 p.147], [IDF soc.h:172–175,182] |
| Windowed ABI | 64 physical AR, window rotates by 4/8/12 (`CALL4/8/12` + `ENTRY`); spills/refills via overflow/underflow exceptions | [ISA §4.7.1 p.204] |
| Overflow/underflow cost | reference handlers: OF4 = 4 × `S32E` + `RFWO`; OF8 = 8 × `S32E` + 1 `L32E` + `RFWO`; OF12 = 12 × `S32E` + 1 `L32E` + `RFWO`; underflow symmetric with `L32E` + `RFWU`. IDF uses equivalent vectors. Exception entry/exit cycles: **not in docs**. | [ISA §4.7.1.6 p.216–217], [IDF xtensa_vectors.S:2025–2222] |
| Windowed constraints | 16 B reserved below SP; windowed calls must stay in the same 1 GB region | [ISA §4.7.1.5 p.216] |

---

## 4. Hardware accelerators

| Block | Coverage | Throughput (TRM) | Interface | Cite |
|---|---|---|---|---|
| AES | AES-128/192/256 encrypt + decrypt, one 128-bit block per start (no chaining modes in HW) | **11–15 cycles/block encrypt, 21–22 decrypt** | 8 key + 4 text 32-bit regs, `AES_START` → poll `AES_IDLE`; key/mode persist across blocks | [TRM §14.1–14.3.5 p.281–284] |
| SHA | SHA-1, SHA-256, SHA-384, SHA-512 (no SHA-224 in HW; IDF uses software for it) | **60–100 cycles per block**, 8–20 cycles for final digest | software pads; writes one 512/1024-bit block into `SHA_TEXT_0..15/31`; per-algorithm START/CONTINUE/LOAD/BUSY regs | [TRM §16.1–16.3.4 p.293–294], [IDF esp_sha256.c:244–261] |
| RSA / MPI | Z = XʸmodM and Z = X·Y mod M for N ∈ {512, 1024, …, 4096}; Z = X·Y for N ∈ {512, 1024, 1536, 2048} (2N result); max 4096 | **not in docs** | 4 memory blocks × 128 words; Montgomery with software-precomputed r = R² mod M and 32-bit M′ | [TRM §15.2–15.3.4 p.287–290], [DS §4.5 p.32], [IDF soc_caps.h:383–387] |
| RNG | 32-bit TRNG in `RNG_DATA_REG` | ≤ 5 MHz reads with HS-ADC noise, ≤ 500 kHz with SAR ADC only | single RO register `0x3FF7_5144` | [TRM §18.3–18.6 p.308–309] |

Details:

| Topic | Fact | Cite |
|---|---|---|
| "Clock cycles" | the AES/SHA chapters don't say which clock domain the cycle counts refer to | [TRM §14.3.5 p.284], [TRM §16.3.4 p.294] |
| SHA word order | big-endian words; one state per algorithm kept in parallel ("ESP32-style parallel engine") | [IDF soc_caps.h:370–374] |
| SHA in IDF | HW used only if that algorithm's engine is free, otherwise software; cloning a HW context turns it into software | [IDF esp_sha256.c:85–97,244–261] |
| RSA bring-up | enable clock, clear `DPORT_RSA_PD` in `DPORT_RSA_PD_CTRL_REG`, wait for `RSA_CLEAN_REG = 1` (HW zeroes the memory blocks) | [TRM §15.3.1 p.287], [IDF mpi_ll.h:64–72] |
| RSA modmul sequence | write X, M, r (n words each) and M′ → `MULT_START` → wait → clear IRQ → write Y into X_MEM → start → wait → read Z: **two HW rounds per modmul** | [TRM §15.3.3 p.289] |
| RSA modexp side effects | X and r are overwritten; mode, Y, M, M′ preserved | [TRM §15.3.2 p.289] |
| **256-bit operands** | not supported natively: minimum N = 512, so a 255-bit Curve25519 element must be padded to 16 words. IDF rounds every operand up to a multiple of 16 words. One operation at a time. | [TRM §15.3.2 p.287], [IDF mpi_ll.h:59–62], [IDF soc_caps.h:383–384] |
| **Derived** MPI setup per 255-bit modmul | ≥ 3 × 16 + 1 word writes before round 1, 16 before round 2, 16 reads, 2 starts + 2 completion polls, all over the DPORT bus, plus one-time r/M′ precompute per modulus; HW cycle count not in docs | derived from [TRM §15.3.3 p.289] |
| RNG entropy | thermal noise from HS-ADC (auto-on when **Wi-Fi or BT is enabled**) and/or SAR ADC; with neither, output is **pseudo-random**; Wi-Fi can saturate the HS-ADC in extreme cases → also enable SAR ADC; 2 GB at 5 MHz passed Dieharder | [TRM §18.3–18.4 p.308–309] |
| RNG in IDF | ESP32 path enforces ≥ 16 APB cycles between reads; `bootloader_random_enable()` provides SAR-ADC entropy when RF is off | [IDF hw_random.c:49,55–80], [IDF bootloader_random.h:33–45] |
| Clock gating / reset | AES/SHA/RSA clocks are gated by default (`DPORT_PERI_CLK_EN_REG` `EN_AES/SHA/RSA`); also reset via `DPORT_PERI_RST_EN_REG`; reset bits are not self-clearing | [TRM §12.3.7 p.238], [TRM Reg 12.3–12.4 p.246–247] |
| DMA | none: the accelerators are register-fed; AES/SHA/RSA aren't DMA modules | [TRM Table 3.3-3 p.70] |
| Bus location | AES `0x3FF0_1000`, RSA `0x3FF0_2000`, SHA `0x3FF0_3000`: inside the DPORT/XLMI window covered by erratum CPU-3.16 (speculative reads; simultaneous continuous access by both CPUs to `0x3FF0_0000–0x3FF1_EFFF` may lose accesses) | [TRM Table 3.3-6 p.72], [ERR §3.3 p.12–13] |

---

## 5. Clocks & power

### 5.1 Clocks

| CPU_CLK | Derivation | APB_CLK | Cite |
|---|---|---|---|
| 80 MHz | PLL 320 MHz / 4 | 80 MHz | [TRM Table 7.2-2 p.168], [TRM Table 7.2-4 p.169] |
| 160 MHz | PLL 320 MHz / 2 | 80 MHz | same |
| **240 MHz** | **PLL 480 MHz / 2** | 80 MHz | same |
| XTAL / (n+1) | 40 MHz crystal | = CPU_CLK | same |
| RC_FAST / (n+1) | ~8 MHz | = CPU_CLK | same |

| Fact | Cite |
|---|---|
| Wi-Fi/BT only work when APB comes from the PLL; the PLL may be stopped only after Wi-Fi and BT are in low-power mode. | [TRM §7.2.5 p.170] |
| 40 MHz crystal is mandatory for Wi-Fi/BT; the module has one. | [DS p.4], [MOD p.2] |
| **Derived:** DFS between 240 MHz and 80/160 MHz changes the PLL frequency (480 ↔ 320 MHz); the switch latency is **not in docs**. | [TRM Table 7.2-2 p.168] |
| `PLL_F160M_CLK` is always 160 MHz. | [TRM §7.2.4.5 p.170] |
| Digital core LDO: typically 1.1 V, adjustable 0.90–1.25 V (`VDD_DIG = 0.90 + DBIAS·0.05 V`). | [TRM §9.3.2 p.181] |
| CPU reset/restart levels never clear RAM. | [TRM §7.1.1 p.165] |

### 5.2 Current by power mode

| Mode | DS Table 4-2 | TRM predefined modes | Cite |
|---|---|---|---|
| Active, RF working | see §5.3 | XTAL or PLL 80/160/240 MHz, radio on | [DS §4.3.1 p.30], [TRM §9.3.9 p.188] |
| Modem-sleep, 240 MHz, dual core | 30–68 mA | — | [DS Table 4-2 p.30] |
| Modem-sleep, 160 MHz, dual core | 27–44 mA | — | same |
| Modem-sleep, 80 MHz, dual core | 20–31 mA | ~30 mA (80 MHz PLL); ~3 mA at 2 MHz XTAL; immediate wake | same, [TRM §9.3.9 p.188–189] |
| Light-sleep | 0.8 mA | ~800 µA; 8 MHz osc, XTAL, PLL, radio off; CPUs stalled; wake < 1 ms | same |
| Deep-sleep, ULP on | 150 µA | — | [DS Table 4-2 p.30] |
| Deep-sleep, ULP sensor pattern (1 %) | 100 µA | — | same |
| Deep-sleep, RTC timer + RTC memory | 10 µA | ~6.5 µA; RTC core 0.7 V; 8 × 32-bit retention regs; wake < 1 ms | same, [TRM §9.3.9 p.189] |
| Hibernation | 5 µA | ~4.5 µA, RTC timer wake only | same |
| Power off (`CHIP_PU` low) | 1 µA | — | [DS Table 4-2 p.30] |

### 5.3 RF current

DS figures are at 50 % TX duty, MOD at 100 % TX duty (RX with peripherals off, CPU idle).

| Mode | DS typ (mA) | MOD avg (mA) | MOD peak (mA) | Cite |
|---|---|---|---|---|
| TX 802.11b 1 Mbps @ 19.5 dBm | 240 | 239 | 379 | [DS Table 5-4 p.52], [MOD Table 16 p.29] |
| TX 802.11g 54 Mbps @ 16 dBm (DS) / 15 dBm (MOD) | 190 | 190 | 276 | same |
| TX 802.11n HT20 MCS7 @ 14 dBm (DS) / 13 dBm (MOD) | 180 | 183 | 258 | same |
| TX 802.11n HT40 MCS7 @ 13 dBm | — | 165 | 211 | [MOD Table 16 p.29] |
| RX 802.11b/g/n HT20 | 95–100 | 112 | 112 | same |
| RX 802.11n HT40 | — | 118 | 118 | [MOD Table 16 p.29] |

TX power at spec mask/EVM: 11b 19.5 dBm; 11g 6 Mbps 18.0, 54 Mbps 14.0; HT20/HT40 MCS0 18.0, MCS7 13.0 dBm [MOD Table 20 p.31]. Chip limits: 11b 18.5–20.5 dBm, 11n MCS7 12–14 dBm [DS Table 5-6 p.53]. **Not in docs:** current as a function of configured TX power (only the fixed-power points above).

### 5.4 Modem-sleep and DTIM

| Fact | Cite |
|---|---|
| With Wi-Fi on, the chip alternates between Active and Modem-sleep; in Modem-sleep the CPU frequency changes automatically with load and peripherals. | [DS §4.3.1 notes p.31] |
| After reset the chip is in Modem-sleep; it goes Active to TX/RX and can drop into a low-power mode after the CPU stalls for a while. | [TRM §9.3.9 p.190] |
| Wi-Fi is a light-sleep wake source; CPU, Wi-Fi and radio are woken at predetermined intervals to keep the connection. | [TRM Table 9.3-2 note 6 p.191] |
| `WIFI_PS_MIN_MODEM` wakes for the beacon every DTIM; `WIFI_PS_MAX_MODEM` uses `listen_interval` (in beacon intervals, default 3). | [IDF wifi_types.h:374–378,558] |
| tinylink runs with `PM_ENABLE=y` and `FREERTOS_USE_TICKLESS_IDLE=y` (automatic light sleep). | [TL sdkconfig] |

---

## 6. Wi-Fi (as far as DS/TRM cover it)

| Feature | Value | Cite |
|---|---|---|
| Standards / channels | 802.11 b/g/n, 2412–2484 MHz | [DS §4.6.4 p.33], [MOD Table 19 p.31] |
| PHY rates | HT20/HT40 MCS0–7, MCS32 RX, 0.4 µs short GI, up to 150 Mbps, RX STBC 2×1 | [DS §4.6.4 p.33] |
| TX power | up to 20.5 dBm, adjustable; antenna diversity needs an external RF switch | [DS §4.6.4 p.33] |
| Receiver | quadrature down-conversion into two high-speed ADCs (the same HS-ADC that seeds the RNG) | [DS §4.6.1 p.32], [TRM §18.3 p.308] |
| MAC | 4 virtual interfaces; simultaneous STA/SoftAP/promiscuous; RTS/CTS protection; Immediate Block ACK; defragmentation; TX/RX A-MPDU, RX A-MSDU; TXOP; WMM | [DS §4.6.5 p.34] |
| MAC hardware crypto | CCMP, TKIP, WAPI (SMS4), WEP, CRC | [DS §4.6.5 p.34] |
| Beacons | automatic beacon monitoring (hardware TSF) | [DS §4.6.5 p.34] |
| RX sensitivity (module) | 11b 1 Mbps −97; 11g 54 Mbps −75; HT20 MCS0 −92, MCS7 −72; HT40 MCS7 −69 dBm | [MOD Table 21 p.31–32] |
| Buffer DMA | WIFI is a DMA module; DMA reaches SRAM1/SRAM2 only, so all Wi-Fi RX/TX buffers must sit in internal DRAM `0x3FFA_E000–0x3FFF_FFFF` | [TRM §3.3.2.6 p.70] |
| Clocking | Wi-Fi needs APB from the PLL | [TRM §7.2.5 p.170] |
| Not in docs | Wi-Fi MAC descriptor format, buffer sizes, RX/TX queue depths, interrupt latency (no Wi-Fi chapter in the TRM; driver is a binary blob) | — |

---

## 7. Errata relevant to rev v3.1 (no PSRAM, Wi-Fi, dual core)

"v3.1?" means affected according to [ERR Tables 2.1–2.2 p.9–10]. The IDF column describes behaviour with `CONFIG_ESP32_REV_MIN_3=y` (FULL = 300) [TL sdkconfig].

| ID | Issue | v3.1? | Workaround | IDF handling | Relevance to tinylink | Cite |
|---|---|---|---|---|---|---|
| CPU-3.5 | crash on direct 240 → 80/160 MHz switch | no (v0.0) | step through 40 MHz | runtime check only for rev < 1.0 | none | [ERR §3.1 p.11], [IDF bootloader_clock_init.c:44–52] |
| CPU-3.18 | summary of DPORT/AHB access limits | yes | on v3.x every DPORT access is correct; FIFO reads via AHB are not allowed on any revision | — | use DPORT (`0x3FF4_xxxx`) aliases for reads | [ERR §3.2 p.11–12] |
| CPU-3.16 | speculative reads in `0x3FF0_0000–0x3FF1_EFFF` / `0x3FF4_0000–0x3FF7_FFFF`; continuous simultaneous access by both CPUs to `0x3FF0_0000–0x3FF1_EFFF` may lose accesses; DPORT FIFO read pointer lags | **yes, no fix** | `MEMW` / `volatile` before such accesses; 6 `nop` (160 MHz) or **7 `nop` (240 MHz)** between consecutive FIFO reads | `REG_*` macros are volatile; `uart_ll_read_rxfifo` adds 1 `nop` per byte only under `COMPILER_OPTIMIZATION_PERF` | crypto accelerator registers, DPORT regs, UART RX | [ERR §3.3 p.12–13], [IDF uart_ll.h:333–343] |
| CPU-3.9 | PSRAM store/load sequence corrupts data | no (v1.0/1.1) | nops / memw | `SPIRAM_CACHE_WORKAROUND` only offered when REV_MIN_FULL < 300; without it the ROM libc (`memcpy` etc. in ROM) is linked | none (no PSRAM) | [ERR §3.4 p.13–14], [IDF Kconfig.spiram:64–66], [IDF esp_rom/CMakeLists.txt:207–214], [IDF rom.libc-funcs.ld:38–42] |
| CPU-3.2 | PSRAM pipelined r/w errors | no (v0.0) | — | — | none | [ERR §3.5 p.14] |
| CPU-3.10 | one CPU reading region A (`0x3FF0_0000–0x3FF1_EFFF`) while the other reads B (`0x3FF4_0000–0x3FF7_FFFF`) → wrong read on B | **no (fixed v3.0)** | locks or a dummy B read with interrupts off | `SOC_DPORT_WORKAROUND` only if `SOC_CAPS_ECO_VER < 200`; at REV_MIN_3 `DPORT_REG_READ` is a plain load (no `rsil 5`, no other-CPU stall) | DPORT/accelerator access is cheap on this build | [ERR §3.6 p.14–15], [IDF soc_caps.h:109–111], [IDF soc/dport_access.h:110–131], [IDF hw/dport_access.h:16–22] |
| CPU-3.21 | interrupt taken while reading UART0/1/2 or I2S0/1 FIFO → bus bridge hangs all later APB peripheral accesses from both CPUs | **yes, no fix** | disable interrupts around those FIFO reads | not Kconfig-gated; `uart_ll_read_rxfifo` doesn't mask interrupts itself | UART console/RX paths | [ERR §3.7 p.15], [IDF uart_ll.h:333–343] |
| CPU-3.3 | repeated DPORT writes to one address lost | no (v0.0) | write FIFOs via AHB | IDF writes the UART TX FIFO via AHB | none | [ERR §3.8 p.15–16], [IDF uart_ll.h:356–357] |
| ULP-3.19 | ULP/touch unusable in deep sleep if RTC_PERIPH stays on | yes | power RTC_PERIPH down (no EXT0) | IDF forces RTC_PERIPH off for touch/ULP wake | none | [ERR §3.9 p.16–17], [IDF sleep_modes.c:2624–2637] |
| GPIO-3.6 | GPIO pull regs ineffective on RTC-capable pads | yes | use RTC_GPIO regs | IDF GPIO driver ≥ v2.1 | only if relying on pulls | [ERR §3.10 p.17] |
| GPIO-3.14 | an edge interrupt in a GPIO group breaks other interrupts in that group | yes, no fix | emulate edges with level interrupts | none | only if GPIO edge ISRs are used | [ERR §3.11 p.18–19] |
| GPIO-3.11 | GPIO36/39 pulled low ~80 ns when SAR ADC1/2 or AMP powers up | yes, no fix | ignore those inputs then | none | only if GPIO36/39 + SAR ADC (e.g. SAR entropy) | [ERR §3.12 p.19] |
| RES-3.4 | brown-out reset doesn't work | no (v0.0) | — | `REV_MIN_0` selects `ESP_BROWNOUT_USE_INTR`; `SOC_BROWNOUT_RESET_SUPPORTED` for ≥ 100 | none | [ERR §3.13 p.19–20], [IDF Kconfig.hw_support:12–15], [IDF soc_caps.h:149–151] |
| RES-3.1 | spurious WDT reset at power-up / deep-sleep wake | no (v0.0) | — | — | none | [ERR §3.14 p.20] |
| RES-3.8 | flash start-up time → spurious WDT reset | no (fixed v3.0) | fast-start flash; deep-sleep wake delay | IDF ≥ v2.0 adds the wake delay | none | [ERR §3.15 p.20–21], [REV3 p.4] |
| CLK-3.7 | APLL range limited | no (v0.0) | — | — | none | [ERR §3.16 p.21] |
| CLK-3.22 | APLL can't be the RMII clock while Wi-Fi is on | yes | external clock | — | none (no Ethernet) | [ERR §3.17 p.22] |
| RTC-126 | RTC-domain register reads may be wrong after light-sleep wake if RTC peripherals were powered down | **yes, no fix** | keep RTC peripherals powered in light sleep ("no impact on power consumption") | **not automatic**: IDF powers RTC_PERIPH off unless EXT0/GPIO wake is configured; override with `esp_sleep_pd_config(ESP_PD_DOMAIN_RTC_PERIPH, ESP_PD_OPTION_ON)` | **yes**: automatic light sleep is enabled | [ERR §3.18 p.22], [IDF sleep_modes.c:1470,2620–2632], [TL sdkconfig] |
| WDT-3.15 | dual-core **cache live lock**: three of the four I/D buses to external memory miss in the same cache set at once → CPUs stall in memory access | **yes (v3.0/v3.1 only), no fix** | per-core level-4/5 interrupt from a shared timer breaks the lock in three stages | `ESP32_ECO3_CACHE_LOCK_FIX` defaults to y but depends on `!SINGLE_CORE && SPIRAM`, so it is **off in this no-PSRAM build**; when on, REV_MIN_3/3_1 select `ESP_INT_WDT` and the INT WDT handler breaks the lock in 20 ms slices | dual core + flash cache; only the plain interrupt WDT (y in tinylink) remains as a detector | [ERR §3.19 p.23], [IDF Kconfig.system:13–16], [IDF Kconfig.hw_support:22–27], [IDF int_wdt.c:96,212–222], [IDF chip_info.c:44–49] |
| UART-3.17 | DPORT `fifo_cnt` decrements wrongly if the read is interrupted | yes, no fix | compute length from rd/wr offsets | `uart_ll_get_rxfifo_len` implements the errata formula | UART RX | [ERR §3.20 p.23–24], [IDF uart_ll.h:415–432] |
| TWAI-3.13.1–11, TWAI-880 | CAN controller issues | yes | — | — | none (TWAI unused) | [ERR §3.21–3.32 p.24–30] |
| LEDC-3.12 | decremental fade duty overflow | yes | — | — | none | [ERR §3.33 p.31] |

### 7.1 What `ESP32_REV_MIN_*` gates in IDF v5.5.4

| Gate | Effect at REV_MIN_FULL ≥ 300 | Cite |
|---|---|---|
| Kconfig choice | `REV_MIN_3` → FULL 300 ("ECO3"); `REV_MIN_3_1` → FULL 301 ("Rev v3.1 (ECO4)"); both `select ESP_INT_WDT if ESP32_ECO3_CACHE_LOCK_FIX`; max supported rev 3.99 | [IDF Kconfig.hw_support:1–45,61–63] |
| Boot check | image refuses to boot on a chip below the minimum revision | [IDF Kconfig.hw_support:5–10], [IDF bootloader_common_loader.c:47] |
| `SOC_CAPS_ECO_VER` | = REV_MIN_FULL; `< 200` enables the DPORT workaround; `≥ 100` brownout reset supported; `≥ 200` TWAI BRP up to 256 | [IDF soc_caps.h:43,109–111,149–151,343–347] |
| ROM symbols | links `esp32.rom.eco3.ld` (ROM Secure Boot V2 / RSA-PSS verify) in bootloader and app | [IDF esp_rom/CMakeLists.txt:161–163,221–223], [IDF rom.eco3.ld] |
| PSRAM cache workaround | `SPIRAM_CACHE_WORKAROUND` disappears, so ROM newlib functions are linked | [IDF Kconfig.spiram:64–66], [IDF esp_rom/CMakeLists.txt:207–214] |
| Secure boot / download mode | RSA Secure Boot V2 supported and preferred; secure/disabled UART ROM download mode selectable; ROM download disable skips the runtime rev check | [IDF bl/Kconfig.projbuild:463–482,1150–1154], [IDF components/efuse/esp32/esp_efuse_fields.c:44] |
| 32 kHz crystal extra current | option hidden (needs < 200) | [IDF Kconfig.rtc:36–39], [IDF rtc_clk.c:53–55] |
| `REV_MIN_3_1` vs `REV_MIN_3` | **no ESP32 code path is gated on 301**; the only difference is the stricter boot-time revision check (`SOC_CAPS_ECO_VER_MAX = 301`) | [IDF soc_caps.h:63], grep of IDF tree for `>= 301` / `REV_MIN_3_1` |

---

## 8. Chip revision v3.0 / v3.1

| Change in v3.0 | Cite |
|---|---|
| Fixed RES-3.8 (flash start-up spurious WDT reset) | [REV3 p.4 item 1] |
| Fixed CPU-3.9 PSRAM cache bug | [REV3 p.4 item 2] |
| Fixed CPU-3.10 dual-CPU concurrent read error | [REV3 p.4 item 3] |
| Better 32.768 kHz crystal start-up stability | [REV3 p.4 item 4] |
| Fault-injection fixes for secure boot and flash encryption (CVE-2019-17391, CVE-2019-15894) | [REV3 p.4 item 5] |
| TWAI minimum bit rate 25 → 12.5 kHz | [REV3 p.4 item 6] |
| New eFuse `UART_DOWNLOAD_DIS` (bit 27 of `EFUSE_BLK0_RDATA0_REG`; write-disable shared with `flash_crypt_cnt`) to disable Download Boot permanently | [REV3 p.4 item 7], [MOD §4.1 p.15] |
| Guidance: set "Minimum Supported ESP32 Revision" to Rev 3; RSA Secure Boot V2 from IDF v4.1; "slightly enhanced PSRAM performance" only with HW + SW upgrade | [REV3 p.5] |
| New erratum appearing from v3.0: WDT-3.15 cache live lock | [ERR Table 2.2 p.10] |

| v3.1 | Cite |
|---|---|
| Identification: eFuse `BLK0_RDATA5[24] = 1` (minor), `BLK0_RDATA5[20] = 1`, `APB_CTRL_DATE[31] = 1` (major 3) | [ERR Table 1.1 p.4] |
| Chip marking `X G XXXXXX`; module marking `MG XXXX` | [ERR Tables 1.2–1.3 p.5–6] |
| A minor-number change means software compatible, no upgrade needed | [ERR §1.1 p.4] |
| ESP32-D0WD-V3 is now produced as v3.1 (PCN20220901) | [DS Table 1-1 note 4 p.11] |
| Errata status is identical for v3.0 and v3.1 on every item | [ERR Tables 2.1–2.2 p.9–10] |
| IDF labels v3.1 "ECO4" and gates no ESP32 code on it | [IDF Kconfig.hw_support:25–27], §7.1 |
| **Not in docs:** what silicon change v3.1 makes compared with v3.0 | — |

---

## 9. Module (ESP32-WROOM-32E) specifics

| Item | Value | Cite |
|---|---|---|
| SoC | ESP32-D0WD-V3 (or D0WDR2-V3 for PSRAM variants) | [MOD §1.2 p.3] |
| Variants | **N4: 4 MB quad-SPI flash, no PSRAM, −40…85 °C**; H4: 4 MB, −40…105 °C (105 °C only with 4/8 MB flash) | [MOD Table 1 p.3], [MOD p.2] |
| On-module | 40 MHz crystal; 448 KB ROM, 520 KB SRAM, 16 KB RTC SRAM | [MOD §1.1 p.2] |
| Flash | VCC 2.7–3.6 V (3.3 V part), fC 80 MHz, timings in §2.3; shipped erased | [MOD Table 17 p.30] |
| Flash pins | GPIO6–GPIO11 tied to on-module flash, not led out | [MOD p.12 note 2] |
| Antenna | PCB antenna (32E) with a keep-out zone; 32UE uses a connector | [MOD p.2], [MOD p.10 Note A] |
| Strapping defaults | GPIO0 pull-up (1), GPIO2 pull-down (0), MTDI/GPIO12 pull-down (0), MTDO/GPIO15 pull-up (1), GPIO5 pull-up (1); latched at reset | [MOD Table 4 p.13] |
| Boot mode | GPIO0 = 1 → SPI boot; GPIO0 = 0 and GPIO2 = 0 → joint download (UART/SDIO) | [MOD Table 6 p.14] |
| VDD_SDIO | MTDI = 0 → VDD3P3_RTC (3.3 V); MTDI = 1 → internal 1.8 V LDO; overridable via `EFUSE_SDIO_FORCE`/`SDIO_TIEH`. **IO12 must be low at power-on** (3.3 V flash). | [MOD §4.2 p.15], [MOD p.39] |
| Boot log | MTDO selects U0TXD boot printing | [MOD Table 7 p.16] |
| Timing | strapping hold tH ≥ 1 ms; rails stable tSTBL ≥ 50 µs before CHIP_PU; reset low tRST ≥ 50 µs; an RC delay on EN is advised | [MOD Table 5 p.14], [MOD Table 9 p.17], [MOD p.39] |
| Recommended operating | VDD33 3.0–3.6 V (typ 3.3); supply ≥ 0.5 A; ambient −40…85 °C (N) / 105 °C (H) | [MOD Table 14 p.28] |
| Absolute maximum | VDD33 −0.3…3.6 V; storage −40…105 °C | [MOD Table 13 p.28] |
| Thermal | soldering the EPAD to ground is optional but improves thermal performance; chip HTOL 125 °C / 1000 h; bare chip rated −40…125 °C | [MOD p.39], [DS Table 5-5 p.53], [DS Table 5-2 p.51] |
| Assembly | single reflow, peak 235–250 °C | [MOD §12.3 p.46] |

---

## 10. Optimization implications for tinylink

- **IRAM vs flash for hot code.** IRAM/ROM/SRAM are single-cycle (§1.2), while a flash miss costs ≈ 86 SPI clocks ≈ 258 CPU cycles per 32-B line at QIO 80 MHz (derived, §2.2) and both cores' misses share one SPI0 (§2.2). The ChaCha20 block, Poly1305 block loop, X25519 field mul/square, BLAKE2s compress and XSalsa20 core belong in IRAM. The flash-resident hot working set per core should stay well under the 32 KiB 2-way cache (§2.1). IRAM is 128 KiB total (§1.3).
- **Literal loads in IRAM code.** L32R reaches only 256 KiB below the PC, and there's no LITBASE (§3.2), so literals sit in IRAM next to the code. The ISA warns that InstRAM data loads may be slower (§1.2). In tight loops, hoist constants into registers once: 64 physical ARs, 16 visible (§3.1). Benchmark L32R from IRAM against DRAM loads.
- **No byte/halfword data in IRAM.** I-bus data access is word-only (exception otherwise). Emulation costs ≤ 167 cycles per access and works only single-core (§1.2). Keep byte tables and state in DRAM; `const` tables in flash go through the D-cache (§2.1), so put hot tables in DRAM (`DRAM_ATTR`).
- **Schedule around load-use.** The reference pipeline needs one independent instruction between a load and its use, and ESP32's 7-stage d-side likely needs more (§3.2, not in docs). Interleave the four ChaCha/BLAKE2s quarter-rounds' loads ahead of use, and measure with `CCOUNT` (§3.1).
- **Use zero-overhead loops for fixed trip counts.** A taken branch kills 2 fetched instructions; `LOOP` avoids that (§3.2). Fixed counts such as 10 ChaCha double-rounds, 10 BLAKE2s rounds and per-16-byte Poly1305 blocks fit if the body is ≤ 256 B, makes no calls, isn't nested and starts aligned (§3.2). Align hot branch targets to 0/1 mod 4.
- **Multiplier timing is unspecified.** 32×32→64 costs 2 instructions (`MULL` + `MULUH`). Latency, and whether timing depends on operand values, isn't documented ("implementation-dependent", §3.2). Constant-time behaviour of the X25519/Poly1305 multiply paths must be checked empirically. MAC16 (16×16 → 40-bit accumulate with parallel MR loads) is the only alternative multiply datapath (§3.1).
- **RSA/MPI is a poor fit for Curve25519.** The minimum operand is 512 bits, so a 255-bit element is padded to 16 words. Each modmul takes two hardware rounds plus ≥ 80 DPORT word transfers and 2 polls (derived), and the TRM gives no cycle counts (§4). That overhead applies to every field operation. The MPI handles one operation at a time and is shared with mbedTLS (TLS ECDHE/RSA). Only a measured benchmark could justify using it.
- **Accelerators don't cover the WireGuard primitives.** AES (11–15 cycles/block) and SHA-1/256/384/512 (60–100 cycles/block) help the TLS control/DERP path only. There is no hardware for ChaCha20, Poly1305, BLAKE2s, Salsa20 or SHA-224 (§4). The SHA engine runs one stream per algorithm and IDF falls back to software when it's busy (§4). Accelerator registers are cheap to reach on REV_MIN_3 because the DPORT read workaround is compiled out (§7, CPU-3.10). CPU-3.16 still applies: keep accesses `volatile`, and don't let both cores hammer `0x3FF0_xxxx` at once (§4, §7).
- **Flash writes stall everything that isn't in IRAM.** NVS/OTA writes disable both caches: up to 5 ms per page program, 70 ms typical / 500 ms worst per 4 KB erase, and 3 s worst per 64 KB block erase (§2.3). ESP32 can't suspend flash (§2.3). Keep NVS writes off the packet path. Anything that must run during them (ISRs, Wi-Fi/lwIP hot paths) has to be IRAM-safe.
- **DMA and SRAM banking.** Wi-Fi DMA reaches only SRAM1/SRAM2 (§1.5, §6), so packet buffers and pbufs must be internal DRAM. SRAM is banked in 32 KiB, and a CPU and DMA in different banks don't contend (§1.2). Placing crypto state away from Wi-Fi buffer banks is a cheap, measurable tweak.
- **RTC FAST memory.** It is PRO_CPU-only and APB-clocked (§1.1–1.2), so it's unsuitable for hot data or anything the APP_CPU touches.
- **Power is dominated by the radio.** TX averages 165–240 mA (379 mA peak) against 20–68 mA for the CPU in modem sleep (§5.2–5.3). CPU speedups mainly shorten time awake. DTIM-based modem sleep (`MIN_MODEM`) sets the wake cadence (§5.4).
- **Apply the RTC-126 workaround.** Automatic light sleep is on in tinylink, and IDF powers RTC_PERIPH down by default, so force `ESP_PD_DOMAIN_RTC_PERIPH` on to avoid wrong RTC register reads after wake (§7).
- **Brownout margin.** The brownout detector is at L0 (2.43 V) while the flash needs ≥ 2.7 V. VDD_SDIO hangs off VDD3P3_RTC through ≈ 6 Ω, and TX peaks reach 379 mA (§2.4, §5.3). IDF's XMC brownout-reset patch keys on vendor 0x20, not this part's 0x46 (§2.4). A higher brownout level (L5 = 2.70 V) is worth considering.
- **Cache live lock (WDT-3.15).** It affects v3.1 dual-core, and IDF's fix is compiled only with PSRAM (§7). Keep the interrupt WDT on. Treat unexplained dual-core stalls under heavy flash-cache traffic as a candidate for this erratum.
- **RNG entropy before Wi-Fi.** Without Wi-Fi/BT the RNG returns pseudo-random numbers unless the SAR ADC is on (§4). Generate WireGuard/node keys after Wi-Fi start, or bracket generation with `bootloader_random_enable()`/`disable()`. IDF already rate-limits reads to the 5 MHz entropy rate (§4).
