# tools/

Host-side helpers for tinylink. None of these are flashed to the device.

## `nvs_provision.py`

Wraps ESP-IDF's `nvs_partition_gen.py` to generate the credentials NVS
image (`nvs_creds`) that ships the WiFi credentials and the Tailscale auth
key to the device. There are no WireGuard keys: node identities are
generated on-device at first boot (`tl_keys` namespace).

Usage:

```bash
source "$VENV/bin/activate"        # the python venv ESP-IDF was installed into
. "$IDF_PATH/export.sh"

cp credentials.csv.example credentials.csv
$EDITOR credentials.csv          # fill in the REPLACE_WITH_… fields
python nvs_provision.py \
    --input credentials.csv \
    --output ../build/nvs_creds.bin
```

The script:
- Refuses to run if any value still starts with `REPLACE_WITH_`.
- Requires the `tl_creds` namespace with `wifi_ssid`, `wifi_pass` and
  `auth_key` (must start with `tskey-`).
- Produces a **plaintext** partition. The firmware does not enable NVS or
  flash encryption (deliberate: eFuse burns are irreversible — see
  `docs/ROADMAP.md` § Execution queue), so an encrypted image would be
  unreadable. `--encrypt` exists only for forks that turn
  `CONFIG_NVS_ENCRYPTION` on.

Flash it to the `nvs_creds` slot (`partitions.csv`: offset `0x320000`,
size `0x4000`) — see [`docs/PROVISIONING.md`](../docs/PROVISIONING.md).
The firmware mounts that partition at boot and falls back to the default
`nvs` partition, so devices provisioned the old way keep working.

## `serial_capture.py`

Captures raw serial output for a fixed duration (default 7 min) to a
file — the input for every smoke/soak grep in the CHANGELOG:

```bash
python serial_capture.py --port /dev/ttyUSB0 --duration 150 --out /tmp/boot.log
```

Needs `pyserial` (ships with the ESP-IDF python environment).

## `stack_worst.py`

Static worst-case stack depth per long-lived task (`tinylink_lp`, `derp`,
`wg_rx`, `wg_tx`, `tlm`, `tiT`, `esp_timer`) and the bringup task `main`
— the evidence for stack trims, to be compared with the 60-s `stack diag`
HWM dumps (and, for `main`, the `main stack: hwm=` line app_main logs
when bringup ends). It needs a
scratch build with stack-usage and call-graph output (the flags do not
change code generation, but keep the dir apart from `build/`):

```bash
W=work/artifacts/stack
EXTRA_CFLAGS="-fstack-usage -fcallgraph-info=su,da" \
EXTRA_CXXFLAGS="-fstack-usage -fcallgraph-info=su,da" \
    idf.py -B $W/build -DSDKCONFIG=$W/sdkconfig reconfigure build
python tools/stack_worst.py --build $W/build --cache-dir $W \
    --toolchain "$IDF_TOOLS_PATH"/tools/xtensa-esp-elf/<ver>/xtensa-esp-elf/bin \
    --rom-elf "$IDF_TOOLS_PATH"/tools/esp-rom-elfs/<ver>/esp32_rev0_rom.elf \
    --summary                      # or --task wg_rx --frames 12 --indirect
```

Each result is the deepest call chain plus 368 B of per-task overhead
(CPSA, one interrupt frame, alignment, canary). Indirect calls are
resolved by the project rules at the end of the script; edges that are
infeasible at run time (TLS renegotiation, TCP on the UDP-only tasks, …)
are cut with a stated reason — `--no-cut` shows the bound without them.
`--why <fn>` explains how a function is reached, `--residual zero` drops
the conservative bound for unresolved Wi-Fi blob callbacks.

## `iram_access_check.py`

Proves on the object code that every access through a pointer into an
IRAM section is 32-bit (round 1.3.4, D6: mapreq.c's jsmn token table is
in `.iram.bss`, where a byte or half-word load / store is a
LoadStoreError). A data-flow pass over `objdump -d -r`: the section's
address enters through code literals and is followed through registers,
stack spills, calls inside the object and zero-overhead loops; it fails
on a narrow access, on such a pointer passed out of the object (memcpy,
string functions, logging, function pointers), stored outside the
frame or kept in initialised data, on an opcode it does not model, and
when nothing reaches the section at all (never a vacuous pass).
`components/tinylink/CMakeLists.txt` runs it after every build of the
component; `--verbose` lists the functions and spills. Its own test —
`iram_check_neg.c`, eight planted violations (the realistic one:
`(type & 0xff) == 4` compiles to an `l8ui`) — must report 8 findings:

```bash
B=build R=$PWD   # an idf.py build dir, the repo root
CMD=$(python -c "import json;print([e['command'] for e in json.load(open('$B/compile_commands.json')) if e['file'].endswith('src/mapreq.c')][0])")
(cd $B && eval "$(echo "$CMD" | sed "s# -o [^ ]*# -o neg.o#; s# -c [^ ]*# -c $R/tools/iram_check_neg.c#") -Wno-strict-aliasing")
python tools/iram_access_check.py --objdump xtensa-esp32-elf-objdump --section .iram.bss $B/neg.o
```

## `power/`

sdkconfig fragments for the steady-state power work (round 1.3.7) and
the boot path's TCP receive side (round 1.3.9). Each is stacked after
`sdkconfig.defaults`; none is meant for production as is.

| fragment | what |
|---|---|
| `sdkconfig.power-diag` | `CONFIG_TINYLINK_POWER_DIAG=y`: three `pwr diag:` lines in each 60-s stack diag (light-sleep residency, sleeps/s by what ended them, sleep-length bins, RTOS-tick drift, CPU per task; format in `components/tinylink/src/pwr_diag.h`) |
| `sdkconfig.ab-wifi-active20` | radio awake 20 ms instead of 50 after each frame under modem sleep |
| `sdkconfig.ab-maxmodem-li3` | `WIFI_PS_MAX_MODEM`, listen interval 3, instead of `MIN_MODEM` |
| `sdkconfig.ab-tcp-tmr500` | lwIP TCP timer 500 ms instead of 250 (initial RTO 1–2 s) |
| `sdkconfig.ab-pm-iram` | `PM_SLP_IRAM_OPT` + `PM_RTOS_IDLE_OPT` |
| `sdkconfig.ab-cpu160` | 160 MHz instead of 240 (boot and DFS max) |
| `sdkconfig.ab-idle2` | light sleep from 2 idle ticks instead of 3 |
| `sdkconfig.ab-txpower13` | Wi-Fi TX power cap 13 dBm instead of 20 |
| `sdkconfig.ab-tcp-sack` | lwIP sends SACK (`LWIP_TCP_SACK_OUT`), window unchanged |
| `sdkconfig.ab-tcp-wnd8` | TCP receive window 11 520 B (8 × MSS) instead of 5 760, mailbox 10, OOSEQ 5, SACK |
| `sdkconfig.ab-tcp-wnd12` | window 17 280 B (12 × MSS), mailbox 14, OOSEQ 8, SACK, Wi-Fi dynamic RX buffers 24 instead of 16 |

A measured variant is the diag fragment plus one A/B fragment, in a
fresh build dir:

```bash
idf.py -B work/artifacts/ab -D SDKCONFIG=work/artifacts/ab/sdkconfig \
    -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;tools/power/sdkconfig.power-diag;tools/power/sdkconfig.ab-wifi-active20" build
```

The `ab-tcp-*` fragments are measured at boot, without the diag
fragment: `sdkconfig.defaults;tools/power/sdkconfig.ab-tcp-wnd8`. Their
figure is the `h2: map body:` line (`components/tinylink/src/tl_bodystat.h`)
and the `map stream answered` → `netmap (initial)` gap, over a series of
boots per image.

## `credentials.csv.example`

Template consumed by `nvs_provision.py`. **Never** commit a populated copy
of this file. The repository's `.gitignore` already excludes
`tools/credentials.csv`.

## `test/`

The host KAT suite — `make -C tools/test test` (see `test/README.md`).
