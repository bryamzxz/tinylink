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

## `credentials.csv.example`

Template consumed by `nvs_provision.py`. **Never** commit a populated copy
of this file. The repository's `.gitignore` already excludes
`tools/credentials.csv`.

## `test/`

The host KAT suite — `make -C tools/test test` (see `test/README.md`).
