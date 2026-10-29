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
`wg_rx`, `wg_tx`, `tlm`, `tiT`, `esp_timer`) — the evidence for stack
trims, to be compared with the 60-s `stack diag` HWM dumps. It needs a
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

## `credentials.csv.example`

Template consumed by `nvs_provision.py`. **Never** commit a populated copy
of this file. The repository's `.gitignore` already excludes
`tools/credentials.csv`.

## `test/`

The host KAT suite — `make -C tools/test test` (see `test/README.md`).
