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

## `credentials.csv.example`

Template consumed by `nvs_provision.py`. **Never** commit a populated copy
of this file. The repository's `.gitignore` already excludes
`tools/credentials.csv`.

## `test/`

The host KAT suite — `make -C tools/test test` (see `test/README.md`).
