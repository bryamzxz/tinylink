# tools/

Host-side helpers for tinylink. None of these are flashed to the device.

## `nvs_provision.py`

Wraps ESP-IDF's `nvs_partition_gen.py` to generate the encrypted
`nvs_creds` partition that ships WiFi + WireGuard credentials to the device.

Usage:

```bash
source ~/entorno_investigación/bin/activate
. ~/esp/esp-idf-v5.5.4/export.sh

cp credentials.csv.example credentials.csv
$EDITOR credentials.csv          # fill in the REPLACE_WITH_… fields
python nvs_provision.py \
    --input credentials.csv \
    --output ../build/nvs_creds.bin
```

The script:
- Refuses to run if any value still starts with `REPLACE_WITH_`.
- Refuses to run if the WG key files referenced in the CSV are not exactly
  32 bytes.
- Defaults to encrypted output (matches `CONFIG_NVS_ENCRYPTION=y`). Pass
  `--no-encrypt` only for development on a board with flash encryption
  disabled.

## `credentials.csv.example`

Template consumed by `nvs_provision.py`. **Never** commit a populated copy
of this file. The repository's `.gitignore` already excludes
`tools/credentials.csv`.
