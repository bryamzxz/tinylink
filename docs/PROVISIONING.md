# Provisioning

tinylink reads all of its long-lived configuration from the encrypted
`nvs_creds` partition (see `partitions.csv`). The firmware never writes to
this partition. Provisioning happens once, at flash time, via
`tools/nvs_provision.py`.

## Required NVS keys

All keys live in namespace `tinylink`.

| Key                  | Type    | Size  | Notes                              |
|----------------------|---------|-------|------------------------------------|
| `wifi_ssid`          | string  | ≤ 32  | WPA2-PSK SSID                      |
| `wifi_pass`          | string  | ≤ 64  | WPA2-PSK passphrase                |
| `wg_priv_key`        | blob    | 32 B  | WireGuard X25519 private key (raw) |
| `wg_peer_pub`        | blob    | 32 B  | WireGuard peer's public key (raw)  |
| `wg_peer_endpoint`   | string  | ≤ 64  | `host:port` of the WG peer         |
| `wg_peer_allowed_ip` | string  | ≤ 32  | `100.x.y.z/32`                     |
| `wg_local_ip`        | string  | ≤ 16  | This device's tailnet IPv4         |

The two `wg_*_key` entries are stored as raw 32-byte binary blobs, not
base64. The firmware base64-encodes them in place before passing them to
`droscy/esp_wireguard`.

## Generate a provisioning binary

```bash
source ~/entorno_investigación/bin/activate
. ~/esp/esp-idf-v5.5.4/export.sh

cp tools/credentials.csv.example tools/credentials.csv
# Edit tools/credentials.csv with the actual values for this device.

python tools/nvs_provision.py \
    --input tools/credentials.csv \
    --output build/nvs_creds.bin \
    --size 0x4000
```

This wraps `nvs_partition_gen.py` from ESP-IDF and produces a binary that
matches the `nvs_creds` slot in `partitions.csv` (offset `0x320000`,
size `0x4000`).

## Flash the provisioning binary

```bash
idf.py -p /dev/ttyUSB0 partition-table-flash      # one-time
esptool.py --chip esp32 -p /dev/ttyUSB0 \
    write_flash 0x320000 build/nvs_creds.bin
```

If flash encryption is enabled (it is, by default in this project), use
`encrypted-flash` instead so the bootloader writes a ciphertext blob:

```bash
esptool.py --chip esp32 -p /dev/ttyUSB0 \
    write_flash --encrypt 0x320000 build/nvs_creds.bin
```

## Rotating credentials

WiFi and peer endpoint can be rotated by re-generating `nvs_creds.bin` and
re-flashing the slot. Rotating the WireGuard private key requires also
updating the peer's `[Peer] PublicKey =` line — there is no on-device key
generation in M1.
