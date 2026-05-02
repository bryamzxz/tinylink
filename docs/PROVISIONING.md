# Provisioning

tinylink reads its long-lived configuration from the encrypted `nvs_creds`
partition (see `partitions.csv`). The firmware never writes credentials
here; node identities live in a separate namespace (`tl_keys`) that the
firmware *does* write on first boot.

## NVS layout

| Namespace   | Owner       | Contents                                      |
|-------------|-------------|-----------------------------------------------|
| `tl_creds`  | provisioner | WiFi credentials + Tailscale auth key         |
| `tl_keys`   | firmware    | Curve25519 identities, generated on first boot |
| `tl_pin`    | firmware    | Pinned control plane public key (TOFU)        |

You only need to populate `tl_creds` at flash time. The firmware fills the
other two namespaces by itself.

## `tl_creds` keys (provisioner-supplied)

| Key         | Type   | Notes                                                |
|-------------|--------|------------------------------------------------------|
| `wifi_ssid` | string | WPA2-PSK SSID                                        |
| `wifi_pass` | string | WPA2-PSK passphrase                                  |
| `auth_key`  | string | One-off Tailscale auth key (`tskey-auth-…`)          |

There are no WireGuard keys in M1 — the WG data plane returns in M2.

## Generate a provisioning binary

```bash
source ~/entorno_investigación/bin/activate
. ~/esp/esp-idf-v5.5.4/export.sh

cp tools/credentials.csv.example tools/credentials.csv
$EDITOR tools/credentials.csv

python tools/nvs_provision.py \
    --input tools/credentials.csv \
    --output build/nvs_creds.bin
```

This wraps `nvs_partition_gen.py` from ESP-IDF and produces a binary that
matches the `nvs_creds` slot in `partitions.csv` (offset `0x320000`,
size `0x4000`).

## Flash the provisioning binary

```bash
esptool.py --chip esp32 -p /dev/ttyUSB0 \
    write_flash --encrypt 0x320000 build/nvs_creds.bin
```

(The `--encrypt` flag is required because `CONFIG_NVS_ENCRYPTION=y` is
on by default in this project.)

## Generate a Tailscale auth key

In the Tailscale admin panel (`Settings → Keys → Generate auth key`):

- **One-off:** yes — the device registers exactly once.
- **Reusable:** no.
- **Ephemeral:** no — we want the node persisted across reboots.
- **Pre-approved:** optional. If off, the device will register but stay
  in `MachineAuthorized=false` until you click "Authorize" in the admin
  panel; tinylink keeps retrying until then.

The `tskey-auth-…` string only appears once in the admin UI; copy it
straight into `tools/credentials.csv`.

## Rotating credentials

- WiFi password change → re-generate `nvs_creds.bin` and re-flash the
  slot.
- Tailscale auth key change → only relevant if the device needs to
  re-register (e.g. node was force-deleted from the admin panel). The
  on-device NodeKey persists across reboots, so under normal operation
  no re-registration is needed.
- NodeKey rotation is not implemented in M1. M6 (hardening) will add a
  rotation hook.
