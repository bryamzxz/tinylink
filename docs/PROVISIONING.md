# Provisioning

tinylink reads its long-lived credentials from NVS. Two partitions can
hold them (see `partitions.csv`):

- `nvs_creds` (offset `0x320000`, 16 KiB) — the dedicated, provisioner-
  written slot. Recommended: re-provisioning it never touches the
  firmware-owned state below.
- `nvs` (offset `0x10000`) — the default partition, which also holds the
  firmware-generated node identity and the control-key pin.

At boot the firmware mounts `nvs_creds` if it is present and looks each
credential up in this order, first hit wins:

1. `nvs_creds` partition, namespace `tl_creds`
2. `nvs` partition, namespace `tl_creds`
3. `nvs` partition, namespace `tinylink` (legacy; firmware before
   2026-09 read the WiFi credentials from here — a warning is logged so
   you know to re-provision when convenient)

**Everything is stored in plaintext.** Flash/NVS encryption is
deliberately not enabled (eFuse burns are irreversible; see
`docs/ROADMAP.md` § Execution queue and `docs/SECURITY-MODEL.md`).

## NVS layout

| Namespace   | Owner       | Contents                                        |
|-------------|-------------|-------------------------------------------------|
| `tl_creds`  | provisioner | WiFi credentials + Tailscale auth key           |
| `tl_keys`   | firmware    | Curve25519 identities, generated on first boot  |
| `tl_pin`    | firmware    | Pinned control plane public key (TOFU / fallback) |
| `tl_state`  | firmware    | TAI64N floor for WireGuard handshake timestamps |

You only need to populate `tl_creds`. The firmware fills the other
namespaces by itself.

## `tl_creds` keys (provisioner-supplied)

| Key         | Type   | Notes                                                |
|-------------|--------|------------------------------------------------------|
| `wifi_ssid` | string | WPA2-PSK SSID                                        |
| `wifi_pass` | string | WPA2-PSK passphrase                                  |
| `auth_key`  | string | Tailscale auth key (`tskey-auth-…`)                  |

There are no WireGuard keys to provision — the node's MachineKey,
NodeKey and DiscoKey are generated on-device at first boot.

## Generate a provisioning binary

```bash
source "$VENV/bin/activate"        # the python venv ESP-IDF was installed into
. "$IDF_PATH/export.sh"

cp tools/credentials.csv.example tools/credentials.csv
$EDITOR tools/credentials.csv

python tools/nvs_provision.py \
    --input tools/credentials.csv \
    --output build/nvs_creds.bin
```

This wraps `nvs_partition_gen.py` from ESP-IDF and produces a plaintext
image that matches the `nvs_creds` slot in `partitions.csv` (offset
`0x320000`, size `0x4000`).

## Flash the provisioning binary

```bash
esptool.py --chip esp32 -p /dev/ttyUSB0 write_flash 0x320000 build/nvs_creds.bin
```

No `--encrypt`: the firmware runs without flash encryption, so an
encrypted image would be unreadable. Flashing this slot leaves the
firmware-owned identity in the `nvs` partition untouched, so the node
keeps its Tailscale identity across re-provisioning.

## Generate a Tailscale auth key

In the Tailscale admin panel (`Settings → Keys → Generate auth key`):

- **One-off:** yes — the device registers exactly once. (Keep the key
  around: the in-place re-register path of M13 needs it if the node is
  ever deleted server-side.)
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
- Node identity rotation is not implemented (no remote trigger; see
  `docs/ROADMAP.md` § OTA).
