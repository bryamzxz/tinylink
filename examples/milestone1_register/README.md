# Example: Milestone 1 — register with the Tailscale control plane

End-to-end walk-through of provisioning a WROOM-32E so it appears in your
Tailscale admin panel as an active node. There is no data plane in M1, so
once the device shows up online you cannot ping it yet — that lands in M2.

## What you should see when this works

In `https://login.tailscale.com/admin/machines`:

- A new machine named `sensor-cali` (or whatever
  `CONFIG_TINYLINK_DEVICE_HOSTNAME` is set to).
- OS reported as `esp32`.
- An assigned `100.x.y.z` IPv4.
- Status: online (green dot).

## Prerequisites

- A Tailscale account with admin access to the tailnet.
- ESP-IDF v5.5.x set up locally (see [`docs/BUILDING.md`](../../docs/BUILDING.md)).
- A WROOM-32E board flashed with tinylink.

## Step 1 — generate a one-off auth key

In the Tailscale admin: **Settings → Keys → Generate auth key**.

- Type: **One-off** (single use; the device will register exactly once).
- Reusable: off.
- Ephemeral: off (we want the node persisted across reboots).
- Pre-approved: optional. If off, the device will register but stay in
  `MachineAuthorized=false` until you click "Authorize" in the admin
  panel; tinylink keeps retrying on a slow cadence until you do.

Copy the `tskey-auth-…` string; you will only see it once.

## Step 2 — fill in `tools/credentials.csv`

```bash
cp tools/credentials.csv.example tools/credentials.csv
$EDITOR tools/credentials.csv
```

Set:

- `wifi_ssid` — your WPA2 network name.
- `wifi_pass` — its passphrase.
- `auth_key` — the `tskey-auth-…` from Step 1.

`tinylink` itself generates the three Curve25519 identities (MachineKey,
NodeKey, DiscoKey) on first boot and persists them in NVS namespace
`tl_keys`. You do not need to provision keys manually.

## Step 3 — generate `nvs_creds.bin`

```bash
source "$VENV/bin/activate"
. "$IDF_PATH/export.sh"

python tools/nvs_provision.py \
    --input tools/credentials.csv \
    --output build/nvs_creds.bin
```

## Step 4 — build, flash, monitor

```bash
idf.py set-target esp32       # one-time per checkout
idf.py build
idf.py -p /dev/ttyUSB0 flash
esptool.py --chip esp32 -p /dev/ttyUSB0 \
    write_flash 0x320000 build/nvs_creds.bin
idf.py -p /dev/ttyUSB0 monitor
```

## What the logs should look like

On a clean first boot, expect (compressed):

```
I (...) tinylink: tinylink 0.1.0 starting on sensor-cali
I (...) app_wifi: STA start, connecting
I (...) app_wifi: got ip 192.168.x.y
I (...) tl_keys: generated new node identity
I (...) ctrl_key: control pub fetched and pinned
I (...) ts2021: sent Noise msg1 (100 bytes), waiting for 101
I (...) ts2021: got 101 Switching Protocols
I (...) ts2021: Noise IK handshake complete
I (...) ts2021: EarlyNoise: signed NodeKeyChallenge (NN bytes)
I (...) register: /machine/register sent (NNN bytes JSON)
I (...) register: MachineAuthorized=true — node registered
I (...) tinylink: node registered, idle waiting for M2 (MapRequest)
```

If the auth key was not pre-approved you will see
`MachineAuthorized=false — waiting for operator approval` instead;
go to the admin panel and click "Authorize." The retry cadence is
`CONFIG_TINYLINK_REGISTER_RETRY_MS` (default 30 s).

## Troubleshooting

- **`control_key fetched and pinned` never appears** → DNS/TLS path is
  broken. Check WiFi connectivity and that
  `CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y` was in `sdkconfig.defaults`.
- **Handshake hangs after `sent Noise msg1`** → the upgrade token might
  have shifted in the Tailscale wire format. Look at
  `components/tinylink/src/ts2021_client.c` and grep for `TS2021_VERIFY`.
- **`MachineAuthorized=false` forever** → check the admin panel:
  the node should be visible but in "pending" state.
- **A bad `auth_key` is reported as a generic error** — re-generate from
  the admin panel, re-flash NVS.
