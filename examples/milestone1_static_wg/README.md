# Example: Milestone 1 — static WireGuard peer

End-to-end walk-through of bringing up a WROOM-32E with tinylink M1 against
a single fixed WireGuard peer (e.g. a Linux box running `wg-quick`).

## What this example is

- One ESP32 (sensor side) running tinylink.
- One peer (server side) running standard WireGuard on Linux/macOS/BSD.
- One TMP117 sensor sending JSON datagrams to the peer over UDP/9999.

No control plane (`controlplane.tailscale.com`) is involved. No DERP. The
peer's pubkey, endpoint and tailnet IP are static and provisioned at flash
time.

## Prerequisites

- A running Linux peer with a public IP or a port-forward to UDP/51820.
- WireGuard installed on the peer.
- An ESP32-WROOM-32E flashed with tinylink (see [`docs/BUILDING.md`](../../docs/BUILDING.md)).
- A populated `nvs_creds` partition flashed to the device
  (see [`docs/PROVISIONING.md`](../../docs/PROVISIONING.md)).

## Step 1 — generate two key pairs

On a trusted host (NOT on the device):

```bash
# Device key pair
wg genkey > device.priv
wg pubkey  < device.priv > device.pub

# Server key pair
wg genkey > server.priv
wg pubkey  < server.priv > server.pub
```

`device.priv` and `server.priv` are 44-character base64 strings. The raw
32-byte forms are what tinylink wants in NVS:

```bash
# Strip base64 → 32-byte raw
base64 -d device.priv > device.priv.bin   # tinylink: wg_priv_key
base64 -d server.pub  > server.pub.bin    # tinylink: wg_peer_pub
```

## Step 2 — provision the device

Edit `tools/credentials.csv` so that:

- `wg_priv_key` points at `device.priv.bin`
- `wg_peer_pub` points at `server.pub.bin`
- `wg_peer_endpoint` is `your.server.tld:51820`
- `wg_peer_allowed_ip` is the tailnet IPv4 you assigned the server (`/32`)
- `wg_local_ip` is the tailnet IPv4 you assigned the device

Then run `tools/nvs_provision.py` and flash the resulting `nvs_creds.bin`.

## Step 3 — configure the peer

Use [`wg_peer_config.txt.example`](wg_peer_config.txt.example) as a starting
point. The peer's `[Peer]` section uses the device's *public* key (base64
form of `device.pub`).

## Step 4 — bring it up

On the peer:

```bash
sudo wg-quick up ./wg_peer_config.txt
sudo nc -ulkp 9999          # see telemetry datagrams
```

Power the device. Within ~30 s of WiFi association you should see JSON
lines like:

```json
{"device":"sensor-cali","ts":42137,"temp_c":24.531}
```

If you do not see them within ~60 s, see the troubleshooting section in
`docs/BUILDING.md`.
