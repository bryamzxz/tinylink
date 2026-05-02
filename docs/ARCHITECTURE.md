# Architecture

This document describes the tinylink runtime layout. For the on-the-wire
protocols see [`PROTOCOL.md`](PROTOCOL.md). For why we picked the cryptographic
primitives we did, see [`SECURITY-MODEL.md`](SECURITY-MODEL.md).

## Component layout

```
+--------------------------- main/ ------------------------------+
|  app_main()                                                    |
|     └── bringup state machine                                  |
|         ├── app_nvs_init()                                     |
|         ├── app_wifi_start() / wait                            |
|         ├── app_wireguard_start() / wait_up                    |
|         ├── app_sensor_init()         (TMP117 / I²C)           |
|         └── app_telemetry_start(peer.allowed_ip)               |
+----------------------------------------------------------------+
        │
        ▼
+----------------- components/tinylink/ -------------------------+
|  tinylink_version_string()           — implemented (M1)        |
|  tinylink_ts2021_handshake()         — TODO (M2)               |
|  tinylink_map_response_parse()       — TODO (M3)               |
|  tinylink_disco_send_ping()          — TODO (M4)               |
|  tinylink_derp_connect()             — TODO (M5)               |
|  tinylink_harden_apply_defaults()    — TODO (M6)               |
+----------------------------------------------------------------+
        │
        ▼
+------------- ESP-IDF v5.5 + droscy/esp_wireguard --------------+
|  wifi / lwIP (CONFIG_LWIP_TCPIP_CORE_LOCKING=y, REQUIRED)      |
|  esp_wireguard (data plane)                                    |
|  mbedTLS (chacha20-poly1305 only, in M2+)                      |
|  vendored: curve25519-donna, blake2s, nacl-box (M2+)           |
+----------------------------------------------------------------+
```

## Data flow (M1 only)

1. `app_nvs_init()` mounts the encrypted `nvs` partition. The secondary
   `nvs_creds` partition holds long-term keys; reads are wrapped by
   `app_nvs_read_str` / `app_nvs_read_blob` against namespace `tinylink`.
2. `app_wifi_start()` registers WIFI/IP event handlers, reads `wifi_ssid` /
   `wifi_pass` from NVS, and calls `esp_wifi_start()`. The event handler
   raises `WIFI_CONNECTED_BIT` on `IP_EVENT_STA_GOT_IP`.
3. `app_wireguard_start()` reads the WG private key (32 B blob), peer pubkey
   (32 B blob), peer endpoint (`host:port`), allowed-ip (`100.x.y.z/32`), and
   local IP. The two binary keys are base64-encoded in place because
   `droscy/esp_wireguard` expects base64 strings in `wireguard_config_t`.
4. `app_sensor_init()` configures the TMP117 for continuous mode with 8-sample
   averaging.
5. `app_telemetry_start()` spawns a FreeRTOS task at priority 5, stack 4 KiB.
   Every `CONFIG_TINYLINK_TELEMETRY_INTERVAL_MS` it reads the sensor and
   sends a JSON datagram to the peer's allowed-ip on
   `CONFIG_TINYLINK_TELEMETRY_UDP_PORT`.

## Memory budget (target)

- Flash: ≤ 1.0 MiB per OTA slot through M5; M6 hardening must keep room for
  the DERP TLS path. The 1.5 MiB OTA slots in `partitions.csv` give ~50 %
  headroom.
- Heap on idle (M1): target ≤ 60 KiB free heap available after bringup, so
  WG packet handling has room for receive bursts.
- No PSRAM. PSRAM-only configurations are explicitly out of scope.

## Threading model

| Task            | Stack | Prio | Owner                  |
|-----------------|-------|------|------------------------|
| `main`          | 4 KiB | 1    | bringup                |
| WiFi internals  | —     | —    | esp_wifi               |
| `wireguard_*`   | —     | —    | esp_wireguard / lwIP   |
| `telemetry`     | 4 KiB | 5    | `app_telemetry`        |

No new tasks are created inside packet hot-paths. `lwIP TCP/IP core locking`
must remain enabled (see `sdkconfig.defaults`).
