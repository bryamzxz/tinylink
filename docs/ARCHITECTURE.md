# Architecture

This document describes the tinylink runtime layout. For the on-the-wire
protocols see [`PROTOCOL.md`](PROTOCOL.md). For why we picked the cryptographic
primitives we did, see [`SECURITY-MODEL.md`](SECURITY-MODEL.md).

## Quick navigation

- [Component layout (M1)](#component-layout-m1) — original ts2021-only build.
- [Component layout (current — M1–M6 landed)](#component-layout-current--m1m6-landed)
- [WG netif as raw-IP carrier](#wg-netif-as-raw-ip-carrier) — why the netif
  has `ESP_NETIF_FLAG_IS_PPP` set yet does NOT speak PPP, and what overrides
  make it carry raw IP.
- [Direct-UDP NAT traversal](#direct-udp-nat-traversal) — the five conditions
  that flip `tailscale ping` from DERP fallback to direct-UDP path.
- [Data flow (M1)](#data-flow-m1) — register-only flow, kept for reference.

## Component layout (current — M1–M6 landed)

```
+------------------------- main/main.c -------------------------+
|  bringup():                                                   |
|     app_nvs_init / app_wifi_start / app_wifi_wait_connected   |
|     tinylink_init                                             |
|     tinylink_wg_socket_init   ← bind WG UDP socket EARLY      |
|     tinylink_stun_probe       ← STUN probes via WG socket so  |
|                                  advertised port == NAT map   |
|     tinylink_register loop                                    |
|     tinylink_dataplane_start  ← Stream=false + OmitPeers=true |
|                                  lite update with WorkingUDP  |
|     tinylink_long_poll_start  ← stream=true read-only poll    |
|     tinylink_derp_supervised_start                            |
|     tinylink_telemetry_start                                  |
|     tinylink_stun_reprobe_start                               |
+---------------------------------------------------------------+
        │
        ▼
+--------------- components/tinylink/src/ ----------------------+
|                                                               |
|  control plane (one Noise+H/2 channel reused for everything): |
|     ts2021_client.c   Noise IK over TLS Upgrade               |
|        ↑                                                      |
|        │                                                      |
|     register.c        POST /machine/register                  |
|     mapreq.c          POST /machine/map                       |
|       ├── mapreq_push_endpoints  Stream=false+OmitPeers=true  |
|       │                          (lite update — only writable |
|       │                          shape at CapVer ≥ 68)        |
|       └── mapreq_run_stream      Stream=true (read-only       |
|                                   netmap stream)              |
|                                                               |
|  data plane (single UDP socket, demuxed):                     |
|     wg_netif.c                                                |
|       ├── socket(AF_INET, SOCK_DGRAM)  ← shared with STUN     |
|       ├── rx_task                                             |
|       │     wg_demux_classify(buf[0])                         |
|       │       ├── HANDSHAKE_RESP  → handle_handshake_response |
|       │       ├── TRANSPORT       → handle_transport →        |
|       │       │                     decrypt → rx_cb           |
|       │       │                       │                       |
|       │       │                       ▼                       |
|       │       │                 wg_lwip::wg_rx_inject →       |
|       │       │                 tcpip_input (bypasses PPP     |
|       │       │                 framing — see below)          |
|       │       └── DISCO          → handle_disco_direct →      |
|       │                            decrypt + sealed Pong via  |
|       │                            sendto on the same socket  |
|       └── tx_task                                             |
|             drains tx_queue → sendto                          |
|             (encrypt happens inline in TCPIP context;         |
|              sendto must run OUTSIDE TCPIP to avoid lwIP      |
|              re-entrancy deadlock — see PR #41)               |
|                                                               |
|     wg_lwip.c                                                 |
|       esp_netif PPP-flagged (sidesteps IDF dhcpc_cb panic)    |
|       BUT we override:                                        |
|         lwn->output      = wg_lwip_ip4_output                 |
|         lwn->linkoutput  = wg_lwip_linkoutput                 |
|       so the netif carries raw IP both ways. Without these    |
|       overrides PPP would HDLC-frame egress and discard       |
|       ingress at the framing layer.                           |
|                                                               |
|     stun_probe.c     RFC 5389; uses wg_netif's socket so the  |
|                      public AddrPort matches the WG NAT map   |
|                                                               |
|     derp_client.c    Long-lived TLS upgrade                   |
|     tinylink.c::derp_supervised_task                          |
|       ├── handle_disco_relayed                                |
|       │     CMM → send_disco_pings_to_cmm_endpoints           |
|       │           (sends DISCO ping via wg_netif socket to    |
|       │            each peer endpoint — NAT punch)            |
|       └── default → wg_netif_inject_packet                    |
|             (DERP-relayed WG transport / handshake-resp re-   |
|              enters the demux + handler chain identically to  |
|              a UDP recv)                                      |
|                                                               |
|  application:                                                 |
|     tmp117.c         I²C continuous-mode driver               |
|     telemetry.c      JSON datagram, routed through wg_netif   |
+---------------------------------------------------------------+
```

## WG netif as raw-IP carrier

The WG netif is created with `ESP_NETIF_FLAG_IS_PPP` set. That flag was
chosen because it:
1. Tells esp_netif "no DHCP, no ARP, point-to-point" — exactly what a
   tunnel netif needs.
2. Sidesteps an IDF v5.5 panic in `esp_netif_internal_dhcpc_cb` that
   killed the trombik-component-based WG netif baseline.

But the flag also pulls in the PPP netstack glue
(`ESP_NETIF_NETSTACK_DEFAULT_PPP`) which assumes the netif speaks
HDLC-framed PPP on the wire. We're a raw-IP tunnel — there's no PPP
modem. Four IDF behaviors had to be overridden:

| Behavior                                                         | Override                                              |
|------------------------------------------------------------------|-------------------------------------------------------|
| `esp_netif_action_start` skips `netif_set_up` for PPP netifs     | call `netif_set_up(lwn)` explicitly post-attach       |
| Same path skips `netif_set_link_up`                              | call `netif_set_link_up(lwn)` explicitly              |
| Same path skips `netif_set_addr`                                 | call `netif_set_addr(lwn, ip, mask, gw)` explicitly   |
| `input_fn = esp_netif_lwip_ppp_input` HDLC-frames raw IP         | bypass: `wg_rx_inject` calls `tcpip_input(p, lwn)`    |
| `lwn->output` / `lwn->linkoutput` PPP-encapsulate egress         | replace both with raw-IP passthroughs                 |

After all five overrides the netif behaves exactly like a normal IP
tunnel netif from lwIP's POV — `ip4_input_accept` matches local dst,
`ip4_output` routes egress by subnet match (100.64.0.0/10 → WG netif),
and ICMP / TCP / UDP all flow through the WireGuard tunnel.

See PR #43's commit message for the diagnostic trail.

## Direct-UDP NAT traversal

`tailscale ping` shows `via 190.x.x.x:port` (direct UDP) instead of
`via DERP(mia)` only when ALL of these are true:

1. **STUN ran on the WG socket** — `tinylink_stun_probe` calls
   `stun_probe_run_on_socket(wg_netif_get_socket(), …)` so the public
   AddrPort the control plane advertises is the same NAT mapping the
   WG keepalives keep alive. Without this, the advertised port is for
   an ephemeral STUN socket that closes immediately.
2. **WG_DEMUX_DISCO classified before the peer-source filter** — the
   RX task in `wg_netif.c` runs `wg_demux_classify` first, then only
   applies the WG-peer source filter to WG protocol kinds. DISCO from
   a peer's reflexive endpoint is NOT from our handshake destination,
   so the old "drop everything not from peer.endpoint" filter would
   have killed the punch ping.
3. **Lite endpoint update** — `mapreq_push_endpoints` sends a
   `Stream=false && OmitPeers=true` MapRequest at boot. Per upstream
   `controlclient/auto.go:249-251`, that's the only shape modern
   Tailscale.com accepts as writable for Hostinfo / NetInfo /
   Endpoints. The success signal is HTTP 200 with body length 0 (the
   server can omit the response on a lite update).
4. **`NetInfo.WorkingUDP=true`** — empirically, controlplane.tailscale.com
   refuses to propagate Endpoints to peers without this signal. We set
   it true whenever the STUN probe succeeded (STUN responding IS proof
   UDP works).
5. **CallMeMaybe punch handler** — when the DERP supervisor receives
   a CMM, `send_disco_pings_to_cmm_endpoints` sends a fresh sealed
   DISCO ping via the WG socket to each v4-mapped peer endpoint. Each
   outbound ping opens our NAT for the peer's simultaneous probe;
   without this, port-restricted-cone NATs on either side stay closed
   against each other and direct never punches through.

The first four landed in PR #42 (`feat: direct UDP path end-to-end`);
the fifth is also in #42. PR #43 then made the netif carry raw IP so
real ICMP could traverse the now-direct path. See `MEMORY.md` entries
`reference_tinylink_direct_udp.md` and PR commit messages for the
forensic detail.

## Component layout (M1)

The original M1-only layout, kept for historical reference:

```
+--------------------------- main/ ------------------------------+
|  app_main()                                                    |
|     └── bringup state machine                                  |
|         ├── app_nvs_init()                                     |
|         ├── app_wifi_start() / wait                            |
|         ├── tinylink_init()                                    |
|         │     ├── keys_load_or_generate (NVS "tl_keys")        |
|         │     └── control_key_get      (NVS "tl_pin")          |
|         └── tinylink_register() loop                           |
|               ├── ts2021_connect (TLS+Upgrade+Noise IK)        |
|               ├── register_emit  (RegisterRequest JSON)        |
|               └── parse RegisterResponse                       |
+----------------------------------------------------------------+
        │
        ▼
+----------------- components/tinylink/ -------------------------+
|  Public API (include/tinylink.h)                               |
|     tinylink_init / tinylink_register / tinylink_get_keys      |
|                                                                |
|  Internal modules (src/)                                       |
|     keys.c           — NVS-backed Curve25519 identities        |
|     control_key.c    — HTTPS GET /key + NVS pinning            |
|     ts2021_client.c  — TLS, HTTP Upgrade, Noise framing        |
|     register.c       — RegisterRequest JSON + response parse   |
|     noise_ik.c       — Noise_IK_25519_ChaChaPoly_BLAKE2s SM    |
|     json_helpers.c   — cJSON wrappers                          |
|                                                                |
|  Vendored crypto (src/crypto/)                                 |
|     blake2s.c        — RFC 7693 reference                      |
|     hkdf_blake2s.c   — HMAC + Noise HKDF + RFC 5869 HKDF       |
|     curve25519.c     — TweetNaCl-derived placeholder           |
|     salsa20.c        — Salsa20 / HSalsa20 / XSalsa20           |
|     nacl_box.c       — crypto_box / crypto_box_open            |
+----------------------------------------------------------------+
        │
        ▼
+------------- ESP-IDF v5.5 ------------------------------------+
|  wifi / lwIP                                                  |
|  esp_tls + mbedtls (ChaCha20-Poly1305, Poly1305, X.509 bundle)|
|  cJSON                                                        |
|  nvs_flash                                                    |
+---------------------------------------------------------------+
```

## Data flow (M1)

1. `app_nvs_init()` mounts the `nvs` partition. Long-lived secrets live in
   the encrypted `nvs_creds` partition (`tl_creds` namespace, key
   `auth_key`); generated identities live in `tl_keys`; the pinned
   control plane public key lives in `tl_pin`.
2. `app_wifi_start()` reads `wifi_ssid` / `wifi_pass` from `tl_creds` and
   joins the network. The IP_EVENT_STA_GOT_IP handler raises a bit so the
   bringup task can proceed.
3. `tinylink_init()`:
   - Loads or generates the three Curve25519 identities (MachineKey,
     NodeKey, DiscoKey). On first boot these are written back to
     `tl_keys` and `"generated new node identity"` is logged.
   - Reads the pinned control plane public key from `tl_pin`. On first
     boot this is missing; we HTTPS-GET `/key?v=100`, parse
     `{"publicKey":"nlpub:<64-hex>"}`, and persist.
4. `tinylink_register()` runs in a loop until success:
   - `ts2021_connect()` opens TLS to `controlplane.tailscale.com:443`,
     sends a `POST /ts2021` HTTP Upgrade request whose body carries Noise
     IK msg1 inside a 4-byte handshake frame, reads the `101 Switching
     Protocols` response and the framed Noise IK msg2, completing the
     handshake. Optionally consumes an EarlyNoise frame containing a
     NodeKeyChallenge and signs it with the NodeKey via NaCl-box.
   - `register_emit()` builds the RegisterRequest JSON (NodeKey,
     OldNodeKey=zero, Hostinfo, Timestamp, Auth.AuthKey, optional
     NodeKeySignature) and sends it as a single Noise transport record.
     Reads the response, parses JSON, returns based on
     `MachineAuthorized`.

There is no data plane. After successful register the bringup logs
`"node registered, idle waiting for M2 (MapRequest)"` and the main task
is dormant.

## Memory budget (target)

Source: protocol research artifact §J. Numbers are projected end-state
sizes once M1–M5 are all landed.

| Component                                                    | Flash KB |
|--------------------------------------------------------------|----------|
| mbedTLS minimal preset + chachapoly + curve25519 + bundle    | 250      |
| nghttp2 (espressif/nghttp managed component)                 | 60       |
| lwIP + WiFi + FreeRTOS                                       | 180      |
| In-tree WireGuard data plane (wg_netif + wg_lwip + wg_*.c)   | 40       |
| Vendored BLAKE2s + HKDF + Salsa20 + NaCl-box                 | 12       |
| ts2021 Noise IK state machine (hand-rolled)                  | 4        |
| DERP client (M5)                                             | 6        |
| DISCO (M3)                                                   | 8        |
| STUN minimal (M4)                                            | 1        |
| MapRequest/Response JSON parser (jsmn-based, M2)             | 15       |
| App logic (TMP117, JSON emit, NVS, provisioning)             | 20       |
| Partition table, bootloader, NVS, OTA metadata               | 40       |
| **Total**                                                    | **~636** |

Fits a 1 MB OTA slot in 4 MB flash with dual-OTA partitions.

| Memory area                           | Peak SRAM KB |
|---------------------------------------|--------------|
| Application heap (mbedTLS, JSON, etc) | ~75          |
| WiFi + lwIP + mbedTLS contexts        | ~40          |
| FreeRTOS overhead                     | ~15          |
| **Total**                             | **~130**     |

Leaves ~390 KB free on the 520 KB SRAM chip. No PSRAM is required.

## FreeRTOS task layout (target, end-state)

| Task            | Stack | Prio   | Role                                               |
|-----------------|-------|--------|----------------------------------------------------|
| `net_io_task`   | 6 KB  | high   | single UDP recv, demux first byte → DISCO/WG/STUN  |
| `control_task`  | 8 KB  | medium | TLS+ts2021+HTTP/2+MapRequest long-poll             |
| `derp_task`     | 10 KB | medium | TLS to home DERP; only alive when direct path down |
| `wg_task`       | 4 KB  | high   | WireGuard encrypt/decrypt (esp_wireguard timer)    |
| `app_task`      | 3 KB  | low    | TMP117 poll → JSON → UDP send                      |

Total task stacks: ~31 KB SRAM. The M1 implementation uses only `main`
(8 KB) for bringup + register; the others land progressively in M2–M5.

## Threading model (M1)

| Task            | Stack | Prio | Owner                  |
|-----------------|-------|------|------------------------|
| `main`          | 8 KiB | 1    | bringup + register     |
| WiFi internals  | —     | —    | esp_wifi               |
| TLS internals   | —     | —    | esp_tls / mbedtls      |

The register state machine runs synchronously inside `main`; there are no
worker tasks in M1. M2 will introduce a long-lived `mapstream` task.
