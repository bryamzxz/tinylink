# Architecture

This document describes the tinylink runtime layout. For the on-the-wire
protocols see [`PROTOCOL.md`](PROTOCOL.md). For why we picked the cryptographic
primitives we did, see [`SECURITY-MODEL.md`](SECURITY-MODEL.md).

## Quick navigation

- [Component layout (M1)](#component-layout-m1) — original ts2021-only build.
- [Component layout (current — M1–M6 landed)](#component-layout-current--m1m6-landed)
- [WG netif as raw-IP carrier](#wg-netif-as-raw-ip-carrier) — why the netif
  uses `ESP_NETIF_FLAG_AUTOUP` + a custom no-op netstack (and why it
  used to need `IS_PPP` + 5 overrides, what changed, and what `idf-patches/`
  applies to make this work).
- [Direct-UDP NAT traversal](#direct-udp-nat-traversal) — the conditions
  that flip `tailscale ping` from DERP fallback to direct-UDP path,
  including pre-punch on netmap-receive and DiscoKey-gated WG
  endpoint roaming.
- [WireGuard handshake lifecycle](#wireguard-handshake-lifecycle) —
  proactive rekey + RX-stale watchdog + indefinite handshake-burst
  backoff. How the firmware survives peer restarts and arbitrary-length
  outages without manual intervention.
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
|       │       │                 tcpip_input (custom netstack |
|       │       │                 has no Ethernet/PPP framing)  |
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

The WG netif uses `ESP_NETIF_FLAG_AUTOUP` and a custom no-op netstack
(`s_wg_netstack_config` in `wg_lwip.c`). The full setup runs inside the
netstack's `init_fn` (which lwIP calls from `netif_add()` after zeroing
the netif's mtu/output/linkoutput/flags fields):

```
wg_lwip_attach():
   esp_netif_new(cfg with .stack = &s_wg_netstack_config)
   esp_netif_attach(s_netif, driver)
   wg_netif_set_rx_callback(wg_rx_inject, s_netif)
   esp_netif_action_start(s_netif, ...)
       └── esp_netif_lwip_add → netif_add(...wg_lwip_netif_init...)
              └── lwIP zeros mtu/output/linkoutput/flags
              └── lwIP applies ip_addr/netmask/gw from base.ip_info
              └── wg_lwip_netif_init():
                     netif->name = "wg"
                     netif->mtu  = s_pending_mtu
                     netif->output     = wg_lwip_ip4_output     (raw IP)
                     netif->linkoutput = wg_lwip_linkoutput     (raw IP)
                     s_lwn = netif    (cached for tcpip_input)
   netif_set_up(s_lwn)        (post-action_start, NOT in init_fn —
   netif_set_link_up(s_lwn)    callbacks fire on a netif not yet linked
                               into netif_list otherwise)
```

End result: lwIP sees a netif up at admin+link level, bound to our
tailnet IP, with raw-IP egress through `wg_netif_send_plaintext()`.
Inbound RX uses `tcpip_input(p, s_lwn)` directly — the no-op netstack's
`input_fn` is a stub returning `ESP_FAIL` (only present to satisfy
`esp_netif_config_sanity_check`, never called).

### REQUIRED: `idf-patches/`

The above only works because two patches in `idf-patches/` are applied
to ESP-IDF v5.5.4. Without them, the boot panics in `dhcp_state.c:52`
from the lwIP task as soon as `wg_lwip_attach()` triggers a
`netif_set_addr()` ext-callback that reaches
`esp_netif_internal_dhcpc_cb()` → `dhcp_ip_addr_store(NULL)`.

| Patch | Target | What it does |
|---|---|---|
| `0001-fix-esp_netif-restore-DHCP_CLIENT-whitelist-in-dhcpc.patch` | `esp_netif_lwip.c` | Gate `dhcp_ip_addr_store()` on `ESP_NETIF_DHCP_CLIENT` (the original 2018 invariant that was silently removed in 2022 commit `356bc603c4`). |
| `0002-fix-lwip-dhcp_state-null-guard-dhcp_ip_addr_-store-r.patch` | `dhcp_state.c` | Defensive NULL-check on `netif_dhcp_data(netif)` before deref. |

See [`idf-patches/README.md`](../idf-patches/README.md) for the full
forensic chain — `esp-protocols#800`, the partial fix in `c8c10214f8`
(2025), and why this branch's whitelist completes the original
intent.

### Historical: why we used to fake PPP

Pre-2026-05, the firmware set `ESP_NETIF_FLAG_IS_PPP` purely to sidestep
the same panic by getting esp_netif to take the PPP code path (where
the `_IS_NETIF_ANY_POINT2POINT_TYPE` gate skipped the broken
`dhcp_ip_addr_store()` call). That cost:

- ~4.4 KiB of heap held by `ppp_pcb` + LCP/IPCP FSM allocations.
- ~30 s of LCP Configure-Request retries at boot trying to negotiate
  with a non-existent serial peer.
- 5 explicit overrides (set_addr, set_up, link_up, output, linkoutput,
  tcpip_input bypass) to undo the PPP-specific defaults.
- `+3 KB` of binary linked-in PPP/LCP/FSM code.

The current architecture removes all of that. The historical setup is
preserved in commit `4a915df^` (the parent of the no-IS_PPP commit) for
anyone bisecting an unrelated regression to before the netstack switch.

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
6. **Pre-punch on netmap-receive** — on every non-KeepAlive netmap
   arrival, `prepunch_pings_to_peer_endpoints` (in `tinylink.c`) sends
   a sealed DISCO ping to every v4 endpoint of every peer. This opens
   or refreshes our NAT mapping proactively, so the very first inbound
   packet from any peer finds an open path instead of waiting for the
   peer to learn our endpoint, send a CMM via DERP, and trigger
   condition (5). Closes the cold-start "direct connection not
   established" gap that previously took 3+ DERP rounds to resolve.
7. **WG endpoint roaming via DISCO direct** — when a sealed DISCO
   ping or pong from the WG peer's DiscoKey arrives at the WG socket,
   `handle_disco_direct` (in `wg_netif.c`) promotes the source
   AddrPort to `g.peer.peer_endpoint_v4_be` + `peer_endpoint_port` if
   different. Without this, the peer's ICMP echo requests would arrive
   via direct UDP but our echo replies would be sent to the
   netmap-picked endpoint (often a stale public NAT mapping), getting
   dropped peer-side. Gated by DiscoKey: only frames from the WG
   peer's DiscoKey roam — DISCO pongs from other Tailscale peers in
   the netmap (e.g. a laptop that ran our prepunch ping) cannot flap
   our WG transport target.

Conditions 1-5 landed in PR #42; condition (1) was also touched by
PR #53 (STUN re-probe via WG socket); the netif ICMP carrier (raw IP
egress/ingress) landed in PR #43. Conditions (6) + (7) landed together
in PR #55 — see `CHANGELOG.md` for the empirical results
(38-min mega-ping from Servidor1: 4.95 % loss, 147 ms avg, 23 ms min
RTT direct UDP). See `MEMORY.md` entry
`reference_tinylink_direct_udp.md` and PR commit messages for the
forensic detail.

## WireGuard handshake lifecycle

The data plane is **initiator-only by design** — `wg_handshake.{c,h}`
intentionally omits responder support, and `wg_netif.c`'s RX path
silently drops every inbound `HANDSHAKE_INIT` (UDP and DERP-injected
both). This halves the WG state machine and the per-session memory
footprint; the trade-off is that we cannot react to a peer-initiated
rekey, so the session lifecycle is driven entirely from our side.

The WireGuard whitepaper §6.5 prescribes:

| constant            | value | role                                          |
|---------------------|-------|-----------------------------------------------|
| `REKEY_AFTER_TIME`  | 120 s | responder fires a fresh `HANDSHAKE_INIT`      |
| `REJECT_AFTER_TIME` | 180 s | responder invalidates the previous session   |
| `REKEY_TIMEOUT`     | 5 s   | retransmit interval for unacknowledged INIT  |

Because we drop the responder's INIT at 120 s, without intervention
the responder hits 180 s, invalidates our transport keys, and our
outbound packets enter a silent black hole — the local `g.state`
still reads `UP`, but every encrypted frame is dropped peer-side.
This was observed in the wild as ICMP failing 100 % at
`icmp_seq=181`.

Fix: proactive rekey from our side, fired *before* the responder's
120 s mark.

```
   t=0       handshake_completed_us = now()
              g.state = UP
              g.rekey_in_flight = false

   t≈110s   rx_task observes session age > WG_REKEY_AFTER_MS:
              start_rekey() builds a fresh INIT (new ephemeral, new
              local_index) and sends it. g.state stays UP. The
              existing g.transport session keeps serving inbound
              decrypts and outbound encrypts with the OLD keys —
              both are still valid until the responder rotates at
              120 s. g.rekey_in_flight = true.

   t≈110s+RTT  HANDSHAKE_RESP arrives. handle_handshake_response
              accepts it because rekey_in_flight is set.
              wg_transport_session_init swaps NEW keys into
              g.transport atomically. Any encrypt that just sampled
              the OLD pointer is fine on the wire (responder accepts
              both during its rotation grace). g.rekey_in_flight =
              false; handshake_completed_us = now(); cycle restarts.
```

Three retry layers + a watchdog cover failure modes:

- **Rekey retry**: same 5 s × 12 budget as the cold path. Each retry
  re-runs `start_rekey()` (new ephemeral, new index). `g.state`
  remains `UP` so app traffic isn't paused.
- **Cold-path fallback**: if all 12 rekey attempts miss (60 s),
  session age is ~170 s and the 180 s deadline is imminent. We
  transition to `HANDSHAKE_PENDING` and run a cold handshake.
  This briefly pauses `wg_netif_send_plaintext` and inbound
  decrypts, but is strictly better than the silent black hole that
  follows the 180 s mark.
- **Indefinite handshake-burst backoff** (PR #56): when the cold-path
  handshake budget itself exhausts (12 × 5 s = 60 s with no peer
  response — typical of a peer offline for a full OS reboot), the
  firmware does NOT transition to `WG_NETIF_FAILED` (which used to be
  terminal and required an ESP32 power-cycle). Instead, log
  `W handshake budget exhausted ... backing off Ns before next burst`,
  reset `handshake_attempt = 0`, and back-date `last_handshake_us` so
  the next burst fires `WG_HANDSHAKE_BACKOFF_MS = 30 s` from now.
  Repeats indefinitely. Recovery is fully autonomous regardless of
  peer outage length.

In addition:

- **RX-stale watchdog** (PR #56): the proactive rekey above triggers
  on session age, not on lack of inbound traffic. That misses a class
  of failures where the peer's tailscaled restarts mid-session — the
  peer's DiscoKey survives but its WG session keys do not, so our
  outbound transport encrypts cleanly with the OLD keys and `sendto`
  succeeds at the wire, but the peer drops every datagram on decrypt.
  Pre-watchdog firmware would wait up to 110 s (until the age-based
  rekey fires) before noticing. The watchdog stamps
  `g.last_transport_recv_us` on every successful transport decrypt
  (including zero-plaintext keepalives — liveness, not payload).
  Fires at `WG_RX_STALE_THRESHOLD_MS = 30 s`: if no decrypt has
  happened in 30 s, force a rekey via the same make-before-break
  path. 30 s is well above WG persistent-keepalive (25 s) and
  Tailscale's typical DISCO cadence (~3 s direct), so genuine RX
  silence on transport for 30 s is abnormal in practice.

The age-based trigger reads `g.last_handshake_completed_us` (set on
every successful handshake response, cold or rekey), not
`g.last_handshake_us` (set on every INIT we send). This matters
during retries — we don't want to delay the next rekey just because
the boot handshake took three attempts to complete.

`WG_NETIF_FAILED` is now unreachable in the current code (kept in the
enum for forward compat / external API stability). The state machine
is effectively `IDLE → HANDSHAKE_PENDING ↔ UP`, with bursts +
backoff handling all failure modes that previously sent the firmware
to `FAILED`.

Empirical validation: `sudo reboot` of the WG peer (~216 s downtime
including BIOS + kernel + service start) recovers in ~130 s of
observable telemetry outage, fully autonomous, zero ESP32
intervention. Pre-fix this scenario required power-cycling the ESP32.

Responder mode is no longer required for steady-state operation. It
remains a follow-up for peer-roaming corner cases where the peer
endpoint changes mid-session and only the peer can re-initiate.

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
