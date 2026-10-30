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
|     tinylink_derp_supervised_start ← spawn + connect the home |
|                                  DERP now, parallel to the    |
|                                  register (1.3.5)             |
|     tinylink_stun_probe_start ← STUN probes via WG socket so  |
|                                  advertised port == NAT map;  |
|                                  own task, parallel to the    |
|                                  register (1.3.5)             |
|     tinylink_register loop                                    |
|     tinylink_dataplane_start  ← waits ≤ 300 ms for STUN, then |
|                                  Stream=false + OmitPeers=true|
|                                  lite update with WorkingUDP  |
|     tinylink_long_poll_start  ← stream=true read-only poll    |
|     (telemetry: started by the first netmap)                  |
|     (endpoint push: no task — flagged by the STUN reprobe,    |
|      executed by the long-poll on its next reconnect)         |
|     tinylink_stun_reprobe_start                               |
+---------------------------------------------------------------+
        │
        ▼
+--------------- components/tinylink/src/ ----------------------+
|                                                               |
|  control plane (one Noise+H/2 channel reused for everything): |
|     ts2021_client.c   Noise IK over HTTP Upgrade (:80/:443)   |
|        │   prologue "Tailscale Control Protocol v148"         |
|        │   (TINYLINK_CAPVER=148, clears headscale floor 116); |
|        │   consume_early_payload reads EarlyNoise as a byte   |
|        │   STREAM across Noise records (5B magic|BE32|JSON)   |
|        ↑                                                      |
|        │                                                      |
|     register.c        POST /machine/register (Version=138)    |
|     mapreq.c          POST /machine/map      (Version=138)    |
|       ├── mapreq_push_endpoints  Stream=false+OmitPeers=true  |
|       │                          (lite update — only writable |
|       │                          shape at CapVer ≥ 68)        |
|       └── mapreq_run_stream      Stream=true (read-only       |
|                                   netmap stream); skip_value  |
|                                   depth-bounded (jsmn_skip.h, |
|                                   MAX_DEPTH=64) so an          |
|                                   adversarial nested netmap    |
|                                   can't overflow the LP stack |
|                                                               |
|  data plane (single UDP socket, demuxed):                     |
|     wg_netif.c                                                |
|       ├── socket(AF_INET, SOCK_DGRAM)  ← shared with STUN     |
|       ├── rx_task                                             |
|       │     wg_demux_classify(buf[0])                         |
|       │       ├── HANDSHAKE_RESP  → handle_handshake_response |
|       │       ├── TRANSPORT       → handle_transport →        |
|       │       │                     decrypt into pbuf → rx_cb |
|       │       │                     (replay check + key copy, |
|       │       │                      AEAD unlocked, commit    |
|       │       │                      under g.lock — C2, 1.3.3)|
|       │       │                       │                       |
|       │       │                       ▼                       |
|       │       │                 wg_lwip::wg_rx_inject →       |
|       │       │                 LOCK_TCPIP_CORE + ip_input in |
|       │       │                 the caller's task, no hop to  |
|       │       │                 tiT (C1-S, 1.3.3; custom      |
|       │       │                 netstack: no Eth/PPP framing) |
|       │       └── DISCO          → handle_disco_direct →      |
|       │                            decrypt + sealed Pong via  |
|       │                            sendto on the same socket  |
|       └── tx_task                                             |
|             drains the TX ring (slot indices) → sendto / DERP |
|             (encrypt happens inline in TCPIP context, on a    |
|              counter reserved under g.lock — C2, 1.3.3;       |
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
|       │     (gated: relayed DISCO whose sender DiscoKey !=    |
|       │      active WG peer's is dropped — knownPeerDiscoKey, |
|       │      via wg_netif_get_peer_disco_pub)                 |
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

## Wall clock and certificate dates (M16, 2026-09)

`tl_time.c`: at boot the clock is floored to max(build epoch, last NTP
time persisted in `tl_state:time_floor`); SNTP starts on GOT_IP. The
three TLS clients attach the IDF certificate bundle through
`tl_crt_bundle_attach()`, whose verify callback clears
`BADCERT_FUTURE`/`EXPIRED` only while the clock is not yet synced and
then defers to the bundle's own callback. Result: offline boots and the
first handshakes of a boot behave as before (no date check); every
handshake after the first sync validates `notBefore`/`notAfter`. The
telemetry task persists the synced time once it is a day past the
stored floor (hourly until 1.3.2 — each NVS write may erase a 4 KB
sector, which stalls both CPUs); the floor only has to stay ≤ real time
and never decrease, which holds at any write interval.

## WireGuard roaming and the handshake lock (M16, 2026-09)

`wg_rx` authenticates TRANSPORT and handshake RESPONSE datagrams from an
unexpected source first (AEAD + RFC 6479 window / Noise response
verification) and, on success, moves the peer endpoint to that source
(`roam_to`, under `g.lock` like every other endpoint write) — the
whitepaper's roaming rule. INIT/COOKIE from unknown sources are dropped
unauthenticated. The handshake state machine (`g.handshake`, `g.state`,
rekey flags, the pending INIT) is serialized by `g.hs_lock` between the
RX task's timer blocks, the DISCO-pong INIT re-send, the DERP task's
kicks (`wg_netif_handshake_kick`) and the DERP-relayed response path;
lock order is always `g.hs_lock` → `g.lock`, and no wg lock is held
across a DERP/TLS call (DERP copies go through the `wg_tx` worker).

Round 1.3.3 (C2) — `g.lock` no longer covers the transport AEAD
(~400 µs per MTU), so an RX decrypt (wg_rx / DERP task) and a TX encrypt
(tiT / telemetry) run on both cores at once. TX reserves its counter and
copies the send key under the lock (`wg_transport_tx_reserve`) and seals
outside it; RX copies the receive key after the header / index / replay
pre-check (`wg_transport_rx_begin`), opens outside the lock and commits
under it (`wg_transport_rx_commit`: refuses a ticket whose keypair
generation is gone — rekey or stop since begin — re-checks the window,
then records the counter). The AEAD never reads `g.transport`'s key
bytes, so a rekey or a scrub cannot pull them from under it.

Round 1.3.3 (C1-S) — the AEAD decrypts straight into the PBUF_RAM pbuf
lwIP receives, and `wg_rx_inject` runs `ip_input` under
`LOCK_TCPIP_CORE()` in the decrypting task (wg_rx or the DERP task)
instead of posting to tiT with `tcpip_input`: one copy and one task hop
less per inbound packet; replies the input triggers (ICMP echo) are
encrypted on that task's stack. Full lock order: `g.hs_lock` → lwIP core
lock → `g.lock`.

Round 1.3.2 (B7) — the first INIT of a boot used to be lost (sent
direct at netmap time, before the peer punched its side and before the
DERP login) and retried only after `REKEY_TIMEOUT` + the old 1-s RX
tick. Now: the RX wait is deadline-based (`wg_timers.h`), every new
INIT also goes via DERP while no direct path is confirmed (an
authenticated datagram on the UDP socket within the RX-stale window),
and while a handshake is pending the INIT *of the attempt in flight* is
re-sent on DERP login, on a CallMeMaybe from the peer (direct, + DERP)
and on a solicited pong (direct). The re-sends are the same 148 bytes,
not new attempts — the responder takes the first copy and drops the rest
as a TAI64N replay — so new INITs stay one per `REKEY_TIMEOUT`
(wireguard-go / kernel rule; magicsock queues the INIT on DERP and sends
to both paths while `bestAddr` is untrusted). Until 1.3.5 a session
that came up on a DERP-relayed response sent every frame on both paths
until something authenticated on the UDP socket ("direct path
confirmed"); since 1.3.6 the path selection below decides. Wake cadence
(B21): `wg_rx` sleeps until its next timer deadline, at most
`REKEY_TIMEOUT` (5 s) when idle; `wg_tx` blocks until a frame arrives
(10-s idle wait, woken by a sentinel on stop); both feed the task WDT at
most once per second — 3 → ~0.3 light-sleep exits/s for an idle tunnel.

Round 1.3.6 — path selection (`wg_path.h`, pure, `test_wg_path.c`).
Every frame goes direct only (DIRECT), direct + DERP (DUAL) or DERP
only (RELAY). DIRECT is entered only on a pong to our own DISCO ping
(txid + source bound by the prober: a round trip on that address pair) —
a datagram *from* the peer proves only peer→us, and on the sensor a
one-way path held the old "confirmed" state for an hour. DIRECT is kept
by the peer's passive keepalives, which answer data it received (we
sent it direct only): the first data frame after the last proof must be
answered within KEEPALIVE_TIMEOUT + 2 s, else the path lapses to DUAL
with one ping; the peer's handshake response and its first data after a
handshake (its TSMP disco advert) cancel its pending keepalive and
restart the window once each. No pong in 5 s → RELAY: every endpoint is
probed (10 s, doubling to 60 s, while data flows). A pong from the
current endpoint with nothing authenticated from the peer since the
unanswered frame means DISCO works and WireGuard does not (1.3.5 soak:
30 s of silence, fixed by the RX-stale rekey in 60 ms): RELAY too, and a
make-before-break rekey at once — the first of a streak only; a fresh
session silent as well backs the direct re-tests off to one a minute.
When a lapse is confirmed — that ping unanswered, answered with
WireGuard silent, or the endpoint moved elsewhere first — the
direct-only frames of the last 40 s are re-sent via DERP (`wg_tx`'s
rescue ring; the peer's replay window drops those it has). Steady state
costs no packet (upstream heartbeats a ping every 3 s). A pong from another endpoint
moves a valid current one only if clearly better (upstream `betterAddr`
points, +20 private, > 15 points and > 25 ms, compared within one ping
round); an authenticated packet from another source roams only while
the current one is not valid. A late answer to a replaced INIT is
logged and dropped; a pong replaces the INIT in flight only when it
changed the path and the INIT is ≥ 2.5 s old.

## `/stats` (M16, 2026-09)

The telemetry task's UDP socket also listens on
`CONFIG_TINYLINK_STATS_PORT` (27822) and answers any datagram from a
100.64.0.0/10 source with one JSON line built from
`tinylink_get_stats()` (`stats_json.h`): uptime, reset reason, boot
counters, heap (`heap_free`, `heap_min` = lowest free heap since boot
from `esp_get_minimum_free_heap_size()`, `heap_largest` = largest free
block), NTP, control/DERP state, public endpoint, WG counters (rekeys,
cold handshakes, RX-stale events, roams, TX drops, relay).
`echo | nc -u -w1 <tailnet-ip> 27822`.

`boots` (1.3.2) = `{total, brownout, panic, task_wdt, int_wdt}`: a
28-byte record in RTC no-init memory (`RTC_NOINIT_ATTR`,
`tl_bootstat.h`), counted once per boot from `esp_reset_reason()` by
`tinylink_bootstat_record()` (first thing in `bringup()`). RTC slow
memory survives every reset except a power loss, so the counters span
boots since the last power-on; a magic + FNV-1a checksum restarts the
record from zero when it holds power-on garbage, a torn write or another
layout (the boot log then says "RTC record restarted"). `total` counts
every boot, this one included; the other four count the boots that
followed that kind of reset (software restarts, RTC WDT and other
reasons only add to `total`).

The reply is formatted into a static `TL_STATS_JSON_CAP` (896 B) buffer
and is not sent at all if it would be truncated. Worst case 862 B —
every counter at its type's widest value, a 63-char hostname and a
63-char DERP host — checked by `tools/test/test_stats.c`; 1.3.1's line
peaked at 721 B in 768 B, which the new fields (+135 B) no longer fit.
About 600 B on the sensor.

## MapResponse parsing (M15, 2026-09)

`mapresp_parse` no longer tokenizes the whole document. `jsmn_split.h`
iterates the top-level object by byte range (string-aware,
depth-bounded) and jsmn tokenizes ONE value at a time into a 640-entry
table (10 KiB BSS): the self `Node`, each `Peers[i]` /
`PeersChanged[i]`, each `DERPMap.Regions[id]`, each
`PeersChangedPatch[i]` (since 1.3.0). Everything else (DNSConfig,
PacketFilter, UserProfiles, …) is skipped by range. An element larger
than the table is skipped with a log instead of failing the map, so
there is no document-size ceiling any more (the previous 2 500-token
table failed outright above ≈ 30 peers). Since M16 the parser also
reports `peers_is_delta` and `PeersRemoved` ids, and `tinylink.c` keeps
a canonical peer table (replace / upsert / delete) that the data plane
is updated from.

Since 1.3.4 (D2) the split runs on the stream: no frame is assembled
whole any more (it was, in a 32 KiB area of the shared control buffer).
`mapresp_stream_feed` takes the DATA bytes cut anywhere, the `LE32 size`
prefix included; the splitter follows the top object byte by byte, scans
past every member it does not need, and copies only the element being
collected — the self `Node`, one `Peers` / `PeersChanged` /
`PeersRemoved` / `PeersChangedPatch` entry, one `DERPMap.Regions` value
— into an 8 KiB element buffer (`TL_CTRL_MAPRESP_CAP`, `ctrl_buf.h`),
then hands it to the same jsmn element parsers. An element over 8 KiB is
skipped with an error log (a patch raises `patches_overflow`); the
length prefix keeps the stream in sync. Each container is also scanned
for its extent the way the whole-body split bounded it, so the results
match the old parser for any input whose elements fit
(`tools/test/test_mapresp.c` checks chunkings, every truncation and
random edits against it). A frame over 4 MiB (`MAPRESP_FRAME_MAX`, a
desync guard) stops the stream.

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
to ESP-IDF v5.5.6. Without them, the boot panics in `dhcp_state.c:52`
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

1. **STUN ran on the WG socket** — the boot probe
   (`tinylink_stun_probe_start`) sends and reads on
   `wg_netif_get_socket()` until wg_rx exists, the re-probe sends there
   and wg_rx hands it the answer, so the public AddrPort the control
   plane advertises is the same NAT mapping the WG keepalives keep
   alive. Without this, the advertised port is for an ephemeral STUN
   socket that closes immediately. Since 1.3.5 the boot probe runs
   alongside the register and the endpoint push waits ≤ 300 ms for it;
   a later or failed probe hands over to the re-probe, which pushes the
   endpoint once the data plane is up (`stun_boot.h` has the socket
   hand-off).
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
8. **DISCO-driven path probe on transport-stale** — when WG transport
   stays silent past `WG_RX_STALE_THRESHOLD_MS` (30 s) and the
   cooldown (`WG_PATH_PROBE_COOLDOWN_MS` = 10 s) has elapsed, `rx_task`
   fires a callback registered by `tinylink.c`. The handler sends
   sealed DISCO pings to every peer endpoint in the latest netmap.
   A peer reply from a different AddrPort triggers the roam in (7) —
   so the next handshake INIT lands on a verified-live address
   instead of hammering whatever was first in the netmap's endpoint
   list. Models the upstream tailscale path-liveness scheme
   (`wgengine/magicsock/endpoint.go::setBestAddrLocked`): DISCO
   pong is the canonical signal, not WG handshake. Recovery after
   peer-NAT-rebind: ~9 min → <10 s in validation. Triggered
   independently of rekey state — both `UP` + `HANDSHAKE_PENDING`
   benefit, so a long outage that's already fallen to cold-handshake
   retries also gets the probe.
9. **Endpoint push on the long-poll task** (`tinylink.c`, "Endpoint
   push" section) — when the STUN re-probe finds a new public AddrPort
   it calls `tinylink_endpoint_push_async()`, which sets
   `s_ep_push_pending` and `ts2021_abort_reads()`: the long-poll's
   blocking record read returns `TS2021_ERR_READ_ABORTED` at its next
   30 s socket poll, the stream is dropped (logged as "recycled for
   endpoint push", healthy-stream backoff ≈ 1 s), and right after the
   reconnect — before the read-only Stream=true cycle claims `s_conn` —
   `long_poll_task` runs `mapreq_push_endpoints(&s_conn)`: the same
   sequence bringup runs at boot. The in-place re-register path (M13)
   sets the same flag. History: until 2026-09 this was a dedicated
   persistent task (`tinylink_ep_up`, 12 KiB static stack) that opened
   its own ts2021 conn from a stack-local `ts2021_conn_t` (8 648 B)
   and then ran `ts2021_connect` (9 888 B frame) + the TLS handshake —
   ≈ 28 KiB on a 12 KiB stack, overflowing into the BSS below it on
   every real push (NAT rebind, WiFi re-association, re-register). The
   PR #102 soak panic ("InstructionFetchError at a DRAM PC" under a
   forced NAT rebind) was this overflow. Verified from the compiled
   `entry` frame sizes; removing the task freed 12.6 KiB of BSS.
   Upstream sends its lite update over the shared HTTP/2 client
   (`controlclient.Auto.updateRoutine`); tinylink's h2_client is one
   stream per conn, so the recycle is the equivalent.
10. **Outbound DISCO prober + tx-id binding** (`disco_prober.{c,h}`,
   replaces the deleted `disco_replay.{c,h}` — commit `31de72d`) — NaCl
   box (XSalsa20-Poly1305) is a stateless AEAD: `nacl_box_open` is
   deterministic, so an attacker who passively captures one DISCO PONG
   could replay it from a spoofed/owned source AddrPort and try to
   trigger the roam in (7) toward an attacker-chosen target,
   black-holing the WG transport. Rather than dedup inbound nonces
   reactively, the prober makes the roam *outbound-bound*: every DISCO
   ping we originate (`disco_prober_record` from `tinylink.c`) stamps
   the 12-byte transaction id together with the destination AddrPort
   into a 16-slot table (`s_table`, 5 s timeout, ~512 B BSS,
   `taskENTER_CRITICAL`-guarded for the two-task RX/relay paths). The
   roam in (7) is then gated by `disco_prober_match_and_remove`
   (ROAM-3, `wg_netif.c:697`): a PONG can only flap the WG endpoint if
   its tx-id matches a ping *we* actually sent to *that* source — a
   replayed or attacker-forged PONG carries no live tx-id and is
   dropped before any side-effect. The DiscoKey gate from (7) still
   filters frames from non-WG-peers; this layer binds the response to a
   genuine in-flight probe even for the legitimate peer's DiscoKey. The
   relayed-DISCO path gets the same DiscoKey gate (see
   `handle_disco_relayed` below). BSS delta vs. the old replay window:
   −3072 (replay) +512 (prober) = −2560 B.

Conditions 1-5 landed in PR #42; condition (1) was also touched by
PR #53 (STUN re-probe via WG socket); the netif ICMP carrier (raw IP
egress/ingress) landed in PR #43. Conditions (6) + (7) landed together
in PR #55 — see `CHANGELOG.md` for the empirical results
(38-min mega-ping from Servidor1: 4.95 % loss, 147 ms avg, 23 ms min
RTT direct UDP). See `MEMORY.md` entry
`reference_tinylink_direct_udp.md` and PR commit messages for the
forensic detail.

## Control-plane liveness + reconnect ladder (M13, 2026-07)

The long-poll task (`tinylink.c::long_poll_task`) owns the control
channel end-to-end: `ensure_control_conn` (TCP :80 or TLS :443 + Noise IK + h2 session)
→ `mapreq_run_stream` (blocking read loop) → `drop_control_conn` →
backoff → repeat. Before M13 the *only* exits from the read loop were
server-initiated (FIN, RST, GOAWAY, HTTP error) — a **half-open** TCP
conn (control instance replaced without FIN, NAT flow expired) parked
the task in `tls_io_read_full`'s WANT_READ retry forever, which is
exactly the "device stops reconnecting after a control change" failure
seen in production. Four escalation layers now guarantee the loop
always cycles and the device always converges back to a working
control channel:

1. **Per-I/O idle budget** (`tls_io.{c,h}` `max_idle`): every blocking
   control/DERP read *and* write tolerates at most
   `CONFIG_TINYLINK_STREAM_IDLE_TIMEOUT_S` (default 120 s = 4× the
   30-s socket timeout ≈ two missed server KeepAlives — mirroring
   upstream `direct.go` `watchdogTimeout`) of consecutive
   zero-progress polls, then fails with `TLS_IO_ERR_IDLE_TIMEOUT`.
   Any received byte resets the budget, so healthy KeepAlive cadence
   (~50-60 s) never trips it. Applies equally to the DERP supervisor's
   frame loop (`derp_run_loop`) — a half-open relay conn previously
   killed the CMM/relay fallback silently for the rest of the session.
2. **Reconnect with fresh handshake + capped backoff** (pre-existing
   RC-2 shape, unchanged): on any stream end the conn is dropped
   entirely and re-established from scratch — `tl_backoff_ms`
   exponential, 30 s cap, jitter, reset after ≥10 s of healthy stream.
   Upstream never resumes a dead Noise session either.
3. **In-place re-register on persistent 4xx** (M13): the reconnect
   loop can spin forever if the server *actively rejects* the node
   (tailscale.com: 404 = node deleted; headscale: machine-key mismatch,
   control DB migrated — since 0.29.4 headscale answers a *deleted*
   node's stream with HTTP 200 + a self node marked `Expired`, handled
   like a rejection, see round 1.3.0). After 2 consecutive non-429 4xx
   cycles — or the first expired/deleted self node — (then 4, 8, … —
   power-of-two schedule) the task
   re-runs `tinylink_register()` with the NVS authkey — the same code
   every boot exercises — and on success signals the endpoint-updater
   so the fresh node record learns the current public endpoint.
4. **Wedge restart last resort** (M13,
   `CONFIG_TINYLINK_CONTROL_WEDGE_RESTART_S`, default 3600 s, 0=off):
   `mapreq.c`'s chunk callback stamps `tinylink_control_mark_alive()`
   on every control-plane byte. If the stamp goes stale for the whole
   window — layers 1-3 keep the loop cycling, so the check is
   guaranteed to run — the task dumps stack diagnostics and
   `esp_restart()`s. Covers what per-connection logic can't: heap
   fragmentation starving mbedtls handshakes, lwIP/DNS wedges. The
   same option converts a failed `bringup()` into a 60-s-delayed
   restart instead of the historical park-for-diagnostics, so a
   wedge-reboot during an AP outage cannot strand the device.

Related M13 stream-content change: a `PeersChangedPatch` carrying a
peer `Key`/`DiscoKey` rotation makes `stream_dispatch` recycle the
stream (clean h2 stop → layer-2 reconnect → guaranteed-full first
netmap) instead of ignoring the patch and leaving the WG data plane
handshaking against dead peer keys. Endpoint-only patches remain
DISCO's problem, as upstream.

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
|     keys.c           — NVS-backed Curve25519 identities;       |
|                        machine+node regenerate ATOMICALLY      |
|                        (1:1 binding, policy in keys_regen.h),  |
|                        disco independent                       |
|     control_key.c    — HTTPS GET /key (esp_tls) + NVS pinning  |
|     ts2021_client.c  — TLS, HTTP Upgrade, Noise framing        |
|     register.c       — RegisterRequest JSON + response parse   |
|     noise_ik.c       — Noise_IK_25519_ChaChaPoly_BLAKE2s SM    |
|     json_helpers.c   — top-level JSON reader/escaping writer   |
|                                                                |
|  Vendored crypto (src/crypto/)                                 |
|     blake2s.c        — RFC 7693 reference                      |
|     hkdf_blake2s.c   — HMAC + Noise HKDF + RFC 5869 HKDF       |
|     curve25519.c     — X25519 shim (clamp, low-order reject)   |
|     curve25519_fiat32.c — fiat-crypto 32-bit field, carry-free |
|                        mul/sqr for the LX6 (MIT; was donna)    |
|     salsa20.c        — Salsa20 / HSalsa20 / XSalsa20           |
|     nacl_box.c       — crypto_box / crypto_box_open            |
|     secure_zero.h    — tl_secure_zero scrubs ALL secret key    |
|                        material (63 sites: wg session/handshake|
|                        keys, noise, nacl box, salsa20, hkdf,   |
|                        blake2s, chachapoly); public            |
|                        nonces/timestamps keep plain memset     |
+----------------------------------------------------------------+
        │
        ▼
+------------- ESP-IDF v5.5 ------------------------------------+
|  wifi / lwIP                                                  |
|  esp_tls + mbedtls (AES-GCM TLS, X.509 bundle; no ChaCha/Poly)|
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
     boot this is missing; we HTTPS-GET `/key?v=<TINYLINK_CAPVER>`
     (was a fixed `v=100` until M14; headscale now gates `/key` on its
     capver floor), parse `{"publicKey":"mkey:<64-hex>"}`, and persist.
4. `tinylink_register()` runs in a loop until success:
   - `ts2021_connect()` opens TCP to `controlplane.tailscale.com:80`
     (pinned key; TLS to :443 otherwise and as the fallback, round 1.3.5),
     sends a `POST /ts2021` HTTP Upgrade request whose body carries Noise
     IK msg1 inside a 4-byte handshake frame, reads the `101 Switching
     Protocols` response and the framed Noise IK msg2, completing the
     handshake. Optionally consumes an EarlyNoise frame containing a
     NodeKeyChallenge and signs it with the NodeKey via NaCl-box.
   - `register_emit()` builds the RegisterRequest JSON (NodeKey,
     OldNodeKey=zero, Hostinfo, Timestamp, Auth.AuthKey — omitted for
     an already-authorized node since 1.3.3 —, optional
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
| mbedTLS minimal preset + curve25519 + bundle (no chachapoly) | 250      |
| HTTP/2 client, in-tree since 1.3.4 (was nghttp2, 60)         | 10       |
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

## FreeRTOS task layout (as built, 2026-09)

Generated from the `xTaskCreate*` call sites; keep in sync when a task
or a stack size changes.

| Task               | Stack    | Prio    | Where                              | Role                                                       |
|--------------------|----------|---------|------------------------------------|------------------------------------------------------------|
| `main`             | 8 KiB    | 1       | `CONFIG_ESP_MAIN_TASK_STACK_SIZE`  | bringup: WiFi, keys, register, dataplane (takes the STUN result), spawns; exits |
| `tinylink_lp`      | 7 KiB    | IDLE+4  | `tinylink.c::tinylink_long_poll_start` | control conn: ts2021 connect, endpoint push, map long-poll, re-register, wedge restart |
| `tinylink_derp`    | 8 KiB    | IDLE+3  | `tinylink.c::tinylink_derp_supervised_start` | DERP TLS session from boot (1.3.5: connects alongside the register): relayed DISCO / WG inject, CMM punch |
| `wg_rx`            | 8 KiB    | IDLE+3  | `wg_netif.c::wg_netif_start`       | UDP recv, demux (WG/DISCO/STUN), handshake, decrypt → lwIP  |
| `wg_tx`            | 5 KiB    | IDLE+2  | `wg_netif.c::wg_netif_init`        | encrypted-frame queue → `sendto` (direct) or DERP relay     |
| `tinylink_stun`    | 5 KiB    | IDLE+2  | `tinylink.c::tinylink_stun_probe_start` | boot STUN probe on the WG socket while the register runs (1.3.5), to the home DERP node's STUN at its cached address (no DNS) or `CONFIG_TINYLINK_STUN_HOST`; exits after one probe (≤ 3 s, + DNS without a record) |
| `tinylink_tlm`     | 4.5 KiB  | IDLE+2  | `telemetry.c::telemetry_task_start` | TMP117 sample → JSON → UDP over the tunnel; `/stats`; periodic / GOT_IP-triggered STUN re-probe (flags endpoint push); 60 s stack diag + NVS time floor + address-cache records (1.3.5, on change only) |
| `tiT` (lwIP)       | 4.5 KiB  | 18      | `CONFIG_LWIP_TCPIP_TASK_STACK_SIZE`| TCP/IP thread (raised 3 → 4.5 KiB in #104)                 |

Application task stacks total ≈ 36.5 KiB (the 8 KiB `main` stack is
returned to the heap when `app_main` returns, the 5 KiB of
`tinylink_stun` when its probe ends, seconds into the boot; 1.3.4's D4 took
`tinylink_lp` 12 → 7 KiB and `main` 24 → 8 KiB, sized from
`tools/stack_worst.py`). The STUN re-probe had its
own 3 KiB task, `tinylink_stun_re`, until 1.3.2; it now runs on
`tinylink_tlm` (−3.4 KiB heap: stack + TCB + wake semaphore), which
exists in every build — with `CONFIG_TINYLINK_TELEMETRY_ENABLE=n` it
only re-probes and does the 60-s housekeeping. `tinylink_tlm` is spawned
by `tinylink_stun_reprobe_start` at the end of bringup (retried every
30 s on NO_MEM) and starts sampling on the first netmap. Its stack,
from the `entry` frames: `telemetry_task` 80 B, then `tlm_wait` 464 B
(`/stats` reply), `tlm_sample` 224 B (telemetry datagram) or
`tinylink_stun_reprobe_poll` 32 B + `tinylink_stun_probe` 176 B; every
path stands ≥ 176 B shallower than in 1.3.1 (one 688-B frame then), and
the STUN path (~1.8 KB on its own task) ≈ 1.9 KB here, well under the
`/stats`/sample paths (≈ 3.3 KB, ≤ 1.3.1's measured 3.5 KB peak). A
GOT_IP wakes the loop at once, except while `select()` serves `/stats`:
then the ≤ 5-s wait slice bounds the delay. The long-poll's stack is
the one to watch: its lifetime peak was 20 KiB in 2026-05, dominated by
`ts2021_connect` (9 888 B frame) → the record decrypt (4 176 B) →
mbedTLS handshake. Those buffers are gone (92c09dd; the record decrypt's
4 KiB `ct` since 1.3.4's D4, which decrypts in place in `h2_rx`), and
its static worst case is 4 864 B against 7 KiB (see
`tinylink_long_poll_start`); the 60-s `stack diag` line shows its
high-water mark.

There is no dedicated endpoint-push task any more (2026-09): the push
runs on `tinylink_lp` — see item 9 below.

### Task watchdog (M15, 2026-09)

Every application task in the table (`tinylink_*`, `wg_*`) subscribes
to the ESP task WDT at entry (`tl_wdt.h`, `CONFIG_TINYLINK_APP_TASK_WDT`, default
y) and feeds once per loop iteration. Blocking TLS reads feed through
the `tls_io` poll hook on every WANT_READ/WRITE poll — one 30-s
`SO_RCVTIMEO` period — so the long-poll and the DERP supervisor feed
at least every 30 s while idle; long sleeps (Retry-After, reconnect
ladders) go through `tl_wdt_sleep_ms` in 10-s slices. `tinylink_tlm` waits in ≤ 5-s slices and feeds on both sides of
a STUN re-probe, whose worst case (lwIP DNS 7 s × 3 servers + the 3-s
response wait ≈ 24 s) fits the budget; the re-probe ran on an
unsubscribed task before 1.3.2. Budget: `CONFIG_ESP_TASK_WDT_TIMEOUT_S=60`, the Kconfig maximum
(a larger value is silently dropped back to the 5-s default — that
exact mistake tripped the long-poll on the first M15 flash, since its
30-s poll cannot feed a 5-s budget). `CONFIG_ESP_TASK_WDT_PANIC=y`: a
task that stops iterating reboots the device into the known-good boot
path, the same stance as the control-path wedge restart. `wg_rx` /
`wg_tx` unsubscribe before `vTaskDelete`.
