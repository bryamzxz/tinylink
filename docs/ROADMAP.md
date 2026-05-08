# Roadmap / Hoja de ruta

> Bilingual (EN / ES). Other docs are English-only.

The detailed protocol map and memory/flash budgets that drive the
milestone breakdown below come from a research artifact maintained
out-of-tree by the maintainer (referenced in
`/home/bryam/Descargas/compass_artifact_*.md`). All section citations of
the form `[research §X]` point at that document; line citations of the
form `tailscale/path/file.go:start-end` point at the upstream Tailscale
Go implementation, which is the authoritative reference for wire format.

## Milestones (high level)

| #  | Name                                          | Status                              | Targeted release | Estimate |
|----|-----------------------------------------------|-------------------------------------|------------------|----------|
| M1 | ts2021 control plane (register only)          | done                                | v0.1             | 2-3 wk   |
| M2 | MapRequest streaming + WireGuard data plane   | done                                | v0.2             | 2-3 wk   |
| M3 | DISCO P2P discovery + TMP117 telemetry        | done — direct UDP + DERP            | v0.3             | 1-2 wk   |
| M4 | STUN minimal binding                          | done — runs on WG socket            | v0.4             | 0.5 wk   |
| M5 | DERP relay + direct-UDP NAT traversal         | done — DISCO punch via CallMeMaybe  | v0.5             | 1-2 wk   |
| M6 | ICMP-over-WG end-to-end                       | done — verified on hardware         | v0.6             | <1 wk    |
| M7 | Production hardening (NVS, secure boot, OTA)  | pending                             | v0.7             | ongoing  |

End-to-end verification on hardware (sensor-cali next to router,
Servidor1 WG peer with public IP):

```
$ tailscale ping sensor-cali        # from Servidor1
pong from sensor-cali (100.67.60.92) via 190.109.12.37:50582 in 403ms
$ ping -c 10 100.67.60.92            # from Servidor1
10 packets transmitted, 10 received, 0% packet loss, time 9008ms
rtt min/avg/max/mdev = 48.916/93.805/141.008/28.296 ms
```

Total realistic timeline to land all of M1–M6 (one engineer
full-time): **8–12 weeks** [research §K]. M7 hardening is
project-lifetime ongoing.

Remaining quality-of-life follow-ups (none blocking the
established direct-UDP + ICMP path):

- **Pre-punch on netmap-receive**: the first `tailscale ping` from a
  fresh peer takes 3 DERP rounds before flipping to direct, because
  the device only punches outbound DISCO when it receives a CMM. If
  we punch every advertised peer endpoint on netmap-receive too, the
  direct path is up by the time the peer first probes us.
- **WG handshake init delay**: handshake retries 2–5× at boot before
  `session up`, because we fire the init at t≈15s while the peer's
  netmap may not yet contain our current AddrPort. Delaying init
  until the first inbound DISCO observation cuts the retry cost.
- **stun_reprobe → fetch_once trigger**: NAT port rotates ~5 min on
  consumer routers; we should re-push Endpoints + NetInfo via
  `mapreq_push_endpoints` whenever the re-probe sees a port change.
- **DERP outbound queue**: needed only for peers behind shared CGNAT
  (where direct UDP can never punch). For peers with public IPs the
  direct path covers all traffic.
- **Responder-mode handshake**: steady-state session expiry is already
  fixed by initiator-side proactive rekey at session_age=110 s (see
  `ARCHITECTURE.md` § "WireGuard handshake lifecycle"). Responder
  mode is only needed for the peer-roaming corner case where the
  peer endpoint changes mid-session and we cannot reach it to
  re-initiate; in practice peer NAT rebindings are observed
  end-to-end via DISCO and handled by `wg_netif_update_peer_endpoint`,
  so this is a long-tail item rather than a blocker.

## M1 — ts2021 control plane (current)

EN: The device:
1. Generates Curve25519 identities (MachineKey, NodeKey, DiscoKey) on first
   boot, after WiFi is up so `esp_random()` is a true TRNG, and persists
   them in NVS namespace `tl_keys` [research §L].
2. Bootstraps the control plane public key via `GET /key?v=100`, pins it
   in NVS namespace `tl_pin`. Compile-in fallback pin recommended for
   production (M6).
3. Opens TLS to `controlplane.tailscale.com:443`, sends `POST /ts2021`
   with `Upgrade: tailscale-control-protocol`, `Connection: upgrade`,
   `Content-Length: 0`, and the 101-byte Noise IK initiation frame
   base64-encoded in `X-Tailscale-Handshake`. The Noise prologue is the
   string `"Tailscale Control Protocol v1"` (per
   `tailscale/control/controlbase/handshake.go`).
4. Reads the 101 Switching Protocols response and the controlbase
   `type=2` response frame containing Noise IK msg2, completing the
   handshake.
5. Drains the optional EarlyPayload sentinel (`"\xff\xff\xffTS"` + BE32
   length + JSON of `tailcfg.EarlyNoise`). Its only field is
   `NodeKeyChallenge`, but the upstream Tailscale client never responds
   to it in production (`SealToChallenge` from `types/key/chal.go` is
   only referenced from tests), so tinylink discards it as well.
6. Sends `POST /machine/register` (HTTP/2 inside the Noise channel via
   nghttp2) with the auth key from NVS. `Version` on the wire is `1`
   (the Noise transport `CapabilityVersion`); `NLKey` is sent as
   `"nlpub:" + 64 zeros` until M6 hardening adds real Ed25519
   NLPrivate generation.
7. Reads the response. On `MachineAuthorized=true` the device is registered
   and idle; on `false` it retries on a slow cadence.

ES: Idem traducido. Definitions of done iguales que en EN.

**Done when:** the device shows up in
`https://login.tailscale.com/admin/machines` with hostname `sensor-cali`,
status online, an assigned `100.x.y.z`. Pings to it will not work yet —
M1 has no data plane.

**Known gaps in the current scaffolding** (see follow-up tasks):
- `NodeKeyChallenge` is intentionally not implemented. The upstream
  Tailscale client defines `SealToChallenge` / `ChallengePrivate.OpenFrom`
  in `types/key/chal.go` but never calls them outside tests, so the
  EarlyPayload reaches no caller in production. tinylink mirrors that
  behavior by draining and discarding the sentinel.
- `NLKey` is sent as 32 zero bytes until M6 hardening lands real
  Ed25519 NLPrivate generation; this is tolerated because TKA is off.
- The vendored crypto only has host-side KATs for BLAKE2s and X25519
  today (commit `358297f`). ChaCha20-Poly1305 / Salsa20 / Poly1305 KATs
  are still pending.

## M2 — MapRequest + WireGuard data plane

EN: After register, the same Noise channel transitions into a long-lived
`POST /machine/map` with `Stream: true`. The server streams
newline-delimited `tailcfg.MapResponse` JSON objects [research §I].
Parse with **jsmn** (zero-alloc tokenizer, ~350 LoC), not cJSON DOM —
budget 20 KB SRAM during parse, 4 KB for retained peer state. Disable
zstd by not advertising support (saves ~30 KB flash).

**Step 1 (landed in `feat(m2): scaffolding`):**
- jsmn vendored at `components/tinylink/src/jsmn.h`.
- `tl_netmap_t` defined in `components/tinylink/src/netmap.h` with a
  4-peer / 4-DERP-region budget.
- `mapreq_fetch_once()` does a one-shot `POST /machine/map` with
  `Stream:false` and `Compress:""`; the server responds with a single
  `MapResponse` and closes. Sufficient for bootstrapping the netmap
  while the data plane is being wired up; long-poll `Stream:true`
  follows in step 3.
- `mapresp_parse()` extracts `Node.Addresses`, `Peers[].{ID,Key,
  DiscoKey,Addresses,Endpoints,HomeDERP}`, and `DERPMap.Regions`.
  v6 endpoints/addresses are dropped during parse — the lwIP build is
  v4-only at the netif layer.
- Host-side KAT in `tools/test/test_mapresp.c` parses a stub modeled
  on a real one-peer MapResponse and checks each extracted field.

**Step 2 (landed in `feat(m2): WireGuard data plane via trombik`):**
- Lifted `trombik/esp_wireguard@0.9.0` (BSD-3) as a managed component.
- `components/tinylink/src/wg_dataplane.{c,h}` is a thin shim that
  translates the parsed netmap into the `wireguard_config_t` the
  upstream component expects. Single-peer (`peers[0]`), v4-only,
  25-second persistent keepalive until DISCO takes over.
- New public API `tinylink_dataplane_start()` opens a fresh ts2021
  channel, drives one `mapreq_fetch_once()`, and brings up the WG
  netif. `main.c` calls it after register succeeds.

**Step 3 (landed in `feat(m2): long-poll MapRequest stream`):**
- `h2_client` grew a streaming variant (`h2_post_json_stream`) that
  invokes a per-DATA-frame callback instead of buffering the whole
  body. Common request setup is shared with the one-shot variant.
- `mapreq_run_stream()` POSTs `/machine/map` with `Stream:true`. The
  reply is a sequence of `LE32 size || body` frames (verified against
  `tailscale/control/controlclient/direct.go:~1248`); the chunk
  callback feeds bytes into a tiny state machine that emits one
  parsed `tl_netmap_t` per non-KeepAlive message.
- New public API `tinylink_long_poll_start()` spawns a dedicated
  8 KiB-stack FreeRTOS task (`tinylink_lp`) that runs the long-poll
  loop and reconnects on stream EOF or transport error. Each
  MapResponse fires `wg_dataplane_update_peer()`, which compares the
  new endpoint to the active one and reconnects WG only if it
  changed.

**Deferred to M3 (alongside DISCO):**
- Patch ~50 lines in upstream `wireguardif.c` to accept packets
  injected from a demuxer task rather than via `udp_bind(IP_ADDR_ANY,
  port)`, so DISCO/STUN can share the WG UDP socket. Until DISCO
  actually arrives, the bare bind is fine.

Cookie reply (WG message type 3, XChaCha20-Poly1305) is intentionally
**dropped on receive** and `mac2 = 0^16` always on send — saves ~1-2 KB
flash and removes XChaCha20/HChaCha20 from the binary. This is
spec-compliant.

ES: Mismo contenido, en español a futuro.

## M3 — DISCO + TMP117 telemetry

**Step 1 (landed in `feat(m3): TMP117 driver + UDP telemetry`):**
- TMP117 driver under `components/tinylink/src/tmp117.{c,h}` using
  IDF v5.5's `driver/i2c_master.h`. Reset-default config (continuous,
  AVG=8, ~1 s conversion) is left as-is, so we never write
  CONFIGURATION; we read TEMP_RESULT and convert via the documented
  7.8125 m°C/LSB scale.
- DEVICE_ID probe at `tmp117_init` — wrong wiring or address fails
  fast.
- `telemetry.c` spawns a 4 KiB-stack FreeRTOS task `tinylink_tlm` that
  reads the TMP117 every `CONFIG_TINYLINK_TELEMETRY_PERIOD_MS` and
  pushes a JSON datagram to `CONFIG_TINYLINK_TELEMETRY_DEST` over
  UDP. The destination is expected to be a 100.x.y.z tailnet address
  reachable through the WG netif.
- Public API `tinylink_telemetry_start()`; main.c invokes it after
  the long-poll task is running. Compile-time disable
  `CONFIG_TINYLINK_TELEMETRY_ENABLE=n` collapses the call to a no-op
  for boards without a TMP117.

**Step 2 (landed in PR #42 `feat: direct UDP path end-to-end`):**
NaCl-box DISCO ping/pong on the same UDP socket as WG (multiplexed
by first byte in `wg_demux_classify`: WG types 1-4, DISCO magic
`0x54 0x53 0xF0 0x9F 0x92 0xAC` = "TS💬", STUN `0x00 0x01`). The
RX task in `wg_netif.c` handles WG_DEMUX_DISCO inline via
`handle_disco_direct` — decrypts the NaCl box with the local
DiscoKey, builds a sealed Pong, and `sendto`s it back to the source
AddrPort. Drops `Pong` (we don't track outbound probers) and
`CallMeMaybe` (handled below).

CallMeMaybe handling lives in `tinylink.c::send_disco_pings_to_cmm_endpoints`:
when the DERP supervisor receives a CMM, the device emits a fresh
sealed DISCO Ping via the WG socket to each v4-mapped peer
endpoint advertised in the CMM. Each outbound ping opens the
device-side NAT mapping for that destination so the peer's
simultaneous probe can land on us — that's the NAT-punching pair
that makes the path go "direct" instead of "DERP" in
`tailscale ping`.

Five interlocking conditions had to land together for direct UDP
to work end-to-end (see PR #42 commit message + `reference_tinylink_direct_udp.md`):

1. STUN runs on the WG socket so the advertised port matches the
   WG NAT mapping that keepalives keep pinned.
2. WG_DEMUX_DISCO classified before the peer-source filter so DISCO
   from a non-WG-peer src isn't dropped.
3. MapRequest is `Stream=false && OmitPeers=true` (lite update —
   the only shape modern Tailscale.com persists).
4. `NetInfo.WorkingUDP=true` accompanies the lite update — server
   refuses to propagate Endpoints without this signal.
5. CMM punch handler emits outbound DISCO pings on receive.

Requires no `wireguardif.c` patch; the data plane is in-tree
(`wg_netif.c`) and owns the socket.

## M4 — STUN

EN: 20-byte RFC 5389 binding request to the STUN port of the home DERP
region (3478) at startup. Decode XOR-MAPPED-ADDRESS, stuff the result
into MapRequest.Endpoints. ~50 LoC C. **Skip** all `netcheck` NAT-type
classification, MTU discovery, and DERP latency ranking [research §E].
Re-do only when the UDP 5-tuple changes (~"never" for a stationary
sensor unless the router reboots).

ES: idem.

## M5 — DERP relay + direct-UDP NAT traversal

EN: Minimal DERP client over TLS (HTTP Upgrade), framed as
`type(1) || BE32 length || payload`. Constants in `derp/derp.go`
upstream. Required frames: `FrameServerKey(0x01)`, `FrameClientInfo(0x02)`,
`FrameSendPacket(0x04)`, `FrameRecvPacket(0x05)`, `FrameKeepAlive(0x06)`,
`FramePing(0x0D)`, `FramePong(0x0E)` [research §D]. **Skipped**:
WatchConns / ForwardPacket / ClosePeer (mesh / admin only),
`FrameHealth` (log-only), `CanAckPings` negotiation (always respond).

`tinylink.c::derp_supervised_task` keeps a long-lived TLS upgrade
to the `PreferredDERP` region's first node (selected from the netmap
on initial bringup; `update_derp_host_from_netmap` switches if the
control plane reroutes). On `DERP_EVT_RECV_PACKET` the task hands
the relayed frame to `handle_disco_relayed`, which:

- DISCO Ping → sealed Pong via the same DERP route.
- DISCO CallMeMaybe → outbound DISCO ping per advertised v4-mapped
  endpoint via the WG socket (`send_disco_pings_to_cmm_endpoints` —
  the NAT-punching pair to peer's simultaneous probe).
- Anything else (WG transport, handshake response over relay) →
  `wg_netif_inject_packet` so it traverses the same demux + handler
  chain a UDP recv would.

The DERP connection stays open for the device's lifetime (not
"on demand") because the supervisor doubles as a netmap-update
listener and the cost of keeping one TLS session is small relative
to the round-trip latency of re-handshaking on demand.

Direct UDP NAT traversal is the M5 step that flips the data plane
off DERP. See M3 step 2 above for the five conditions; together they
make `tailscale ping` show `via 190.x.x.x:port` instead of
`via DERP(mia)` after one CMM round-trip.

Outbound DERP queue (relayed WG transport for end-to-end ICMP via
DERP for CGNAT-trapped peers) is the only piece left for M5 and is
deferred — for peers with public IPs the direct path covers
everything.

ES: idem.

## M6 — ICMP-over-WG end-to-end

`tailscale ping` uses DISCO and bypasses lwIP entirely. Real ICMP
(`ping <our-tailnet-ip>`) needs the WG netif to actually carry IP
packets through lwIP both directions — which the original
PPP-flagged `esp_netif` did NOT do.

Four problems were chained (PR #43 commit message has the full
forensic trail):

1. `esp_netif_action_start` with `ESP_NETIF_FLAG_IS_PPP` dispatches
   to `esp_netif_start_ppp` and returns before the AUTOUP block, so
   `netif_set_up` and `netif_set_link_up` never fire — `lwn->flags`
   keeps both bits at 0 and `ip4_input_accept` drops every inbound.
2. The same path skips `netif_set_addr`, so `lwn->ip_addr.addr` is
   0.0.0.0 even though `esp_netif_get_ip_info` returns the right
   address — `ip4_input` finds no matching local netif for
   inbound dst=100.x.y.z and drops before ICMP echo can reply.
3. `ESP_NETIF_NETSTACK_DEFAULT_PPP` registers `input_fn =
   esp_netif_lwip_ppp_input` which calls `pppos_input_tcpip_as_ram_pbuf`,
   an HDLC-framed-PPP parser. Raw IP (`0x45 0x00 ...`) gets
   silently discarded at the framer.
4. The egress side wraps each outbound packet in HDLC + PPP
   protocol headers (`0xff 0x03 0x00 0x21 ...`); peer's WireGuard
   decrypts cleanly but the inner bytes aren't a valid IP header.

Fix in `wg_lwip.c::wg_lwip_attach`:

- Cache `s_lwn = esp_netif_get_netif_impl(s_netif)`.
- `netif_set_addr` + `netif_set_up` + `netif_set_link_up` explicitly.
- Override `lwn->output` and `lwn->linkoutput` with raw-IP
  passthroughs that hand the pbuf payload straight to
  `wg_netif_send_plaintext`.
- `wg_rx_inject` now calls `tcpip_input(pbuf, lwn)` directly instead
  of `esp_netif_receive`, bypassing the PPP `input_fn`.

The PPP flag is kept because removing it triggers an IDF v5.5
`dhcpc_cb` panic from the trombik baseline. After the four
overrides above, the netif behaves as a true raw-IP carrier.

Verified on hardware: 10/10 ICMP echo packets, 0% packet loss,
~93 ms RTT through the tunnel from the active WG peer.

## M7 — Hardening

EN: TAI64N monotonicity tests across reboot scenarios (NVS-persisted
epoch counter). NVS encryption with HMAC key in eFuses. Watchdog +
reconnection with exponential backoff (cap 30 s). Auth-key rotation
path. Compile-in fallback control plane pubkey. Constant-time
Curve25519 swap (`trombik/esp_wireguard/src/crypto/x25519.c`). Disassembly
review of all crypto functions to verify no secret-dependent branches
[research §L].

ES: idem.
