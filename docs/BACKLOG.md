# Backlog after 1.4.0

1.4.0 is the last release of the 1.3.x optimization line (rounds
1.3.1–1.3.9). What is left goes here, to do later. Each item has the
evidence that put it on the list and why it waited. The numbers are from
the sensor logs in CHANGELOG.md.

## Boot and control plane

- **Bigger TCP receive window.** A window of 2–3 × the current 4 × MSS
  halved the netmap body's median (830 → 440 / 330 ms, 36-boot A/B,
  round 1.3.9). It also stalled 2 of 9 boots for 2.4–2.9 s at the body's
  tail. Three of the four stalls came on a boot seconds after the
  previous one, and each was followed by `prepunch sendto: errno=12`
  (Wi-Fi TX buffers full). Find what blocks Wi-Fi TX for ~2.7 s after a
  quick reboot before adopting it (`tools/power/sdkconfig.ab-tcp-wnd*`).
  The warm start moved the netmap off the WireGuard path, so the payoff
  is smaller now.
- **Wi-Fi TX stall after a quick reboot.** The ~2.7-s TX blackout above,
  seen with the bigger windows. Unexplained: AP-side state from the
  previous association, RX/TX buffer pressure, or the driver.
- **Prepunch burst vs a full TX queue.** The 9–11 DISCO pings go out
  back to back. After a TX stall several fail with ENOMEM. Pace them, or
  retry once after a few ms.
- **Fixed local UDP port.** The sensor binds a random UDP port at every
  boot, and the home NAT preserves ports, so the public endpoint changes
  at every boot. Control then pushes a peer update to every peer.
  tailscaled keeps 41641 for the same reason. A port kept in NVS or a
  Kconfig would make the boot's endpoint push a no-op.
- **Peer answers the first INIT late.** 2 of 36 boots: the response to
  the first INIT came via DERP 2.6–3.1 s later, in the same instant as
  the peer's call-me-maybe, after the 2-s retry had replaced it. It was
  dropped as late. The cause is likely peer-side (its reconfiguration on
  our endpoint change; see the fixed port above). Keeping the replaced
  INIT's state for one more response would win ~0.1 s.
- **Register and push in one burst.** Saves ~200 ms per boot. Push +
  stream pipelining (B1, `CONFIG_TINYLINK_CONTROL_PUSH_PIPELINE`) made
  tailscale.com end the map stream cleanly. Re-test B1 now that the
  `Ts-Lb` header (1.3.8) is sent, then decide on register + push.
- **Boot connection FIN.** tailscale.com closes the boot's control
  connection once, ~400 s in. The reconnect takes < 1 s. Try a fresh
  connection for the long poll.
- **Boot map stream without keep-alives.** 1 of 9 boots (1.3.8 smoke),
  silent past 120 s, then a clean reconnect. Watch only.
- **Post-association network stall.** One series boot lost both TCP
  connections for ~20 s right after the association. The DERP
  cached-IP 3-s per-step budget is tight then (one fallback in 20
  connects).
- **TLS ticket resumption.** Implemented (RTC session store) but never
  yet seen to resume on the sensor: the DERP servers restart often.

## Data plane

- **In-tunnel TSMP probe.** Would bring WG-silent failover below the
  ~13 s of the doubt handshake (1.3.8).
- **Warm start, second iteration.** On the sensor (1.4.0, 7 warm boots)
  got-ip → session up was median 1.55 s / mean 2.34 s, against
  2.17–2.20 / 2.49–2.74 s for 18 cold boots. In 4 of 7 the peer answered
  the early INIT in 100–590 ms. In 3 of 7 it answered only 3.4–4.4 s
  after our endpoint push, together with its call-me-maybe; the INIT
  before the netmap lands in that window more often than a cold boot's
  (2 of 36). The fixed local UDP port above should remove the window.
  Also measure how often the netmap corrects the warm start, and
  whether the 600-s bound (`CONFIG_TINYLINK_WARM_START_MAX_S`) and the
  30-day record age are right.

## Wi-Fi

- **PMF comeback on every quick reboot (+1.1 s).** The AP still holds
  the old security association and SA-queries it. On software restarts
  (OTA, warm-start corrections) a deauth before `esp_restart` would
  avoid it. Panics and power cuts cannot.
- **Legacy NVS credentials namespace.** Every boot warns that `wifi_ssid`
  and `wifi_pass` are in the legacy `tinylink` namespace. Migrating them
  writes NVS on the production sensor: needs the owner's OK.
- **802.11r (FT).** The AP advertises FT-PSK. Only useful with several
  APs.

## Footprint and build (from `docs/rounds/2026-10-optimization-list.md`)

- D8 mbedTLS direct, D13 Wi-Fi RX buffers (low value now that the heap
  is ample), D3 single core (recommended skip: it conflicts with the
  parallel handshakes), D12 core dump (needs a full-flash authorization).
- Kconfig defaults: the device hostname and the telemetry target default
  to the production sensor's values. Move them to generic defaults plus
  a local, git-ignored overlay (owner decision).

## Test infrastructure

- **Own ESP32 QEMU.** Built like the maintainer's RouterOS QEMU twin, on
  the newest upstream QEMU release at the moment the work starts, with
  the Espressif ESP32 machine patches on top. Espressif's QEMU build
  stays the reference until then.
- **Fault-injection lab ("war hardening").** Provoke the failures
  instead of waiting for them on the sensor: Wi-Fi drops, WAN stalls,
  DERP and control restarts, flash and heap pressure. Deferred on
  2026-10-29. Needs the QEMU above.
