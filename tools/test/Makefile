# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Bryam (bryamzxz)
#
# Host-side smoke tests for the vendored crypto. These compile with stock
# gcc — no ESP-IDF needed. They exercise the algorithm; the on-target
# build still has to be verified independently.
#
#   make            # build everything
#   make test       # build + run everything
#   make test_blake2s.run / test_curve25519.run

CC      ?= gcc
# EXTRA_CFLAGS is appended (sanitizers, -g, coverage) without restating
# the base flags; RUNNER wraps every test invocation (valgrind, qemu…).
#   make test                                   # plain
#   make asan                                   # ASan+UBSan, clean rebuild
#   make test RUNNER='valgrind -q --error-exitcode=9'
CFLAGS  ?= -O2 -Wall -Wextra -Werror -Wno-unused-parameter -Wno-sign-compare \
           -Wno-unterminated-string-initialization \
           -std=c11 -D_DEFAULT_SOURCE $(EXTRA_CFLAGS)
RUNNER  ?=
CRYPTO  := ../../components/tinylink/src/crypto

TL_SRC  := ../../components/tinylink/src
TL_INC  := ../../components/tinylink/include
TL_MAIN := ../../main

TARGETS := test_blake2s test_curve25519 test_x25519 test_mapresp \
           test_chacha20 test_poly1305 test_chacha20poly1305 \
           test_hkdf_noise test_wg_handshake test_wg_transport \
           test_wg_demux test_wg_timers test_wg_path test_disco test_stun test_tls_io test_derp \
           test_disco_handler test_disco_prober test_retry_after \
           test_backoff test_keys_regen test_stun_boot test_skip_value test_jsmn_split \
           test_tai64n test_nacl_box test_tsmp test_tl_date test_stats test_noise_ik \
           test_http1 test_ctrl_json test_ts2021 test_hpack test_h2_core test_tls_resume \
           test_addr test_wifi_hint test_wifi_psk test_pwr_diag test_tlm_sched test_tls_offer \
           test_tls_rtc test_ts2021_e2e test_derp_wlock

all: $(TARGETS) $(H2_INTEROP)

# /stats: RTC boot-counter record + worst-case JSON line. Header-only;
# host_include/esp_err.h stands in for ESP-IDF's under tinylink.h.
test_stats: test_stats.c $(TL_SRC)/tl_bootstat.h $(TL_SRC)/stats_json.h $(TL_INC)/tinylink.h \
            $(TL_SRC)/jsmn.h host_include/esp_err.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -I$(TL_INC) -Ihost_include -o $@ test_stats.c

# HTTP/1.1 response parser behind the TOFU GET /key (round 1.3.2). Header-only.
test_http1: test_http1.c $(TL_SRC)/tl_http1.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_http1.c

# cJSON replacement on the control plane (round 1.3.2): top-level JSON
# reader + escaping writer, RegisterRequest bytes pinned to cJSON's.
test_ctrl_json: test_ctrl_json.c $(TL_SRC)/json_helpers.c $(TL_SRC)/json_helpers.h \
                $(TL_SRC)/register_json.h $(TL_SRC)/jsmn_split.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_ctrl_json.c $(TL_SRC)/json_helpers.c

# RFC 3339 / IMF-fixdate parsers (KeyExpiry, Retry-After). Header-only.
test_tl_date: test_tl_date.c $(TL_SRC)/tl_date.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_tl_date.c

# TSMP disco-key advertisement builder (capver 144). Header-only.
test_tsmp: test_tsmp.c $(TL_SRC)/tsmp.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_tsmp.c

# Pure exponential-backoff-with-jitter helper (RC-2). Header-only.
test_backoff: test_backoff.c $(TL_INC)/backoff.h
	$(CC) $(CFLAGS) -I$(TL_INC) -o $@ test_backoff.c

# Pure identity-regeneration policy (headscale 1:1 NodeKey/MachineKey). Header-only.
test_keys_regen: test_keys_regen.c $(TL_SRC)/keys_regen.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_keys_regen.c

# Boot STUN probe hand-off (round 1.3.5): every interleaving of the
# probe task and the waiter. Header-only.
test_stun_boot: test_stun_boot.c $(TL_SRC)/stun_boot.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_stun_boot.c

# Last-known server addresses (round 1.3.5): IPv4 literals, the NVS
# records, write-only-on-change over a fake NVS. Header-only.
test_addr: test_addr.c $(TL_SRC)/tl_addr.h $(TL_SRC)/netmap.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_addr.c

# Wi-Fi association hint + retry policy (round 1.3.7, main/wifi_hint.h):
# the record, write-only-on-change over a fake NVS, the retry decisions
# and a random walk over a simulated driver. Header-only.
test_wifi_hint: test_wifi_hint.c $(TL_MAIN)/wifi_hint.h
	$(CC) $(CFLAGS) -I$(TL_MAIN) -o $@ test_wifi_hint.c

# The early WPA2 PSK (round 1.3.8, main/wifi_psk.h): published vectors,
# a plain reference PBKDF2, bounds, hex digits, scrub, task hand-off.
# Header-only; tools/qemu_crypto also runs it on the ESP32.
test_wifi_psk: test_wifi_psk.c $(TL_MAIN)/wifi_psk.h
	$(CC) $(CFLAGS) -I$(TL_MAIN) -o $@ test_wifi_psk.c

# Depth-bounded JSON value skipper (MapResponse stack-overflow guard). Header-only.
test_skip_value: test_skip_value.c $(TL_SRC)/jsmn_skip.h $(TL_SRC)/jsmn.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_skip_value.c

# Shallow JSON splitter feeding jsmn one MapResponse value at a time. Header-only.
test_jsmn_split: test_jsmn_split.c $(TL_SRC)/jsmn_split.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_jsmn_split.c

# TAI64N floor / reservation logic (cross-reboot handshake monotonicity).
test_tai64n: test_tai64n.c $(TL_SRC)/wg_proto.c $(TL_SRC)/wg_proto.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -I$(CRYPTO) -o $@ test_tai64n.c $(TL_SRC)/wg_proto.c \
	    $(CRYPTO)/blake2s.c $(CRYPTO)/hkdf_blake2s.c

# libsodium reference vectors for the NaCl box (DISCO sealing). Since
# 1.3.2 nacl_box.c runs on the in-tree poly1305-donna on target too, so
# the host build is the firmware's code path (no mbedTLS shim).
test_nacl_box: test_nacl_box.c $(CRYPTO)/nacl_box.c $(CRYPTO)/salsa20.c $(CRYPTO)/poly1305_donna.c \
               $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_fiat32.c $(CRYPTO)/secure_zero.h
	$(CC) $(CFLAGS) -I$(CRYPTO) -o $@ test_nacl_box.c $(CRYPTO)/nacl_box.c \
	    $(CRYPTO)/salsa20.c $(CRYPTO)/poly1305_donna.c $(CRYPTO)/curve25519.c \
	    $(CRYPTO)/curve25519_fiat32.c

test_blake2s: test_blake2s.c $(CRYPTO)/blake2s.c $(CRYPTO)/blake2s.h
	$(CC) $(CFLAGS) -I$(CRYPTO) -o $@ test_blake2s.c $(CRYPTO)/blake2s.c

test_curve25519: test_curve25519.c $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_fiat32.c $(CRYPTO)/curve25519.h
	$(CC) $(CFLAGS) -I$(CRYPTO) -o $@ test_curve25519.c $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_fiat32.c

# X25519 on the round-1.3.3 field (C6): RFC 7748 iterated vector, 4 000
# cross-checks against curve25519-donna (ref/, the pre-1.3.3 X25519),
# the carry-free field ops against a mod-p reference. Includes
# curve25519_fiat32.c itself to reach the static field functions.
test_x25519: test_x25519.c $(CRYPTO)/curve25519_fiat32.c $(CRYPTO)/curve25519.c \
             $(CRYPTO)/curve25519.h ref/curve25519_donna.c
	$(CC) $(CFLAGS) -I$(CRYPTO) -o $@ test_x25519.c $(CRYPTO)/curve25519.c ref/curve25519_donna.c

# mapreq.c builds on host because its ESP-IDF-specific code is guarded
# by #ifdef ESP_PLATFORM; the MapResponse parser (the round-1.3.4
# streaming splitter and its framing) is platform-independent. Linked
# next to the 1.3.3 whole-body parser (ref/mapresp_133.c, as ref_*), the
# oracle for chunking / truncation / mutation tests.
test_mapresp: test_mapresp.c $(TL_SRC)/mapreq.c $(TL_SRC)/mapreq.h $(TL_SRC)/netmap.h \
              $(TL_SRC)/jsmn.h $(TL_SRC)/jsmn_split.h $(TL_SRC)/jsmn_skip.h $(TL_SRC)/ctrl_buf.h \
              $(TL_SRC)/tl_addr.h \
              ref/mapresp_ref.c ref/mapresp_133.c
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_mapresp.c $(TL_SRC)/mapreq.c ref/mapresp_ref.c

# RFC 8439 §2.3.2 / §2.4.2 / A.1 / A.2 + HChaCha20 KATs, and a
# differential test against the 1.3.2 ChaCha20 (ref/chacha20_132.c,
# linked as ref_* through ref/chacha20_ref.c) — round 1.3.3, C4.
test_chacha20: test_chacha20.c $(CRYPTO)/chacha20.c $(CRYPTO)/chacha20.h \
               ref/chacha20_ref.c ref/chacha20_132.c
	$(CC) $(CFLAGS) -I$(CRYPTO) -o $@ test_chacha20.c $(CRYPTO)/chacha20.c ref/chacha20_ref.c

# RFC 8439 §2.5.2 — poly1305-donna one-time-MAC KAT.
test_poly1305: test_poly1305.c $(CRYPTO)/poly1305_donna.c $(CRYPTO)/poly1305_donna.h $(CRYPTO)/poly1305_donna_32.h
	$(CC) $(CFLAGS) -I$(CRYPTO) -o $@ test_poly1305.c $(CRYPTO)/poly1305_donna.c

# RFC 8439 §2.8.2 — AEAD construction KAT. This is the security-critical
# glue (pad16, length encoding, constant-time tag verify) that lives in
# our own wrapper, not in the lifted primitives.
test_chacha20poly1305: test_chacha20poly1305.c \
                      $(CRYPTO)/chacha20poly1305.c $(CRYPTO)/chacha20poly1305.h \
                      $(CRYPTO)/chacha20.c $(CRYPTO)/chacha20.h \
                      $(CRYPTO)/poly1305_donna.c $(CRYPTO)/poly1305_donna.h $(CRYPTO)/poly1305_donna_32.h
	$(CC) $(CFLAGS) -I$(CRYPTO) -o $@ test_chacha20poly1305.c \
	    $(CRYPTO)/chacha20poly1305.c $(CRYPTO)/chacha20.c $(CRYPTO)/poly1305_donna.c

# Cross-consistency KAT for HKDF-BLAKE2s / Noise §4.3 KDFs.
test_hkdf_noise: test_hkdf_noise.c \
                $(CRYPTO)/hkdf_blake2s.c $(CRYPTO)/hkdf_blake2s.h \
                $(CRYPTO)/blake2s.c $(CRYPTO)/blake2s.h
	$(CC) $(CFLAGS) -I$(CRYPTO) -o $@ test_hkdf_noise.c \
	    $(CRYPTO)/hkdf_blake2s.c $(CRYPTO)/blake2s.c

# ts2021 Noise IK initiator (noise_ik.c): handshake + transport records
# against gen_noise_vectors.py (OpenSSL) and an in-file responder.
# host_include/ supplies esp_err.h / esp_log.h.
NOISE_SRCS := $(TL_SRC)/noise_ik.c $(CRYPTO)/blake2s.c $(CRYPTO)/hkdf_blake2s.c \
              $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_fiat32.c \
              $(CRYPTO)/chacha20poly1305.c $(CRYPTO)/chacha20.c $(CRYPTO)/poly1305_donna.c
test_noise_ik: test_noise_ik.c $(NOISE_SRCS) $(TL_SRC)/noise_ik.h $(CRYPTO)/secure_zero.h \
               host_include/esp_err.h host_include/esp_log.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -I$(CRYPTO) -Ihost_include -o $@ test_noise_ik.c $(NOISE_SRCS)

# ts2021 record layer after the Noise handshake (round 1.3.4: D5's
# EarlyPayload window) and the connect over plain :80 with the :443
# fallback (round 1.3.5, D10a: a real socketpair for :80, the :80
# budget cut to 200 ms so the silent-server case stays fast), first at
# the cached control address, and the one-shot request deadline (cut
# to 300 ms in 100-ms polls, doubling to 1.2 s; round 1.3.5) and the map
# stream's first-response deadline (400 ms doubling to 1.6 s; round
# 1.3.8). Includes
# ts2021_client.c over a fake esp_tls; host_include/ supplies esp_tls.h,
# esp_timer.h, lwip/sockets.h and friends.
TS2021_DEFS := -DCONFIG_TINYLINK_CONTROL_HOST='"controlplane.test"' \
               -DCONFIG_TINYLINK_CONTROL_PORT=443 -DCONFIG_TINYLINK_STREAM_IDLE_TIMEOUT_S=120 \
               -DCONFIG_TINYLINK_CONTROL_PLAIN_HTTP=1 -DTS2021_PLAIN_TIMEOUT_MS=200 \
               -DTS2021_REQ_TIMEOUT_MS=300 -DTS2021_REQ_POLL_MS=100 \
               -DTS2021_REQ_TIMEOUT_MAX_MS=1200 -DTS2021_RESP_TIMEOUT_MS=400 \
               -DTS2021_RESP_TIMEOUT_MAX_MS=1600
test_ts2021: test_ts2021.c $(TL_SRC)/ts2021_client.c $(TL_SRC)/ts2021_client.h \
             $(TL_SRC)/tls_io.c $(TL_SRC)/tls_resume.h $(TL_SRC)/tls_offer.c $(TL_SRC)/tls_offer.h \
             $(TL_SRC)/tl_addr.h $(NOISE_SRCS) host_include/esp_tls.h host_include/esp_timer.h
	$(CC) $(CFLAGS) $(TS2021_DEFS) -I$(TL_SRC) -I$(TL_INC) -I$(CRYPTO) -Ihost_include -o $@ \
	    test_ts2021.c $(TL_SRC)/tls_io.c $(TL_SRC)/tls_offer.c $(NOISE_SRCS)

# TLS 1.2 session resumption slot (round 1.3.5, D9) over a scripted
# esp_tls: tickets on, host shims for the session fields it reads.
test_tls_resume: test_tls_resume.c $(TL_SRC)/tls_resume.c $(TL_SRC)/tls_resume.h \
                 host_include/esp_tls.h host_include/mbedtls/ssl.h host_include/esp_timer.h
	$(CC) $(CFLAGS) -DCONFIG_ESP_TLS_CLIENT_SESSION_TICKETS=1 -I$(TL_SRC) -Ihost_include \
	    -o $@ test_tls_resume.c

# TLS ClientHello offer (round 1.3.8): ECDHE-RSA first, one full-offer
# retry on a handshake failure, remembered per server for 6 h.
test_tls_offer: test_tls_offer.c $(TL_SRC)/tls_offer.c $(TL_SRC)/tls_offer.h \
                host_include/esp_tls.h host_include/mbedtls/ssl.h host_include/mbedtls/x509.h \
                host_include/esp_timer.h
	$(CC) $(CFLAGS) -DCONFIG_ESP_TLS_CLIENT_SESSION_TICKETS=1 -DCONFIG_TINYLINK_TLS_RSA_FIRST=1 \
	    -I$(TL_SRC) -Ihost_include -o $@ test_tls_offer.c

# TLS sessions across warm resets (round 1.3.8): the RTC record (tls_rtc.h)
# and tls_resume.c's glue over a fake RTC timer and session serializer.
test_tls_rtc: test_tls_rtc.c $(TL_SRC)/tls_resume.c $(TL_SRC)/tls_resume.h $(TL_SRC)/tls_rtc.h \
              host_include/esp_tls.h host_include/mbedtls/ssl.h host_include/esp_timer.h
	$(CC) $(CFLAGS) -DCONFIG_ESP_TLS_CLIENT_SESSION_TICKETS=1 -DCONFIG_TINYLINK_TLS_RESUME_RTC=1 \
	    -I$(TL_SRC) -Ihost_include -o $@ test_tls_rtc.c

# In-tree HTTP/2 client (round 1.3.4, D1): HPACK (RFC 7541 Appendix C,
# Huffman, fuzz) and the frame / connection engine against a scripted
# peer. Platform-independent sources, no shims.
H2_SRCS := $(TL_SRC)/h2_core.c $(TL_SRC)/hpack.c
test_hpack: test_hpack.c $(TL_SRC)/hpack.c $(TL_SRC)/hpack.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_hpack.c $(TL_SRC)/hpack.c

test_h2_core: test_h2_core.c $(H2_SRCS) $(TL_SRC)/h2_core.h $(TL_SRC)/hpack.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_h2_core.c $(H2_SRCS)

# The map stream's first-response deadline end to end (round 1.3.8
# review): test_ts2021.c again, with the real HTTP/2 client instead of its
# stubs — h2_post_json_stream on conns ts2021_connect dials, through
# ts2021_close's port and address rules.
test_ts2021_e2e: test_ts2021.c $(TL_SRC)/ts2021_client.c $(TL_SRC)/ts2021_client.h \
                 $(TL_SRC)/h2_client.c $(TL_SRC)/h2_client.h $(H2_SRCS) \
                 $(TL_SRC)/tls_io.c $(TL_SRC)/tls_offer.c $(TL_SRC)/tls_offer.h $(NOISE_SRCS) \
                 host_include/esp_tls.h host_include/esp_timer.h
	$(CC) $(CFLAGS) $(TS2021_DEFS) -DTS2021_E2E -I$(TL_SRC) -I$(TL_INC) -I$(CRYPTO) -Ihost_include \
	    -o $@ test_ts2021.c $(TL_SRC)/tls_io.c $(TL_SRC)/tls_offer.c $(TL_SRC)/h2_client.c \
	    $(H2_SRCS) $(NOISE_SRCS)

# HTTP/2 interop against nghttp2's server side, in memory: the firmware
# stack (h2_client.c → h2_core → ts2021_client.c, Noise records over a
# fake esp_tls) as test_h2_interop, and the 1.3.4 nghttp2 client
# (ref/h2_134/) on the same scenarios as test_h2_ref. nghttp2 comes from
# NGHTTP2_COMPONENT — by default the managed component the firmware built
# against until D1 (idf.py fetched it into managed_components/; any IDF
# project with espressif/nghttp has one) — compiled here for the host;
# else the system library (pkg-config libnghttp2); else both are skipped
# with a notice (CI's host job has neither).
NGHTTP2_COMPONENT ?= ../../managed_components/espressif__nghttp
NG_LIB_DIR := test_nghttp2_host
NG_COMP := $(abspath $(NGHTTP2_COMPONENT))
ifneq ($(wildcard $(NG_COMP)/nghttp2/lib/nghttp2_session.c),)
  NG_SRC_DIR := $(NG_COMP)/nghttp2/lib
  NG_CFLAGS  := -I$(NG_SRC_DIR)/includes -I$(NG_COMP)/port/include
  NG_LIBS    := $(NG_LIB_DIR)/libnghttp2_host.a
  NG_DEP     := $(NG_LIBS)
  H2_INTEROP := test_h2_interop test_h2_ref
else ifneq ($(shell pkg-config --exists libnghttp2 2>/dev/null && echo y),)
  NG_CFLAGS  := $(shell pkg-config --cflags libnghttp2)
  NG_LIBS    := $(shell pkg-config --libs libnghttp2)
  NG_DEP     :=
  H2_INTEROP := test_h2_interop test_h2_ref
else
  H2_INTEROP :=
endif

$(NG_LIB_DIR)/libnghttp2_host.a:
	mkdir -p $(NG_LIB_DIR)
	cd $(NG_LIB_DIR) && for f in $(NG_SRC_DIR)/*.c; do \
	    $(CC) -O1 -w $(EXTRA_CFLAGS) -DHAVE_ARPA_INET_H -DHAVE_NETINET_IN_H -DHAVE_TIME_H \
	        -DHAVE_CLOCK_GETTIME $(NG_CFLAGS) -I$(NG_SRC_DIR) -c $$f || exit 1; done
	ar rcs $@ $(NG_LIB_DIR)/*.o

H2_STACK := $(TL_SRC)/h2_client.c $(H2_SRCS) $(TL_SRC)/ts2021_client.c $(TL_SRC)/tls_io.c \
            $(TL_SRC)/tls_offer.c $(NOISE_SRCS)
test_h2_interop: test_h2_interop.c $(H2_STACK) $(TL_SRC)/h2_client.h $(TL_SRC)/ts2021_client.h $(NG_DEP)
	$(CC) $(CFLAGS) $(TS2021_DEFS) $(NG_CFLAGS) -I$(TL_SRC) -I$(TL_INC) -I$(CRYPTO) -Ihost_include \
	    -o $@ test_h2_interop.c $(H2_STACK) $(NG_LIBS)

# The reference: nghttp2's deprecated ssize_t callback API, and atoi
# from an IDF header the host lacks — compiled as it was, warnings off
# for those two only.
test_h2_ref: test_h2_interop.c ref/h2_134/h2_client.c ref/h2_134/h2_client.h \
             ref/h2_134/ts2021_client.h $(NG_DEP)
	$(CC) $(CFLAGS) -DH2_REF -Wno-deprecated-declarations -include stdlib.h $(TS2021_DEFS) \
	    $(NG_CFLAGS) -Iref/h2_134 -I$(TL_SRC) -I$(TL_INC) -I$(CRYPTO) -Ihost_include \
	    -o $@ test_h2_interop.c ref/h2_134/h2_client.c $(NG_LIBS)

# WG handshake initiator (step 3a). Pulls in the crypto stack +
# wg_proto.c + wg_handshake.c. Uses host fallback for time(2) /
# clock_gettime(2) — the ESP_PLATFORM branches in wg_proto.c are
# guarded out at compile time.
test_wg_handshake: test_wg_handshake.c \
                  $(TL_SRC)/wg_handshake.c $(TL_SRC)/wg_handshake.h $(TL_SRC)/wg_path.h \
                  $(TL_SRC)/wg_proto.c $(TL_SRC)/wg_proto.h \
                  $(CRYPTO)/blake2s.c $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_fiat32.c \
                  $(CRYPTO)/hkdf_blake2s.c $(CRYPTO)/chacha20.c \
                  $(CRYPTO)/poly1305_donna.c $(CRYPTO)/chacha20poly1305.c
	$(CC) $(CFLAGS) -I$(TL_SRC) -I$(CRYPTO) -o $@ test_wg_handshake.c \
	    $(TL_SRC)/wg_handshake.c $(TL_SRC)/wg_proto.c \
	    $(CRYPTO)/blake2s.c $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_fiat32.c \
	    $(CRYPTO)/hkdf_blake2s.c $(CRYPTO)/chacha20.c \
	    $(CRYPTO)/poly1305_donna.c $(CRYPTO)/chacha20poly1305.c

# WG datagram classifier (UDP demuxer dispatch logic).
test_wg_demux: test_wg_demux.c $(TL_SRC)/wg_demux.c $(TL_SRC)/wg_demux.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_wg_demux.c $(TL_SRC)/wg_demux.c

# Power diagnostic bookkeeping (round 1.3.7, CONFIG_TINYLINK_POWER_DIAG):
# sleep classification, length bins, wrap-safe deltas, line formats, a
# replayed steady state. Header-only.
test_pwr_diag: test_pwr_diag.c $(TL_SRC)/pwr_diag.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_pwr_diag.c

# Telemetry task wake planning (round 1.3.7): the loop replayed over a
# fake clock with the soaks' tick drift — one wake per sample, the
# housekeeping and STUN re-probe never late. Header-only.
test_tlm_sched: test_tlm_sched.c $(TL_SRC)/tlm_sched.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_tlm_sched.c

# wg_netif RX-task deadline helpers (B7/B21). Header-only.
test_wg_timers: test_wg_timers.c $(TL_SRC)/wg_timers.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_wg_timers.c

# Data-plane path selection (round 1.3.6): direct / dual / DERP-only,
# pong rounds, the rescue ring, late RX wakes, and a simulation of the
# peer's passive keepalives over healthy, lossy, dead, one-way, healing
# and WireGuard-silent paths. Header-only.
test_wg_path: test_wg_path.c $(TL_SRC)/wg_path.h $(TL_SRC)/wg_rescue.h $(TL_SRC)/wg_timers.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_wg_path.c

# DISCO codec (Tailscale magicsock NAT-traversal messages). Pulls in the
# nacl_box wrapper (XSalsa20 + the in-tree poly1305-donna).
test_disco: test_disco.c \
            $(TL_SRC)/disco.c $(TL_SRC)/disco.h \
            $(CRYPTO)/nacl_box.c $(CRYPTO)/nacl_box.h \
            $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_fiat32.c $(CRYPTO)/salsa20.c \
            $(CRYPTO)/poly1305_donna.c
	$(CC) $(CFLAGS) -I$(TL_SRC) -I$(CRYPTO) -o $@ \
	    test_disco.c $(TL_SRC)/disco.c \
	    $(CRYPTO)/nacl_box.c $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_fiat32.c $(CRYPTO)/salsa20.c \
	    $(CRYPTO)/poly1305_donna.c

# STUN binding client (RFC 5389) — public-endpoint discovery for
# magicsock NAT traversal. Pure codec, no I/O, no platform deps.
test_stun: test_stun.c $(TL_SRC)/stun.c $(TL_SRC)/stun.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_stun.c $(TL_SRC)/stun.c

# tls_io — retry-on-WANT regression KAT. Gates against the long-poll
# disconnect bug fixed in c2d8d63 (treating MBEDTLS_ERR_SSL_WANT_READ
# as fatal would tear down the /machine/map stream every 30 s).
# Uses host_include/mbedtls/ssl.h shim for the WANT_* constants only.
test_tls_io: test_tls_io.c $(TL_SRC)/tls_io.c $(TL_SRC)/tls_io.h \
             host_include/mbedtls/ssl.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -Ihost_include -o $@ \
	    test_tls_io.c $(TL_SRC)/tls_io.c

# DISCO inbound handler (M3 step 2) — orchestrates open + parse +
# encode + seal to turn an incoming Ping into a sealed Pong reply.
# Pure-C, host-testable. Pulls the same nacl_box bundle as test_disco.
test_disco_handler: test_disco_handler.c \
                    $(TL_SRC)/disco_handler.c $(TL_SRC)/disco_handler.h \
                    $(TL_SRC)/disco.c $(TL_SRC)/disco.h \
                    $(CRYPTO)/nacl_box.c $(CRYPTO)/nacl_box.h \
                    $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_fiat32.c $(CRYPTO)/salsa20.c \
                    $(CRYPTO)/poly1305_donna.c
	$(CC) $(CFLAGS) -I$(TL_SRC) -I$(CRYPTO) -o $@ \
	    test_disco_handler.c \
	    $(TL_SRC)/disco_handler.c $(TL_SRC)/disco.c \
	    $(CRYPTO)/nacl_box.c $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_fiat32.c $(CRYPTO)/salsa20.c \
	    $(CRYPTO)/poly1305_donna.c

# DISCO outbound prober (M3 step 3) — tx-id table that binds inbound
# Pongs to outbound Pings; defeats the same capture-and-replay attack
# class that the deleted disco_replay.c targeted, but with a tighter
# control (a replayed Pong with no matching outstanding Ping is dropped
# silently). Standalone module, no crypto.
test_disco_prober: test_disco_prober.c \
                   $(TL_SRC)/disco_prober.c $(TL_SRC)/disco_prober.h \
                   $(TL_SRC)/disco.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ \
	    test_disco_prober.c $(TL_SRC)/disco_prober.c

# DERP wire codec + recv loop — frame header + login handshake +
# packet relay + ping/pong + control frames + the M5 step 2b dispatch
# loop. Pulls in nacl_box like test_disco does and tls_io for the
# WANT_READ-tolerant frame reader (host_include/mbedtls/ssl.h shim).
test_derp: test_derp.c \
           $(TL_SRC)/derp.c $(TL_SRC)/derp.h \
           $(TL_SRC)/tls_io.c $(TL_SRC)/tls_io.h \
           $(CRYPTO)/nacl_box.c $(CRYPTO)/nacl_box.h \
           $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_fiat32.c $(CRYPTO)/salsa20.c \
           $(CRYPTO)/poly1305_donna.c \
           host_include/mbedtls/ssl.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -I$(CRYPTO) -Ihost_include -o $@ \
	    test_derp.c $(TL_SRC)/derp.c $(TL_SRC)/tls_io.c \
	    $(CRYPTO)/nacl_box.c $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_fiat32.c $(CRYPTO)/salsa20.c \
	    $(CRYPTO)/poly1305_donna.c

# The DERP write lock (round 1.3.9): close vs a writer on a stalled conn,
# waits that feed the task WDT (capped), a failed write closing the conn
# to frames — derp_client.c itself (#included) over fakes of esp_tls,
# FreeRTOS and select(), a scripted DERP login, pthreads.
DERP_WLOCK_SRCS := $(TL_SRC)/derp.c $(TL_SRC)/tls_io.c $(TL_SRC)/tls_offer.c \
                   $(CRYPTO)/nacl_box.c $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_fiat32.c \
                   $(CRYPTO)/salsa20.c $(CRYPTO)/poly1305_donna.c
test_derp_wlock: test_derp_wlock.c $(TL_SRC)/derp_client.c $(TL_SRC)/derp_client.h \
                 $(TL_SRC)/derp_wlock.h $(TL_SRC)/derp.h $(TL_SRC)/tls_io.h $(TL_SRC)/tls_offer.h \
                 $(DERP_WLOCK_SRCS) host_include/esp_tls.h host_include/freertos/semphr.h \
                 host_include/esp_random.h host_include/mbedtls/ssl.h
	$(CC) $(CFLAGS) -pthread -I$(TL_SRC) -I$(TL_INC) -I$(CRYPTO) -Ihost_include -o $@ \
	    test_derp_wlock.c $(DERP_WLOCK_SRCS)

# HTTP/2 Retry-After header parser (RFC 7231 §7.1.3 delta-seconds).
# Header-only; the test just compiles the .c against the .h. No platform
# deps, no crypto.
test_retry_after: test_retry_after.c $(TL_SRC)/h2_retry_after.h $(TL_SRC)/tl_date.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_retry_after.c

# WG transport (data plane) — encrypt/decrypt + RFC 6479 anti-replay, and
# the 1.3.3 (C2) split RX/TX lock protocol (pthread stress: -pthread).
test_wg_transport: test_wg_transport.c \
                  $(TL_SRC)/wg_transport.c $(TL_SRC)/wg_transport.h \
                  $(TL_SRC)/wg_proto.c $(TL_SRC)/wg_proto.h \
                  $(CRYPTO)/blake2s.c $(CRYPTO)/hkdf_blake2s.c \
                  $(CRYPTO)/chacha20.c $(CRYPTO)/poly1305_donna.c \
                  $(CRYPTO)/chacha20poly1305.c $(CRYPTO)/secure_zero.h
	$(CC) $(CFLAGS) -pthread -I$(TL_SRC) -I$(CRYPTO) -o $@ test_wg_transport.c \
	    $(TL_SRC)/wg_transport.c $(TL_SRC)/wg_proto.c \
	    $(CRYPTO)/blake2s.c $(CRYPTO)/hkdf_blake2s.c \
	    $(CRYPTO)/chacha20.c $(CRYPTO)/poly1305_donna.c \
	    $(CRYPTO)/chacha20poly1305.c

.PHONY: all test asan clean mbedtls-ref h2_interop.run $(addsuffix .run,$(TARGETS))

# ---- Optional: the pre-1.3.2 mbedTLS path as a reference ----------------
# Not part of `make test` (CI has no ESP-IDF). Needs IDF_PATH (or
# MBEDTLS_DIR) for the mbedTLS sources IDF ships:
#   make mbedtls-ref IDF_PATH=/path/to/esp-idf
#  - test_aead_mbedtls: in-tree ChaCha20-Poly1305 / Poly1305 vs
#    mbedtls_chachapoly_* / mbedtls_poly1305_mac, fixed-seed fuzz;
#  - test_noise_ik_mbedtls: test_noise_ik.c linked against noise_ik.c as
#    of $(NOISE_OLD_REV) (git), i.e. on mbedTLS chachapoly — the same
#    vectors must pass.
MBEDTLS_DIR    ?= $(IDF_PATH)/components/mbedtls/mbedtls
NOISE_OLD_REV  ?= 1477aa3
MBEDTLS_REF    := test_mbedtls_ref
MBEDTLS_LIB    := $(MBEDTLS_REF)/libmbedref.a
MBEDTLS_REF_SRCS := chachapoly.c chacha20.c poly1305.c platform_util.c constant_time.c

$(MBEDTLS_LIB):
	@test -d "$(MBEDTLS_DIR)/library" || { echo "set IDF_PATH or MBEDTLS_DIR"; exit 2; }
	mkdir -p $(MBEDTLS_REF)
	cd $(MBEDTLS_REF) && $(CC) -O2 -w -c -I$(MBEDTLS_DIR)/include -I$(MBEDTLS_DIR)/library \
	    $(addprefix $(MBEDTLS_DIR)/library/,$(MBEDTLS_REF_SRCS))
	ar rcs $@ $(addprefix $(MBEDTLS_REF)/,$(MBEDTLS_REF_SRCS:.c=.o))

$(MBEDTLS_REF)/noise_ik_pre132.c:
	mkdir -p $(MBEDTLS_REF)
	git -C ../.. show $(NOISE_OLD_REV):components/tinylink/src/noise_ik.c > $@

test_aead_mbedtls: test_aead_mbedtls.c $(MBEDTLS_LIB) \
                   $(CRYPTO)/chacha20poly1305.c $(CRYPTO)/chacha20.c $(CRYPTO)/poly1305_donna.c
	$(CC) $(CFLAGS) -I$(CRYPTO) -isystem $(MBEDTLS_DIR)/include -o $@ test_aead_mbedtls.c \
	    $(CRYPTO)/chacha20poly1305.c $(CRYPTO)/chacha20.c $(CRYPTO)/poly1305_donna.c $(MBEDTLS_LIB)

test_noise_ik_mbedtls: test_noise_ik.c $(MBEDTLS_REF)/noise_ik_pre132.c $(MBEDTLS_LIB) $(NOISE_SRCS)
	$(CC) $(CFLAGS) -DNOISE_OLD_PATH -I$(TL_SRC) -I$(CRYPTO) -Ihost_include \
	    -isystem $(MBEDTLS_DIR)/include -o $@ test_noise_ik.c \
	    $(MBEDTLS_REF)/noise_ik_pre132.c $(filter-out $(TL_SRC)/noise_ik.c,$(NOISE_SRCS)) $(MBEDTLS_LIB)

mbedtls-ref: test_aead_mbedtls test_noise_ik_mbedtls
	$(RUNNER) ./test_aead_mbedtls
	$(RUNNER) ./test_noise_ik_mbedtls

# Sanitized run: AddressSanitizer + UndefinedBehaviorSanitizer (incl.
# alignment checks — the crypto fast paths depend on the
# aligned/unaligned dispatch being right). `shift-base` is excluded on
# purpose: the vendored curve25519-donna does `limb << n` on negative
# 64-bit limbs (curve25519_donna.c:226 and friends), which C11 calls
# undefined but GCC documents as two's-complement (and every KAT
# confirms); flagging it would only hide real findings. Donna is only
# the X25519 test oracle since round 1.3.3 (ref/curve25519_donna.c).
# Always rebuilds
# from clean so stale unsanitized binaries can't slip through.
asan:
	$(MAKE) clean
	$(MAKE) EXTRA_CFLAGS='-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize=shift-base -fno-sanitize-recover=all' test
	$(MAKE) clean

test: test_blake2s.run test_curve25519.run test_x25519.run test_mapresp.run \
      test_chacha20.run test_poly1305.run test_chacha20poly1305.run \
      test_hkdf_noise.run test_wg_handshake.run test_wg_transport.run \
      test_wg_demux.run test_wg_timers.run test_wg_path.run test_disco.run test_stun.run test_tls_io.run \
      test_derp.run test_disco_handler.run test_disco_prober.run \
      test_retry_after.run test_backoff.run test_keys_regen.run test_stun_boot.run \
      test_skip_value.run test_jsmn_split.run test_tai64n.run \
      test_nacl_box.run test_tsmp.run test_tl_date.run test_stats.run test_noise_ik.run \
      test_http1.run test_ctrl_json.run test_ts2021.run test_hpack.run test_h2_core.run \
      test_tls_resume.run test_addr.run test_wifi_hint.run test_wifi_psk.run test_pwr_diag.run \
      test_tlm_sched.run test_tls_offer.run test_tls_rtc.run test_ts2021_e2e.run \
      test_derp_wlock.run h2_interop.run

test_tls_rtc.run: test_tls_rtc
	$(RUNNER) ./test_tls_rtc

test_tls_offer.run: test_tls_offer
	$(RUNNER) ./test_tls_offer

test_tls_resume.run: test_tls_resume
	$(RUNNER) ./test_tls_resume

test_addr.run: test_addr
	$(RUNNER) ./test_addr

test_wifi_hint.run: test_wifi_hint
	$(RUNNER) ./test_wifi_hint

test_wifi_psk.run: test_wifi_psk
	$(RUNNER) ./test_wifi_psk

test_pwr_diag.run: test_pwr_diag
	$(RUNNER) ./test_pwr_diag

test_tlm_sched.run: test_tlm_sched
	$(RUNNER) ./test_tlm_sched

test_hpack.run: test_hpack
	$(RUNNER) ./test_hpack

test_h2_core.run: test_h2_core
	$(RUNNER) ./test_h2_core

ifneq ($(H2_INTEROP),)
h2_interop.run: test_h2_interop test_h2_ref
	$(RUNNER) ./test_h2_interop
	$(RUNNER) ./test_h2_ref
else
h2_interop.run:
	@echo "h2 interop: skipped — no nghttp2 (set NGHTTP2_COMPONENT=<espressif__nghttp dir> or install libnghttp2)"
endif

test_ts2021.run: test_ts2021
	$(RUNNER) ./test_ts2021

test_ts2021_e2e.run: test_ts2021_e2e
	$(RUNNER) ./test_ts2021_e2e

test_http1.run: test_http1
	$(RUNNER) ./test_http1

test_ctrl_json.run: test_ctrl_json
	$(RUNNER) ./test_ctrl_json

test_blake2s.run: test_blake2s
	$(RUNNER) ./test_blake2s

test_curve25519.run: test_curve25519
	$(RUNNER) ./test_curve25519

test_x25519.run: test_x25519
	$(RUNNER) ./test_x25519

test_mapresp.run: test_mapresp
	$(RUNNER) ./test_mapresp

test_chacha20.run: test_chacha20
	$(RUNNER) ./test_chacha20

test_tl_date.run: test_tl_date
	$(RUNNER) ./test_tl_date

test_stats.run: test_stats
	$(RUNNER) ./test_stats

test_tsmp.run: test_tsmp
	$(RUNNER) ./test_tsmp

test_backoff.run: test_backoff
	$(RUNNER) ./test_backoff

test_keys_regen.run: test_keys_regen
	$(RUNNER) ./test_keys_regen

test_stun_boot.run: test_stun_boot
	$(RUNNER) ./test_stun_boot

test_skip_value.run: test_skip_value
	$(RUNNER) ./test_skip_value

test_jsmn_split.run: test_jsmn_split
	$(RUNNER) ./test_jsmn_split

test_tai64n.run: test_tai64n
	$(RUNNER) ./test_tai64n

test_nacl_box.run: test_nacl_box
	$(RUNNER) ./test_nacl_box

test_noise_ik.run: test_noise_ik
	$(RUNNER) ./test_noise_ik

test_poly1305.run: test_poly1305
	$(RUNNER) ./test_poly1305

test_chacha20poly1305.run: test_chacha20poly1305
	$(RUNNER) ./test_chacha20poly1305

test_hkdf_noise.run: test_hkdf_noise
	$(RUNNER) ./test_hkdf_noise

test_wg_handshake.run: test_wg_handshake
	$(RUNNER) ./test_wg_handshake

test_wg_transport.run: test_wg_transport
	$(RUNNER) ./test_wg_transport

test_wg_demux.run: test_wg_demux
	$(RUNNER) ./test_wg_demux

test_wg_timers.run: test_wg_timers
	$(RUNNER) ./test_wg_timers

test_wg_path.run: test_wg_path
	$(RUNNER) ./test_wg_path

test_disco.run: test_disco
	$(RUNNER) ./test_disco

test_stun.run: test_stun
	$(RUNNER) ./test_stun

test_tls_io.run: test_tls_io
	$(RUNNER) ./test_tls_io

test_derp_wlock.run: test_derp_wlock
	$(RUNNER) ./test_derp_wlock

test_derp.run: test_derp
	$(RUNNER) ./test_derp

test_disco_handler.run: test_disco_handler
	$(RUNNER) ./test_disco_handler

test_disco_prober.run: test_disco_prober
	$(RUNNER) ./test_disco_prober

test_retry_after.run: test_retry_after
	$(RUNNER) ./test_retry_after

clean:
	rm -f $(TARGETS) test_aead_mbedtls test_noise_ik_mbedtls test_h2_interop test_h2_ref
	rm -rf $(MBEDTLS_REF) $(NG_LIB_DIR)
