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

TARGETS := test_blake2s test_curve25519 test_mapresp \
           test_chacha20 test_poly1305 test_chacha20poly1305 \
           test_hkdf_noise test_wg_handshake test_wg_transport \
           test_wg_demux test_disco test_stun test_tls_io test_derp \
           test_disco_handler test_disco_prober test_retry_after \
           test_backoff test_keys_regen test_skip_value test_jsmn_split \
           test_tai64n test_nacl_box

all: $(TARGETS)

# Pure exponential-backoff-with-jitter helper (RC-2). Header-only.
test_backoff: test_backoff.c $(TL_INC)/backoff.h
	$(CC) $(CFLAGS) -I$(TL_INC) -o $@ test_backoff.c

# Pure identity-regeneration policy (headscale 1:1 NodeKey/MachineKey). Header-only.
test_keys_regen: test_keys_regen.c $(TL_SRC)/keys_regen.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_keys_regen.c

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

# libsodium reference vectors for the NaCl box (DISCO sealing).
test_nacl_box: test_nacl_box.c $(CRYPTO)/nacl_box.c $(CRYPTO)/salsa20.c $(CRYPTO)/poly1305_donna.c \
               $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_donna.c host_mbedtls_shim.c
	$(CC) $(CFLAGS) -Ihost_include -I$(CRYPTO) -o $@ test_nacl_box.c $(CRYPTO)/nacl_box.c \
	    $(CRYPTO)/salsa20.c $(CRYPTO)/poly1305_donna.c $(CRYPTO)/curve25519.c \
	    $(CRYPTO)/curve25519_donna.c host_mbedtls_shim.c

test_blake2s: test_blake2s.c $(CRYPTO)/blake2s.c $(CRYPTO)/blake2s.h
	$(CC) $(CFLAGS) -I$(CRYPTO) -o $@ test_blake2s.c $(CRYPTO)/blake2s.c

test_curve25519: test_curve25519.c $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_donna.c $(CRYPTO)/curve25519.h
	$(CC) $(CFLAGS) -I$(CRYPTO) -o $@ test_curve25519.c $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_donna.c

# mapreq.c builds on host because its ESP-IDF-specific code is guarded
# by #ifdef ESP_PLATFORM; the mapresp_parse() entry point we test here
# is platform-independent and depends only on the vendored jsmn.h.
test_mapresp: test_mapresp.c $(TL_SRC)/mapreq.c $(TL_SRC)/netmap.h $(TL_SRC)/jsmn.h $(TL_SRC)/jsmn_split.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_mapresp.c $(TL_SRC)/mapreq.c

# RFC 8439 §2.4.2 — ChaCha20 keystream KAT.
test_chacha20: test_chacha20.c $(CRYPTO)/chacha20.c $(CRYPTO)/chacha20.h
	$(CC) $(CFLAGS) -I$(CRYPTO) -o $@ test_chacha20.c $(CRYPTO)/chacha20.c

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

# WG handshake initiator (step 3a). Pulls in the crypto stack +
# wg_proto.c + wg_handshake.c. Uses host fallback for time(2) /
# clock_gettime(2) — the ESP_PLATFORM branches in wg_proto.c are
# guarded out at compile time.
test_wg_handshake: test_wg_handshake.c \
                  $(TL_SRC)/wg_handshake.c $(TL_SRC)/wg_handshake.h \
                  $(TL_SRC)/wg_proto.c $(TL_SRC)/wg_proto.h \
                  $(CRYPTO)/blake2s.c $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_donna.c \
                  $(CRYPTO)/hkdf_blake2s.c $(CRYPTO)/chacha20.c \
                  $(CRYPTO)/poly1305_donna.c $(CRYPTO)/chacha20poly1305.c
	$(CC) $(CFLAGS) -I$(TL_SRC) -I$(CRYPTO) -o $@ test_wg_handshake.c \
	    $(TL_SRC)/wg_handshake.c $(TL_SRC)/wg_proto.c \
	    $(CRYPTO)/blake2s.c $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_donna.c \
	    $(CRYPTO)/hkdf_blake2s.c $(CRYPTO)/chacha20.c \
	    $(CRYPTO)/poly1305_donna.c $(CRYPTO)/chacha20poly1305.c

# WG datagram classifier (UDP demuxer dispatch logic).
test_wg_demux: test_wg_demux.c $(TL_SRC)/wg_demux.c $(TL_SRC)/wg_demux.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_wg_demux.c $(TL_SRC)/wg_demux.c

# DISCO codec (Tailscale magicsock NAT-traversal messages). Pulls in the
# nacl_box wrapper, which on-target depends on mbedtls poly1305; on host
# we satisfy that single symbol with host_mbedtls_shim.c using the
# in-tree poly1305-donna.
test_disco: test_disco.c \
            $(TL_SRC)/disco.c $(TL_SRC)/disco.h \
            $(CRYPTO)/nacl_box.c $(CRYPTO)/nacl_box.h \
            $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_donna.c $(CRYPTO)/salsa20.c \
            $(CRYPTO)/poly1305_donna.c host_mbedtls_shim.c \
            host_include/mbedtls/poly1305.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -I$(CRYPTO) -Ihost_include -o $@ \
	    test_disco.c $(TL_SRC)/disco.c \
	    $(CRYPTO)/nacl_box.c $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_donna.c $(CRYPTO)/salsa20.c \
	    $(CRYPTO)/poly1305_donna.c host_mbedtls_shim.c

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
                    $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_donna.c $(CRYPTO)/salsa20.c \
                    $(CRYPTO)/poly1305_donna.c host_mbedtls_shim.c \
                    host_include/mbedtls/poly1305.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -I$(CRYPTO) -Ihost_include -o $@ \
	    test_disco_handler.c \
	    $(TL_SRC)/disco_handler.c $(TL_SRC)/disco.c \
	    $(CRYPTO)/nacl_box.c $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_donna.c $(CRYPTO)/salsa20.c \
	    $(CRYPTO)/poly1305_donna.c host_mbedtls_shim.c

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
# loop. Pulls in nacl_box like test_disco does (same poly1305 host
# shim) and tls_io for the WANT_READ-tolerant frame reader.
test_derp: test_derp.c \
           $(TL_SRC)/derp.c $(TL_SRC)/derp.h \
           $(TL_SRC)/tls_io.c $(TL_SRC)/tls_io.h \
           $(CRYPTO)/nacl_box.c $(CRYPTO)/nacl_box.h \
           $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_donna.c $(CRYPTO)/salsa20.c \
           $(CRYPTO)/poly1305_donna.c host_mbedtls_shim.c \
           host_include/mbedtls/poly1305.h \
           host_include/mbedtls/ssl.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -I$(CRYPTO) -Ihost_include -o $@ \
	    test_derp.c $(TL_SRC)/derp.c $(TL_SRC)/tls_io.c \
	    $(CRYPTO)/nacl_box.c $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519_donna.c $(CRYPTO)/salsa20.c \
	    $(CRYPTO)/poly1305_donna.c host_mbedtls_shim.c

# HTTP/2 Retry-After header parser (RFC 7231 §7.1.3 delta-seconds).
# Header-only; the test just compiles the .c against the .h. No platform
# deps, no crypto.
test_retry_after: test_retry_after.c $(TL_SRC)/h2_retry_after.h
	$(CC) $(CFLAGS) -I$(TL_SRC) -o $@ test_retry_after.c

# WG transport (data plane) — encrypt/decrypt + RFC 6479 anti-replay.
test_wg_transport: test_wg_transport.c \
                  $(TL_SRC)/wg_transport.c $(TL_SRC)/wg_transport.h \
                  $(TL_SRC)/wg_proto.c $(TL_SRC)/wg_proto.h \
                  $(CRYPTO)/blake2s.c $(CRYPTO)/hkdf_blake2s.c \
                  $(CRYPTO)/chacha20.c $(CRYPTO)/poly1305_donna.c \
                  $(CRYPTO)/chacha20poly1305.c
	$(CC) $(CFLAGS) -I$(TL_SRC) -I$(CRYPTO) -o $@ test_wg_transport.c \
	    $(TL_SRC)/wg_transport.c $(TL_SRC)/wg_proto.c \
	    $(CRYPTO)/blake2s.c $(CRYPTO)/hkdf_blake2s.c \
	    $(CRYPTO)/chacha20.c $(CRYPTO)/poly1305_donna.c \
	    $(CRYPTO)/chacha20poly1305.c

.PHONY: all test asan clean $(addsuffix .run,$(TARGETS))

# Sanitized run: AddressSanitizer + UndefinedBehaviorSanitizer (incl.
# alignment checks — the crypto fast paths depend on the
# aligned/unaligned dispatch being right). `shift-base` is excluded on
# purpose: the vendored curve25519-donna does `limb << n` on negative
# 64-bit limbs (curve25519_donna.c:226 and friends), which C11 calls
# undefined but GCC documents as two's-complement (and every KAT
# confirms); flagging it would only hide real findings. Always rebuilds
# from clean so stale unsanitized binaries can't slip through.
asan:
	$(MAKE) clean
	$(MAKE) EXTRA_CFLAGS='-g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize=shift-base -fno-sanitize-recover=all' test
	$(MAKE) clean

test: test_blake2s.run test_curve25519.run test_mapresp.run \
      test_chacha20.run test_poly1305.run test_chacha20poly1305.run \
      test_hkdf_noise.run test_wg_handshake.run test_wg_transport.run \
      test_wg_demux.run test_disco.run test_stun.run test_tls_io.run \
      test_derp.run test_disco_handler.run test_disco_prober.run \
      test_retry_after.run test_backoff.run test_keys_regen.run \
      test_skip_value.run test_jsmn_split.run test_tai64n.run \
      test_nacl_box.run

test_blake2s.run: test_blake2s
	$(RUNNER) ./test_blake2s

test_curve25519.run: test_curve25519
	$(RUNNER) ./test_curve25519

test_mapresp.run: test_mapresp
	$(RUNNER) ./test_mapresp

test_chacha20.run: test_chacha20
	$(RUNNER) ./test_chacha20

test_backoff.run: test_backoff
	$(RUNNER) ./test_backoff

test_keys_regen.run: test_keys_regen
	$(RUNNER) ./test_keys_regen

test_skip_value.run: test_skip_value
	$(RUNNER) ./test_skip_value

test_jsmn_split.run: test_jsmn_split
	$(RUNNER) ./test_jsmn_split

test_tai64n.run: test_tai64n
	$(RUNNER) ./test_tai64n

test_nacl_box.run: test_nacl_box
	$(RUNNER) ./test_nacl_box

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

test_disco.run: test_disco
	$(RUNNER) ./test_disco

test_stun.run: test_stun
	$(RUNNER) ./test_stun

test_tls_io.run: test_tls_io
	$(RUNNER) ./test_tls_io

test_derp.run: test_derp
	$(RUNNER) ./test_derp

test_disco_handler.run: test_disco_handler
	$(RUNNER) ./test_disco_handler

test_disco_prober.run: test_disco_prober
	$(RUNNER) ./test_disco_prober

test_retry_after.run: test_retry_after
	$(RUNNER) ./test_retry_after

clean:
	rm -f $(TARGETS)
