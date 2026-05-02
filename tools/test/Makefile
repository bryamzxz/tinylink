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
CFLAGS  ?= -O2 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare \
           -std=c11 -D_DEFAULT_SOURCE
CRYPTO  := ../../components/tinylink/src/crypto

TL_SRC  := ../../components/tinylink/src

TARGETS := test_blake2s test_curve25519 test_mapresp \
           test_chacha20 test_poly1305 test_chacha20poly1305 \
           test_hkdf_noise

all: $(TARGETS)

test_blake2s: test_blake2s.c $(CRYPTO)/blake2s.c $(CRYPTO)/blake2s.h
	$(CC) $(CFLAGS) -I$(CRYPTO) -o $@ test_blake2s.c $(CRYPTO)/blake2s.c

test_curve25519: test_curve25519.c $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519.h
	$(CC) $(CFLAGS) -I$(CRYPTO) -o $@ test_curve25519.c $(CRYPTO)/curve25519.c

# mapreq.c builds on host because its ESP-IDF-specific code is guarded
# by #ifdef ESP_PLATFORM; the mapresp_parse() entry point we test here
# is platform-independent and depends only on the vendored jsmn.h.
test_mapresp: test_mapresp.c $(TL_SRC)/mapreq.c $(TL_SRC)/netmap.h $(TL_SRC)/jsmn.h
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

.PHONY: test test_blake2s.run test_curve25519.run test_mapresp.run \
        test_chacha20.run test_poly1305.run test_chacha20poly1305.run \
        test_hkdf_noise.run clean

test: test_blake2s.run test_curve25519.run test_mapresp.run \
      test_chacha20.run test_poly1305.run test_chacha20poly1305.run \
      test_hkdf_noise.run

test_blake2s.run: test_blake2s
	./test_blake2s

test_curve25519.run: test_curve25519
	./test_curve25519

test_mapresp.run: test_mapresp
	./test_mapresp

test_chacha20.run: test_chacha20
	./test_chacha20

test_poly1305.run: test_poly1305
	./test_poly1305

test_chacha20poly1305.run: test_chacha20poly1305
	./test_chacha20poly1305

test_hkdf_noise.run: test_hkdf_noise
	./test_hkdf_noise

clean:
	rm -f $(TARGETS)
