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

TARGETS := test_blake2s test_curve25519 test_mapresp

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

.PHONY: test test_blake2s.run test_curve25519.run test_mapresp.run clean

test: test_blake2s.run test_curve25519.run test_mapresp.run

test_blake2s.run: test_blake2s
	./test_blake2s

test_curve25519.run: test_curve25519
	./test_curve25519

test_mapresp.run: test_mapresp
	./test_mapresp

clean:
	rm -f $(TARGETS)
