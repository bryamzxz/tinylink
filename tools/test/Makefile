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

TARGETS := test_blake2s test_curve25519

all: $(TARGETS)

test_blake2s: test_blake2s.c $(CRYPTO)/blake2s.c $(CRYPTO)/blake2s.h
	$(CC) $(CFLAGS) -I$(CRYPTO) -o $@ test_blake2s.c $(CRYPTO)/blake2s.c

test_curve25519: test_curve25519.c $(CRYPTO)/curve25519.c $(CRYPTO)/curve25519.h
	$(CC) $(CFLAGS) -I$(CRYPTO) -o $@ test_curve25519.c $(CRYPTO)/curve25519.c

.PHONY: test test_blake2s.run test_curve25519.run clean

test: test_blake2s.run test_curve25519.run

test_blake2s.run: test_blake2s
	./test_blake2s

test_curve25519.run: test_curve25519
	./test_curve25519

clean:
	rm -f $(TARGETS)
