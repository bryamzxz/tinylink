#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Bryam (bryamzxz)
"""Regenerate the libsodium reference vectors embedded in test_nacl_box.c.

Requires PyNaCl (`pip install pynacl`). Keys are SHA-256 of two fixed
strings, the nonce is 0..23, and the messages are the four cases the KAT
exercises (empty, DISCO magic, 1..63, 113 bytes). Prints C initializers.
"""
import hashlib
import nacl.bindings as b

sk_a = hashlib.sha256(b"tinylink-nacl-kat-a").digest()
sk_b = hashlib.sha256(b"tinylink-nacl-kat-b").digest()
pk_a = b.crypto_scalarmult_base(sk_a)
pk_b = b.crypto_scalarmult_base(sk_b)
nonce = bytes(range(24))
msgs = [b"", b"TS\xf0\x9f\x92\xac\x01\x00", bytes(range(1, 64)), b"x" * 113]

def hexc(x):
    return ", ".join("0x%02x" % c for c in x)

print("kSkA:", hexc(sk_a)); print("kPkA:", hexc(pk_a))
print("kSkB:", hexc(sk_b)); print("kPkB:", hexc(pk_b))
for i, m in enumerate(msgs):
    print("kC%d:" % i, hexc(b.crypto_box(m, nonce, pk_b, sk_a)))
