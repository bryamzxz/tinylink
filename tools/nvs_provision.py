#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Bryam (bryamzxz)
"""Generate the tinylink credentials NVS partition (`nvs_creds`).

Wraps ESP-IDF's nvs_partition_gen.py so the user only has to edit a CSV
file. Fails loudly if the input still contains REPLACE_WITH_ placeholders,
if a required key is missing, or if the auth key does not look like a
Tailscale auth key.

The CSV must declare the `tl_creds` namespace with three string keys:
`wifi_ssid`, `wifi_pass`, `auth_key` — see tools/credentials.csv.example
and docs/PROVISIONING.md. There are no WireGuard keys: node identities are
generated on the device at first boot.

Output is PLAINTEXT by default. The project deliberately does not enable
flash encryption / NVS encryption (eFuse burns are irreversible; see
docs/ROADMAP.md "Execution queue"), so an encrypted partition would be
unreadable by the firmware. `--encrypt` remains available for forks that
do enable CONFIG_NVS_ENCRYPTION.
"""

from __future__ import annotations

import argparse
import csv
import os
import shutil
import subprocess
import sys
from pathlib import Path

NAMESPACE = "tl_creds"
REQUIRED_KEYS = {"wifi_ssid", "wifi_pass", "auth_key"}
AUTH_KEY_PREFIX = "tskey-"


def find_idf_tool() -> Path:
    idf_path = os.environ.get("IDF_PATH")
    if not idf_path:
        sys.exit("error: IDF_PATH is not set. Source ESP-IDF's export.sh first.")
    candidate = (Path(idf_path) / "components" / "nvs_flash"
                 / "nvs_partition_generator" / "nvs_partition_gen.py")
    if not candidate.is_file():
        sys.exit(f"error: nvs_partition_gen.py not found at {candidate}")
    return candidate


def validate_csv(csv_path: Path) -> None:
    seen: set[str] = set()
    namespaces: set[str] = set()
    with csv_path.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = row.get("key", "").strip()
            value = row.get("value", "").strip()
            row_type = row.get("type", "").strip()
            if not key:
                continue
            if row_type == "namespace":
                namespaces.add(key)
                continue
            if value.startswith("REPLACE_WITH_") or value.endswith("REPLACE_ME"):
                sys.exit(f"error: {csv_path} still has placeholder for '{key}'")
            seen.add(key)
            if key == "auth_key" and not value.startswith(AUTH_KEY_PREFIX):
                sys.exit(f"error: auth_key must start with '{AUTH_KEY_PREFIX}' "
                         f"(got '{value[:8]}…')")
    if NAMESPACE not in namespaces:
        sys.exit(f"error: {csv_path} must declare the '{NAMESPACE}' namespace "
                 f"(found: {', '.join(sorted(namespaces)) or 'none'})")
    missing = REQUIRED_KEYS - seen
    if missing:
        sys.exit(f"error: {csv_path} is missing keys: {', '.join(sorted(missing))}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", required=True, type=Path,
                        help="Path to credentials CSV (see tools/credentials.csv.example).")
    parser.add_argument("--output", required=True, type=Path,
                        help="Output binary path (e.g. build/nvs_creds.bin).")
    parser.add_argument("--size", default="0x4000",
                        help="Partition size in bytes (hex). Default 0x4000, matching "
                             "the nvs_creds entry in partitions.csv.")
    parser.add_argument("--encrypt", action="store_true",
                        help="Generate an NVS-encrypted partition (only for builds with "
                             "CONFIG_NVS_ENCRYPTION=y; the stock firmware cannot read it).")
    parser.add_argument("--keyfile", type=Path,
                        help="With --encrypt: NVS encryption keyfile. If omitted, "
                             "nvs_partition_gen.py generates one next to --output.")
    args = parser.parse_args()

    if not args.input.is_file():
        sys.exit(f"error: input {args.input} does not exist")
    args.output.parent.mkdir(parents=True, exist_ok=True)

    validate_csv(args.input)

    tool = find_idf_tool()
    cmd = [sys.executable, str(tool)]
    cmd.append("encrypt" if args.encrypt else "generate")
    cmd.extend([str(args.input), str(args.output), args.size])
    if args.encrypt:
        if args.keyfile:
            cmd.extend(["--inputkey", str(args.keyfile)])
        else:
            cmd.extend(["--keygen", "--keyfile",
                        str(args.output.with_suffix(".key"))])

    print(f"+ {' '.join(cmd)}")
    if shutil.which(sys.executable) is None:
        sys.exit("error: python interpreter not on PATH")
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
