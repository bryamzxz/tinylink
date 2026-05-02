#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Bryam (bryamzxz)
"""Generate the encrypted nvs_creds partition for tinylink.

Wraps ESP-IDF's nvs_partition_gen.py so the user only has to edit a CSV
file. Designed to fail loudly if the input still contains REPLACE_WITH_
placeholders or if any binary file referenced in the CSV is the wrong size.
"""

from __future__ import annotations

import argparse
import csv
import os
import shutil
import subprocess
import sys
from pathlib import Path

REQUIRED_KEYS = {
    "wifi_ssid",
    "wifi_pass",
    "wg_priv_key",
    "wg_peer_pub",
    "wg_peer_endpoint",
    "wg_peer_allowed_ip",
    "wg_local_ip",
}
WG_KEY_LEN = 32


def find_idf_tool() -> Path:
    idf_path = os.environ.get("IDF_PATH")
    if not idf_path:
        sys.exit("error: IDF_PATH is not set. Source ESP-IDF's export.sh first.")
    candidate = Path(idf_path) / "components" / "nvs_flash" / "nvs_partition_generator" / "nvs_partition_gen.py"
    if not candidate.is_file():
        sys.exit(f"error: nvs_partition_gen.py not found at {candidate}")
    return candidate


def validate_csv(csv_path: Path) -> None:
    seen = set()
    with csv_path.open(newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            key = row.get("key", "").strip()
            value = row.get("value", "").strip()
            row_type = row.get("type", "").strip()
            if not key or row_type == "namespace":
                continue
            if value.startswith("REPLACE_WITH_"):
                sys.exit(f"error: {csv_path} still has placeholder for '{key}'")
            seen.add(key)
            if key in {"wg_priv_key", "wg_peer_pub"}:
                bin_path = Path(value)
                if not bin_path.is_file():
                    sys.exit(f"error: {key} points to missing file {bin_path}")
                size = bin_path.stat().st_size
                if size != WG_KEY_LEN:
                    sys.exit(
                        f"error: {key} file {bin_path} is {size} B, expected {WG_KEY_LEN} B"
                    )
    missing = REQUIRED_KEYS - seen
    if missing:
        sys.exit(f"error: {csv_path} is missing keys: {', '.join(sorted(missing))}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path,
                        help="Path to credentials CSV (see tools/credentials.csv.example).")
    parser.add_argument("--output", required=True, type=Path,
                        help="Output binary path (e.g. build/nvs_creds.bin).")
    parser.add_argument("--size", default="0x4000",
                        help="Partition size in bytes (hex). Default 0x4000, matching partitions.csv.")
    parser.add_argument("--no-encrypt", action="store_true",
                        help="Generate a plaintext partition (development only; default is encrypted).")
    parser.add_argument("--keyfile", type=Path,
                        help="Optional NVS encryption keyfile. If omitted and encryption is on, "
                             "nvs_partition_gen.py generates one next to --output.")
    args = parser.parse_args()

    if not args.input.is_file():
        sys.exit(f"error: input {args.input} does not exist")
    args.output.parent.mkdir(parents=True, exist_ok=True)

    validate_csv(args.input)

    tool = find_idf_tool()
    cmd = [sys.executable, str(tool)]
    if args.no_encrypt:
        cmd.append("generate")
    else:
        cmd.append("encrypt")
    cmd.extend([str(args.input), str(args.output), args.size])
    if not args.no_encrypt:
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
