#!/usr/bin/env python3
"""Capture ESP32 serial output for a fixed duration. Writes raw bytes
verbatim to the output path; rely on grep over the file for metrics."""
import argparse
import os
import sys
import time

import serial


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--port", default="/dev/ttyUSB0")
    p.add_argument("--baud", type=int, default=115200)
    p.add_argument("--duration", type=float, default=420.0,
                   help="seconds (default 420 = 7 min)")
    p.add_argument("--out", required=True)
    args = p.parse_args()

    deadline = time.monotonic() + args.duration
    last_status = time.monotonic()
    bytes_total = 0

    with serial.Serial(args.port, args.baud, timeout=1) as ser, \
            open(args.out, "wb", buffering=0) as f:
        while time.monotonic() < deadline:
            chunk = ser.read(4096)
            if chunk:
                f.write(chunk)
                bytes_total += len(chunk)
            now = time.monotonic()
            if now - last_status > 30:
                remaining = max(0, deadline - now)
                print(f"[{int(now)}] {bytes_total} bytes captured, "
                      f"{remaining:.0f}s remaining", file=sys.stderr)
                last_status = now
    print(f"done: {bytes_total} bytes -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
