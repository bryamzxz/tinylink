#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Bryam (bryamzxz)
#
# Build tools/qemu_crypto and run it on Espressif's QEMU (esp32 machine).
# Needs an exported ESP-IDF (v5.5.6) and the qemu-xtensa tool:
#   python "$IDF_PATH/tools/idf_tools.py" install qemu-xtensa
# Exit 0 only when every suite passed. Usage: run.sh [build-dir] [timeout-s]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
build="${1:-$here/build}"
limit="${2:-1800}"

qemu="$(command -v qemu-system-xtensa || true)"
if [ -z "$qemu" ]; then
    qemu="$(ls -d "${IDF_TOOLS_PATH:-$HOME/.espressif}"/tools/qemu-xtensa/*/qemu/bin/qemu-system-xtensa 2>/dev/null | tail -1)"
fi
[ -x "$qemu" ] || { echo "qemu-system-xtensa not found (idf_tools.py install qemu-xtensa)"; exit 2; }

idf.py -C "$here" -B "$build" build
(cd "$build" && esptool.py --chip esp32 merge_bin --fill-flash-size 4MB -o flash.bin @flash_args)

log="$build/qemu.log"
rm -f "$log"
"$qemu" -nographic -machine esp32 -drive file="$build/flash.bin",if=mtd,format=raw \
        -serial file:"$log" -monitor none &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT
start=$(date +%s)
until grep -aqE 'QEMU-DONE|Guru Meditation|abort\(\) was called' "$log" 2>/dev/null; do
    if ! kill -0 "$pid" 2>/dev/null; then echo "QEMU exited early"; cat "$log" || true; exit 1; fi
    if [ $(( $(date +%s) - start )) -gt "$limit" ]; then echo "timeout after ${limit}s"; tail -50 "$log"; exit 1; fi
    sleep 2
done
grep -aE 'QEMU-SUITE|QEMU-DONE|\[qemu/|FAIL|Guru|abort' "$log"
ok=$(tr -d '\r' < "$log" | grep -cE '\] OK$|^ALL OK$' || true)   # QEMU serial is CRLF
echo "summary: $ok OK lines, $(( $(date +%s) - start )) s in QEMU"
grep -aq 'QEMU-DONE failed_suites=0' "$log" && ! grep -aq 'FAIL' "$log"
