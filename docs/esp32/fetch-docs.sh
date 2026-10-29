#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Bryam (bryamzxz)
#
# Download the ESP32 vendor PDFs that docs/esp32/REFERENCE.md cites into
# docs/esp32/pdf/ (git-ignored) and compare them with the hashes recorded
# in docs/esp32/README.md. A mismatch is reported, not fatal: Espressif
# revises documents in place, so it usually means a newer revision.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dest="$here/pdf"
mkdir -p "$dest"

espressif="https://www.espressif.com/sites/default/files/documentation"
errata="https://docs.espressif.com/projects/esp-chip-errata/en/latest/esp32/esp-chip-errata-en-master-esp32.pdf"

# file|url|sha256
docs=(
  "esp32_technical_reference_manual_en.pdf|$espressif/esp32_technical_reference_manual_en.pdf|1007b90e6fafc16541d693d7444b63e1c5b01e46e60cce9b6810e02340a64b82"
  "esp32_datasheet_en.pdf|$espressif/esp32_datasheet_en.pdf|a7917e6b47528c9dcab06837a49d452e582751335797db879f1cf2d17cd29adf"
  "esp32-wroom-32e_esp32-wroom-32ue_datasheet_en.pdf|$espressif/esp32-wroom-32e_esp32-wroom-32ue_datasheet_en.pdf|4c7a345d1c1bfec34c38665639e39a7f43b79a35a12f6adcc2c7c0f83850f8b8"
  "esp32_errata_en.pdf|$errata|a31e6a35d6ebccd54d49493cf8fe4befe754eeea0dc744c3db06cd62b587fd44"
  "esp32_chip_revision_v3_0_user_guide_en.pdf|$espressif/esp32_chip_revision_v3_0_user_guide_en.pdf|7fa403d962987837c516a3b7c2769c06ca33a2b74db76d4e8eedbae28745a9d1"
)
xtensa_name="xtensa_isa_reference_manual_RB-2010.1.pdf"
xtensa_sha="52c28fa26c5287825953c12bb69e4cd7683f46f2f0efa0994d1a78e6318dbd46"

check() {  # file expected-sha
  local got
  got="$(sha256sum "$dest/$1" | cut -d' ' -f1)"
  if [[ "$got" == "$2" ]]; then
    echo "ok        $1"
  else
    echo "CHANGED   $1 (sha256 $got) — newer revision? re-check the pages REFERENCE.md cites"
  fi
}

for entry in "${docs[@]}"; do
  IFS='|' read -r name url sha <<<"$entry"
  if [[ ! -s "$dest/$name" ]]; then
    curl -fsSL --max-time 300 -o "$dest/$name.part" "$url"
    if ! head -c 5 "$dest/$name.part" | grep -q '%PDF-'; then
      rm -f "$dest/$name.part"
      echo "FAILED    $name: $url did not return a PDF" >&2
      continue
    fi
    mv "$dest/$name.part" "$dest/$name"
  fi
  check "$name" "$sha"
done

if [[ -n "${XTENSA_ISA_PDF:-}" ]]; then
  cp "$XTENSA_ISA_PDF" "$dest/$xtensa_name"
fi
if [[ -s "$dest/$xtensa_name" ]]; then
  check "$xtensa_name" "$xtensa_sha"
else
  echo "missing   $xtensa_name — no stable public URL; set XTENSA_ISA_PDF=/path/to/copy"
fi
