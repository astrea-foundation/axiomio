#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

assets=(
  axiomio-linux-x86_64.AppImage
  axiomio-macos-aarch64.app.tar.gz
  axiomio-macos-aarch64.dmg
  axiomio-macos-x86_64.app.tar.gz
  axiomio-macos-x86_64.dmg
  axiomio-windows-aarch64-setup.exe
  axiomio-windows-x86_64-setup.exe
)

for asset in "${assets[@]}"; do
  rg -Fq "$asset" "$ROOT/install/README.md"
done

rg -Fq 'axiomio-linux-${{ matrix.arch }}.AppImage' "$ROOT/.github/workflows/release.yml"
rg -Fq 'axiomio-macos-${{ matrix.arch }}.app.tar.gz' "$ROOT/.github/workflows/release.yml"
rg -Fq 'axiomio-macos-${{ matrix.arch }}.dmg' "$ROOT/.github/workflows/release.yml"
rg -Fq 'axiomio-windows-${{ matrix.arch }}-setup.exe' "$ROOT/.github/workflows/release.yml"
rg -Fq 'axiomio-linux-${arch}.AppImage' "$ROOT/install/axiomup.sh"
rg -Fq 'Linux desktop installation currently supports x86_64 only' \
  "$ROOT/install/axiomup.sh" "$ROOT/install/README.md"
rg -Fq 'axiomio-macos-${arch}.app.tar.gz' "$ROOT/install/axiomup.sh"
rg -Fq 'axiomio-windows-$architecture-setup.exe' "$ROOT/install/axiomup.ps1"
rg -Fq 'astrea-foundation/axiomio' "$ROOT/install/axiomup.sh" "$ROOT/install/axiomup.ps1"
rg -Fq 'SHA256SUMS' "$ROOT/install/axiomup.sh" "$ROOT/install/axiomup.ps1" \
  "$ROOT/.github/workflows/release.yml"
rg -Fq 'Start-Process' "$ROOT/install/axiomup.ps1"
rg -Fq 'configure opencode' "$ROOT/install/axiomup.sh" "$ROOT/install/axiomup.ps1"
rg -Fq 'axiom.stream/axiomup.sh' "$ROOT/install/README.md"
rg -Fq 'axiom.stream/axiomup.ps1' "$ROOT/install/README.md"

if rg -n '(axiom-proxy-headless|axiom\.exe|cli/target)' \
  "$ROOT/.github/workflows/release.yml"; then
  echo "release contract still references obsolete binaries" >&2
  exit 1
fi

echo "Release contract tests passed"
