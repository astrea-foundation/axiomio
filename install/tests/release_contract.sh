#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

assets=(
  axiom-proxy-linux-aarch64.tar.gz
  axiom-proxy-linux-x86_64.tar.gz
  axiom-proxy-macos-aarch64.tar.gz
  axiom-proxy-macos-x86_64.tar.gz
  axiom-proxy-windows-aarch64.zip
  axiom-proxy-windows-x86_64.zip
)

for asset in "${assets[@]}"; do
  rg -Fq "$asset" "$ROOT/.github/workflows/release.yml"
  rg -Fq "$asset" "$ROOT/install/README.md"
done

rg -Fq 'axiom-proxy-${os}-${arch}.tar.gz' "$ROOT/install/install.sh"
rg -Fq 'axiom-proxy-windows-$architecture.zip' "$ROOT/install/install.ps1"
rg -Fq 'astrea-foundation/axiomio' "$ROOT/install/install.sh" "$ROOT/install/install.ps1"
rg -Fq 'SHA256SUMS' "$ROOT/install/install.sh" "$ROOT/install/install.ps1" \
  "$ROOT/.github/workflows/release.yml"
rg -Fq 'axiom-proxy-headless' "$ROOT/install/install.sh" "$ROOT/install/install.ps1" \
  "$ROOT/.github/workflows/release.yml"

echo "Release contract tests passed"
