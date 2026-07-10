#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${POWERSHELL_TEST_IMAGE:-mcr.microsoft.com/powershell:7.5-ubuntu-22.04}"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/axiomio-powershell-test.XXXXXX")"
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

mkdir -p "$TEST_ROOT/release" "$TEST_ROOT/install/AxiomIO"
printf 'fake NSIS setup executable\n' > "$TEST_ROOT/release/axiomio-windows-x86_64-setup.exe"
printf 'fake installed desktop executable\n' > "$TEST_ROOT/install/AxiomIO/axiomio.exe"
(
  cd "$TEST_ROOT/release"
  sha256sum axiomio-windows-x86_64-setup.exe > SHA256SUMS
)

PORT="${POWERSHELL_TEST_PORT:-18765}"
python3 -m http.server "$PORT" --bind 0.0.0.0 --directory "$TEST_ROOT/release" \
  >"$TEST_ROOT/server.log" 2>&1 &
SERVER_PID="$!"

for _ in 1 2 3 4 5; do
  if curl -fsS "http://127.0.0.1:$PORT/SHA256SUMS" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS "http://127.0.0.1:$PORT/SHA256SUMS" >/dev/null

docker run --rm \
  --network host \
  -v "$ROOT:/work:ro" \
  -v "$TEST_ROOT/install:/output" \
  "$IMAGE" \
  pwsh -NoProfile -File /work/install/install.ps1 \
    -DownloadBase "http://127.0.0.1:$PORT" \
    -DesktopInstallDir /output/AxiomIO \
    -SkipDesktopInstall \
    -SkipPathUpdate \
    -SkipOpenCode

[[ -f "$TEST_ROOT/install/AxiomIO/axiomio.exe" ]]

printf 'tampered' >> "$TEST_ROOT/release/axiomio-windows-x86_64-setup.exe"
if docker run --rm \
  --network host \
  -v "$ROOT:/work:ro" \
  -v "$TEST_ROOT/install:/output" \
  "$IMAGE" \
  pwsh -NoProfile -File /work/install/install.ps1 \
    -DownloadBase "http://127.0.0.1:$PORT" \
    -DesktopInstallDir /output/AxiomIO \
    -SkipDesktopInstall \
    -SkipPathUpdate \
    -SkipOpenCode >/dev/null 2>&1; then
  echo "PowerShell installer accepted a tampered desktop artifact" >&2
  exit 1
fi

echo "PowerShell installer tests passed"
