#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${POWERSHELL_TEST_IMAGE:-mcr.microsoft.com/powershell:7.5-ubuntu-22.04}"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/axiom-powershell-test.XXXXXX")"
SERVER_PID=""

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TEST_ROOT"
}
trap cleanup EXIT

mkdir -p "$TEST_ROOT/release/payload" "$TEST_ROOT/install"
printf 'fake axiom executable\n' > "$TEST_ROOT/release/payload/axiom.exe"
printf 'fake proxy executable\n' > "$TEST_ROOT/release/payload/axiom-proxy-headless.exe"
(
  cd "$TEST_ROOT/release/payload"
  python3 -m zipfile -c "$TEST_ROOT/release/axiom-proxy-windows-x86_64.zip" \
    axiom.exe axiom-proxy-headless.exe
)
(
  cd "$TEST_ROOT/release"
  sha256sum axiom-proxy-windows-x86_64.zip > SHA256SUMS
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
    -InstallDir /output \
    -SkipPathUpdate \
    -SkipOpenCode

[[ -f "$TEST_ROOT/install/axiom.exe" ]]
[[ -f "$TEST_ROOT/install/axiom-proxy-headless.exe" ]]

printf 'tampered' >> "$TEST_ROOT/release/axiom-proxy-windows-x86_64.zip"
if docker run --rm \
  --network host \
  -v "$ROOT:/work:ro" \
  -v "$TEST_ROOT/install:/output" \
  "$IMAGE" \
  pwsh -NoProfile -File /work/install/install.ps1 \
    -DownloadBase "http://127.0.0.1:$PORT" \
    -InstallDir /output \
    -SkipPathUpdate \
    -SkipOpenCode >/dev/null 2>&1; then
  echo "PowerShell installer accepted a tampered archive" >&2
  exit 1
fi

echo "PowerShell installer tests passed"
