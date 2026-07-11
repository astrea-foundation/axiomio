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

mkdir -p "$TEST_ROOT/release" "$TEST_ROOT/install/legacy"
cat > "$TEST_ROOT/release/axiomio-windows-x86_64-setup.exe" <<'SCRIPT'
fake installer payload
SCRIPT
cat > "$TEST_ROOT/install/run-axiomup.ps1" <<'POWERSHELL'
$scriptArguments = $args

function Start-Process {
    param(
        [string]$FilePath,
        [string]$ArgumentList,
        [switch]$Wait,
        [switch]$PassThru
    )

    if ($ArgumentList -notmatch '^/S /D=(.+)$') {
        throw "Unexpected NSIS arguments: $ArgumentList"
    }
    $destination = $Matches[1]
    if ($destination.Contains('"')) {
        throw "NSIS /D= destination must not be quoted: $ArgumentList"
    }
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $destination "axiomio.exe") -Value "upgraded desktop executable"
    return [pscustomobject]@{ ExitCode = 0 }
}

& /work/install/axiomup.ps1 @scriptArguments
POWERSHELL
printf 'legacy cli\n' > "$TEST_ROOT/install/legacy/axiom.exe"
printf 'legacy proxy\n' > "$TEST_ROOT/install/legacy/axiom-proxy-headless.exe"
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
  --user "$(id -u):$(id -g)" \
  --network host \
  -v "$ROOT:/work:ro" \
  -v "$TEST_ROOT/install:/output" \
  "$IMAGE" \
  pwsh -NoProfile -File /output/run-axiomup.ps1 \
    -DownloadBase "http://127.0.0.1:$PORT" \
    -DesktopInstallDir "/output/AxiomIO With Spaces" \
    -LegacyInstallDir /output/legacy \
    -SkipPathUpdate \
    -SkipOpenCode

grep -Fq 'upgraded desktop executable' "$TEST_ROOT/install/AxiomIO With Spaces/axiomio.exe"
[[ ! -e "$TEST_ROOT/install/legacy/axiom.exe" ]]
[[ ! -e "$TEST_ROOT/install/legacy/axiom-proxy-headless.exe" ]]

grep -Fq '$installerArguments = "/S /D=$DesktopInstallDir"' "$ROOT/install/axiomup.ps1"

printf 'tampered' >> "$TEST_ROOT/release/axiomio-windows-x86_64-setup.exe"
if docker run --rm \
  --user "$(id -u):$(id -g)" \
  --network host \
  -v "$ROOT:/work:ro" \
  -v "$TEST_ROOT/install:/output" \
  "$IMAGE" \
  pwsh -NoProfile -File /work/install/axiomup.ps1 \
    -DownloadBase "http://127.0.0.1:$PORT" \
    -DesktopInstallDir "/output/AxiomIO With Spaces" \
    -SkipDesktopInstall \
    -SkipPathUpdate \
    -SkipOpenCode >/dev/null 2>&1; then
  echo "PowerShell installer accepted a tampered desktop artifact" >&2
  exit 1
fi

echo "PowerShell installer tests passed"
