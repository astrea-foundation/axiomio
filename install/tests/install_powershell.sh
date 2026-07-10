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

mkdir -p "$TEST_ROOT/release" "$TEST_ROOT/install/AxiomIO" "$TEST_ROOT/install/legacy"
cat > "$TEST_ROOT/release/axiomio-windows-x86_64-setup.exe" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
destination=""
for argument in "$@"; do
  case "$argument" in
    /D=*) destination="${argument#/D=}" ;;
  esac
done
destination="${destination%\"}"
destination="${destination#\"}"
[[ -n "$destination" ]]
mkdir -p "$destination"
printf 'upgraded desktop executable\n' > "$destination/axiomio.exe"
SCRIPT
chmod +x "$TEST_ROOT/release/axiomio-windows-x86_64-setup.exe"
printf 'old desktop executable\n' > "$TEST_ROOT/install/AxiomIO/axiomio.exe"
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
  --network host \
  -v "$ROOT:/work:ro" \
  -v "$TEST_ROOT/install:/output" \
  "$IMAGE" \
  pwsh -NoProfile -File /work/install/axiomup.ps1 \
    -DownloadBase "http://127.0.0.1:$PORT" \
    -DesktopInstallDir /output/AxiomIO \
    -LegacyInstallDir /output/legacy \
    -SkipDesktopInstall \
    -SkipPathUpdate \
    -SkipOpenCode

grep -Fq 'old desktop executable' "$TEST_ROOT/install/AxiomIO/axiomio.exe"
[[ ! -e "$TEST_ROOT/install/legacy/axiom.exe" ]]
[[ ! -e "$TEST_ROOT/install/legacy/axiom-proxy-headless.exe" ]]

printf 'tampered' >> "$TEST_ROOT/release/axiomio-windows-x86_64-setup.exe"
if docker run --rm \
  --network host \
  -v "$ROOT:/work:ro" \
  -v "$TEST_ROOT/install:/output" \
  "$IMAGE" \
  pwsh -NoProfile -File /work/install/axiomup.ps1 \
    -DownloadBase "http://127.0.0.1:$PORT" \
    -DesktopInstallDir /output/AxiomIO \
    -SkipDesktopInstall \
    -SkipPathUpdate \
    -SkipOpenCode >/dev/null 2>&1; then
  echo "PowerShell installer accepted a tampered desktop artifact" >&2
  exit 1
fi

echo "PowerShell installer tests passed"
