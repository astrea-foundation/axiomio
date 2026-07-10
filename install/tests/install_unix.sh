#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="$ROOT/install/install.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/axiom-installer-test.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT

make_release() {
  local release_dir="$1"
  local payload_dir="$release_dir/payload"
  mkdir -p "$payload_dir"
  cat > "$payload_dir/axiom" <<'SCRIPT'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$AXIOM_TEST_LOG"
SCRIPT
  cat > "$payload_dir/axiom-proxy-headless" <<'SCRIPT'
#!/usr/bin/env bash
echo proxy
SCRIPT
  chmod +x "$payload_dir/axiom" "$payload_dir/axiom-proxy-headless"
  tar -czf "$release_dir/axiom-proxy-linux-x86_64.tar.gz" -C "$payload_dir" \
    axiom axiom-proxy-headless
  (
    cd "$release_dir"
    sha256sum axiom-proxy-linux-x86_64.tar.gz > SHA256SUMS
  )
}

test_install_and_opencode_setup() {
  local case_dir="$TEST_ROOT/success"
  local release_dir="$case_dir/release"
  local install_dir="$case_dir/bin"
  local fake_path="$case_dir/path"
  local log="$case_dir/axiom.log"
  mkdir -p "$release_dir" "$fake_path"
  make_release "$release_dir"
  cat > "$fake_path/opencode" <<'SCRIPT'
#!/usr/bin/env bash
exit 0
SCRIPT
  chmod +x "$fake_path/opencode"

  AXIOM_OS=linux \
  AXIOM_ARCH=x86_64 \
  AXIOM_INSTALL_DIR="$install_dir" \
  AXIOM_DOWNLOAD_BASE="file://$release_dir" \
  AXIOM_TEST_LOG="$log" \
  PATH="$fake_path:/usr/bin:/bin" \
    bash "$INSTALLER"

  [[ -x "$install_dir/axiom" ]]
  [[ -x "$install_dir/axiom-proxy-headless" ]]
  [[ "$(cat "$log")" == "configure opencode" ]]
}

test_skips_missing_opencode() {
  local case_dir="$TEST_ROOT/no-opencode"
  local release_dir="$case_dir/release"
  local install_dir="$case_dir/bin"
  mkdir -p "$release_dir"
  make_release "$release_dir"
  local output
  output="$(
    AXIOM_OS=linux \
    AXIOM_ARCH=x86_64 \
    AXIOM_INSTALL_DIR="$install_dir" \
    AXIOM_DOWNLOAD_BASE="file://$release_dir" \
    PATH="/usr/bin:/bin" \
      bash "$INSTALLER"
  )"
  [[ "$output" == *"OpenCode was not found"* ]]
}

test_rejects_tampered_archive() {
  local case_dir="$TEST_ROOT/tampered"
  local release_dir="$case_dir/release"
  local install_dir="$case_dir/bin"
  mkdir -p "$release_dir"
  make_release "$release_dir"
  printf 'tampered' >> "$release_dir/axiom-proxy-linux-x86_64.tar.gz"
  if AXIOM_OS=linux \
    AXIOM_ARCH=x86_64 \
    AXIOM_INSTALL_DIR="$install_dir" \
    AXIOM_DOWNLOAD_BASE="file://$release_dir" \
    PATH="/usr/bin:/bin" \
      bash "$INSTALLER" >/dev/null 2>&1; then
    echo "tampered archive was accepted" >&2
    return 1
  fi
  [[ ! -e "$install_dir/axiom" ]]
}

bash -n "$INSTALLER"
test_install_and_opencode_setup
test_skips_missing_opencode
test_rejects_tampered_archive
echo "Unix installer tests passed"
