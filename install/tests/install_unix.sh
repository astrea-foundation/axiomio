#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="$ROOT/install/axiomup.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/axiomio-installer-test.XXXXXX")"
trap 'rm -rf "$TEST_ROOT"' EXIT

write_checksums() {
  local release_dir="$1"
  (cd "$release_dir" && sha256sum axiomio-* > SHA256SUMS)
}

make_linux_release() {
  local release_dir="$1"
  local marker="${2:-v1}"
  mkdir -p "$release_dir"
  cat > "$release_dir/axiomio-linux-x86_64.AppImage" <<'SCRIPT'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$AXIOM_TEST_LOG"
SCRIPT
  printf '# %s\n' "$marker" >> "$release_dir/axiomio-linux-x86_64.AppImage"
  chmod +x "$release_dir/axiomio-linux-x86_64.AppImage"
  printf 'fake icon\n' > "$release_dir/axiomio-icon.png"
  write_checksums "$release_dir"
}

make_macos_release() {
  local release_dir="$1"
  local marker="${2:-v1}"
  local app="$release_dir/payload/AxiomIO.app/Contents/MacOS"
  mkdir -p "$app"
  cat > "$app/axiomio" <<'SCRIPT'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$AXIOM_TEST_LOG"
SCRIPT
  printf '# %s\n' "$marker" >> "$app/axiomio"
  chmod +x "$app/axiomio"
  tar -czf "$release_dir/axiomio-macos-aarch64.app.tar.gz" \
    -C "$release_dir/payload" AxiomIO.app
  rm -rf "$release_dir/payload"
  write_checksums "$release_dir"
}

make_fake_opencode() {
  local directory="$1"
  mkdir -p "$directory"
  cat > "$directory/opencode" <<'SCRIPT'
#!/usr/bin/env bash
exit 0
SCRIPT
  chmod +x "$directory/opencode"
}

test_linux_desktop_install_and_setup() {
  local case_dir="$TEST_ROOT/linux"
  local release_dir="$case_dir/release"
  local bin_dir="$case_dir/bin"
  local desktop_dir="$case_dir/desktop"
  local fake_path="$case_dir/path"
  local log="$case_dir/axiomio.log"
  make_linux_release "$release_dir"
  make_fake_opencode "$fake_path"
  mkdir -p "$bin_dir"
  printf 'legacy cli\n' > "$bin_dir/axiom"
  printf 'legacy proxy\n' > "$bin_dir/axiom-proxy-headless"

  AXIOM_OS=linux \
  AXIOM_ARCH=x86_64 \
  AXIOM_INSTALL_DIR="$bin_dir" \
  AXIOM_DESKTOP_DIR="$desktop_dir" \
  AXIOM_ICON_DIR="$case_dir/icons" \
  AXIOM_DESKTOP_ENTRY_DIR="$case_dir/applications" \
  AXIOM_DOWNLOAD_BASE="file://$release_dir" \
  AXIOM_TEST_LOG="$log" \
  PATH="$fake_path:/usr/bin:/bin" \
    bash "$INSTALLER"

  [[ -x "$desktop_dir/AxiomIO.AppImage" ]]
  [[ -L "$bin_dir/axiomio" ]]
  [[ -f "$case_dir/applications/axiomio.desktop" ]]
  [[ -f "$case_dir/icons/axiomio.png" ]]
  [[ "$(cat "$log")" == "configure opencode" ]]
  [[ ! -e "$bin_dir/axiom" ]]
  [[ ! -e "$bin_dir/axiom-proxy-headless" ]]

  make_linux_release "$release_dir" v2
  AXIOM_OS=linux \
  AXIOM_ARCH=x86_64 \
  AXIOM_INSTALL_DIR="$bin_dir" \
  AXIOM_DESKTOP_DIR="$desktop_dir" \
  AXIOM_ICON_DIR="$case_dir/icons" \
  AXIOM_DESKTOP_ENTRY_DIR="$case_dir/applications" \
  AXIOM_DOWNLOAD_BASE="file://$release_dir" \
  AXIOM_TEST_LOG="$log" \
  PATH="$fake_path:/usr/bin:/bin" \
    bash "$INSTALLER"

  grep -Fq '# v2' "$desktop_dir/AxiomIO.AppImage"
  [[ "$(grep -c '^configure opencode$' "$log")" -eq 2 ]]
}

test_macos_app_install() {
  local case_dir="$TEST_ROOT/macos"
  local release_dir="$case_dir/release"
  local bin_dir="$case_dir/bin"
  local applications_dir="$case_dir/Applications"
  local fake_path="$case_dir/path"
  local log="$case_dir/axiomio.log"
  make_macos_release "$release_dir"
  make_fake_opencode "$fake_path"

  AXIOM_OS=macos \
  AXIOM_ARCH=aarch64 \
  AXIOM_INSTALL_DIR="$bin_dir" \
  AXIOM_APPLICATIONS_DIR="$applications_dir" \
  AXIOM_DOWNLOAD_BASE="file://$release_dir" \
  AXIOM_TEST_LOG="$log" \
  PATH="$fake_path:/usr/bin:/bin" \
    bash "$INSTALLER"

  [[ -x "$applications_dir/AxiomIO.app/Contents/MacOS/axiomio" ]]
  [[ -L "$bin_dir/axiomio" ]]
  [[ "$(cat "$log")" == "configure opencode" ]]

  make_macos_release "$release_dir" v2
  AXIOM_OS=macos \
  AXIOM_ARCH=aarch64 \
  AXIOM_INSTALL_DIR="$bin_dir" \
  AXIOM_APPLICATIONS_DIR="$applications_dir" \
  AXIOM_DOWNLOAD_BASE="file://$release_dir" \
  AXIOM_TEST_LOG="$log" \
  PATH="$fake_path:/usr/bin:/bin" \
    bash "$INSTALLER"

  grep -Fq '# v2' "$applications_dir/AxiomIO.app/Contents/MacOS/axiomio"
  [[ ! -e "$applications_dir/.AxiomIO.app.old."* ]]
}

test_rejects_tampered_artifact() {
  local case_dir="$TEST_ROOT/tampered"
  local release_dir="$case_dir/release"
  local bin_dir="$case_dir/bin"
  make_linux_release "$release_dir"
  mkdir -p "$bin_dir"
  printf 'legacy cli\n' > "$bin_dir/axiom"
  printf 'legacy proxy\n' > "$bin_dir/axiom-proxy-headless"
  printf 'tampered' >> "$release_dir/axiomio-linux-x86_64.AppImage"
  if AXIOM_OS=linux \
    AXIOM_ARCH=x86_64 \
    AXIOM_INSTALL_DIR="$bin_dir" \
    AXIOM_DESKTOP_DIR="$case_dir/desktop" \
    AXIOM_DOWNLOAD_BASE="file://$release_dir" \
    PATH="/usr/bin:/bin" \
      bash "$INSTALLER" >/dev/null 2>&1; then
    echo "tampered desktop artifact was accepted" >&2
    return 1
  fi
  [[ ! -e "$bin_dir/axiomio" ]]
  [[ -e "$bin_dir/axiom" ]]
  [[ -e "$bin_dir/axiom-proxy-headless" ]]
}

test_rejects_linux_arm() {
  local output
  if output="$(AXIOM_OS=linux AXIOM_ARCH=aarch64 bash "$INSTALLER" 2>&1)"; then
    echo "Linux ARM installation unexpectedly succeeded" >&2
    return 1
  fi
  grep -Fq 'Linux desktop installation currently supports x86_64 only' <<<"$output"
}

bash -n "$INSTALLER"
test_linux_desktop_install_and_setup
test_macos_app_install
test_rejects_tampered_artifact
test_rejects_linux_arm
echo "Unix installer tests passed"
