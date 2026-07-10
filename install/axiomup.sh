#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="${AXIOM_REPOSITORY:-astrea-foundation/axiomio}"
VERSION="${AXIOM_VERSION:-latest}"
INSTALL_DIR="${AXIOM_INSTALL_DIR:-$HOME/.local/bin}"
DESKTOP_DIR="${AXIOM_DESKTOP_DIR:-$HOME/.local/share/axiomio}"
APPLICATIONS_DIR="${AXIOM_APPLICATIONS_DIR:-$HOME/Applications}"
TEMPORARY=""
ROLLBACK_APP=""
ROLLBACK_TARGET=""

fail() {
  echo "axiomup: $*" >&2
  exit 1
}

download() {
  local url="$1"
  local destination="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$destination"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$url" -O "$destination"
  else
    fail "curl or wget is required"
  fi
}

detect_os() {
  if [[ -n "${AXIOM_OS:-}" ]]; then
    echo "$AXIOM_OS"
    return
  fi
  case "$(uname -s)" in
    Linux) echo "linux" ;;
    Darwin) echo "macos" ;;
    *) fail "unsupported operating system: $(uname -s)" ;;
  esac
}

detect_arch() {
  local machine
  if [[ -n "${AXIOM_ARCH:-}" ]]; then
    machine="$AXIOM_ARCH"
  else
    machine="$(uname -m)"
  fi
  case "$machine" in
    x86_64|amd64) echo "x86_64" ;;
    arm64|aarch64) echo "aarch64" ;;
    *) fail "unsupported architecture: $machine" ;;
  esac
}

release_base() {
  if [[ -n "${AXIOM_DOWNLOAD_BASE:-}" ]]; then
    echo "${AXIOM_DOWNLOAD_BASE%/}"
  elif [[ "$VERSION" == "latest" ]]; then
    echo "https://github.com/$REPOSITORY/releases/latest/download"
  else
    echo "https://github.com/$REPOSITORY/releases/download/$VERSION"
  fi
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

verify_download() {
  local path="$1"
  local asset="$2"
  local expected actual
  expected="$(awk -v asset="$asset" '$2 == asset || $2 == "*" asset { print $1; exit }' "$TEMPORARY/SHA256SUMS")"
  [[ "$expected" =~ ^[0-9A-Fa-f]{64}$ ]] || fail "SHA256SUMS has no valid entry for $asset"
  actual="$(sha256_file "$path")"
  [[ "$actual" == "$expected" ]] || fail "checksum mismatch for $asset"
}

cleanup() {
  if [[ -n "$ROLLBACK_APP" && -e "$ROLLBACK_APP" ]]; then
    if [[ -n "$ROLLBACK_TARGET" && ! -e "$ROLLBACK_TARGET" ]]; then
      mv "$ROLLBACK_APP" "$ROLLBACK_TARGET" || true
    else
      rm -rf "$ROLLBACK_APP"
    fi
  fi
  if [[ -n "$TEMPORARY" ]]; then
    rm -rf "$TEMPORARY"
  fi
}

migrate_legacy_install() {
  local legacy_cli="$INSTALL_DIR/axiom"
  local legacy_proxy="$INSTALL_DIR/axiom-proxy-headless"
  if [[ -e "$legacy_cli" && -e "$legacy_proxy" ]]; then
    rm -f "$legacy_cli" "$legacy_proxy"
    echo "Removed the legacy two-binary AxiomIO installation"
  fi
}

install_linux() {
  local base="$1"
  local arch="$2"
  local asset="axiomio-linux-${arch}.AppImage"
  local icon_asset="axiomio-icon.png"
  local executable="$DESKTOP_DIR/AxiomIO.AppImage"
  local staged="$DESKTOP_DIR/.AxiomIO.AppImage.new.$$"
  local icon_dir="${AXIOM_ICON_DIR:-$HOME/.local/share/icons/hicolor/128x128/apps}"
  local applications_dir="${AXIOM_DESKTOP_ENTRY_DIR:-$HOME/.local/share/applications}"

  echo "Downloading $asset"
  download "$base/$asset" "$TEMPORARY/$asset"
  download "$base/$icon_asset" "$TEMPORARY/$icon_asset"
  verify_download "$TEMPORARY/$asset" "$asset"
  verify_download "$TEMPORARY/$icon_asset" "$icon_asset"

  mkdir -p "$DESKTOP_DIR" "$INSTALL_DIR" "$icon_dir" "$applications_dir"
  install -m 0755 "$TEMPORARY/$asset" "$staged"
  mv -f "$staged" "$executable"
  install -m 0644 "$TEMPORARY/$icon_asset" "$icon_dir/axiomio.png"
  ln -sfn "$executable" "$INSTALL_DIR/axiomio"
  cat > "$applications_dir/axiomio.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=AxiomIO
Exec="$executable"
Icon=$icon_dir/axiomio.png
Terminal=false
Categories=Development;
EOF
}

install_macos() {
  local base="$1"
  local arch="$2"
  local asset="axiomio-macos-${arch}.app.tar.gz"
  local app="$APPLICATIONS_DIR/AxiomIO.app"
  local staged="$APPLICATIONS_DIR/.AxiomIO.app.new.$$"
  local previous="$APPLICATIONS_DIR/.AxiomIO.app.old.$$"
  local executable

  echo "Downloading $asset"
  download "$base/$asset" "$TEMPORARY/$asset"
  verify_download "$TEMPORARY/$asset" "$asset"
  mkdir -p "$TEMPORARY/extracted" "$APPLICATIONS_DIR" "$INSTALL_DIR"
  tar -xzf "$TEMPORARY/$asset" -C "$TEMPORARY/extracted"
  [[ -d "$TEMPORARY/extracted/AxiomIO.app" ]] || fail "$asset does not contain AxiomIO.app"
  executable="$TEMPORARY/extracted/AxiomIO.app/Contents/MacOS/axiomio"
  [[ -x "$executable" ]] || fail "$asset does not contain the axiomio executable"

  rm -rf "$staged"
  mv "$TEMPORARY/extracted/AxiomIO.app" "$staged"
  if [[ -e "$app" ]]; then
    rm -rf "$previous"
    mv "$app" "$previous"
    ROLLBACK_APP="$previous"
    ROLLBACK_TARGET="$app"
  fi
  if ! mv "$staged" "$app"; then
    fail "could not replace $app"
  fi
  if [[ -n "$ROLLBACK_APP" ]]; then
    rm -rf "$ROLLBACK_APP"
    ROLLBACK_APP=""
    ROLLBACK_TARGET=""
  fi
  ln -sfn "$app/Contents/MacOS/axiomio" "$INSTALL_DIR/axiomio"
}

main() {
  local os arch base executable
  os="$(detect_os)"
  arch="$(detect_arch)"
  base="$(release_base)"
  TEMPORARY="$(mktemp -d "${TMPDIR:-/tmp}/axiomup.XXXXXX")"
  trap cleanup EXIT
  download "$base/SHA256SUMS" "$TEMPORARY/SHA256SUMS"

  case "$os" in
    linux)
      install_linux "$base" "$arch"
      executable="$DESKTOP_DIR/AxiomIO.AppImage"
      ;;
    macos)
      install_macos "$base" "$arch"
      executable="$APPLICATIONS_DIR/AxiomIO.app/Contents/MacOS/axiomio"
      ;;
    *) fail "unsupported operating system: $os" ;;
  esac

  migrate_legacy_install
  echo "AxiomIO desktop application is up to date"
  if command -v opencode >/dev/null 2>&1; then
    echo "Configuring OpenCode"
    "$executable" configure opencode
  else
    echo "OpenCode was not found; skipping OpenCode configuration"
  fi

  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) echo "Add $INSTALL_DIR to PATH to use axiomio" ;;
  esac
}

main "$@"
