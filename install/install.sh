#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="${AXIOM_REPOSITORY:-astrea-foundation/axiomio}"
VERSION="${AXIOM_VERSION:-latest}"
INSTALL_DIR="${AXIOM_INSTALL_DIR:-$HOME/.local/bin}"
TEMPORARY=""

fail() {
  echo "axiom installer: $*" >&2
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

install_binary() {
  local source="$1"
  local destination="$2"
  local temporary="${destination}.tmp.$$"
  install -m 0755 "$source" "$temporary"
  mv -f "$temporary" "$destination"
}

cleanup() {
  if [[ -n "$TEMPORARY" ]]; then
    rm -rf "$TEMPORARY"
  fi
}

main() {
  local os arch asset base temporary expected actual
  os="$(detect_os)"
  arch="$(detect_arch)"
  asset="axiom-proxy-${os}-${arch}.tar.gz"
  base="$(release_base)"
  temporary="$(mktemp -d "${TMPDIR:-/tmp}/axiom-install.XXXXXX")"
  TEMPORARY="$temporary"
  trap cleanup EXIT

  echo "Downloading $asset"
  download "$base/$asset" "$temporary/$asset"
  download "$base/SHA256SUMS" "$temporary/SHA256SUMS"

  expected="$(awk -v asset="$asset" '$2 == asset || $2 == "*" asset { print $1; exit }' "$temporary/SHA256SUMS")"
  [[ "$expected" =~ ^[0-9A-Fa-f]{64}$ ]] || fail "SHA256SUMS has no valid entry for $asset"
  actual="$(sha256_file "$temporary/$asset")"
  [[ "$actual" == "$expected" ]] || fail "checksum mismatch for $asset"

  mkdir "$temporary/extracted"
  tar -xzf "$temporary/$asset" -C "$temporary/extracted"
  [[ -f "$temporary/extracted/axiom" ]] || fail "$asset does not contain axiom"
  [[ -f "$temporary/extracted/axiom-proxy-headless" ]] || \
    fail "$asset does not contain axiom-proxy-headless"

  mkdir -p "$INSTALL_DIR"
  install_binary "$temporary/extracted/axiom" "$INSTALL_DIR/axiom"
  install_binary "$temporary/extracted/axiom-proxy-headless" "$INSTALL_DIR/axiom-proxy-headless"

  echo "Installed Axiom proxy tools to $INSTALL_DIR"
  if command -v opencode >/dev/null 2>&1; then
    echo "Configuring OpenCode"
    "$INSTALL_DIR/axiom" configure opencode
  else
    echo "OpenCode was not found; skipping OpenCode configuration"
  fi

  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) echo "Add $INSTALL_DIR to PATH to use axiom and axiom-proxy-headless" ;;
  esac
}

main "$@"
