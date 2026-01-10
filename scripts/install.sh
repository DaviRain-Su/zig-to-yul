#!/usr/bin/env bash
set -euo pipefail

VERSION="v0.1.0"
REPO="DaviRain-Su/zig-to-yul"

OS="$(uname -s)"
case "$OS" in
  Darwin)
    PKG="zig-to-yul-macos-latest.tar.gz"
    ;;
  Linux)
    PKG="zig-to-yul-ubuntu-latest.tar.gz"
    ;;
  *)
    echo "Unsupported OS: $OS"
    exit 1
    ;;
 esac

URL="https://github.com/${REPO}/releases/download/${VERSION}/${PKG}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

curl -fsSL "$URL" -o "$TMP_DIR/$PKG"
mkdir -p "$HOME/.local/bin"
tar -xzf "$TMP_DIR/$PKG" -C "$HOME/.local/bin"

cat <<'EOF'
Installed z2y and zig_to_yul to ~/.local/bin
Ensure ~/.local/bin is in PATH.
Zig 0.15.2 must be installed separately.
EOF
