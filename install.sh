#!/bin/sh
# meerkat installer. Downloads the latest release binary for your platform.
#   curl -fsSL https://raw.githubusercontent.com/ezequielcamezzana/meerkat/main/install.sh | sh
set -e

REPO="ezequielcamezzana/meerkat"
BIN="meerkat"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m)
case "$arch" in
	x86_64 | amd64) arch="amd64" ;;
	arm64 | aarch64) arch="arm64" ;;
	*) echo "meerkat: unsupported architecture: $arch" >&2; exit 1 ;;
esac
case "$os" in
	darwin | linux) ;;
	*) echo "meerkat: unsupported OS: $os (macOS and Linux only)" >&2; exit 1 ;;
esac

asset="meerkat_${os}_${arch}.tar.gz"
url="https://github.com/${REPO}/releases/latest/download/${asset}"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading ${url}"
curl -fsSL "$url" -o "$tmp/$asset"
tar -xzf "$tmp/$asset" -C "$tmp"

if [ -w "$INSTALL_DIR" ]; then
	mv "$tmp/$BIN" "$INSTALL_DIR/$BIN"
	chmod +x "$INSTALL_DIR/$BIN"
else
	echo "Installing to ${INSTALL_DIR} (requires sudo)"
	sudo mv "$tmp/$BIN" "$INSTALL_DIR/$BIN"
	sudo chmod +x "$INSTALL_DIR/$BIN"
fi

echo "Installed: $("$INSTALL_DIR/$BIN" version 2>/dev/null || echo "$BIN")"
