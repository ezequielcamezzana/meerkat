#!/usr/bin/env bash
set -euo pipefail   # stop on any error, undefined var, or failed pipe

# Local deploy. Cross-compiles the server for Linux, then pushes the binary and
# .env to the box over your SSH connection and restarts the systemd service.
# The box is private — reach it via a ~/.ssh/config Host alias or VPN; port and
# key come from your SSH config as usual.
#
# Usage:
#   ./deploy.sh <user@host> [remote-dir]
#
#   ./deploy.sh deploy@meerkat-box
#   ./deploy.sh deploy@meerkat-box /opt/meerkat
#   VERSION=v0.2.0 ./deploy.sh deploy@meerkat-box

HOST="${1:?usage: deploy.sh <user@host> [remote-dir]}"
REMOTE_DIR="${2:-/opt/meerkat}"
SERVICE="meerkat"
BINARY="bin/meerkat"   # `make build` output
ENV=".env"
# Real version for the ldflags; override with VERSION=... if needed.
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"

echo "→ Building for Linux (version $VERSION)..."
GOOS=linux GOARCH=amd64 make build VERSION="$VERSION"

echo "→ Stopping service..."
ssh "$HOST" "systemctl stop $SERVICE || true"

echo "→ Uploading binary to $HOST:$REMOTE_DIR ..."
scp "$BINARY" "$HOST:$REMOTE_DIR/"

echo "→ Uploading env to $HOST:$REMOTE_DIR ..."
scp "$ENV" "$HOST:$REMOTE_DIR/"

echo "→ Starting service..."
ssh "$HOST" "systemctl start $SERVICE && systemctl is-active $SERVICE"

echo "✓ Deployed. Recent logs:"
ssh "$HOST" "journalctl -u $SERVICE -n 15 --no-pager"
