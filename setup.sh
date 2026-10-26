#!/bin/bash
# setup.sh -- run this on the Pi after `git clone` (once) or `git pull`
# (whenever dependencies, the service file, or kiosk files changed).
#
# This no longer writes file contents itself -- that's git's job now.
# It just handles the install/wiring steps: venv, pip deps, nmap's raw
# socket capability, the kiosk autostart files, and the systemd service.
#
# Usage: bash setup.sh

set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

echo "==> Setting up Python venv..."
if [ ! -d venv ]; then
    python3 -m venv venv
fi
./venv/bin/pip install -q -r requirements.txt

echo "==> Granting nmap raw-socket capability (no-op if already set)..."
sudo setcap cap_net_raw,cap_net_admin+eip "$(which nmap)"

echo "==> Installing kiosk files..."
mkdir -p "$HOME/.aliana-kiosk"
cp "$REPO_DIR/kiosk/splash.html" "$HOME/.aliana-kiosk/splash.html"
cp "$REPO_DIR/kiosk/.xinitrc" "$HOME/.xinitrc"
chmod +x "$HOME/.xinitrc"

MARKER="# --- Aliana kiosk autostart ---"
if ! grep -qF "$MARKER" "$HOME/.bash_profile" 2>/dev/null; then
    cat "$REPO_DIR/kiosk/bash_profile_snippet.sh" >> "$HOME/.bash_profile"
    echo "    added autostart block to .bash_profile"
else
    echo "    autostart block already present, skipped"
fi

echo "==> Installing/updating systemd service..."
sudo cp "$REPO_DIR/aliana.service" /etc/systemd/system/aliana.service
sudo systemctl daemon-reload
sudo systemctl enable aliana >/dev/null 2>&1
sudo systemctl restart aliana

echo ""
echo "==> Done. Service status:"
sudo systemctl status aliana --no-pager -l | head -8
