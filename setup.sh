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
# Old splash page location -- no longer used, clean it up
rm -rf "$HOME/.aliana-kiosk"
cp "$REPO_DIR/kiosk/.xinitrc" "$HOME/.xinitrc"
chmod +x "$HOME/.xinitrc"

MARKER="# --- Aliana kiosk autostart ---"
if ! grep -qF "$MARKER" "$HOME/.bash_profile" 2>/dev/null; then
    cat "$REPO_DIR/kiosk/bash_profile_snippet.sh" >> "$HOME/.bash_profile"
    echo "    added autostart block to .bash_profile"
else
    echo "    autostart block already present, skipped"
fi

echo "==> Installing touchscreen Y-axis fix (X11 input config)..."
# The SunFounder/piscreen touch panel reports Y inverted at rotate=270.
# Flip it in the X input layer (works with both libinput and evdev) rather
# than in the display overlay, which can break the LCD driver.
sudo mkdir -p /etc/X11/xorg.conf.d
sudo tee /etc/X11/xorg.conf.d/99-touch-flip.conf > /dev/null <<'EOF'
Section "InputClass"
    Identifier "Touch Y flip"
    MatchIsTouchscreen "on"
    Option "CalibrationMatrix" "1 0 0 0 -1 1"
    Option "InvertY" "true"
EndSection
EOF

echo "==> Allowing Aliana to manage Wi-Fi (NetworkManager polkit rule)..."
# The aliana service runs as a normal user (User= in aliana.service). This
# rule lets that one user -- and only for NetworkManager actions -- scan,
# join and forget Wi-Fi networks from the dashboard without sudo.
ALIANA_USER="$(grep -oP '^User=\K.*' "$REPO_DIR/aliana.service" || id -un)"
sudo mkdir -p /etc/polkit-1/rules.d
sudo tee /etc/polkit-1/rules.d/50-aliana-networkmanager.rules > /dev/null <<EOF
// Installed by Aliana's setup.sh: lets the aliana service manage Wi-Fi
polkit.addRule(function(action, subject) {
    if (action.id.indexOf("org.freedesktop.NetworkManager.") == 0 &&
        subject.user == "$ALIANA_USER") {
        return polkit.Result.YES;
    }
});
EOF
sudo systemctl restart polkit 2>/dev/null || true

echo "==> Installing/updating systemd service..."
sudo cp "$REPO_DIR/aliana.service" /etc/systemd/system/aliana.service
sudo systemctl daemon-reload
sudo systemctl enable aliana >/dev/null 2>&1
sudo systemctl restart aliana

echo ""
echo "==> Done. Service status:"
sudo systemctl status aliana --no-pager -l | head -8
