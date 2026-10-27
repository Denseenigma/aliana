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

echo "==> Keeping /etc/hosts in sync with the hostname..."
# A renamed Pi with a stale /etc/hosts breaks sudo and can stall the kiosk.
# Fix it now, and install a boot-time service so future renames self-heal.
sudo install -m 755 "$REPO_DIR/system/aliana-sync-hostname.sh" /usr/local/sbin/aliana-sync-hostname
sudo cp "$REPO_DIR/system/aliana-sync-hostname.service" /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable aliana-sync-hostname >/dev/null 2>&1
sudo /usr/local/sbin/aliana-sync-hostname

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

echo "==> Setting up NetworkManager for Wi-Fi..."
# Wi-Fi is managed through NetworkManager. If systemd-networkd already runs
# other interfaces (e.g. usb0 for the USB gadget link, eth0), leave those to
# networkd and let NetworkManager handle only Wi-Fi, so the two don't fight.
UNMANAGED="interface-name:usb0"
if systemctl is-active --quiet systemd-networkd; then
    for name in $(grep -hoP '^Name=\K\S+' /etc/systemd/network/*.network 2>/dev/null | sort -u); do
        case "$name" in
            wl*|usb0) ;;  # Wi-Fi stays with NetworkManager; usb0 already listed
            *) UNMANAGED="$UNMANAGED;interface-name:$name" ;;
        esac
    done
fi
sudo mkdir -p /etc/NetworkManager/conf.d
# "zz-" so this loads last and wins over any other unmanaged-devices setting
printf '[keyfile]\nunmanaged-devices=%s\n' "$UNMANAGED" | \
    sudo tee /etc/NetworkManager/conf.d/zz-aliana-unmanaged.conf > /dev/null
echo "    left to systemd-networkd: ${UNMANAGED//interface-name:/}"
# A failed/stopped dhcpcd would only fight NetworkManager over wlan0
if systemctl is-enabled --quiet dhcpcd 2>/dev/null && ! systemctl is-active --quiet dhcpcd; then
    sudo systemctl disable dhcpcd >/dev/null 2>&1 || true
    echo "    disabled inactive dhcpcd"
fi
# Don't let boot wait for a network to come online (it can stall the
# kiosk for minutes when no network is available). NetworkManager's own
# wait-online is disabled further down, AFTER enabling NetworkManager --
# enabling it switches wait-online back on.
sudo mkdir -p /etc/systemd/system/systemd-networkd-wait-online.service.d
sudo tee /etc/systemd/system/systemd-networkd-wait-online.service.d/override.conf > /dev/null <<'EOF'
[Service]
ExecStart=
ExecStart=/lib/systemd/systemd-networkd-wait-online --any --timeout=5
EOF
sudo systemctl daemon-reload
sudo systemctl enable NetworkManager >/dev/null 2>&1
sudo systemctl disable NetworkManager-wait-online >/dev/null 2>&1 || true
if systemctl is-active --quiet NetworkManager; then
    sudo systemctl reload NetworkManager || sudo systemctl restart NetworkManager
else
    sudo systemctl start NetworkManager
fi

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
# Fallback if polkit doesn't apply: passwordless sudo for nmcli only
NMCLI="$(command -v nmcli || echo /usr/bin/nmcli)"
echo "$ALIANA_USER ALL=(root) NOPASSWD: $NMCLI" | sudo tee /etc/sudoers.d/aliana-nmcli > /dev/null
sudo chmod 440 /etc/sudoers.d/aliana-nmcli
if ! sudo visudo -cf /etc/sudoers.d/aliana-nmcli >/dev/null; then
    echo "    WARNING: sudoers entry failed validation, removing it"
    sudo rm -f /etc/sudoers.d/aliana-nmcli
fi

echo "==> Installing/updating systemd service..."
sudo cp "$REPO_DIR/aliana.service" /etc/systemd/system/aliana.service
sudo systemctl daemon-reload
sudo systemctl enable aliana >/dev/null 2>&1
sudo systemctl restart aliana

echo ""
echo "==> Done. Service status:"
sudo systemctl status aliana --no-pager -l | head -8
