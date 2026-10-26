#!/bin/sh
# Starts a bare window manager + Chromium in kiosk mode, pointed straight
# at the Aliana dashboard. (The old splash page was dropped: Chromium's own
# cold start is slower than Flask's, so the splash was never visible.)

DASHBOARD_URL="http://localhost:8080/"

# Set the root window to solid black immediately -- otherwise X's default
# grey/checkered background shows briefly before anything else loads.
xsetroot -solid "#000000"

# Hide the mouse cursor when idle (useful since this is a touchscreen)
unclutter -idle 0.5 -root &

# Disable screen blanking/DPMS so the display doesn't go dark on this
# always-on kiosk screen
xset s off
xset s noblank
xset -dpms

# Minimal window manager -- just enough to give Chromium a window to live in
openbox-session &
sleep 1

# Make sure Flask is answering before Chromium opens the page, so we never
# land on an error page. Normally this returns instantly (the systemd
# service starts well before the console login); gives up after 60s.
for i in $(seq 1 120); do
    curl -s -o /dev/null "$DASHBOARD_URL" && break
    sleep 0.5
done

# The SPI screen has no GPU acceleration, so skip Chromium's GPU startup
# probing -- it only slows the launch down.
exec chromium-browser \
    --disable-gpu \
    --kiosk \
    --noerrdialogs \
    --disable-infobars \
    --disable-session-crashed-bubble \
    --disable-translate \
    --disable-features=OverlayScrollbar \
    --no-first-run \
    --check-for-update-interval=31536000 \
    --window-size=480,320 \
    --window-position=0,0 \
    "$DASHBOARD_URL"
