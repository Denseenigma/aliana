#!/bin/sh
# Starts a bare window manager + Chromium in kiosk mode, pointed at the
# Aliana splash screen. The splash page itself polls the Aliana Flask
# server in the background and navigates to the dashboard once it's
# ready -- all within one Chromium instance, so there's no second
# cold-start browser launch (which was the slow part before).

SPLASH="$HOME/.aliana-kiosk/splash.html"

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

# Launch Chromium once, pointed at the splash page. It'll navigate itself
# to the real dashboard once Aliana's Flask server responds.
exec chromium-browser \
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
    "file://$SPLASH"
