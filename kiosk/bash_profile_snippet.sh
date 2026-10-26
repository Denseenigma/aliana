# --- Aliana kiosk autostart ---
# Only auto-start X if logging in on the physical console (tty1),
# and only if X isn't already running (avoids double-starting over SSH).
if [ -z "$DISPLAY" ] && [ "$(tty)" = "/dev/tty1" ]; then
    startx -- -nocursor
fi
