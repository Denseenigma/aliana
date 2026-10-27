#!/bin/sh
# Keeps /etc/hosts' 127.0.1.1 line matching the Pi's current hostname.
# Changing the hostname without updating /etc/hosts makes sudo hang with
# "unable to resolve host" and can stall X / the kiosk at boot. Installed by
# setup.sh to /usr/local/sbin and run at every boot by
# aliana-sync-hostname.service, so renaming the Pi heals itself on reboot.
set -e
name="$(hostname)"
[ -n "$name" ] || exit 0

if grep -qE "^127\.0\.1\.1[[:space:]]+$name([[:space:]]|\$)" /etc/hosts; then
    exit 0  # already correct
fi

if grep -qE '^127\.0\.1\.1[[:space:]]' /etc/hosts; then
    sed -i -E "s/^127\.0\.1\.1[[:space:]].*/127.0.1.1\t$name/" /etc/hosts
else
    printf '127.0.1.1\t%s\n' "$name" >> /etc/hosts
fi
echo "aliana: /etc/hosts updated for hostname '$name'"
