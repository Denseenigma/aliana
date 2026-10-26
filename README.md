# Aliana

A minimal recon dashboard for the Pi: scans whatever subnet is reachable
over a chosen network interface, stores results in SQLite, and shows them
on a small web UI — no attack/HID functionality, scanning only. Also
includes a kiosk-mode setup for displaying it on an attached screen.

## Repo layout

```
aliana/
  app.py              Flask app
  scanner.py           nmap wrapper + SQLite storage
  requirements.txt
  aliana.service       systemd unit (expects the repo cloned at ~/aliana)
  setup.sh             one-time/after-pull install steps (Pi only)
  templates/
    index.html          full dashboard (browser)
    kiosk.html          compact control screen for the 480x320 display
  kiosk/
    .xinitrc             launches Chromium in kiosk mode on boot
    bash_profile_snippet.sh   autostarts X on the console login
```

## Workflow

This repo is the single source of truth. Changes get committed and pushed
(from Windows, or anywhere else), and the Pi just pulls — no more manually
copying files around.

### One-time setup — Windows (or wherever you edit/push from)

1. Install [Git for Windows](https://git-scm.com/download/win) if you don't
   already have it (this also gives you Git Bash, a terminal that
   understands normal `bash`/git commands).
2. Clone the repo:
   ```bash
   git clone https://github.com/<your-username>/aliana.git
   cd aliana
   ```
3. Commit and push as usual whenever files change:
   ```bash
   git add .
   git commit -m "describe what changed"
   git push
   ```

### One-time setup — Pi

```bash
cd ~
git clone https://github.com/<your-username>/aliana.git
cd aliana
bash setup.sh
```

`setup.sh` creates the Python venv, installs dependencies, grants nmap
raw-socket access, installs the kiosk files (`.xinitrc`,
`.bash_profile` autostart block), and installs/enables/starts the
`aliana` systemd service.

**Important:** clone it as `~/aliana` specifically — `aliana.service`
hardcodes `/home/admin/aliana` as the working directory. If your username
isn't `admin` or you clone it somewhere else, edit the paths in
`aliana.service` before running `setup.sh`.

### Day to day — Pi

Whenever there's a new commit to pull:
```bash
cd ~/aliana
git pull
bash setup.sh
```
`setup.sh` is safe to re-run any time — it's idempotent (won't duplicate
the `.bash_profile` block, reinstalls deps cleanly, restarts the service
at the end so changes take effect immediately).

If a pull *only* changed `app.py`, `scanner.py`, or `templates/index.html`
(no dependency, service, or kiosk file changes), you can skip `setup.sh`
and just restart the service directly:
```bash
sudo systemctl restart aliana
```

## Configuration

**Interface selection happens from the dashboard itself** — a dropdown at
the top lists every detected network interface (name, up/down state, and
IPv4 address if it has one) and lets you switch which one gets scanned.
Changing it takes effect immediately and is saved to the database, so it
persists across restarts.

Environment variables in `aliana.service` are just the *initial* default,
used only before anything's been selected in the UI:

- `ALIANA_IFACE` — initial interface to scan (default `usb0`)
- `ALIANA_SCAN_INTERVAL` — seconds between automatic scans (default `300`)

## What it does

- Every `ALIANA_SCAN_INTERVAL` seconds, runs `nmap -sV -T4 --top-ports 100`
  against the subnet detected on the selected interface
- Parses results (hosts, MAC/vendor, open ports, service/version) into
  SQLite
- Serves a dashboard at `/` showing the latest scan plus recent history
- "Scan now" button on the dashboard triggers an on-demand scan
- JSON endpoints at `/api/latest`, `/api/status`, `/api/history`,
  `/api/interfaces`

## Kiosk mode (optional)

If a screen is attached and you want Aliana to boot straight into it in
kiosk mode, `setup.sh` already wires this up. Chromium opens straight to
`/kiosk` once Aliana's Flask server is answering: a single, no-scroll
screen showing the scan in progress live (phase, % done, hosts up, open
ports as they're found), a summary of the last scan when idle, and two
buttons -- Scan now, and cycle the scan interface. The full detail stays
on the browser dashboard at `/`.

## Notes

- Each scan writes its nmap XML output to a uniquely-named temp file and
  deletes it afterward, so leftover-file ownership conflicts can't happen.
- Only point this at networks/hosts you're authorized to scan.
