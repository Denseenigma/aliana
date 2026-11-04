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
  wifi.py              Wi-Fi management via NetworkManager (nmcli)
  qr.py                tiny built-in QR code generator (no dependencies)
  auth.py              access control: authenticator-app sign-in, recovery codes, erase & reset
  passive.py           passive discovery: listens for DHCP / ARP / mDNS / SSDP / NetBIOS / LLDP + TCP replies
  labels.py            your own device labels (overrule the triad)
  fpdb.py              FINGERPRINT signature library: stack signatures, app chatter, mismatches
  requirements.txt
  aliana.service       systemd unit (expects the repo cloned at ~/aliana)
  setup.sh             one-time/after-pull install steps (Pi only)
  system/              boot-time helpers installed by setup.sh (hostname sync)
  templates/
    index.html          full dashboard (browser)
    kiosk.html          compact control screen for the 480x320 display
    wifi.html           Wi-Fi setup page (desktop + phone)
    auth.html           sign in / set up authenticator / erase & reset
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
- `ALIANA_AUTO_SCAN` — `1` to start with automatic scans on (default `0`, off)
- `ALIANA_NMAP_PRIVILEGED` — `0` to never use raw sockets (default `1`)

## Auto-scan

Automatic scans are **off by default** -- nothing touches the network until
you press Scan now or switch auto-scan on. Turn it on (and pick 5 / 15 / 30 /
60 min) on the Settings page. The setting is saved, so it survives restarts. The first automatic
scan runs a minute after switching on (or after boot); after that, the
interval is counted from the end of the last scan -- a manual scan resets
the countdown too. Automatic scans use the selected profile.

## Scan mode (SYN vs connect)

`setup.sh` gives nmap the `cap_net_raw` capability, so Aliana runs it with
`--privileged`: ARP host discovery (MAC + vendor), half-open SYN port scans,
and on the **Deep** profile, OS fingerprinting (`-O --osscan-limit
--max-os-tries 1`), shown on each host card with nmap's confidence. If the
capability is missing (e.g. nmap was upgraded -- re-run `setup.sh`), Aliana
falls back to TCP connect scans without OS detection and says so on the
dashboard ("Mode: Connect") and in the Pi screen's boot sequence.

## Settings page

`/settings` (Settings in the dashboard menu) holds options that apply to
every scan; changes save immediately:

- **Auto-scan** -- off, or every 5 / 15 / 30 / 60 min (off by default).
- **Never-probe ports** -- add/remove ports or ranges that are reported as
  open but never get service-identification probes (default `9999`;
  `ALIANA_NO_PROBE_PORTS` sets the default for a fresh install).

## Triad decision (three systems vote)

Every device's type is decided by three independent systems, each using only
its own evidence:

| System | Evidence |
|---|---|
| **1 SCAN** | what it serves when asked: open ports, services, web pages, the NetBIOS / mDNS / UPnP / DNS lookups Aliana sends, and its scanned MAC (maker, virtual / randomized prefixes, gateway) |
| **2 LISTEN** | what it announced on its own (passive discovery): DHCP, mDNS / UPnP / NetBIOS announcements |
| **3 FINGERPRINT** | how it behaves: its network stack (starting TTL, IP ID pattern, TCP options, packet size), reply timing (**wired vs wireless**, when the Pi is on a cable), nmap's OS fingerprint (Deep scans), and the **RMM** record when there is one |

FINGERPRINT reads the replies to Aliana's own scans through the passive
listener, so it sends nothing extra. Its **signature library** (`fpdb.py`)
turns those traits into named answers ("Windows 10 / 11", "Windows 7 / 8",
"macOS / iOS", "Linux 4.19+", "Cisco IOS", "small embedded stack") and
flags **Old OS** when the stack matches an out-of-support Windows / Linux.
It also listens to **background chatter** -- broadcasts apps make on their own:
Dropbox, Steam, Spotify, BitTorrent (flagged), Syncthing, SSDP searches (their
user agent names the OS: Windows 10, iOS 17, Android, Xbox, smart TVs),
WS-Discovery (ONVIF cameras, printers, Windows), Windows browser
announcements (OS version, domain controllers, Samba servers), Ubiquiti and
MikroTik discovery (model, firmware), LIFX / Tuya / Hue, BACnet. When the
MAC maker doesn't fit how the device behaves (Apple hardware with a Windows
stack, a printer maker's MAC acting like a PC) the decision board shows a
**mismatch** warning: Boot Camp, a VM, or a changed MAC. On its own it often only knows the
family ("Windows", "Unix-like", "network gear / embedded"); that's enough to
confirm -- or dispute -- a specific answer from the others.

Each system votes for its best-supported answer (or abstains if it has
nothing better than a weak hint). Broad and specific answers agree
("Unix-like" + "Apple computer"; "Computer" + "Windows computer"). Then:

- **Unanimous** (3/3) or **Confirmed** (2/3) -- high confidence.
- **Single source** -- only one system has an answer; medium at best. A weak
  contrary hint (like a randomized MAC) doesn't count as a dispute.
- **Disputed** -- systems disagree; the strongest answer is shown, low
  confidence unless it's very strong.

**Your label** overrules all three: on a device page, set its type (plus an
optional name and note). The decision board shows *SET BY YOU* and what the
triad would have said.

The device page shows the full decision board (the FINGERPRINT card lists
what it measured); dashboard cards and the Devices table show three small
hexes (green = agrees, red = dissents, dark = no answer), and the latest
scan has a Triad bar.

## Passive discovery (listening only)

Alongside scans, Aliana **listens** to what devices announce about themselves
and never sends anything (`passive.py`):

- **DHCP** requests: the device's own **hostname** (even on networks whose DNS
  can't do reverse lookups), its vendor class (`MSFT 5.0` = Windows,
  `android-dhcp-14` = Android 14, Yealink / HP / Axis...), and the options it
  asks for, which fingerprint iPhones and Macs. DHCP replies show the DHCP
  server, router, DNS servers and domain.
- **ARP**: every device that talks, with its IP -- including quiet ones that
  ignore scans.
- **mDNS / Bonjour**, **UPnP NOTIFY** and **NetBIOS** announcements.
- **LLDP** from the switch: switch name, port and VLAN (Settings shows them).

Heard devices get a **DHCP** chip on the dashboard and feed the device-type
guess; devices heard but never scanned show on the Devices page as
**Heard** (filter: *Never scanned*). The dashboard header shows how many were
heard in the last hour. Turn it off in Settings > Passive discovery.

It hears the Pi's own network segment: on Wi-Fi or a switch port it hears the
whole LAN's broadcasts; over only the USB-C gadget link it hears just the
laptop. It needs raw sockets, so `aliana.service` grants the service
`CAP_NET_RAW` -- **run `bash setup.sh` once after pulling** this change. Data
is flushed to `aliana.db` every 30 s and is erased by Erase & reset.

## Device identification

After each scan (stage 3, "Identifying devices") Aliana works out what every
device is and what it's called (`identify.py`), using light, read-only
lookups that LAN devices answer all the time:

| Method | What it gives |
|---|---|
| MAC vendor database (`data/oui.tsv.gz`, current IEEE registry, offline) | Manufacturer -- far newer than nmap's built-in list |
| Private-MAC check | Flags randomized "private Wi-Fi" addresses (phones, tablets, laptops) |
| NetBIOS (UDP 137) | Windows / Samba computer name and workgroup/domain |
| mDNS / Bonjour (UDP 5353, unicast) | `name.local`, advertised services (`_ipp`, `_airplay`, `_googlecast`, `_hap`...), friendly names, model strings |
| SSDP / UPnP (UDP 1900) | Friendly name, manufacturer, model, device type (TVs, routers, speakers) |
| Reverse DNS against the gateway / LAN DNS | Names your router or DNS server knows (public resolvers are skipped) |
| Web title / server / certificate | Only on web ports already found open; never-probe ports and excluded hosts skipped |

The classifier (`insights.classify_host`) weighs every clue -- advertised
services, names, page titles, port signatures, vendor, OS guess, private
MAC -- and shows a type badge (faded when confidence is low), the model when
known, and the evidence on hover and on each device's page. Turn the network
lookups off in Settings > Device identification; the vendor database is
always used. Refresh the vendor database from Settings (needs internet on
the Pi) or with `python3 tools/build_oui.py`.

## Devices & long-term history

Aliana keeps a **living history** of each network, with devices identified
by **MAC address** (IPs change with DHCP; hosts without a MAC -- this unit,
or anything behind a router -- are counted but not tracked).

- **Devices** page (`/devices`): one row per MAC ever seen -- type, last IP
  (and how many IPs it's had), first/last seen, times seen, open ports, RMM
  status, flags. Search and filter (in latest scan / not seen lately / no
  RMM agent / flagged). Click a device for its **timeline** (`/device/<mac>`):
  every sighting with IP, hostname, open ports, IP changes and ports
  opened/closed between scans.
- **Export all history** (`/export/history.json`, also on the dashboard and
  Devices page) saves every scan in one file; **Import history** on the
  Devices page merges exports back in -- on this unit or another. Scans
  already present are skipped (each scan has a uid), so re-importing is
  safe. Single-scan JSON exports import too. Routine: scan, export; next
  visit, import, scan -- change alerts then compare against the last visit.
- Scans are ordered by when they finished, so imported (older) scans slot
  into the right place in the timeline.
- **Devices (CSV)** exports the inventory.

## RMM integration (Datto RMM; more providers welcome)

Settings > **RMM integration**: choose a provider, enter credentials, *Test
connection*, pick which sites to check (or all), *Save* -- Aliana syncs the
RMM's device list (read-only) and re-syncs after network scans when the
copy is over 30 minutes old. Hosts are matched by MAC, then hostname:
cards show "Datto RMM ✓ hostname · site" (linking to the device in Datto)
or "Not in Datto RMM"; computers with no match get a **No RMM agent**
finding; printers, cameras, door controllers and network gear show "no
agent expected".

API keys are **encrypted at rest** (key file in `~/.config/aliana/`,
outside the repo) and never sent back to the browser. Step-by-step Datto
setup, how the keys are stored, and how to add another RMM:
[`rmm/README.md`](rmm/README.md).

## Insights: changes, device types, findings, export

All worked out from what the scans already recorded -- no extra probing
(`insights.py`).

- **Change alerts** -- each network scan is compared with the previous scan
  of the same subnet: new devices, devices gone, ports opened/closed (ports
  only where both scans checked them). The dashboard shows a hexagon
  "Changes since ..." banner with the details, NEW tags on new hosts and
  new ports; the Pi screen flashes **ALERT** (instead of COMPLETE) when new
  devices or newly opened ports turn up, and keeps a CHANGES n chip in its
  header (red when something new appeared).
- **Device types** -- a best guess per host (printer, camera, access
  control, network gear, phone, storage, Windows, Apple, Linux, Raspberry
  Pi, IoT, VM) from MAC vendor, hostname, open ports and nmap's OS guess,
  shown as a hex badge on each card (hover for the reason).
- **Exposure flags** -- services worth a follow-up, by level: high (Telnet,
  rsh/rlogin), medium (FTP, RDP, VNC, TFTP), low (SNMP, SMB, web admin
  without HTTPS). Shown on host cards and as a Findings tile.
- **Export** -- CSV (one row per open port), JSON, and a printable one-page
  report (`/scan/<id>/report`, "Print / Save as PDF") from the buttons next
  to the scan title.

## Safety: exclusions and subnet size guard

Both live on the Settings page and are enforced in the scanner itself, so
they apply to every way a scan can start (dashboard, Pi screen, Queue page,
auto-scan).

- **Exclusions** -- IPs, ranges (`172.16.0.10-20` / `172.16.0.10-172.16.0.20`)
  or CIDR blocks that are never scanned, each with an optional note. Network
  scans pass them to nmap `--exclude` (no discovery packets, no probes);
  Deep scans of an excluded host are refused, and queued ones are cancelled
  when the host is excluded. Host cards have an **Exclude** button (click
  twice); excluded hosts show an "Excluded" tag instead of scan buttons.
- **Subnet size guard** -- the subnet on the selected interface is checked
  before a network scan is queued:
  - /24 or smaller: scans freely
  - /23 - /22: scans, with a size warning (dashboard shows the subnet in orange)
  - /21 - /16: needs confirmation every time ("Scan anyway" on the dashboard,
    Queue page and Pi screen); **auto-scan skips it** and leaves a note
  - larger than /16: refused

## Two-stage scans (no more hangs on silent devices)

Standard and Deep scans run in two stages:

1. **Find ports** -- port scan (plus OS guess on Deep). These results are
   always kept.
2. **Identify services** -- `nmap -sV` on just the open ports found, with a
   per-host time cap (Standard 2 min, Deep 5 min). Never-probe ports are
   left out entirely.

Some devices (e.g. Paxton door-access controllers on 9999) accept a
connection and then never answer, which made nmap wait out dozens of probes
per port and could time a whole host out. Now such ports show as
*Not identified* (or *Not probed · skip list*) instead of stalling the scan,
and stopping a job during "Identifying services" saves the ports already
found (the Queue page's button reads "Stop identifying · keep ports").

## Scan queue

Every scan goes through one queue and runs one at a time, so the Pi is never
running two nmaps at once: SCAN NOW, automatic scans, and per-host **Deep
scan** buttons (on each host card on the dashboard). The **Queue** page
(`/queue`) shows the running job live (phase, %, hosts, ports found, stop),
the waiting jobs (run next / cancel), recent jobs with links to their
results, and lets you pause/resume the queue, cancel everything waiting,
queue a Deep scan of any IP, or queue a network scan with any profile. Up to
20 jobs can wait; the same host can't be queued twice. Jobs still waiting
when Aliana restarts are cancelled rather than run unattended.

A host's Deep scan results replace that host's card on the dashboard (tagged
"Deep scan · time") until the next network scan. The Pi screen shows a small
QUEUE n ticker in its header; manage the queue from the browser.

## Scan history and "last seen" ports

Every scan is kept. Host cards show the current scan's results plus open
ports found by earlier scans (matched by MAC, else IP): dimmed with "last
seen <time> · <profile>" when this scan didn't check that port (e.g. a
Discovery scan, or Standard after Deep), or struck through in red as
"closed now" when it did check and the port is no longer open. Aliana
records which ports each scan covered (nmap's scaninfo) to tell these
apart. Click any row in Scan history to open that scan (`/scan/<id>`).

## What it does

- Runs nmap (see Scan profiles) against the subnet detected on the
  selected interface, on demand or on the auto-scan interval
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
ports as they're found), a summary of the last scan when idle, and
buttons for Scan now, cycling the scan interface, and Wi-Fi. Auto-scan is
set from the browser dashboard; the Pi screen shows its countdown. The full detail stays
on the browser dashboard at `/`.

## Scan profiles

Network scans use **Discovery** or **Standard** -- pick one on the dashboard
(dropdown), the Queue page, or the Pi screen's scan picker. **Deep** is
per-device only: the **Deep scan** button on a host card (or "Deep scan
host" on the Queue page) runs it against that one address. Network-wide
Deep scans aren't offered -- too much traffic for a whole subnet.

| Profile | nmap options | Impact |
|---|---|---|
| Discovery | `-sn -T3` | Host sweep only (ARP/ping, MAC vendor, hostname). No port scan. |
| Standard (default) | `-T3 --top-ports 100 --max-rate 300 --host-timeout 5m`, then `-sV --version-light` on open ports | Light, rate-capped. Fine for most office networks. |
| Deep (one device only) | `-T3 --top-ports 1000 --max-rate 300 --host-timeout 15m -O --osscan-limit`, then full `-sV` | Top 1000 ports, full service probing, OS guess. Host card button only. |

Profiles are defined in `PROFILES` at the top of `scanner.py`.

## Access control (authenticator app)

There's no password: browsers unlock Aliana with the **6-digit code from an
authenticator app** on your phone (Microsoft / Google Authenticator, Authy,
1Password, Bitwarden... any TOTP app). A browser stays signed in for 12 hours;
**Lock** in the header signs out. The Pi's own screen (requests from the Pi
itself) never asks.

**First run:** opening Aliana in a browser goes to the setup page. It asks for
a **pairing code shown on the Pi's screen** (proof you have the device in
hand), then shows a QR code to scan with the app, then shows **10 recovery
codes** once -- save them. No screen? The code is also in
`journalctl -u aliana | grep pairing`.

**Lost the phone:** "Use a recovery code" on the sign-in page. Each code works
once. Settings > Access control can make new recovery codes or move the
authenticator to a new phone (both need a current code).

**Lost the phone and the recovery codes:** **Erase & reset** on the sign-in
page. It shows a reset code on the Pi's screen; enter it and type ERASE. This
permanently erases the RMM connection and credentials (and the vault key),
all scan history, the device inventory and the queue, then goes straight to
setting up a new authenticator. Scan settings, exclusions, never-probe ports
and Wi-Fi networks are kept so the Pi stays reachable. Over SSH, the same
thing: `./venv/bin/python3 auth.py --reset`, then restart the service.

The authenticator secret, recovery-code hashes and the session-signing key
live in `~/.config/aliana/` (owner-only, outside the repo). Codes are
single-use, and wrong guesses are rate-limited per address.

Note: anything on the Pi that connects to Aliana from 127.0.0.1 counts as
"the Pi's screen", so don't put a reverse proxy on the Pi in front of it.

## Wi-Fi setup

Open **Wi-Fi** from the dashboard header (`/wifi`) -- e.g. from your
computer over the USB gadget link. It shows the current link, lists
nearby networks (tap one, enter the password, Connect), and lets you
forget saved networks. Changes go through NetworkManager; `setup.sh`
installs a polkit rule so the service user is allowed to make them.

On the onboard screen, the **WI-FI** button shows the current network,
signal and address, plus a QR code that opens the Wi-Fi page on a phone
(the phone needs to be on a network that can reach the Pi, and signs in with
the authenticator code first).

If Wi-Fi shows as off or `nmcli device` lists wlan0 as "unavailable", the
radio is blocked or the Wi-Fi country isn't set yet (use your country code):

```bash
sudo rfkill unblock wifi
sudo iw reg set US
nmcli radio wifi on
# make the country permanent:
grep -q ieee80211_regdom /boot/firmware/cmdline.txt || \
  sudo sed -i '1 s/$/ cfg80211.ieee80211_regdom=US/' /boot/firmware/cmdline.txt
```

## Notes

- Each scan writes its nmap XML output to a uniquely-named temp file and
  deletes it afterward, so leftover-file ownership conflicts can't happen.
- Only point this at networks/hosts you're authorized to scan.
