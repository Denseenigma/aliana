"""
scanner.py - runs nmap scans and stores results in SQLite.
"""
import subprocess
import sqlite3
import xml.etree.ElementTree as ET
import datetime
import threading
import time
import ipaddress
import os
import tempfile
import uuid
import traceback
import re
import pty
import select
import shutil

DB_PATH = os.path.join(os.path.dirname(__file__), "aliana.db")
SCAN_INTERFACE = os.environ.get("ALIANA_IFACE", "usb0")
SCAN_INTERVAL_SECONDS = int(os.environ.get("ALIANA_SCAN_INTERVAL", "300"))  # 5 min default
# Wait this long after startup (or after auto-scan is switched on) before the
# first automatic scan, so the Pi and its network links can settle
FIRST_SCAN_DELAY_SECONDS = int(os.environ.get("ALIANA_FIRST_SCAN_DELAY", "60"))
# Automatic scans are OFF until switched on from the dashboard or the Pi
# screen (safer when plugged into a network you don't own). Set
# ALIANA_AUTO_SCAN=1 to make a fresh install start with them on. Once the
# setting has been changed in the UI, the saved value wins.
AUTO_SCAN_DEFAULT = os.environ.get("ALIANA_AUTO_SCAN", "0") == "1"
# Intervals offered in the UI (seconds). The env default is added if it's
# not one of them, so a custom ALIANA_SCAN_INTERVAL still shows up.
INTERVAL_CHOICES = sorted({300, 900, 1800, 3600, SCAN_INTERVAL_SECONDS})

# Run nmap with --privileged, relying on the raw-socket capabilities setup.sh
# grants it: ARP host discovery on the local subnet (the only way to get MAC
# addresses + vendors) and SYN port scans. Set ALIANA_NMAP_PRIVILEGED=0 to
# fall back to unprivileged connect scans.
NMAP_PRIVILEGED = os.environ.get("ALIANA_NMAP_PRIVILEGED", "1") == "1"

# Scan profiles, gentlest first. "args" are the nmap options that define
# what each one does; output/progress options are added in run_scan().
PROFILES = {
    "discovery": {
        "label": "Discovery",
        "description": "Who's on the network: host sweep only (ARP/ping), MAC vendor, "
                       "hostname. No port scan -- very low impact.",
        "short": "Who's here: host sweep, no port scan",
        "args": ["-sn", "-T3"],
        "timeout": 300,
    },
    "standard": {
        "label": "Standard",
        "description": "Top 100 TCP ports with light version detection, normal timing, "
                       "rate-capped. Safe for most office networks.",
        "short": "Top 100 ports, light probing, rate-capped",
        "args": ["-T3", "--top-ports", "100", "--max-rate", "300", "--host-timeout", "5m"],
        # Stage 2 (service identification on the ports found open)
        "version_args": ["--version-light"],
        "version_host_timeout": "2m",
        "timeout": 1200,
    },
    "deep": {
        "label": "Deep",
        "description": "Top 1000 TCP ports with full version detection and OS "
                       "fingerprinting. Much more traffic and probing -- run "
                       "deliberately, not on fragile/OT networks.",
        "short": "Top 1000 ports, full probing + OS guess",
        "args": ["-T3", "--top-ports", "1000", "--max-rate", "300", "--host-timeout", "15m"],
        "version_args": [],
        "version_host_timeout": "5m",
        # Only used when nmap has raw sockets (OS detection needs them).
        # --osscan-limit skips hosts without both an open and a closed port
        # (the guess would be poor anyway); one try keeps the traffic down.
        "privileged_args": ["-O", "--osscan-limit", "--max-os-tries", "1"],
        "timeout": 3600,
    },
}
DEFAULT_PROFILE = "standard"

# Scans run in two stages (see run_scan): stage 1 finds open ports (+ OS
# guess on Deep) and those results are kept no matter what; stage 2 then
# identifies the services on those ports, with a time cap per host. Some
# devices accept a connection and then never answer (e.g. door-access
# controllers on 9999), which makes nmap wait out every probe -- minutes
# per port -- and can lock up small embedded TCP stacks. Ports listed here
# are reported as open but never get identification probes.
# Edited on the Settings page (saved in the DB); ALIANA_NO_PROBE_PORTS sets
# the default for a fresh install: comma-separated ports/ranges, e.g. "9999,10001-10003".
NO_PROBE_PORTS_DEFAULT = os.environ.get("ALIANA_NO_PROBE_PORTS", "9999")


def _parse_port_list(spec):
    out = set()
    for part in (spec or "").replace(" ", "").split(","):
        if not part:
            continue
        a, _, b = part.partition("-")
        try:
            lo, hi = int(a), int(b or a)
        except ValueError:
            continue
        out.update(range(max(1, lo), min(65535, hi) + 1))
    return out


def _format_port_list(ports):
    """{9999, 10001, 10002, 10003} -> ["9999", "10001-10003"]"""
    out, ports = [], sorted(ports)
    i = 0
    while i < len(ports):
        j = i
        while j + 1 < len(ports) and ports[j + 1] == ports[j] + 1:
            j += 1
        out.append(str(ports[i]) if i == j else f"{ports[i]}-{ports[j]}")
        i = j + 1
    return out

_scan_lock = threading.Lock()
_stop_requested = threading.Event()
# Wakes the auto-scan loop when its settings change or a scan finishes, so
# the countdown is recomputed straight away
_schedule_changed = threading.Event()
_last_scan_end = None  # time.monotonic() when the last scan (any kind) ended


class ScanStopped(Exception):
    pass
_last_scan_status = {"running": False, "last_run": None, "last_error": None, "next_run": None,
                     # how the most recent scan ended ("complete" / "stopped" / "failed"),
                     # and a counter that bumps every time one ends (kiosk "stamps")
                     "last_outcome": None, "outcome_seq": 0,
                     # non-fatal note about the last scan (e.g. ran unprivileged)
                     "notice": None}

# Live info about the scan in progress, filled in from nmap's verbose output
# as it runs, so the kiosk screen can show what's happening mid-scan.
_progress = {}

# nmap -v output lines we care about
_RE_INITIATING = re.compile(r"^Initiating (.+?)(?: at \d\d:\d\d|$)")
_RE_PERCENT = re.compile(r"About ([\d.]+)% done")
_RE_SCANNING_N = re.compile(r"^Scanning (\d+) hosts")
_RE_SCANNING_ONE = re.compile(r"^Scanning \S+.*\[\d+ ports")
_RE_DNS = re.compile(r"Parallel DNS resolution of (\d+) hosts?")
_RE_OPEN = re.compile(r"^Discovered open port (\d+)/(\w+) on (\S+)")

# Friendlier names for nmap's scan phases
_PHASES = [
    ("Ping Scan", "Discovering hosts"),
    ("ARP Ping", "Discovering hosts"),
    ("DNS", "Resolving names"),
    ("SYN Stealth", "Scanning ports"),
    ("Connect Scan", "Scanning ports"),
    ("Service scan", "Identifying services"),
    ("NSE", "Running checks"),
    ("OS detection", "Detecting OS"),
]


def _reset_progress(subnet):
    _progress.clear()
    _progress.update({
        "subnet": subnet,
        "started": time.time(),
        "phase": "Starting",
        "percent": None,
        "hosts_up": 0,
        "open_ports": 0,
        "recent": [],  # newest first: {"ip", "port", "proto"}
        "stage": 1,    # 1 = finding ports, 2 = identifying services
    })


def _handle_nmap_line(line):
    """Updates _progress from one line of nmap -v output."""
    line = line.strip()
    m = _RE_INITIATING.search(line)
    if m:
        name = m.group(1)
        for key, friendly in _PHASES:
            if key in name:
                _progress["phase"] = friendly
                break
        else:
            _progress["phase"] = name
        _progress["percent"] = None
        m = _RE_DNS.search(line)
        if m:
            _progress["hosts_up"] = max(_progress["hosts_up"], int(m.group(1)))
        return
    m = _RE_PERCENT.search(line)
    if m:
        _progress["percent"] = float(m.group(1))
        return
    # "Scanning N hosts" during host discovery means addresses to probe, not
    # hosts found -- only trust it once the port scan has started.
    discovering = _progress["phase"] in ("Starting", "Discovering hosts") or _progress.get("stage") == 2
    m = _RE_SCANNING_N.search(line)
    if m:
        if not discovering:
            _progress["hosts_up"] = max(_progress["hosts_up"], int(m.group(1)))
        return
    if _RE_SCANNING_ONE.search(line):
        if not discovering:
            _progress["hosts_up"] = max(_progress["hosts_up"], 1)
        return
    m = _RE_OPEN.search(line)
    if m:
        if _progress.get("stage") == 2:
            return  # stage 2 re-checks ports stage 1 already counted
        _progress["open_ports"] += 1
        _progress["recent"].insert(0, {"port": int(m.group(1)), "proto": m.group(2), "ip": m.group(3)})
        del _progress["recent"][8:]


def _run_nmap_live(cmd, timeout):
    """Runs nmap, feeding each output line to _handle_nmap_line as it arrives.
    nmap's stdout goes to a pseudo-terminal so it's line-buffered (a plain
    pipe would hold the output back until the scan finished). Returns the last
    few output lines, for error messages."""
    master, slave = pty.openpty()
    proc = subprocess.Popen(cmd, stdout=slave, stderr=slave, stdin=subprocess.DEVNULL, close_fds=True)
    os.close(slave)
    deadline = time.time() + timeout
    buf = b""
    tail = []
    try:
        while True:
            if _stop_requested.is_set():
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                raise ScanStopped()
            if time.time() > deadline:
                proc.kill()
                raise subprocess.TimeoutExpired(cmd, timeout)
            ready, _, _ = select.select([master], [], [], 1.0)
            if not ready:
                if proc.poll() is not None:
                    break
                continue
            try:
                chunk = os.read(master, 4096)
            except OSError:  # EIO: nmap exited and closed the terminal
                break
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                line = raw.decode(errors="ignore").rstrip("\r")
                if line:
                    tail = (tail + [line])[-5:]
                    _handle_nmap_line(line)
    finally:
        os.close(master)
        proc.wait()
    if proc.returncode != 0:
        raise RuntimeError("nmap failed: " + " | ".join(tail)[:300])
    return tail


def cleanup_stale_temp_files():
    """Removes any leftover aliana_scan_*.xml files in the temp dir, e.g. from
    a crashed run or an older version that used a fixed filename. Safe to call
    on every startup."""
    tmp_dir = tempfile.gettempdir()
    try:
        for name in os.listdir(tmp_dir):
            if name.startswith("aliana_scan") and name.endswith(".xml"):
                try:
                    os.remove(os.path.join(tmp_dir, name))
                except OSError:
                    pass  # owned by another user or already gone -- not fatal
    except OSError:
        pass


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT,
            finished_at TEXT,
            subnet TEXT,
            host_count INTEGER
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip TEXT,
            mac TEXT,
            vendor TEXT,
            hostname TEXT,
            status TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id INTEGER,
            port INTEGER,
            protocol TEXT,
            state TEXT,
            service TEXT,
            product TEXT,
            version TEXT,
            FOREIGN KEY(host_id) REFERENCES hosts(id)
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    # Older databases: add the scans.profile column
    cols = [r[1] for r in c.execute("PRAGMA table_info(scans)")]
    if "profile" not in cols:
        c.execute("ALTER TABLE scans ADD COLUMN profile TEXT")
    if "mode" not in cols:  # "syn" (raw sockets) or "connect"
        c.execute("ALTER TABLE scans ADD COLUMN mode TEXT")
    if "ports_checked" not in cols:  # e.g. "tcp:1,3,7-9,21" (from nmap's scaninfo)
        c.execute("ALTER TABLE scans ADD COLUMN ports_checked TEXT")
    if "scope" not in cols:  # "subnet" (whole network) or "host" (one target)
        c.execute("ALTER TABLE scans ADD COLUMN scope TEXT DEFAULT 'subnet'")
    # Scan job queue (see enqueue / queue_worker)
    c.execute("""
        CREATE TABLE IF NOT EXISTS jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT,            -- "subnet" or "host"
            target TEXT,          -- host IP (host jobs); subnet jobs: filled in when it runs
            interface TEXT,       -- subnet jobs: interface to scan
            profile TEXT,
            source TEXT,          -- "manual", "auto", "host-card"
            status TEXT,          -- queued / running / done / stopped / failed / cancelled
            created_at TEXT,
            started_at TEXT,
            finished_at TEXT,
            scan_id INTEGER,
            hosts INTEGER,
            open_ports INTEGER,
            error TEXT
        )
    """)
    jcols = [r[1] for r in c.execute("PRAGMA table_info(jobs)")]
    if "priority" not in jcols:  # set by "run next"; otherwise jobs run in id order
        c.execute("ALTER TABLE jobs ADD COLUMN priority INTEGER")
    # Jobs left over from before a restart never run by themselves (nobody
    # may be watching) -- mark them so they show up in the queue history.
    now = datetime.datetime.now().isoformat()
    c.execute("UPDATE jobs SET status = 'cancelled', finished_at = ?, error = 'Aliana restarted' "
              "WHERE status IN ('queued', 'running')", (now,))
    pcols = [r[1] for r in c.execute("PRAGMA table_info(ports)")]
    if "probe" not in pcols:  # None, "skipped" (never-probe list) or "timeout"
        c.execute("ALTER TABLE ports ADD COLUMN probe TEXT")
    # Older databases: OS guess columns (Deep scans with raw sockets)
    hcols = [r[1] for r in c.execute("PRAGMA table_info(hosts)")]
    for col, typ in (("os_name", "TEXT"), ("os_accuracy", "INTEGER"), ("os_type", "TEXT")):
        if col not in hcols:
            c.execute(f"ALTER TABLE hosts ADD COLUMN {col} {typ}")
    # Clean up "down" hosts stored by earlier builds (nmap -v lists every
    # unresponsive address) and fix those scans' host counts.
    c.execute("DELETE FROM ports WHERE host_id IN (SELECT id FROM hosts WHERE status = 'down')")
    c.execute("DELETE FROM hosts WHERE status = 'down'")
    c.execute("UPDATE scans SET host_count = (SELECT COUNT(*) FROM hosts WHERE hosts.scan_id = scans.id)")
    conn.commit()
    conn.close()


def list_interfaces():
    """Returns a list of dicts describing each non-loopback network interface:
    name, state (up/down/unknown), and ipv4 address (or None if not assigned)."""
    interfaces = []
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except FileNotFoundError:
        names = []

    for name in names:
        if name == "lo":
            continue

        state = "unknown"
        try:
            with open(f"/sys/class/net/{name}/operstate") as f:
                state = f.read().strip()
        except OSError:
            pass

        ipv4 = None
        try:
            out = subprocess.check_output(
                ["ip", "-4", "-o", "addr", "show", name], text=True
            )
            for p in out.split():
                if "/" in p and p[0].isdigit():
                    ipv4 = p
                    break
        except Exception:
            pass

        interfaces.append({"name": name, "state": state, "ipv4": ipv4})

    return interfaces


def _get_setting(key, default=None):
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row[0] if row else default


def _set_setting(key, value):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
    conn.commit()
    conn.close()


def get_profile():
    name = _get_setting("profile", DEFAULT_PROFILE)
    return name if name in PROFILES else DEFAULT_PROFILE


def set_profile(name):
    if name not in PROFILES:
        raise ValueError(f"Unknown scan profile: {name}")
    _set_setting("profile", name)


def get_auto_scan():
    """True when automatic scans are switched on."""
    v = _get_setting("auto_scan")
    return AUTO_SCAN_DEFAULT if v is None else v == "1"


def get_scan_interval():
    """Seconds between automatic scans (kept even while auto-scan is off)."""
    try:
        v = int(_get_setting("scan_interval", SCAN_INTERVAL_SECONDS))
    except (TypeError, ValueError):
        v = SCAN_INTERVAL_SECONDS
    return v if v in INTERVAL_CHOICES else SCAN_INTERVAL_SECONDS


def set_auto_scan(enabled=None, interval=None):
    """Switches automatic scans on/off and/or changes the interval. The
    auto-scan loop picks the change up immediately."""
    if interval is not None:
        interval = int(interval)
        if interval not in INTERVAL_CHOICES:
            raise ValueError(f"Unsupported interval: {interval}")
        _set_setting("scan_interval", str(interval))
    if enabled is not None:
        _set_setting("auto_scan", "1" if enabled else "0")
    _schedule_changed.set()


def get_no_probe_ports():
    """Set of TCP ports that never get service-identification probes."""
    return _parse_port_list(_get_setting("no_probe_ports", NO_PROBE_PORTS_DEFAULT))


def set_no_probe_ports(spec):
    """Saves the never-probe list from "9999, 10001-10003" (or a list of
    such strings). Returns the normalised list, e.g. ["9999", "10001-10003"]."""
    if isinstance(spec, (list, tuple)):
        spec = ",".join(str(x) for x in spec)
    ports = _parse_port_list(spec)
    norm = _format_port_list(ports)
    _set_setting("no_probe_ports", ",".join(norm))
    return norm


def get_current_interface():
    """Returns the currently selected scan interface: DB setting if present,
    otherwise falls back to the ALIANA_IFACE env var / 'usb0' default."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT value FROM settings WHERE key = 'interface'")
    row = c.fetchone()
    conn.close()
    if row:
        return row[0]
    return SCAN_INTERFACE


def set_current_interface(name):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO settings (key, value) VALUES ('interface', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (name,),
    )
    conn.commit()
    conn.close()


def get_local_subnet(interface=SCAN_INTERFACE):
    """Reads the IPv4 address+prefix off the given interface and returns the subnet as CIDR."""
    try:
        out = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show", interface], text=True
        )
        # Example line: "3: usb0    inet 172.20.2.1/24 brd ..."
        parts = out.split()
        for p in parts:
            if "/" in p and p[0].isdigit():
                iface = ipaddress.ip_interface(p)
                return str(iface.network)
    except Exception as e:
        _last_scan_status["last_error"] = f"Could not read interface {interface}: {e}"
    return None


_RAW_ERRORS = ("requires root privileges", "Operation not permitted", "raw socket",
               "Failed to open device", "dnet:", "pcap", "privileged")
_raw_caps_cache = None


def has_raw_sockets():
    """True when nmap can open raw sockets: running as root, or the nmap
    binary carries cap_net_raw (setup.sh grants it with setcap). Cached --
    restart the service after re-running setup.sh."""
    global _raw_caps_cache
    if _raw_caps_cache is not None:
        return _raw_caps_cache
    ok = os.geteuid() == 0
    if not ok:
        nmap = shutil.which("nmap")
        getcap = shutil.which("getcap") or next(
            (p for p in ("/usr/sbin/getcap", "/sbin/getcap") if os.path.exists(p)), None)
        if nmap and getcap:
            try:
                out = subprocess.run([getcap, os.path.realpath(nmap)], capture_output=True,
                                     text=True, timeout=5).stdout
                ok = "cap_net_raw" in out
            except Exception:
                ok = False
    _raw_caps_cache = ok
    return ok


def scan_mode():
    """'syn' when scans will use raw sockets (SYN scan, ARP discovery, OS
    detection on Deep), otherwise 'connect'."""
    return "syn" if NMAP_PRIVILEGED and has_raw_sockets() else "connect"


def _nmap_cmd(profile, subnet, xml_path, privileged):
    p = PROFILES[profile]
    cmd = ["nmap"]
    if privileged:
        cmd.append("--privileged")
    cmd += p["args"]
    if privileged:
        cmd += p.get("privileged_args", [])
    # -v and --stats-every make nmap report progress as it goes (hosts
    # found, ports discovered, % done), which the kiosk screen shows live.
    return cmd + ["-v", "--stats-every", "2s", "-oX", xml_path, subnet]


def _version_cmd(profile, targets, ports, xml_path, privileged):
    """Stage 2: service identification on known-open ports of known-up
    hosts. -Pn (they're up), -n (names came from stage 1), and a per-host
    time cap so one silent device can't hold the scan."""
    p = PROFILES[profile]
    cmd = ["nmap"]
    if privileged:
        cmd.append("--privileged")
    cmd += ["-sV"] + p.get("version_args", []) + [
        "-Pn", "-n", "-T3", "--max-rate", "300",
        "--host-timeout", p.get("version_host_timeout", "3m"),
        "-p", "T:" + ",".join(str(x) for x in sorted(ports)),
        "-v", "--stats-every", "2s", "-oX", xml_path] + sorted(targets, key=ipaddress.IPv4Address)
    return cmd


def _identify_services(profile, hosts, privileged, xml_path):
    """Runs stage 2 and merges what it learns into `hosts` (stage-1 results,
    modified in place). Every open port ends up with probe = None
    (identified, or nmap tried and had no match), "skipped" (on the
    never-probe list), or "timeout" (cap hit, or stopped by the operator).
    Returns "ok", "timeout" or "stopped"."""
    targets, ports = set(), set()
    no_probe = get_no_probe_ports()
    for h in hosts:
        for pt in h["ports"]:
            if pt["state"] != "open" or pt["protocol"] != "tcp":
                continue
            if pt["port"] in no_probe:
                pt["probe"] = "skipped"
                continue
            pt["probe"] = "timeout"      # until stage 2 says otherwise
            targets.add(h["ip"])
            ports.add(pt["port"])
    if not targets:
        return "ok"
    try:
        os.remove(xml_path)  # so stage-1 output can't be mistaken for stage 2's
    except OSError:
        pass
    _progress["stage"] = 2
    _progress["phase"] = "Identifying services"
    _progress["percent"] = None
    result = "ok"
    try:
        _run_nmap_live(_version_cmd(profile, targets, ports, xml_path, privileged),
                       timeout=PROFILES[profile]["timeout"])
    except ScanStopped:
        result = "stopped"
    except subprocess.TimeoutExpired:
        result = "timeout"
    except RuntimeError:
        result = "timeout"   # nmap error in stage 2: keep stage-1 results
    try:
        found = {h["ip"]: h for h in _parse_nmap_xml(xml_path)}
    except Exception:
        found = {}           # stopped/killed before nmap wrote the file
    for h in hosts:
        h2 = found.get(h["ip"])
        if not h2:
            continue         # host hit its time cap (or stage 2 cut short)
        by_port = {(p2["protocol"], p2["port"]): p2 for p2 in h2["ports"]}
        for pt in h["ports"]:
            p2 = by_port.get((pt["protocol"], pt["port"]))
            if pt.get("probe") != "timeout" or not p2:
                continue
            pt["probe"] = None
            for k in ("service", "product", "version"):
                if p2.get(k):
                    pt[k] = p2[k]
    return result


def run_scan(subnet=None, profile=None, scope="subnet", interface=None):
    """Runs an nmap scan using a scan profile (default: the saved one) and
    stores results. Returns scan_id or None. scope "subnet" scans the subnet
    on `interface` (default: the selected one); scope "host" scans the
    single address in `subnet`. Normally called by the job queue worker --
    use enqueue() so only one scan ever runs at a time."""
    global _raw_caps_cache, _last_scan_end
    if not _scan_lock.acquire(blocking=False):
        return None  # a scan is already running

    try:
        _stop_requested.clear()
        _last_scan_status["running"] = True
        _last_scan_status["last_job"] = {"scope": scope, "target": subnet}
        if subnet is None:
            subnet = get_local_subnet(interface or get_current_interface())
        if not subnet:
            _last_scan_status["last_error"] = "No subnet detected to scan."
            _last_scan_status["last_outcome"] = "failed"
            return None
        profile = profile if profile in PROFILES else get_profile()
        _reset_progress(subnet)
        _progress["profile"] = profile
        _progress["mode"] = scan_mode()

        started = datetime.datetime.now().isoformat()
        # Unique filename per scan (pid + uuid) so a leftover file from a
        # previous run -- possibly owned by a different user, e.g. a manual
        # sudo run vs. the systemd service -- can never collide with this one.
        xml_path = os.path.join(
            tempfile.gettempdir(), f"aliana_scan_{os.getpid()}_{uuid.uuid4().hex}.xml"
        )

        # The profile decides what gets scanned and how hard (see PROFILES).
        # With raw sockets nmap does ARP discovery + SYN scans (and OS
        # detection on Deep); without, it falls back to TCP connect scans.
        _last_scan_status["notice"] = None
        mode = scan_mode()
        timeout = PROFILES[profile]["timeout"]
        try:
            _run_nmap_live(_nmap_cmd(profile, subnet, xml_path, mode == "syn"), timeout=timeout)
        except RuntimeError as e:
            if mode != "syn" or not any(k.lower() in str(e).lower() for k in _RAW_ERRORS):
                raise
            # Raw sockets refused (capability lost, e.g. nmap was upgraded
            # and setup.sh not re-run): retry once as a connect scan.
            _raw_caps_cache = False
            mode = "connect"
            _last_scan_status["notice"] = ("Raw sockets unavailable -- ran a connect scan without "
                                           "OS detection. Re-run setup.sh and restart Aliana.")
            _reset_progress(subnet)
            _progress["profile"] = profile
            _run_nmap_live(_nmap_cmd(profile, subnet, xml_path, False), timeout=timeout)
        _progress["mode"] = mode

        hosts = _parse_nmap_xml(xml_path)
        checked = _parse_scaninfo(xml_path)

        # Stage 2: identify services on the open ports. Stage-1 results are
        # kept whatever happens here; stopping now saves what's been found.
        stage2 = "ok"
        if profile != "discovery":
            stage2 = _identify_services(profile, hosts, mode == "syn", xml_path)
        finished = datetime.datetime.now().isoformat()

        scan_id = _store_results(subnet, started, finished, hosts, profile, mode, checked, scope)
        n_slow = sum(1 for h in hosts for pt in h["ports"] if pt.get("probe") == "timeout")
        note = None
        if stage2 == "stopped":
            note = f"Service identification stopped -- open ports were saved; {n_slow} not identified."
        elif n_slow:
            note = (f"{n_slow} open port(s) didn't answer identification probes in time -- "
                    "shown as not identified.")
        if note:
            prev = _last_scan_status.get("notice")
            _last_scan_status["notice"] = f"{prev} {note}" if prev else note
        _last_scan_status["last_job"] = {
            "scope": scope, "target": subnet, "hosts": len(hosts),
            "open_ports": sum(1 for h in hosts for p in h["ports"] if p["state"] == "open")}

        _last_scan_status["last_run"] = finished
        _last_scan_status["last_error"] = None
        _last_scan_status["last_outcome"] = "stopped" if stage2 == "stopped" else "complete"
        _last_scan_status["last_job"]["partial"] = stage2 == "stopped"
        return scan_id

    except ScanStopped:
        # Stopped by the user: nothing to save, and not an error
        _last_scan_status["last_error"] = None
        _last_scan_status["last_outcome"] = "stopped"
        return None
    except subprocess.TimeoutExpired:
        _last_scan_status["last_error"] = f"nmap timed out after {timeout // 60} minutes."
        _last_scan_status["last_outcome"] = "failed"
        return None
    except Exception as e:
        _last_scan_status["last_error"] = str(e)
        _last_scan_status["last_outcome"] = "failed"
        return None
    finally:
        # Always clean up the temp file, win or lose, so nothing stale is
        # left behind to cause ownership conflicts on the next run.
        try:
            if 'xml_path' in locals() and os.path.exists(xml_path):
                os.remove(xml_path)
        except Exception:
            pass
        if scope == "subnet":  # host deep scans don't move the auto-scan schedule
            _last_scan_end = time.monotonic()
        _last_scan_status["outcome_seq"] += 1
        _last_scan_status["running"] = False
        _scan_lock.release()
        _schedule_changed.set()  # the next auto-scan counts from now


def _parse_nmap_xml(path):
    tree = ET.parse(path)
    root = tree.getroot()
    hosts = []

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        status = status_el.get("state") if status_el is not None else "unknown"

        addr_ipv4 = None
        mac = None
        vendor = None
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                addr_ipv4 = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")

        hostname = None
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        ports = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")
                ports.append({
                    "port": int(port_el.get("portid")),
                    "protocol": port_el.get("protocol"),
                    "state": state_el.get("state") if state_el is not None else "unknown",
                    "service": service_el.get("name") if service_el is not None else "",
                    "product": service_el.get("product") if service_el is not None else "",
                    "version": service_el.get("version") if service_el is not None else "",
                })

        # OS guess (Deep scans with raw sockets): nmap lists matches best first
        os_name = os_accuracy = os_type = None
        os_el = host_el.find("os")
        if os_el is not None:
            m = os_el.find("osmatch")
            if m is not None:
                os_name = m.get("name")
                try:
                    os_accuracy = int(m.get("accuracy"))
                except (TypeError, ValueError):
                    pass
                cls = m.find("osclass")
                if cls is not None:
                    os_type = cls.get("type")

        # With -v, nmap also lists every address that did NOT respond
        # (status "down") -- skip those, we only want live hosts.
        if addr_ipv4 and status == "up":
            hosts.append({
                "ip": addr_ipv4,
                "mac": mac,
                "vendor": vendor,
                "hostname": hostname,
                "status": status,
                "ports": ports,
                "os_name": os_name,
                "os_accuracy": os_accuracy,
                "os_type": os_type,
            })

    return hosts


def _parse_scaninfo(path):
    """Which ports the scan actually checked, from nmap's <scaninfo> lines,
    as "tcp:1,3,7-9;udp:53". Empty string for host-only (Discovery) scans.
    Lets later views tell "port closed now" apart from "port not checked"."""
    try:
        root = ET.parse(path).getroot()
    except Exception:
        return None
    parts = [f"{si.get('protocol')}:{si.get('services')}"
             for si in root.findall("scaninfo") if si.get("protocol") and si.get("services")]
    return ";".join(parts)


def _checked_set(ports_checked):
    """'tcp:1,3,7-9' -> {('tcp', 1), ('tcp', 3), ('tcp', 7), ...}, or None
    when unknown (scans recorded before this was stored)."""
    if ports_checked is None:
        return None
    out = set()
    for part in filter(None, ports_checked.split(";")):
        proto, _, spec = part.partition(":")
        for r in filter(None, spec.split(",")):
            a, _, b = r.partition("-")
            try:
                lo, hi = int(a), int(b or a)
            except ValueError:
                continue
            out.update((proto, n) for n in range(lo, hi + 1))
    return out


def _store_results(subnet, started, finished, hosts, profile=None, mode=None, ports_checked=None,
                   scope="subnet"):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO scans (started_at, finished_at, subnet, host_count, profile, mode, ports_checked, scope) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (started, finished, subnet, len(hosts), profile, mode, ports_checked, scope),
    )
    scan_id = c.lastrowid

    for h in hosts:
        c.execute(
            "INSERT INTO hosts (scan_id, ip, mac, vendor, hostname, status, os_name, os_accuracy, os_type) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (scan_id, h["ip"], h["mac"], h["vendor"], h["hostname"], h["status"],
             h.get("os_name"), h.get("os_accuracy"), h.get("os_type")),
        )
        host_id = c.lastrowid
        for p in h["ports"]:
            c.execute(
                "INSERT INTO ports (host_id, port, protocol, state, service, product, version, probe) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (host_id, p["port"], p["protocol"], p["state"], p["service"], p["product"], p["version"],
                 p.get("probe")),
            )

    conn.commit()
    conn.close()
    return scan_id


HISTORY_LOOKBACK = 50  # earlier scans consulted for "last seen" ports


def get_latest_scan():
    return get_scan(None)


def latest_subnet_scan_id():
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT MAX(id) FROM scans WHERE COALESCE(scope, 'subnet') = 'subnet'").fetchone()
    conn.close()
    return row[0] if row else None


def get_scan(scan_id=None):
    """One scan (default: the latest network scan) with its hosts and ports.

    For a network scan, a host that got its own Deep scan afterwards (from
    the dashboard's per-host button, before the next network scan) shows
    that Deep scan's results instead, flagged with host["host_scan"].

    Each host also gets "earlier": open ports found by previous scans that
    the shown results don't list, each marked
      state "unchecked" -- not looked at this time (e.g. a Discovery scan,
                           or Standard after Deep), or
      state "closed"    -- checked and no longer open,
    with when/which profile last saw it open. Hosts are matched across scans
    by MAC address when known, otherwise by IP."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    if scan_id is None:
        c.execute("SELECT * FROM scans WHERE COALESCE(scope, 'subnet') = 'subnet' ORDER BY id DESC LIMIT 1")
    else:
        c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan = c.fetchone()
    if not scan:
        conn.close()
        return None
    scan = dict(scan)
    scan["scope"] = scan.get("scope") or "subnet"

    def load_hosts(sid):
        c.execute("SELECT * FROM hosts WHERE scan_id = ? ORDER BY id", (sid,))
        out = []
        for h in c.fetchall():
            c.execute("SELECT * FROM ports WHERE host_id = ? ORDER BY port", (h["id"],))
            host = dict(h)
            host["ports"] = [dict(p) for p in c.fetchall()]
            out.append(host)
        return out

    def hkey(mac, ip):
        return ("mac", mac.lower()) if mac else ("ip", ip)

    hosts = load_hosts(scan["id"])
    for h in hosts:
        h["shown_scan"] = scan          # which scan the card's ports come from
        h["host_scan"] = None

    # Per-host Deep scans run after this network scan (and before the next)
    if scan["scope"] == "subnet":
        nxt = c.execute("SELECT MIN(id) FROM scans WHERE id > ? AND COALESCE(scope, 'subnet') = 'subnet'",
                        (scan["id"],)).fetchone()[0]
        c.execute("SELECT * FROM scans WHERE scope = 'host' AND id > ? AND id < ? ORDER BY id DESC",
                  (scan["id"], nxt if nxt is not None else 2 ** 62))
        host_scans = [dict(r) for r in c.fetchall()]
        if host_scans:
            by_key = {}
            for h in hosts:
                by_key.setdefault(hkey(h["mac"], h["ip"]), h)
                by_key.setdefault(("ip", h["ip"]), h)
            for hs in host_scans:           # newest first: first match wins
                for hh in load_hosts(hs["id"]):
                    card = by_key.get(hkey(hh["mac"], hh["ip"])) or by_key.get(("ip", hh["ip"]))
                    if card is None or card["host_scan"] is not None:
                        continue
                    card["host_scan"] = {"id": hs["id"], "finished_at": hs["finished_at"],
                                         "profile": hs["profile"]}
                    card["shown_scan"] = hs
                    card["ports"] = hh["ports"]
                    for k in ("os_name", "os_accuracy", "os_type", "hostname", "vendor", "mac"):
                        if hh.get(k):
                            card[k] = hh[k]

    # Earlier scans (network and host), newest first, with each host's open ports
    top = max(h["shown_scan"]["id"] for h in hosts) if hosts else scan["id"]
    c.execute("SELECT id, finished_at, profile, ports_checked FROM scans WHERE id < ? "
              "ORDER BY id DESC LIMIT ?", (top, HISTORY_LOOKBACK))
    earlier_scans = [dict(r) for r in c.fetchall()]
    by_scan = {}
    if earlier_scans:
        ids = [e["id"] for e in earlier_scans]
        q = ",".join("?" * len(ids))
        c.execute(f"SELECT h.scan_id, h.ip, h.mac, p.port, p.protocol, p.state, p.service, p.product, p.version "
                  f"FROM hosts h LEFT JOIN ports p ON p.host_id = h.id WHERE h.scan_id IN ({q})", ids)
        for r in c.fetchall():
            entry = by_scan.setdefault(r["scan_id"], {})
            ports = entry.setdefault(hkey(r["mac"], r["ip"]), {})
            if r["port"] is not None and r["state"] == "open":
                ports[(r["protocol"], r["port"])] = dict(r)
            # also index by IP, for hosts whose MAC isn't known in one of the scans
            entry.setdefault(("ip", r["ip"]), ports)
    conn.close()

    checked_cache = {}

    def checked(sc):
        if sc["id"] not in checked_cache:
            chk = _checked_set(sc.get("ports_checked"))
            if chk is None and sc.get("profile") == "discovery":
                chk = set()
            checked_cache[sc["id"]] = chk
        return checked_cache[sc["id"]]

    for host in hosts:
        shown = host.pop("shown_scan")
        cur_checked = checked(shown)
        key = hkey(host["mac"], host["ip"])
        # every port the shown results report on (open, or closed/filtered listed by nmap)
        open_now = {(p["protocol"], p["port"]) for p in host["ports"]}
        decided = set()      # ports whose most recent earlier check we've already used
        earlier = []
        for es in earlier_scans:   # newest first
            if es["id"] >= shown["id"]:
                continue
            seen = by_scan.get(es["id"], {})
            ports = seen.get(key) if key in seen else seen.get(("ip", host["ip"]))
            if ports is None:
                continue           # host not found in that scan: tells us nothing
            chk = checked(es)
            for pk, row in ports.items():
                if pk in decided or pk in open_now:
                    continue
                decided.add(pk)
                state = "unchecked" if cur_checked is None or pk not in cur_checked else "closed"
                earlier.append({
                    "port": pk[1], "protocol": pk[0], "service": row["service"],
                    "product": row["product"], "version": row["version"],
                    "state": state, "last_seen": es["finished_at"], "profile": es["profile"],
                })
            # Ports this earlier scan checked and found NOT open: older
            # sightings of them are stale, so stop looking further back
            if chk:
                decided.update(pk for pk in chk if pk not in ports)
        earlier.sort(key=lambda e: (e["state"] != "unchecked", e["port"]))
        host["earlier"] = earlier

    scan["hosts"] = hosts
    return scan


def get_scan_history(limit=20):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_status():
    status = dict(_last_scan_status)
    status["interface"] = get_current_interface()
    status["profile"] = get_profile()
    status["auto_scan"] = get_auto_scan()
    status["scan_interval"] = get_scan_interval()
    status["next_in"] = next_scan_in()
    status["mode"] = scan_mode()
    status["queue"] = queue_summary()
    return status


def stop_scan(wait=5.0):
    """Stops the running scan (if any). Waits briefly for it to wind down.
    Returns True if a scan was running."""
    if not _last_scan_status["running"]:
        return False
    _stop_requested.set()
    deadline = time.time() + wait
    while _last_scan_status["running"] and time.time() < deadline:
        time.sleep(0.1)
    return True


# ---------------------------------------------------------------- job queue
#
# Every scan -- SCAN NOW, automatic scans, and per-host Deep scans from the
# dashboard -- goes through one queue with a single worker thread, so only
# one nmap ever runs at a time and the Pi never gets overloaded.

MAX_QUEUED = 20
_queue_wake = threading.Event()
_current_job = {}  # the running job's row, or empty


def _db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _now():
    return datetime.datetime.now().isoformat()


def get_queue_paused():
    return _get_setting("queue_paused", "0") == "1"


def set_queue_paused(paused):
    """Paused: the running job finishes, queued jobs wait."""
    _set_setting("queue_paused", "1" if paused else "0")
    _queue_wake.set()


def enqueue(kind, target=None, profile=None, source="manual"):
    """Adds a scan job. kind "subnet" (target ignored; scans the selected
    interface's subnet with `profile`, default the saved one) or "host"
    (target = one IPv4 address, Deep profile unless given). Returns
    (job_dict, None) or (None, "reason it wasn't queued")."""
    if kind not in ("subnet", "host"):
        return None, "Unknown job type."
    iface = None
    if kind == "host":
        try:
            target = str(ipaddress.IPv4Address(str(target).strip()))
        except (ipaddress.AddressValueError, ValueError):
            return None, "Not a valid IPv4 address."
        profile = profile if profile in PROFILES else "deep"
    else:
        target = None
        iface = get_current_interface()
        profile = profile if profile in PROFILES else get_profile()
    conn = _db()
    try:
        c = conn.cursor()
        if kind == "host":
            dup = c.execute("SELECT * FROM jobs WHERE kind = 'host' AND target = ? AND profile = ? "
                            "AND status IN ('queued', 'running')", (target, profile)).fetchone()
        else:
            dup = c.execute("SELECT * FROM jobs WHERE kind = 'subnet' "
                            "AND status IN ('queued', 'running')").fetchone()
        if dup:
            return None, ("That host is already queued." if kind == "host"
                          else "A network scan is already queued or running.")
        n = c.execute("SELECT COUNT(*) FROM jobs WHERE status = 'queued'").fetchone()[0]
        if n >= MAX_QUEUED:
            return None, f"Queue is full ({MAX_QUEUED} jobs)."
        c.execute("INSERT INTO jobs (kind, target, interface, profile, source, status, created_at) "
                  "VALUES (?, ?, ?, ?, ?, 'queued', ?)", (kind, target, iface, profile, source, _now()))
        job_id = c.lastrowid
        conn.commit()
        job = dict(c.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone())
    finally:
        conn.close()
    _queue_wake.set()
    _schedule_changed.set()
    return job, None


def cancel_job(job_id):
    """Removes a queued job, or stops the job that's running."""
    if _current_job.get("id") == job_id:
        stop_scan(wait=0)
        return True
    conn = _db()
    n = conn.execute("UPDATE jobs SET status = 'cancelled', finished_at = ? "
                     "WHERE id = ? AND status = 'queued'", (_now(), job_id)).rowcount
    conn.commit()
    conn.close()
    _schedule_changed.set()
    return n > 0


def cancel_all_queued():
    conn = _db()
    conn.execute("UPDATE jobs SET status = 'cancelled', finished_at = ? WHERE status = 'queued'", (_now(),))
    conn.commit()
    conn.close()
    _schedule_changed.set()


def move_job_to_front(job_id):
    """Makes a queued job the next to run (it takes the lowest id slot's
    turn by being given priority ordering)."""
    conn = _db()
    first = conn.execute("SELECT MIN(COALESCE(priority, id)) FROM jobs WHERE status = 'queued'").fetchone()[0]
    if first is not None:
        conn.execute("UPDATE jobs SET priority = ? WHERE id = ? AND status = 'queued'", (first - 1, job_id))
        conn.commit()
    conn.close()


def clear_finished_jobs():
    conn = _db()
    conn.execute("DELETE FROM jobs WHERE status NOT IN ('queued', 'running')")
    conn.commit()
    conn.close()


def get_queue(recent=25):
    """Running job, queued jobs (in run order) and recent finished jobs."""
    conn = _db()
    queued = [dict(r) for r in conn.execute(
        "SELECT * FROM jobs WHERE status = 'queued' ORDER BY COALESCE(priority, id), id")]
    done = [dict(r) for r in conn.execute(
        "SELECT * FROM jobs WHERE status NOT IN ('queued', 'running') ORDER BY id DESC LIMIT ?", (recent,))]
    conn.close()
    running = dict(_current_job) if _current_job else None
    if running:
        running["progress"] = get_progress()
    for i, j in enumerate(queued):
        j["position"] = i + 1
    return {"running": running, "queued": queued, "recent": done, "paused": get_queue_paused(),
            "max_queued": MAX_QUEUED}


def queue_summary():
    """Small summary for status displays."""
    conn = _db()
    n = conn.execute("SELECT COUNT(*) FROM jobs WHERE status = 'queued'").fetchone()[0]
    hosts = {r[0]: r[1] for r in conn.execute(
        "SELECT target, status FROM jobs WHERE kind = 'host' AND status IN ('queued', 'running')")}
    conn.close()
    cur = _current_job
    return {
        "queued": n,
        "paused": get_queue_paused(),
        "current": {k: cur.get(k) for k in ("id", "kind", "target", "profile", "source")} if cur else None,
        "hosts": hosts,  # ip -> queued/running, for the dashboard's Deep scan buttons
    }


def _subnet_job_pending():
    conn = _db()
    n = conn.execute("SELECT COUNT(*) FROM jobs WHERE kind = 'subnet' "
                     "AND status IN ('queued', 'running')").fetchone()[0]
    conn.close()
    return n > 0


def queue_worker():
    """Runs queued jobs one at a time, forever. Call in a daemon thread."""
    global _current_job
    while True:
        try:
            _queue_wake.clear()
            if get_queue_paused():
                _queue_wake.wait()
                continue
            conn = _db()
            row = conn.execute("SELECT * FROM jobs WHERE status = 'queued' "
                               "ORDER BY COALESCE(priority, id), id LIMIT 1").fetchone()
            if not row:
                conn.close()
                _queue_wake.wait()
                continue
            job = dict(row)
            job["status"] = "running"
            job["started_at"] = _now()
            conn.execute("UPDATE jobs SET status = 'running', started_at = ? WHERE id = ?",
                         (job["started_at"], job["id"]))
            conn.commit()
            conn.close()
            _current_job = job

            if job["kind"] == "host":
                scan_id = run_scan(subnet=job["target"], profile=job["profile"], scope="host")
            else:
                scan_id = run_scan(profile=job["profile"], scope="subnet", interface=job["interface"])

            outcome = _last_scan_status.get("last_outcome")
            info = _last_scan_status.get("last_job") or {}
            status = {"complete": "done", "stopped": "stopped"}.get(outcome, "failed")
            conn = _db()
            conn.execute(
                "UPDATE jobs SET status = ?, finished_at = ?, scan_id = ?, target = COALESCE(target, ?), "
                "hosts = ?, open_ports = ?, error = ? WHERE id = ?",
                (status, _now(), scan_id, info.get("target"), info.get("hosts"), info.get("open_ports"),
                 _last_scan_status.get("last_error") if status == "failed" else None, job["id"]))
            conn.commit()
            conn.close()
        except Exception:
            traceback.print_exc()
            time.sleep(5)
        finally:
            _current_job = {}


def get_progress():
    """Live progress of the running scan, or None when idle."""
    if not _last_scan_status["running"] or not _progress:
        return None
    p = dict(_progress)
    p["recent"] = list(_progress["recent"])
    p["elapsed"] = int(time.time() - p.pop("started"))
    return p


def get_latest_summary():
    """Small summary of the most recent finished scan, for the kiosk screen."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, finished_at, subnet, host_count, profile FROM scans "
              "WHERE COALESCE(scope, 'subnet') = 'subnet' ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    if not row:
        conn.close()
        return None
    scan_id, finished_at, subnet, host_count, profile = row
    c.execute(
        "SELECT COUNT(*) FROM ports p JOIN hosts h ON p.host_id = h.id "
        "WHERE h.scan_id = ? AND p.state = 'open'", (scan_id,))
    open_ports = c.fetchone()[0]
    c.execute(
        "SELECT COALESCE(NULLIF(p.service, ''), p.port || '/' || p.protocol) AS svc, COUNT(*) "
        "FROM ports p JOIN hosts h ON p.host_id = h.id "
        "WHERE h.scan_id = ? AND p.state = 'open' GROUP BY svc ORDER BY 2 DESC, svc LIMIT 6",
        (scan_id,))
    services = [{"name": r[0], "count": r[1]} for r in c.fetchall()]
    conn.close()
    ago = None
    try:
        ago = int((datetime.datetime.now() - datetime.datetime.fromisoformat(finished_at)).total_seconds())
    except (TypeError, ValueError):
        pass
    return {
        "subnet": subnet,
        "hosts": host_count,
        "open_ports": open_ports,
        "services": services,
        "ago": ago,
        "profile": PROFILES.get(profile, {}).get("label") if profile else None,
    }


def background_loop():
    """Runs forever, starting automatic scans while auto-scan is switched on.
    Call in a daemon thread. Sleeps until the next scan is due, waking early
    whenever the settings change or any scan (manual too) finishes, so the
    countdown always reflects the current settings. Any unexpected error is
    logged and the loop carries on, so automatic scans can't silently stop."""
    # (init_db() has already run -- app.py calls it before starting threads)
    try:
        cleanup_stale_temp_files()
    except Exception:
        traceback.print_exc()
    while True:
        try:
            _schedule_changed.clear()
            if get_auto_scan() and _subnet_job_pending():
                # a network scan is already waiting/running: count from its end
                _last_scan_status["next_run"] = None
                _last_scan_status["next_total"] = None
                _schedule_changed.wait()
                continue
            if not get_auto_scan():
                _last_scan_status["next_run"] = None
                _last_scan_status["next_total"] = None
                _schedule_changed.wait()
                continue
            interval = get_scan_interval()
            now = time.monotonic()
            # Next scan: one interval after the last scan ended, but never
            # sooner than the settle delay (boot, or just switched on).
            # Uses the monotonic clock: the Pi has no battery-backed clock and
            # its wall time jumps when it syncs after boot.
            soonest = now + FIRST_SCAN_DELAY_SECONDS
            if _last_scan_end is not None and _last_scan_end + interval >= soonest:
                target, since = _last_scan_end + interval, _last_scan_end
            else:
                target, since = soonest, now
            _last_scan_status["next_run"] = target
            _last_scan_status["next_total"] = int(round(target - since))  # for the kiosk progress bar
            if _schedule_changed.wait(max(0, target - now)):
                continue  # settings changed or a scan ended: recompute
            if get_auto_scan():
                _last_scan_status["next_run"] = None
                job, err = enqueue("subnet", source="auto")
                if err:
                    time.sleep(5)  # e.g. queue full: try again shortly
        except Exception:
            traceback.print_exc()
            time.sleep(5)


def next_scan_in():
    """Seconds until the next automatic scan, or None if not scheduled."""
    nr = _last_scan_status.get("next_run")
    if nr is None or _last_scan_status["running"]:
        return None
    return max(0, int(round(nr - time.monotonic())))
