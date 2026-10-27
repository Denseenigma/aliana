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
import re
import pty
import select

DB_PATH = os.path.join(os.path.dirname(__file__), "aliana.db")
SCAN_INTERFACE = os.environ.get("ALIANA_IFACE", "usb0")
SCAN_INTERVAL_SECONDS = int(os.environ.get("ALIANA_SCAN_INTERVAL", "300"))  # 5 min default
# Wait this long after startup before the first automatic scan, so the Pi
# (and its network links) can settle after boot
FIRST_SCAN_DELAY_SECONDS = int(os.environ.get("ALIANA_FIRST_SCAN_DELAY", "60"))

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
        "args": ["-sV", "--version-light", "-T3", "--top-ports", "100",
                 "--max-rate", "300", "--host-timeout", "5m"],
        "timeout": 1200,
    },
    "deep": {
        "label": "Deep",
        "description": "Top 1000 TCP ports with full version detection. Much more "
                       "traffic and probing -- run deliberately, not on fragile/OT networks.",
        "short": "Top 1000 ports, full version probing",
        "args": ["-sV", "-T3", "--top-ports", "1000",
                 "--max-rate", "300", "--host-timeout", "15m"],
        "timeout": 3600,
    },
}
DEFAULT_PROFILE = "standard"

_scan_lock = threading.Lock()
_stop_requested = threading.Event()


class ScanStopped(Exception):
    pass
_last_scan_status = {"running": False, "last_run": None, "last_error": None, "next_run": None}

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
    discovering = _progress["phase"] in ("Starting", "Discovering hosts")
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


def run_scan(subnet=None, profile=None):
    """Runs an nmap scan against the subnet using a scan profile (default: the
    saved one) and stores results. Returns scan_id or None."""
    if not _scan_lock.acquire(blocking=False):
        return None  # a scan is already running

    try:
        _stop_requested.clear()
        _last_scan_status["running"] = True
        if subnet is None:
            subnet = get_local_subnet(get_current_interface())
        if not subnet:
            _last_scan_status["last_error"] = "No subnet detected to scan."
            return None
        profile = profile if profile in PROFILES else get_profile()
        _reset_progress(subnet)
        _progress["profile"] = profile

        started = datetime.datetime.now().isoformat()
        # Unique filename per scan (pid + uuid) so a leftover file from a
        # previous run -- possibly owned by a different user, e.g. a manual
        # sudo run vs. the systemd service -- can never collide with this one.
        xml_path = os.path.join(
            tempfile.gettempdir(), f"aliana_scan_{os.getpid()}_{uuid.uuid4().hex}.xml"
        )

        # The profile decides what gets scanned and how hard (see PROFILES).
        # -v and --stats-every make nmap report progress as it goes (hosts
        # found, ports discovered, % done), which the kiosk screen shows live.
        p = PROFILES[profile]
        cmd = ["nmap"] + p["args"] + ["-v", "--stats-every", "2s", "-oX", xml_path, subnet]

        timeout = p["timeout"]
        _run_nmap_live(cmd, timeout=timeout)

        hosts = _parse_nmap_xml(xml_path)
        finished = datetime.datetime.now().isoformat()

        scan_id = _store_results(subnet, started, finished, hosts, profile)

        _last_scan_status["last_run"] = finished
        _last_scan_status["last_error"] = None
        return scan_id

    except ScanStopped:
        # Stopped by the user: nothing to save, and not an error
        _last_scan_status["last_error"] = None
        return None
    except subprocess.TimeoutExpired:
        _last_scan_status["last_error"] = f"nmap timed out after {timeout // 60} minutes."
        return None
    except Exception as e:
        _last_scan_status["last_error"] = str(e)
        return None
    finally:
        # Always clean up the temp file, win or lose, so nothing stale is
        # left behind to cause ownership conflicts on the next run.
        try:
            if 'xml_path' in locals() and os.path.exists(xml_path):
                os.remove(xml_path)
        except Exception:
            pass
        _last_scan_status["running"] = False
        _scan_lock.release()


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
            })

    return hosts


def _store_results(subnet, started, finished, hosts, profile=None):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO scans (started_at, finished_at, subnet, host_count, profile) VALUES (?, ?, ?, ?, ?)",
        (started, finished, subnet, len(hosts), profile),
    )
    scan_id = c.lastrowid

    for h in hosts:
        c.execute(
            "INSERT INTO hosts (scan_id, ip, mac, vendor, hostname, status) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, h["ip"], h["mac"], h["vendor"], h["hostname"], h["status"]),
        )
        host_id = c.lastrowid
        for p in h["ports"]:
            c.execute(
                "INSERT INTO ports (host_id, port, protocol, state, service, product, version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (host_id, p["port"], p["protocol"], p["state"], p["service"], p["product"], p["version"]),
            )

    conn.commit()
    conn.close()
    return scan_id


def get_latest_scan():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
    scan = c.fetchone()
    if not scan:
        conn.close()
        return None

    c.execute("SELECT * FROM hosts WHERE scan_id = ?", (scan["id"],))
    hosts = []
    for h in c.fetchall():
        c.execute("SELECT * FROM ports WHERE host_id = ? ORDER BY port", (h["id"],))
        ports = [dict(p) for p in c.fetchall()]
        host = dict(h)
        host["ports"] = ports
        hosts.append(host)

    conn.close()
    result = dict(scan)
    result["hosts"] = hosts
    return result


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
    c.execute("SELECT id, finished_at, subnet, host_count, profile FROM scans ORDER BY id DESC LIMIT 1")
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
    """Runs forever, scanning on an interval. Call in a daemon thread."""
    init_db()
    cleanup_stale_temp_files()
    _schedule_next(FIRST_SCAN_DELAY_SECONDS)
    while True:
        run_scan()
        _schedule_next(SCAN_INTERVAL_SECONDS)


def _schedule_next(seconds):
    """Sleeps until the next automatic scan, publishing when it will be."""
    _last_scan_status["next_run"] = time.time() + seconds
    _last_scan_status["next_total"] = seconds
    time.sleep(seconds)
