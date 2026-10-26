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

DB_PATH = os.path.join(os.path.dirname(__file__), "aliana.db")
SCAN_INTERFACE = os.environ.get("ALIANA_IFACE", "usb0")
SCAN_INTERVAL_SECONDS = int(os.environ.get("ALIANA_SCAN_INTERVAL", "300"))  # 5 min default

_scan_lock = threading.Lock()
_last_scan_status = {"running": False, "last_run": None, "last_error": None}


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


def run_scan(subnet=None, fast=True):
    """Runs an nmap scan against the subnet and stores results. Returns scan_id or None."""
    if not _scan_lock.acquire(blocking=False):
        return None  # a scan is already running

    try:
        _last_scan_status["running"] = True
        if subnet is None:
            subnet = get_local_subnet(get_current_interface())
        if not subnet:
            _last_scan_status["last_error"] = "No subnet detected to scan."
            return None

        started = datetime.datetime.now().isoformat()
        # Unique filename per scan (pid + uuid) so a leftover file from a
        # previous run -- possibly owned by a different user, e.g. a manual
        # sudo run vs. the systemd service -- can never collide with this one.
        xml_path = os.path.join(
            tempfile.gettempdir(), f"aliana_scan_{os.getpid()}_{uuid.uuid4().hex}.xml"
        )

        # -sV: version detection, -T4: faster timing, -oX: xml output
        # fast=True keeps it to a light port set so it finishes quickly on a /24
        cmd = ["nmap", "-sV", "-T4", "-oX", xml_path]
        if fast:
            cmd += ["--top-ports", "100"]
        cmd.append(subnet)

        subprocess.run(cmd, check=True, capture_output=True, timeout=600)

        hosts = _parse_nmap_xml(xml_path)
        finished = datetime.datetime.now().isoformat()

        scan_id = _store_results(subnet, started, finished, hosts)

        _last_scan_status["last_run"] = finished
        _last_scan_status["last_error"] = None
        return scan_id

    except subprocess.CalledProcessError as e:
        _last_scan_status["last_error"] = f"nmap failed: {e.stderr.decode(errors='ignore')[:300]}"
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

        if addr_ipv4:
            hosts.append({
                "ip": addr_ipv4,
                "mac": mac,
                "vendor": vendor,
                "hostname": hostname,
                "status": status,
                "ports": ports,
            })

    return hosts


def _store_results(subnet, started, finished, hosts):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO scans (started_at, finished_at, subnet, host_count) VALUES (?, ?, ?, ?)",
        (started, finished, subnet, len(hosts)),
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
    return status


def background_loop():
    """Runs forever, scanning on an interval. Call in a daemon thread."""
    init_db()
    cleanup_stale_temp_files()
    while True:
        run_scan()
        time.sleep(SCAN_INTERVAL_SECONDS)
