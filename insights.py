"""
insights.py - makes sense of scan results, using only what the scans already
recorded (no extra probing):

  * classify_host()  -- a best guess at what kind of device a host is
  * host_flags()     -- exposure flags: services worth a follow-up
  * scan_changes()   -- what changed since the previous network scan
  * annotate()       -- adds all of the above to a scan from scanner.get_scan()
"""
import sqlite3

import scanner

# ---------------------------------------------------------------- device types

# key -> (short code shown in the hex badge, label)
TYPES = {
    "access":  ("ACC", "Access control"),
    "camera":  ("CAM", "Camera / video"),
    "printer": ("PRN", "Printer"),
    "phone":   ("TEL", "IP phone / voice"),
    "network": ("NET", "Network equipment"),
    "nas":     ("NAS", "Storage"),
    "windows": ("WIN", "Windows computer"),
    "apple":   ("MAC", "Apple device"),
    "linux":   ("LNX", "Linux / Unix host"),
    "pi":      ("RPI", "Raspberry Pi"),
    "iot":     ("IOT", "Smart / IoT device"),
    "vm":      ("VM",  "Virtual machine"),
    "unknown": ("?",   "Unknown device"),
}

# Vendor name fragments (from the MAC address) -> type. First match wins.
_VENDORS = [
    ("access", ["paxton", "hid global", "lenel", "honeywell security", "genetec", "axis access",
                "salto", "brivo", "gallagher", "avigilon alta", "openpath"]),
    ("camera", ["hikvision", "dahua", "axis communications", "hanwha", "vivotek", "uniview",
                "mobotix", "avigilon", "reolink", "amcrest", "bosch security"]),
    ("network", ["cisco", "ubiquiti", "aruba", "juniper", "netgear", "mikrotik", "fortinet",
                 "palo alto", "meraki", "ruckus", "extreme networks", "zyxel", "d-link", "tp-link",
                 "sonicwall", "watchguard", "hewlett packard enterprise", "routerboard", "edgecore", "allied telesis"]),
    ("printer", ["hewlett packard", "hp inc", "brother", "canon", "epson", "lexmark", "xerox",
                 "ricoh", "kyocera", "konica", "sharp", "zebra", "oki data"]),
    ("phone", ["polycom", "yealink", "avaya", "grandstream", "snom", "mitel", "poly ", "plantronics",
               "fanvil", "obihai"]),
    ("nas", ["synology", "qnap", "western digital", "buffalo", "asustor", "drobo"]),
    ("pi", ["raspberry"]),
    ("apple", ["apple"]),
    ("iot", ["espressif", "tuya", "shenzhen", "sonos", "amazon technologies", "google", "nest",
             "philips lighting", "signify", "roku", "lifx", "ecobee", "wiz", "belkin"]),
    ("vm", ["vmware", "xensource", "parallels", "qemu", "virtualbox"]),
    ("windows", ["dell", "lenovo", "intel corporate", "microsoft", "asustek", "gigabyte",
                 "micro-star", "hon hai", "liteon", "azurewave", "intel"]),
]

# Hostname fragments -> type
_HOSTNAMES = [
    ("printer", ["printer", "prn", "mfp", "laserjet", "officejet", "copier"]),
    ("camera", ["cam", "nvr", "dvr", "ipcam"]),
    ("phone", ["phone", "sip", "voip"]),
    ("network", ["switch", "sw-", "router", "rtr", "fw-", "firewall", "ap-", "gateway", "gw-"]),
    ("nas", ["nas", "diskstation", "storage"]),
    ("windows", ["desktop-", "laptop-", "win-", "pc-"]),
    ("apple", ["macbook", "imac", "iphone", "ipad"]),
    ("pi", ["raspberrypi", "pi-"]),
]


def classify_host(host):
    """Returns {"type", "code", "label", "why"} -- a best guess from the MAC
    vendor, hostname, open ports and nmap's OS guess."""
    vendor = (host.get("vendor") or "").lower()
    hostname = (host.get("hostname") or "").lower()
    ports = {p["port"] for p in host.get("ports", []) if p.get("state") == "open"}
    services = " ".join((p.get("service") or "") + " " + (p.get("product") or "")
                        for p in host.get("ports", []) if p.get("state") == "open").lower()
    os_name = (host.get("os_name") or "").lower()
    os_type = (host.get("os_type") or "").lower()

    def result(t, why):
        code, label = TYPES[t]
        return {"type": t, "code": code, "label": label, "why": why}

    # Strong signals first: services that only one kind of device runs
    if ports & {9100, 515, 631} or "printer" in services or "ipp" in services or "jetdirect" in services:
        return result("printer", "printing ports open")
    if 554 in ports or "rtsp" in services:
        return result("camera", "video streaming (RTSP) port open")
    if 5060 in ports or 5061 in ports or "sip" in services.split():
        return result("phone", "SIP voice port open")
    for t, frags in _VENDORS[:6]:   # access, camera, network, printer, phone, nas
        for f in frags:
            if f in vendor:
                return result(t, f"vendor {host.get('vendor')}")
    if "printer" in os_type:
        return result("printer", "OS fingerprint")
    if any(k in os_type for k in ("switch", "router", "firewall", "wap", "broadband")):
        return result("network", "OS fingerprint")
    if "webcam" in os_type:
        return result("camera", "OS fingerprint")
    for t, frags in _HOSTNAMES:
        if any(f in hostname for f in frags):
            return result(t, f"hostname {host.get('hostname')}")
    if "windows" in os_name or ports & {135, 3389} or (445 in ports and 139 in ports):
        return result("windows", "Windows services / OS fingerprint")
    if any(k in os_name for k in ("mac os", "macos", "ios", "darwin")) or 548 in ports:
        return result("apple", "OS fingerprint")
    for t, frags in _VENDORS[6:]:   # pi, apple, iot, vm, windows-ish PC makers
        for f in frags:
            if f in vendor:
                return result(t, f"vendor {host.get('vendor')}")
    if "linux" in os_name or "unix" in os_name or ports == {22}:
        return result("linux", "SSH only / OS fingerprint")
    return result("unknown", "not enough information")


# ---------------------------------------------------------------- exposure flags

# Services worth a follow-up when found open. Matched by port number or by
# the service name nmap reported. Levels: high / medium / low.
_FLAG_RULES = [
    ("telnet", {23}, "high", "Telnet", "Unencrypted remote login -- credentials cross the network in clear text."),
    ("ftp", {21}, "medium", "FTP", "Unencrypted file transfer -- logins and files are sent in clear text."),
    ("ms-wbt-server", {3389}, "medium", "RDP", "Remote Desktop is reachable -- make sure it's meant to be and requires NLA."),
    ("vnc", {5900, 5901, 5902, 5903}, "medium", "VNC", "Remote screen access is reachable -- often weakly protected."),
    ("rlogin", {512, 513, 514}, "high", "r-services", "Legacy rsh/rlogin services -- no encryption, weak authentication."),
    ("tftp", {69}, "medium", "TFTP", "Trivial FTP has no authentication at all."),
    ("snmp", {161}, "low", "SNMP", "SNMP management is reachable -- check it isn't using default community strings."),
    ("microsoft-ds", {445}, "low", "SMB", "Windows file sharing is reachable on this host."),
    ("http", {80, 8080}, "low", "HTTP only", "Web interface without HTTPS -- logins to it aren't encrypted."),
]
LEVEL_ORDER = {"high": 0, "medium": 1, "low": 2}


def host_flags(host):
    """[{"key", "level", "label", "detail", "ports"}] for this host, worst first."""
    open_ports = [p for p in host.get("ports", []) if p.get("state") == "open"]
    nums = {p["port"] for p in open_ports}
    flags = []
    for svc, ports, level, label, detail in _FLAG_RULES:
        hit = sorted(p["port"] for p in open_ports
                     if p["port"] in ports or (p.get("service") or "").lower() == svc)
        if not hit:
            continue
        if label == "HTTP only" and nums & {443, 8443}:
            continue   # has an HTTPS interface too
        flags.append({"key": svc, "level": level, "label": label, "detail": detail, "ports": hit})
    flags.sort(key=lambda f: LEVEL_ORDER[f["level"]])
    return flags


# ---------------------------------------------------------------- changes

def _key(mac, ip):
    return ("mac", mac.lower()) if mac else ("ip", ip)


def _load(c, scan_id):
    """{key: {"ip", "mac", "vendor", "hostname", "open": {(proto, port)}}} for one scan."""
    hosts = {}
    for h in c.execute("SELECT id, ip, mac, vendor, hostname FROM hosts WHERE scan_id = ?", (scan_id,)).fetchall():
        open_ = {(r[0], r[1]) for r in c.execute(
            "SELECT protocol, port FROM ports WHERE host_id = ? AND state = 'open'", (h[0],))}
        hosts[_key(h[2], h[1])] = {"ip": h[1], "mac": h[2], "vendor": h[3], "hostname": h[4], "open": open_}
    return hosts


def _checked(row):
    chk = scanner._checked_set(row["ports_checked"])
    if chk is None and row["profile"] == "discovery":
        chk = set()
    return chk


def scan_changes(scan_id):
    """Differences between a network scan and the previous network scan of
    the same subnet, or None if there's nothing to compare with.
    {"previous": {id, finished_at, profile}, "new_hosts": [...], "missing_hosts": [...],
     "opened": [{ip, port, protocol}], "closed": [...], "ports_compared": bool, "count": n}"""
    conn = sqlite3.connect(scanner.DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    cur = c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not cur or (cur["scope"] or "subnet") != "subnet":
        conn.close()
        return None
    prev = c.execute("SELECT * FROM scans WHERE id < ? AND COALESCE(scope, 'subnet') = 'subnet' "
                     "AND subnet = ? ORDER BY id DESC LIMIT 1", (scan_id, cur["subnet"])).fetchone()
    if not prev:
        conn.close()
        return None
    a, b = _load(c, prev["id"]), _load(c, cur["id"])
    conn.close()

    def ident(h):
        return {"ip": h["ip"], "mac": h["mac"], "vendor": h["vendor"], "hostname": h["hostname"]}

    # match by MAC, then fall back to IP for hosts without a MAC in one scan
    by_ip_a = {h["ip"]: k for k, h in a.items()}
    matched = {}
    for k, h in b.items():
        if k in a:
            matched[k] = k
        elif h["ip"] in by_ip_a and (k[0] == "ip" or by_ip_a[h["ip"]][0] == "ip"):
            matched[k] = by_ip_a[h["ip"]]
    new_hosts = [ident(h) for k, h in b.items() if k not in matched]
    gone_keys = set(a) - set(matched.values())
    missing = [ident(a[k]) for k in gone_keys]

    # Ports: only where both scans actually looked at the port
    chk_a, chk_b = _checked(prev), _checked(cur)
    both = None
    if chk_a is not None and chk_b is not None:
        both = chk_a & chk_b
    elif prev["profile"] == cur["profile"] and cur["profile"] != "discovery":
        both = "all"   # older scans without the record: same profile = same ports
    opened, closed = [], []
    if both:
        for kb, ka in matched.items():
            pa, pb = a[ka]["open"], b[kb]["open"]
            for proto, port in sorted(pb - pa, key=lambda x: x[1]):
                if both == "all" or (proto, port) in both:
                    opened.append({"ip": b[kb]["ip"], "port": port, "protocol": proto})
            for proto, port in sorted(pa - pb, key=lambda x: x[1]):
                if both == "all" or (proto, port) in both:
                    closed.append({"ip": b[kb]["ip"], "port": port, "protocol": proto})

    ipkey = lambda h: tuple(int(x) for x in h["ip"].split("."))
    new_hosts.sort(key=ipkey)
    missing.sort(key=ipkey)
    return {
        "previous": {"id": prev["id"], "finished_at": prev["finished_at"], "profile": prev["profile"]},
        "new_hosts": new_hosts,
        "missing_hosts": missing,
        "opened": opened,
        "closed": closed,
        "ports_compared": bool(both),
        "count": len(new_hosts) + len(missing) + len(opened) + len(closed),
    }


_summary_cache = {}


def latest_changes_summary():
    """Counts for the latest network scan (cached per scan), for the Pi screen."""
    sid = scanner.latest_subnet_scan_id()
    if sid is None:
        return None
    if sid not in _summary_cache:
        ch = scan_changes(sid)
        _summary_cache.clear()
        _summary_cache[sid] = None if ch is None else {
            "scan_id": sid, "new": len(ch["new_hosts"]), "missing": len(ch["missing_hosts"]),
            "opened": len(ch["opened"]), "closed": len(ch["closed"]), "count": ch["count"]}
    return _summary_cache[sid]


# ---------------------------------------------------------------- all together

def annotate(scan):
    """Adds device type, flags and change markers to a scan from
    scanner.get_scan(). Returns the same dict."""
    if not scan:
        return scan
    ch = scan_changes(scan["id"])
    scan["changes"] = ch
    new_ips = {h["ip"] for h in (ch or {}).get("new_hosts", [])}
    opened = {(o["ip"], o["port"], o["protocol"]) for o in (ch or {}).get("opened", [])}
    counts = {"high": 0, "medium": 0, "low": 0}
    for h in scan.get("hosts", []):
        h["device"] = classify_host(h)
        h["flags"] = host_flags(h)
        for f in h["flags"]:
            counts[f["level"]] += 1
        h["is_new"] = h["ip"] in new_ips
        for p in h.get("ports", []):
            p["is_new"] = (h["ip"], p["port"], p["protocol"]) in opened
    scan["flag_counts"] = counts
    scan["flag_total"] = sum(counts.values())
    return scan
