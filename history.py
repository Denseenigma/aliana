"""
history.py - Aliana's long-term memory of a network.

Every scan is kept. Exports can be imported back (on this unit or another),
so a network's history builds up over days, weeks, units: scan Monday,
export, scan Friday somewhere else, import Monday's file -- one timeline.

Devices are identified by **MAC address** (IP addresses change with DHCP).
Hosts seen without a MAC (the Aliana unit itself, or hosts behind a router)
can't be tracked across scans and are only counted.

  export_bundle(scan_ids=None)  -> dict  (all scans when scan_ids is None)
  import_bundle(data)           -> summary dict
  list_devices()                -> one row per MAC
  device_history(mac)           -> one device's timeline
"""
import datetime
import hashlib
import ipaddress
import re
import socket
import sqlite3
import uuid

import identify
import scanner

FORMAT = "aliana-history"
VERSION = 1
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def norm_mac(mac):
    """'aa-bb-cc-dd-ee-ff' / 'AABBCCDDEEFF' -> 'AA:BB:CC:DD:EE:FF' (or None)."""
    if not mac:
        return None
    hexes = re.sub(r"[^0-9A-Fa-f]", "", str(mac))
    if len(hexes) != 12:
        return None
    return ":".join(hexes[i:i + 2] for i in range(0, 12, 2)).upper()


def _db():
    conn = sqlite3.connect(scanner.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ipkey(ip):
    try:
        return int(ipaddress.IPv4Address(ip))
    except ValueError:
        return 0


# ---------------------------------------------------------------- export

def export_bundle(scan_ids=None):
    """The importable export format: {"format", "version", "exported_at",
    "node", "scans": [ {scan fields..., "hosts": [ {..., "ports": [...]} ]} ]}.
    scan_ids=None exports every scan (the whole history), oldest first."""
    conn = _db()
    c = conn.cursor()
    if scan_ids is None:
        rows = c.execute("SELECT * FROM scans ORDER BY finished_at, id").fetchall()
    else:
        q = ",".join("?" * len(scan_ids))
        rows = c.execute(f"SELECT * FROM scans WHERE id IN ({q}) ORDER BY finished_at, id", list(scan_ids)).fetchall()
    scans = []
    for s in rows:
        hosts = []
        for h in c.execute("SELECT * FROM hosts WHERE scan_id = ? ORDER BY id", (s["id"],)).fetchall():
            ports = [{k: p[k] for k in ("port", "protocol", "state", "service", "product", "version", "probe")}
                     for p in c.execute("SELECT * FROM ports WHERE host_id = ? ORDER BY port", (h["id"],))]
            hosts.append({**{k: h[k] for k in ("ip", "mac", "vendor", "hostname", "status",
                                               "os_name", "os_accuracy", "os_type")},
                          "ident": scanner._ident(h["ident"]) or None, "ports": ports})
        scans.append({**{k: s[k] for k in ("uid", "started_at", "finished_at", "subnet", "profile", "mode",
                                          "scope", "ports_checked", "source", "node")},
                      "host_count": len(hosts), "hosts": hosts})
    conn.close()
    return {"format": FORMAT, "version": VERSION, "exported_at": datetime.datetime.now().isoformat(),
            "node": socket.gethostname(), "scans": scans}


# ---------------------------------------------------------------- import

class ImportFailed(ValueError):
    pass


def _s(v, n=255):
    """Clean optional string from untrusted input."""
    if v is None:
        return None
    v = str(v).strip()
    return v[:n] if v else None


def _time(v):
    v = _s(v, 40)
    if not v:
        return None
    try:
        datetime.datetime.fromisoformat(v)
    except ValueError:
        return None
    return v


def _scans_from(data):
    """Accepts the export format, a list of scans, or a single scan dict (e.g.
    an older per-scan JSON export from the dashboard)."""
    if isinstance(data, dict) and isinstance(data.get("scans"), list):
        return data["scans"], _s(data.get("node"), 64)
    if isinstance(data, list):
        return data, None
    if isinstance(data, dict) and isinstance(data.get("hosts"), list):
        return [data], None
    raise ImportFailed("Not an Aliana export (expected a file from Export / Export all history).")


def import_bundle(data, max_scans=5000):
    """Merges exported scans into this unit's history. Scans already here
    (same uid, or same subnet + start/finish times) are skipped. Returns
    {"scans_added", "scans_skipped", "hosts_added", "new_devices", "errors"}."""
    scans, node = _scans_from(data)
    if len(scans) > max_scans:
        raise ImportFailed(f"Too many scans in one file ({len(scans)}; limit {max_scans}).")
    conn = _db()
    known_macs = {r[0] for r in conn.execute("SELECT DISTINCT UPPER(mac) FROM hosts WHERE mac IS NOT NULL")}
    conn.close()
    added = skipped = hosts_added = 0
    new_macs, errors = set(), []
    conn = _db()
    c = conn.cursor()
    try:
        for i, s in enumerate(scans):
            if not isinstance(s, dict):
                errors.append(f"item {i + 1}: not a scan")
                continue
            finished, started = _time(s.get("finished_at")), _time(s.get("started_at"))
            subnet = _s(s.get("subnet"), 64)
            if not finished or not subnet or not isinstance(s.get("hosts"), list):
                errors.append(f"item {i + 1}: missing finished_at / subnet / hosts")
                continue
            uid = _s(s.get("uid"), 64)
            if not uid:   # older exports: derive a stable id so re-imports still dedupe
                uid = hashlib.sha1(f"{subnet}|{started}|{finished}".encode()).hexdigest()
            dup = c.execute("SELECT 1 FROM scans WHERE uid = ? OR (subnet = ? AND finished_at = ? "
                            "AND COALESCE(started_at, '') = COALESCE(?, ''))",
                            (uid, subnet, finished, started)).fetchone()
            if dup:
                skipped += 1
                continue
            profile = s.get("profile") if s.get("profile") in scanner.PROFILES else None
            scope = s.get("scope") if s.get("scope") in ("subnet", "host") else "subnet"
            mode = s.get("mode") if s.get("mode") in ("syn", "connect") else None
            c.execute("INSERT INTO scans (started_at, finished_at, subnet, host_count, profile, mode, ports_checked, "
                      "scope, uid, source, node) VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, 'import', ?)",
                      (started, finished, subnet, profile, mode, _s(s.get("ports_checked"), 20000), scope, uid,
                       _s(s.get("node"), 64) or node))
            scan_id = c.lastrowid
            n = 0
            for h in s["hosts"]:
                if not isinstance(h, dict):
                    continue
                try:
                    ip = str(ipaddress.IPv4Address(str(h.get("ip", "")).strip()))
                except ValueError:
                    continue
                mac = norm_mac(h.get("mac"))
                try:
                    acc = int(h["os_accuracy"]) if h.get("os_accuracy") not in (None, "") else None
                except (TypeError, ValueError):
                    acc = None
                ident = identify.ident_json(h["ident"]) if isinstance(h.get("ident"), dict) else None
                c.execute("INSERT INTO hosts (scan_id, ip, mac, vendor, hostname, status, os_name, os_accuracy, os_type, "
                          "ident) VALUES (?, ?, ?, ?, ?, 'up', ?, ?, ?, ?)",
                          (scan_id, ip, mac, _s(h.get("vendor"), 128), _s(h.get("hostname"), 255),
                           _s(h.get("os_name"), 255), acc, _s(h.get("os_type"), 64), ident))
                host_id = c.lastrowid
                n += 1
                if mac and mac not in known_macs:
                    new_macs.add(mac)
                for p in h.get("ports") or []:
                    if not isinstance(p, dict):
                        continue
                    try:
                        port = int(p.get("port"))
                    except (TypeError, ValueError):
                        continue
                    proto = p.get("protocol") if p.get("protocol") in ("tcp", "udp") else "tcp"
                    if not 0 < port < 65536:
                        continue
                    c.execute("INSERT INTO ports (host_id, port, protocol, state, service, product, version, probe) "
                              "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                              (host_id, port, proto, _s(p.get("state"), 20) or "open", _s(p.get("service"), 64),
                               _s(p.get("product"), 128), _s(p.get("version"), 128),
                               p.get("probe") if p.get("probe") in ("skipped", "timeout") else None))
            c.execute("UPDATE scans SET host_count = ? WHERE id = ?", (n, scan_id))
            added += 1
            hosts_added += n
        conn.commit()
    finally:
        conn.close()
    return {"scans_added": added, "scans_skipped": skipped, "hosts_added": hosts_added,
            "new_devices": len(new_macs), "errors": errors[:20]}


# ---------------------------------------------------------------- inventory

def _sightings(mac=None):
    """All host rows (optionally for one MAC) joined with their scan, oldest first."""
    conn = _db()
    sql = ("SELECT h.id AS host_id, h.ip, UPPER(h.mac) AS mac, h.vendor, h.hostname, h.os_name, h.os_accuracy, "
           "h.os_type, h.ident, s.id AS scan_id, s.finished_at, s.subnet, s.profile, s.scope, s.ports_checked, s.source, s.node "
           "FROM hosts h JOIN scans s ON s.id = h.scan_id WHERE h.mac IS NOT NULL")
    args = ()
    if mac:
        sql += " AND UPPER(h.mac) = ?"
        args = (mac,)
    rows = [dict(r) for r in conn.execute(sql + " ORDER BY s.finished_at, s.id", args)]
    if rows:
        ids = [r["host_id"] for r in rows]
        ports = {}
        for i in range(0, len(ids), 900):
            chunk = ids[i:i + 900]
            q = ",".join("?" * len(chunk))
            for p in conn.execute(f"SELECT host_id, port, protocol, state, service, product, version, probe "
                                  f"FROM ports WHERE host_id IN ({q}) ORDER BY port", chunk):
                ports.setdefault(p["host_id"], []).append(dict(p))
        for r in rows:
            r["ports"] = ports.get(r["host_id"], [])
            r["ident"] = scanner._ident(r.get("ident"))
    conn.close()
    return rows


def _latest_network_times():
    """subnet -> finished_at of its latest network scan."""
    conn = _db()
    out = {r[0]: r[1] for r in conn.execute(
        "SELECT subnet, MAX(finished_at) FROM scans WHERE COALESCE(scope, 'subnet') = 'subnet' GROUP BY subnet")}
    conn.close()
    return out


def _summarise(mac, rows, latest_times):
    import insights
    last = rows[-1]
    # Most recent sighting that actually looked at ports
    port_rows = [r for r in rows if r["profile"] != "discovery"]
    latest_ports = port_rows[-1]["ports"] if port_rows else []
    ident = next((r["ident"] for r in reversed(rows) if r.get("ident") and r["ident"].get("sources")), None) \
        or next((r["ident"] for r in reversed(rows) if r.get("ident")), {})
    vendor = next((r["vendor"] for r in reversed(rows) if r["vendor"]), None) or ident.get("vendor_db") \
        or identify.vendor_for(mac)
    hostname = next((r["hostname"] for r in reversed(rows) if r["hostname"]), None) or ident.get("name")
    os_row = next((r for r in reversed(rows) if r["os_name"]), None)
    ips, hostnames, networks = {}, {}, set()
    for r in rows:
        ips[r["ip"]] = r["finished_at"]
        if r["hostname"]:
            hostnames[r["hostname"]] = r["finished_at"]
        if r["scope"] != "host":
            networks.add(r["subnet"])
    host_like = {"mac": mac, "ip": last["ip"], "vendor": vendor, "hostname": hostname, "ports": latest_ports,
                 "ident": ident,
                 "os_name": os_row["os_name"] if os_row else None,
                 "os_type": os_row["os_type"] if os_row else None}
    present = any(r["finished_at"] == latest_times.get(r["subnet"]) for r in rows if r["scope"] != "host")
    return {
        "mac": mac,
        "vendor": vendor,
        "hostname": hostname,
        "ip": last["ip"],
        "ips": sorted(ips, key=lambda ip: ips[ip], reverse=True),
        "hostnames": sorted(hostnames, key=lambda n: hostnames[n], reverse=True),
        "networks": sorted(networks),
        "first_seen": rows[0]["finished_at"],
        "last_seen": last["finished_at"],
        "sightings": len({r["scan_id"] for r in rows}),
        "present": present,
        "open_ports": sorted({(p["port"], p["protocol"]) for p in latest_ports if p["state"] == "open"}),
        "os_name": host_like["os_name"],
        "ident": ident,
        "device": insights.classify_host(host_like),
        "flags": insights.host_flags(host_like),
        "_host": host_like,
    }


def list_devices():
    """One entry per MAC address ever seen, most recently seen first, plus
    how many host sightings had no MAC (not trackable)."""
    rows = _sightings()
    by_mac = {}
    for r in rows:
        by_mac.setdefault(r["mac"], []).append(r)
    latest = _latest_network_times()
    devices = [_summarise(m, rs, latest) for m, rs in by_mac.items()]
    devices.sort(key=lambda d: (not d["present"], d["last_seen"] and -_ts(d["last_seen"]), _ipkey(d["ip"])))
    conn = _db()
    no_mac = conn.execute("SELECT COUNT(DISTINCT ip) FROM hosts WHERE mac IS NULL").fetchone()[0]
    span = conn.execute("SELECT MIN(finished_at), MAX(finished_at), COUNT(*), "
                        "SUM(CASE WHEN source = 'import' THEN 1 ELSE 0 END) FROM scans").fetchone()
    conn.close()
    return {"devices": devices, "untracked_ips": no_mac,
            "scans": {"first": span[0], "last": span[1], "count": span[2], "imported": span[3] or 0}}


def _ts(iso):
    try:
        return datetime.datetime.fromisoformat(iso).timestamp()
    except (TypeError, ValueError):
        return 0


def device_history(mac):
    """Summary + timeline for one MAC: every sighting (time, network, IP,
    hostname, open ports) and the port changes between port-checking scans."""
    mac = norm_mac(mac)
    if not mac:
        return None
    rows = _sightings(mac)
    if not rows:
        return None
    summary = _summarise(mac, rows, _latest_network_times())
    timeline, prev = [], None
    for r in rows:
        open_ = {(p["port"], p["protocol"]) for p in r["ports"] if p["state"] == "open"}
        checked = None if r["profile"] == "discovery" else scanner._checked_set(r["ports_checked"])
        entry = {"scan_id": r["scan_id"], "finished_at": r["finished_at"], "subnet": r["subnet"],
                 "profile": r["profile"], "scope": r["scope"], "source": r["source"], "node": r["node"],
                 "ip": r["ip"], "hostname": r["hostname"], "os_name": r["os_name"],
                 "ports": [p for p in r["ports"] if p["state"] == "open"],
                 "port_check": r["profile"] != "discovery", "opened": [], "closed": [],
                 "ip_changed": bool(timeline) and timeline[-1]["ip"] != r["ip"]}
        if r["profile"] != "discovery":
            if prev is not None:
                both = None if (checked is None or prev["checked"] is None) else checked & prev["checked"]
                entry["opened"] = sorted(p for p in open_ - prev["open"] if both is None or p in both)
                entry["closed"] = sorted(p for p in prev["open"] - open_ if both is None or p in both)
            prev = {"open": open_, "checked": checked}
        timeline.append(entry)
    timeline.reverse()   # newest first
    return {"device": summary, "timeline": timeline}
