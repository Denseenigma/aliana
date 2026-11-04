"""
passive.py - passive discovery: Aliana listens to what devices announce
about themselves and never sends anything.

Heard on the local network segment (broadcast / multicast traffic, so the Pi
must be on the same Wi-Fi or switch as the devices -- over the USB-C gadget
link it only hears the laptop at the other end):

  DHCP     a device asking for an address: its hostname (option 12 / 81),
           vendor class (60, e.g. "MSFT 5.0", "android-dhcp-14"), and the
           list of options it asks for (55), which hints at the OS.
           Replies also tell us the DHCP server, router, DNS and domain.
  ARP      every device that talks on the network: MAC <-> IP.
  mDNS     Bonjour announcements: names, services, model TXT records.
  SSDP     UPnP NOTIFY announcements: server string, device type.
  NetBIOS  Windows name registrations / refreshes.
  LLDP     the switch announcing itself: switch name, port, VLAN.

Needs the CAP_NET_RAW capability (aliana.service grants it; run setup.sh
after pulling). Without it, passive discovery shows as unavailable and
everything else works as before.

Heard devices are kept in aliana.db (table passive_devices), flushed every
30 seconds, so the SD card isn't written on every packet.
"""
import ctypes
import datetime
import json
import os
import socket
import sqlite3
import struct
import threading
import time

ETH_P_ALL = 0x0003
SO_ATTACH_FILTER = 26
PACKET_OUTGOING = 4
FLUSH_SECONDS = 30
MAX_DEVICES = 5000           # memory cap; oldest are dropped from memory first

_lock = threading.RLock()
_devices = {}                # mac -> record (see _rec)
_dirty = set()
_network = {}                # what the DHCP server / switch told us
_state = {"running": False, "error": None, "started": None, "frames": 0, "parsed": 0,
          "last_frame": None, "by_kind": {}}
_stop = threading.Event()
_thread = None
_own_macs = set()


# ---------------------------------------------------------------- kernel packet filter
#
# Classic BPF, attached to the socket so the kernel only hands Python the
# frames we parse (scans can generate thousands of frames a second):
#   ARP, LLDP, and UDP (not fragmented) to ports 67, 68, 137, 1900, 5353.

def _bpf_program():
    LDH_ABS, LDB_ABS, LDXB_MSH, LDH_IND = 0x28, 0x30, 0xB1, 0x48
    JEQ, JSET, RET = 0x15, 0x45, 0x06
    ins = [
        (LDH_ABS, 0, 0, 12),           # 0  ethertype
        (JEQ, 15, 0, 0x0806),          # 1  ARP -> accept
        (JEQ, 14, 0, 0x88CC),          # 2  LLDP -> accept
        (JEQ, 0, 14, 0x0800),          # 3  not IPv4 -> drop
        (LDB_ABS, 0, 0, 23),           # 4  IP protocol
        (JEQ, 0, 12, 17),              # 5  not UDP -> drop
        (LDH_ABS, 0, 0, 20),           # 6  flags + fragment offset
        (JSET, 10, 0, 0x1FFF),         # 7  fragment -> drop
        (LDXB_MSH, 0, 0, 14),          # 8  X = IP header length
        (LDH_IND, 0, 0, 16),           # 9  UDP destination port
        (JEQ, 6, 0, 67),               # 10 DHCP server port
        (JEQ, 5, 0, 68),               # 11 DHCP client port
        (JEQ, 4, 0, 137),              # 12 NetBIOS name service
        (JEQ, 3, 0, 1900),             # 13 SSDP
        (JEQ, 2, 0, 5353),             # 14 mDNS
        (RET, 0, 0, 0),                # 15 drop
        (RET, 0, 0, 0),                # 16 (unused)
        (RET, 0, 0, 0x0000FFFF),       # 17 accept
        (RET, 0, 0, 0),                # 18 drop
    ]
    return ins


def _attach_filter(sock):
    ins = _bpf_program()
    buf = ctypes.create_string_buffer(b"".join(struct.pack("HBBI", *i) for i in ins))
    prog = struct.pack("HP", len(ins), ctypes.addressof(buf))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, prog)
    return buf   # keep alive while attached


# ---------------------------------------------------------------- helpers

def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def _mac(b):
    return ":".join("%02X" % x for x in b[:6])


def _clean(s, n=80):
    if s is None:
        return None
    if isinstance(s, bytes):
        s = s.decode("utf-8", "replace")
    s = "".join(ch for ch in s if ch.isprintable()).strip().strip("\x00")
    return s[:n] or None


def _skip_mac(mac):
    if mac in _own_macs or mac == "00:00:00:00:00:00" or mac == "FF:FF:FF:FF:FF:FF":
        return True
    return int(mac[:2], 16) & 1 == 1      # multicast source: never a device


def _rec(mac, iface):
    r = _devices.get(mac)
    if r is None:
        if len(_devices) >= MAX_DEVICES:
            oldest = min(_devices, key=lambda m: _devices[m]["last_seen"])
            _devices.pop(oldest, None)
        r = _devices[mac] = {"mac": mac, "ip": None, "first_seen": _now(), "last_seen": _now(),
                             "iface": iface, "info": {}}
    r["last_seen"] = _now()
    r["iface"] = iface or r["iface"]
    _dirty.add(mac)
    return r


def _set_ip(r, ip, how):
    if not ip or ip in ("0.0.0.0", "255.255.255.255") or ip.startswith(("169.254.", "127.")):
        return
    r["ip"] = ip
    ips = r["info"].setdefault("ips", {})
    ips[ip] = _now()
    if len(ips) > 8:
        for old in sorted(ips, key=ips.get)[:-8]:
            ips.pop(old, None)
    r["info"]["ip_source"] = how


def _count(kind):
    _state["by_kind"][kind] = _state["by_kind"].get(kind, 0) + 1


# ---------------------------------------------------------------- parsers

_DHCP_MSG = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE", 5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}


def _dhcp_options(data):
    opts, i = {}, 240
    if data[236:240] != b"\x63\x82\x53\x63":
        return None
    while i < len(data):
        code = data[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= len(data):
            break
        ln = data[i + 1]
        opts[code] = data[i + 2:i + 2 + ln]
        i += 2 + ln
    return opts


def _ip4(b):
    return socket.inet_ntoa(b) if b and len(b) >= 4 else None


def _parse_dhcp(payload, src_mac, iface):
    if len(payload) < 240:
        return
    op = payload[0]
    chaddr = _mac(payload[28:34])
    opts = _dhcp_options(payload)
    if opts is None:
        return
    msg = _DHCP_MSG.get((opts.get(53) or b"\x00")[0])
    if op == 1:                                   # client -> server
        if _skip_mac(chaddr):
            return
        _count("dhcp")
        r = _rec(chaddr, iface)
        d = r["info"].setdefault("dhcp", {})
        if 12 in opts:
            d["hostname"] = _clean(opts[12], 64)
        if 81 in opts and len(opts[81]) > 3:
            fq = opts[81][3:]
            if opts[81][0] & 0x04:                  # E flag: DNS wire format
                try:
                    import identify
                    fq = identify._read_name(fq, 0)[0]
                except Exception:
                    fq = None
            d["fqdn"] = _clean(fq, 120)
        if 60 in opts:
            d["vendor_class"] = _clean(opts[60], 120)
        if 55 in opts:
            d["params"] = ",".join(str(x) for x in opts[55])
        if 61 in opts and len(opts[61]) > 1 and opts[61][0] != 1:
            d["client_id"] = _clean(opts[61][1:], 60)
        if 77 in opts:
            d["user_class"] = _clean(opts[77], 60)
        d["msg"] = msg
        d["at"] = _now()
        _set_ip(r, _ip4(opts.get(50)) or _ip4(payload[12:16]), "dhcp")
    elif op == 2 and msg in ("ACK", "OFFER"):     # server -> client
        _count("dhcp")
        yiaddr = _ip4(payload[16:20])
        if msg == "ACK" and not _skip_mac(chaddr) and chaddr in _devices:
            _set_ip(_devices[chaddr], yiaddr, "dhcp")
            _dirty.add(chaddr)
        net = _network.setdefault("dhcp", {})
        net.update({k: v for k, v in {
            "server": _ip4(opts.get(54)), "server_mac": src_mac,
            "router": _ip4(opts.get(3)),
            "mask": _ip4(opts.get(1)),
            "dns": [socket.inet_ntoa(opts[6][i:i + 4]) for i in range(0, len(opts.get(6, b"")) // 4 * 4, 4)] or None,
            "domain": _clean(opts.get(15), 80),
            "lease_s": struct.unpack(">I", opts[51])[0] if len(opts.get(51, b"")) == 4 else None,
            "iface": iface}.items() if v})
        net["at"] = _now()


def _parse_arp(frame, iface):
    if len(frame) < 42:
        return
    htype, ptype, hlen, plen, op = struct.unpack(">HHBBH", frame[14:22])
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
        return
    smac = _mac(frame[22:28])
    sip = socket.inet_ntoa(frame[28:32])
    if _skip_mac(smac):
        return
    _count("arp")
    r = _rec(smac, iface)
    a = r["info"].setdefault("arp", {})
    a["at"] = _now()
    a["n"] = a.get("n", 0) + 1
    _set_ip(r, sip, "arp")


def _parse_mdns(payload, src_mac, src_ip, iface):
    try:
        import identify
        if len(payload) < 12 or not (struct.unpack(">H", payload[2:4])[0] & 0x8000):
            return                                 # queries: not about the sender
        recs = identify._parse_dns(payload)
    except Exception:
        return
    if not recs or _skip_mac(src_mac):
        return
    _count("mdns")
    r = _rec(src_mac, iface)
    m = r["info"].setdefault("mdns", {})
    names, services, txt = set(m.get("names") or []), set(m.get("services") or []), dict(m.get("txt") or {})
    for name, rtype, val in recs:
        if rtype == 1 and name.lower().endswith(".local"):
            names.add(name[:-6])
            if val == src_ip:
                _set_ip(r, val, "mdns")
        elif rtype == 12 and val:
            if name.startswith("_services._dns-sd"):
                services.add(val.split(".")[0])
            elif "._tcp" in name or "._udp" in name:
                services.add(name.split(".")[0])
                if not val.startswith("_"):
                    inst = val.split("._")[0]
                    if inst:
                        m["instance"] = _clean(inst, 80)
            elif name.endswith(".in-addr.arpa") and val.lower().endswith(".local"):
                names.add(val[:-6])
        elif rtype == 16 and isinstance(val, list):
            for kv in val:
                k, _, v = kv.partition("=")
                if k in ("md", "model", "fn", "ty", "product", "usb_MFG", "usb_MDL", "am", "manufacturer", "rpMd", "osxvers") and v:
                    txt[k] = _clean(v, 80)
    m["names"] = sorted(names)[:6]
    m["services"] = sorted(services)[:20]
    if txt:
        m["txt"] = txt
    m["at"] = _now()


def _parse_ssdp(payload, src_mac, src_ip, iface):
    try:
        text = payload[:2048].decode("utf-8", "replace")
    except Exception:
        return
    first = text.split("\r\n", 1)[0].upper()
    if not first.startswith("NOTIFY") or _skip_mac(src_mac):
        return
    _count("ssdp")
    h = {}
    for line in text.split("\r\n")[1:]:
        k, _, v = line.partition(":")
        if v:
            h[k.strip().lower()] = v.strip()
    r = _rec(src_mac, iface)
    s = r["info"].setdefault("ssdp", {})
    if h.get("server"):
        s["server"] = _clean(h["server"], 120)
    if h.get("location"):
        s["location"] = _clean(h["location"], 160)
    nt = h.get("nt") or ""
    if "device:" in nt:
        s["device_type"] = _clean(nt, 120)
    s["at"] = _now()
    _set_ip(r, src_ip, "ssdp")


def _nb_decode(enc):
    if len(enc) != 32:
        return None
    try:
        raw = bytes(((enc[i] - 0x41) << 4) | (enc[i + 1] - 0x41) for i in range(0, 32, 2))
    except ValueError:
        return None
    return raw[:15].decode("ascii", "replace").strip(), raw[15]


def _parse_netbios(payload, src_mac, src_ip, iface):
    if len(payload) < 12 + 34:
        return
    flags = struct.unpack(">H", payload[2:4])[0]
    opcode = (flags >> 11) & 0xF
    if flags & 0x8000 or opcode not in (5, 8, 9):   # registration / refresh requests only
        return
    if payload[12] != 32 or _skip_mac(src_mac):
        return
    dec = _nb_decode(payload[13:45])
    if not dec:
        return
    name, suffix = dec
    if not name or name.startswith("\x01"):
        return
    _count("netbios")
    r = _rec(src_mac, iface)
    nb = r["info"].setdefault("netbios", {})
    is_group = False
    if len(payload) >= 68:          # additional record: pointer, type, class, ttl, rdlen, NB_FLAGS, addr
        is_group = bool(struct.unpack(">H", payload[62:64])[0] & 0x8000)
    if suffix == 0x00 and is_group:
        nb["group"] = _clean(name, 15)
    elif suffix in (0x00, 0x20) and not is_group:
        nb["name"] = _clean(name, 15)
    nb["at"] = _now()
    _set_ip(r, src_ip, "netbios")


def _parse_lldp(frame, src_mac, iface):
    i, info = 14, {}
    while i + 2 <= len(frame):
        hdr = struct.unpack(">H", frame[i:i + 2])[0]
        t, ln = hdr >> 9, hdr & 0x1FF
        v = frame[i + 2:i + 2 + ln]
        i += 2 + ln
        if t == 0:
            break
        if t == 2 and v:
            info["port_id"] = _clean(v[1:], 60) if v[0] in (1, 5, 7) else _mac(v[1:7]) if v[0] == 3 else None
        elif t == 4:
            info["port_desc"] = _clean(v, 80)
        elif t == 5:
            info["system_name"] = _clean(v, 80)
        elif t == 6:
            info["system_desc"] = _clean(v, 200)
        elif t == 8 and len(v) >= 6 and v[1] == 1:
            info["mgmt_ip"] = socket.inet_ntoa(v[2:6])
        elif t == 127 and len(v) >= 6 and v[:3] == b"\x00\x80\xc2" and v[3] == 1:
            info["vlan"] = struct.unpack(">H", v[4:6])[0]
    if not info:
        return
    _count("lldp")
    info.update({"switch_mac": src_mac, "iface": iface, "at": _now()})
    _network.setdefault("lldp", {})[iface] = {k: v for k, v in info.items() if v is not None}


def handle_frame(frame, iface, pkttype=0):
    """Parses one Ethernet frame (also used by the tests)."""
    if pkttype == PACKET_OUTGOING or len(frame) < 14:
        return
    _state["frames"] += 1
    _state["last_frame"] = _now()
    etype = struct.unpack(">H", frame[12:14])[0]
    src_mac = _mac(frame[6:12])
    with _lock:
        try:
            if etype == 0x0806:
                _parse_arp(frame, iface)
            elif etype == 0x88CC:
                _parse_lldp(frame, src_mac, iface)
            elif etype == 0x0800 and len(frame) >= 34:
                ihl = (frame[14] & 0x0F) * 4
                if frame[23] != 17 or len(frame) < 14 + ihl + 8:
                    return
                src_ip = socket.inet_ntoa(frame[26:30])
                u = 14 + ihl
                sport, dport = struct.unpack(">HH", frame[u:u + 4])
                payload = frame[u + 8:]
                if dport in (67, 68):
                    _parse_dhcp(payload, src_mac, iface)
                elif dport == 5353:
                    _parse_mdns(payload, src_mac, src_ip, iface)
                elif dport == 1900:
                    _parse_ssdp(payload, src_mac, src_ip, iface)
                elif dport == 137:
                    _parse_netbios(payload, src_mac, src_ip, iface)
                else:
                    return
            else:
                return
            _state["parsed"] += 1
        except Exception:      # a malformed packet must never stop the listener
            pass


# ---------------------------------------------------------------- storage

def _db_path():
    import scanner
    return scanner.DB_PATH


def init_db():
    conn = sqlite3.connect(_db_path())
    conn.execute("""CREATE TABLE IF NOT EXISTS passive_devices (
        mac TEXT PRIMARY KEY, ip TEXT, first_seen TEXT, last_seen TEXT, iface TEXT, info TEXT)""")
    conn.execute("CREATE TABLE IF NOT EXISTS passive_network (key TEXT PRIMARY KEY, value TEXT)")
    conn.commit()
    rows = conn.execute("SELECT mac, ip, first_seen, last_seen, iface, info FROM passive_devices "
                        "ORDER BY last_seen DESC LIMIT ?", (MAX_DEVICES,)).fetchall()
    net = conn.execute("SELECT key, value FROM passive_network").fetchall()
    conn.close()
    with _lock:
        for mac, ip, fs, ls, iface, info in rows:
            try:
                info = json.loads(info or "{}")
            except ValueError:
                info = {}
            _devices[mac] = {"mac": mac, "ip": ip, "first_seen": fs, "last_seen": ls, "iface": iface, "info": info}
        for k, v in net:
            try:
                _network[k] = json.loads(v)
            except ValueError:
                pass


def flush():
    with _lock:
        rows = [(r["mac"], r["ip"], r["first_seen"], r["last_seen"], r["iface"], json.dumps(r["info"]))
                for m in list(_dirty) if (r := _devices.get(m))]
        _dirty.clear()
        net = [(k, json.dumps(v)) for k, v in _network.items()]
    if not rows and not net:
        return
    try:
        conn = sqlite3.connect(_db_path(), timeout=10)
        conn.executemany("INSERT INTO passive_devices (mac, ip, first_seen, last_seen, iface, info) "
                         "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(mac) DO UPDATE SET ip = excluded.ip, "
                         "last_seen = excluded.last_seen, iface = excluded.iface, info = excluded.info", rows)
        conn.executemany("INSERT INTO passive_network (key, value) VALUES (?, ?) "
                         "ON CONFLICT(key) DO UPDATE SET value = excluded.value", net)
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print("aliana passive: couldn't save:", e, flush=True)


def forget_all():
    """Erase & reset (auth.py) clears the table; drop the in-memory copy too."""
    with _lock:
        _devices.clear()
        _dirty.clear()
        _network.clear()
        for k in ("frames", "parsed"):
            _state[k] = 0
        _state["by_kind"] = {}


# ---------------------------------------------------------------- the listener

def _load_own_macs():
    _own_macs.clear()
    try:
        for name in os.listdir("/sys/class/net"):
            try:
                with open(f"/sys/class/net/{name}/address") as f:
                    _own_macs.add(f.read().strip().upper())
            except OSError:
                pass
    except OSError:
        pass


def _listen():
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except PermissionError:
        _state["error"] = ("Needs permission to listen: run setup.sh on the Pi "
                           "(it gives the Aliana service the CAP_NET_RAW capability), then restart.")
        _state["running"] = False
        print("aliana passive:", _state["error"], flush=True)
        return
    except OSError as e:
        _state["error"] = f"Couldn't open a listening socket: {e}"
        _state["running"] = False
        return
    try:
        keep = _attach_filter(sock)   # noqa: F841 (must stay referenced)
    except OSError as e:
        print("aliana passive: kernel filter unavailable, filtering in Python:", e, flush=True)
    sock.settimeout(1.0)
    _state.update(running=True, error=None, started=_now())
    _load_own_macs()
    last_flush = last_macs = time.time()
    print("aliana passive: listening", flush=True)
    try:
        while not _stop.is_set():
            try:
                frame, addr = sock.recvfrom(4096)
                handle_frame(frame, addr[0], addr[2])
            except socket.timeout:
                pass
            except OSError as e:
                _state["error"] = f"Listener error: {e}"
                time.sleep(1)
            now = time.time()
            if now - last_flush >= FLUSH_SECONDS:
                flush()
                last_flush = now
            if now - last_macs >= 60:      # interfaces come and go (USB gadget, Wi-Fi)
                _load_own_macs()
                last_macs = now
    finally:
        sock.close()
        flush()
        _state["running"] = False


def start():
    global _thread
    if _thread and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_listen, name="aliana-passive", daemon=True)
    _thread.start()


def stop():
    _stop.set()
    if _thread:
        _thread.join(timeout=3)


# ---------------------------------------------------------------- what the rest of Aliana uses

def lookup(mac):
    """Everything heard from one MAC (a copy), or None."""
    if not mac:
        return None
    with _lock:
        r = _devices.get(mac.upper())
        return json.loads(json.dumps(r)) if r else None


def heard_devices():
    with _lock:
        return [json.loads(json.dumps(r)) for r in _devices.values()]


def network_info():
    with _lock:
        return json.loads(json.dumps(_network))


def status():
    with _lock:
        now = time.time()

        def recent(r, secs):
            try:
                return now - datetime.datetime.fromisoformat(r["last_seen"]).timestamp() <= secs
            except (TypeError, ValueError):
                return False
        devs = list(_devices.values())
        return {"running": _state["running"], "error": _state["error"], "started": _state["started"],
                "frames": _state["frames"], "parsed": _state["parsed"], "last_frame": _state["last_frame"],
                "by_kind": dict(_state["by_kind"]), "devices": len(devs),
                "last_hour": sum(1 for r in devs if recent(r, 3600)),
                "last_day": sum(1 for r in devs if recent(r, 86400)),
                "dhcp_names": sum(1 for r in devs if (r["info"].get("dhcp") or {}).get("hostname")),
                "network": json.loads(json.dumps(_network))}


def best_name(info):
    """The name a device gave itself, most reliable first: (name, source)."""
    info = info or {}
    d = info.get("dhcp") or {}
    nb = info.get("netbios") or {}
    md = info.get("mdns") or {}
    for v, src in ((nb.get("name"), "NetBIOS"), (d.get("hostname"), "DHCP"),
                   ((d.get("fqdn") or "").split(".")[0] or None, "DHCP"),
                   (md.get("instance"), "mDNS"), ((md.get("names") or [None])[0], "mDNS")):
        if v:
            return v, src
    return None, None


def merge_into(ident, mac):
    """Adds what was heard passively to a host's ident dict (in place,
    returns it). Scan-time lookups win; passive data fills the gaps."""
    rec = lookup(mac)
    if not rec:
        return ident
    info = rec["info"]
    ident = ident if ident is not None else {}
    ident.setdefault("names", {})
    ident.setdefault("sources", [])
    ident["passive"] = {k: info[k] for k in ("dhcp", "mdns", "ssdp", "netbios", "arp") if k in info}
    ident["passive"]["first_heard"] = rec["first_seen"]
    ident["passive"]["last_heard"] = rec["last_seen"]
    d = info.get("dhcp") or {}
    if d.get("hostname"):
        ident["names"]["dhcp"] = d["hostname"]
    if d and "dhcp" not in ident["sources"]:
        ident["sources"].append("dhcp")
    nb = info.get("netbios") or {}
    if nb.get("name") and not ident.get("netbios"):
        ident["netbios"] = {"name": nb["name"], "group": nb.get("group"), "passive": True}
        ident["names"].setdefault("netbios", nb["name"])
    md = info.get("mdns") or {}
    if md and not ident.get("mdns"):
        ident["mdns"] = {"name": (md.get("names") or [None])[0], "services": md.get("services") or [],
                         "instances": [md["instance"]] if md.get("instance") else [], "txt": md.get("txt") or {},
                         "passive": True}
        if md.get("names"):
            ident["names"].setdefault("mdns", md["names"][0])
        if md.get("instance"):
            ident["names"].setdefault("mdns_instance", md["instance"])
    ss = info.get("ssdp") or {}
    if ss and not ident.get("upnp"):
        ident["upnp"] = {"server": ss.get("server"), "device_type": ss.get("device_type"), "passive": True}
    for key, src in (("netbios", "netbios"), ("mdns", "mdns"), ("upnp", "upnp")):
        if (ident.get(key) or {}).get("passive") and src not in ident["sources"]:
            ident["sources"].append(src)
    if not ident.get("name"):
        n, src = best_name(info)
        if n:
            ident["name"], ident["name_source"] = n, src
    return ident


# ---------------------------------------------------------------- settings

def enabled():
    import scanner
    return scanner._get_setting("passive", "1") == "1"


def set_enabled(on):
    import scanner
    scanner._set_setting("passive", "1" if on else "0")
    if on:
        start()
    else:
        stop()
