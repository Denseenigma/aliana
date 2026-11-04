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
  CHATTER  background broadcasts apps make (Dropbox, Steam, Spotify, LLMNR,
           WS-Discovery, SSDP searches with user agents, Windows browser
           announcements, Ubiquiti / MikroTik discovery... see fpdb.py).
  TCP      replies to Aliana's own scans (and connections to the Pi):
           TTL, IP ID, window and options of the device's network stack,
           and reply timing (wired vs wireless). Used by the FINGERPRINT
           system in insights.py.

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
SO_TIMESTAMPNS = 35
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
    LDH_ABS, LDB_ABS, LDXB_MSH, LDB_IND = 0x28, 0x30, 0xB1, 0x50
    JEQ, JSET, RET = 0x15, 0x45, 0x06
    ins = [
        (LDH_ABS, 0, 0, 12),           # 0  ethertype
        (JEQ, 13, 0, 0x0806),          # 1  ARP -> accept
        (JEQ, 12, 0, 0x88CC),          # 2  LLDP -> accept
        (JEQ, 0, 10, 0x0800),          # 3  not IPv4 -> drop
        (LDH_ABS, 0, 0, 20),           # 4  flags + fragment offset
        (JSET, 8, 0, 0x1FFF),          # 5  fragment -> drop
        (LDXB_MSH, 0, 0, 14),          # 6  X = IP header length
        (LDB_ABS, 0, 0, 23),           # 7  IP protocol
        (JEQ, 0, 2, 6),                # 8  TCP?
        (LDB_IND, 0, 0, 27),           # 9  TCP flags
        (JSET, 4, 3, 0x02),            # 10 SYN or SYN-ACK -> accept, other TCP -> drop
        (JEQ, 0, 2, 17),               # 11 not UDP -> drop
        (LDB_ABS, 0, 0, 0),            # 12 destination MAC, first byte
        (JSET, 1, 0, 0x01),            # 13 broadcast / multicast UDP -> accept
        (RET, 0, 0, 0),                # 14 drop
        (RET, 0, 0, 0x0000FFFF),       # 15 accept
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


def _parse_arp(frame, iface, ts=None):
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
    if op == 2 and ts:                       # reply: did we ask?
        sent = _pending_arp.pop(sip, None)
        if sent:
            _rtt(r, (ts - sent) * 1000, iface)


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
    if _skip_mac(src_mac):
        return
    if first.startswith("M-SEARCH"):           # an app looking for devices: its user agent
        ua = next((ln.split(":", 1)[1].strip() for ln in text.split("\r\n")
                   if ln.lower().startswith("user-agent:")), None)
        r = _rec(src_mac, iface)
        ch = _chatter(r)
        ch["apps"]["SSDP search"] = _now()
        if ua:
            ua = _clean(ua, 120)
            ch["ua"] = ([ua] + [u for u in ch.get("ua", []) if u != ua])[:4]
        _count("chatter")
        _set_ip(r, src_ip, "ssdp")
        return
    if not first.startswith("NOTIFY"):
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


def _chatter(r):
    ch = r["info"].setdefault("chatter", {})
    ch.setdefault("apps", {})
    return ch


def _tlvs(data, off, tlen=1, llen=2):
    out = {}
    while off + tlen + llen <= len(data):
        t = int.from_bytes(data[off:off + tlen], "big")
        n = int.from_bytes(data[off + tlen:off + tlen + llen], "big")
        out.setdefault(t, data[off + tlen + llen:off + tlen + llen + n])
        off += tlen + llen + n
    return out


def _parse_chatter(payload, src_mac, src_ip, sport, dport, iface):
    """Background broadcasts from apps (fpdb.CHATTER_PORTS). True if kept."""
    import fpdb
    app = fpdb.CHATTER_PORTS.get(dport) or (fpdb.CHATTER_PORTS.get(sport) if sport in (10001, 5678) else None)
    if _skip_mac(src_mac):
        return False
    r = _rec(src_mac, iface)
    ch = _chatter(r)
    _set_ip(r, src_ip, "chatter")
    _count("chatter")
    if not app:                       # unknown broadcast port: remember it as a trait
        ports = ch.setdefault("ports", {})
        if len(ports) < 12 or str(dport) in ports:
            ports[str(dport)] = ports.get(str(dport), 0) + 1
        return True
    if app == "Ubiquiti discovery":
        if len(payload) <= 4:
            app = "UniFi discovery tool"           # someone asking, not a Ubiquiti device
        else:
            t = _tlvs(payload, 4)
            ch["ubnt"] = {k: v for k, v in {"model": _clean(t.get(0x15) or t.get(0x14), 40),
                                            "platform": _clean(t.get(0x0C), 40), "name": _clean(t.get(0x0B), 40),
                                            "version": _clean(t.get(0x03), 60)}.items() if v}
    elif app == "MikroTik discovery":
        t = _tlvs(payload, 4, 2, 2)
        ch["mndp"] = {k: v for k, v in {"name": _clean(t.get(5), 40), "version": _clean(t.get(7), 40),
                                        "platform": _clean(t.get(8), 40), "model": _clean(t.get(12), 40)}.items() if v}
    elif app == "WS-Discovery":
        text = payload[:4096].decode("utf-8", "replace")
        w = ch.setdefault("wsd", {})
        if "/Hello" in text or "ProbeMatches" in text:
            import re as _re
            types = " ".join(_re.findall(r"Types>([^<]{1,300})<", text))
            if types:
                w["types"] = sorted(set(types.split()))[:12]
        elif "/Probe" in text:
            w["probes"] = True
    elif app == "Windows browser":
        i = payload.find(b"\\MAILSLOT\\BROWSE\x00")
        if i >= 0:
            b = payload[i + 17:]
            if len(b) >= 32 and b[0] in (0x01, 0x0F):          # host / local master announcement
                ch["browser"] = {"name": _clean(b[6:22].split(b"\x00")[0], 16),
                                 "os": f"{b[22]}.{b[23]}", "type": int.from_bytes(b[24:28], "little"),
                                 "comment": _clean(b[32:].split(b"\x00")[0], 60)}
    ch["apps"][app] = _now()
    return True


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


def handle_frame(frame, iface, pkttype=0, ts=None):
    """Parses one Ethernet frame (also used by the tests). ts = kernel
    receive time (seconds); our own outgoing frames are only used to time
    the replies to them."""
    if len(frame) < 14:
        return
    ts = ts or time.time()
    etype = struct.unpack(">H", frame[12:14])[0]
    src_mac = _mac(frame[6:12])
    if pkttype == PACKET_OUTGOING:
        with _lock:
            try:
                _outgoing(frame, etype, ts)
            except Exception:
                pass
        return
    _state["frames"] += 1
    _state["last_frame"] = _now()
    with _lock:
        try:
            if etype == 0x0806:
                _parse_arp(frame, iface, ts)
            elif etype == 0x88CC:
                _parse_lldp(frame, src_mac, iface)
            elif etype == 0x0800 and len(frame) >= 34:
                ihl = (frame[14] & 0x0F) * 4
                if len(frame) < 14 + ihl + 8:
                    return
                src_ip = socket.inet_ntoa(frame[26:30])
                u = 14 + ihl
                if frame[23] == 6:
                    _parse_tcp(frame, ihl, src_mac, src_ip, iface, ts)
                    _state["parsed"] += 1
                    return
                if frame[23] != 17:
                    return
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
                    if not _parse_chatter(payload, src_mac, src_ip, sport, dport, iface):
                        return
            else:
                return
            _state["parsed"] += 1
        except Exception:      # a malformed packet must never stop the listener
            pass


# ---------------------------------------------------------------- fingerprint: stack traits + timing
#
# Replies to Aliana's own scans reach the Pi, so the listener can read how
# each device's network stack answers (TTL, IP ID, window, options) and how
# long it took (wired devices answer in well under a millisecond and
# steadily; Wi-Fi is slower and jumpier). Nothing extra is sent.

_pending_arp = {}      # target ip -> time we asked
_pending_syn = {}      # (dst ip, dst port, src port) -> time our SYN left
_local_nets = []       # [(ipaddress network, iface)]


def _outgoing(frame, etype, ts):
    if etype == 0x0806 and len(frame) >= 42:
        if struct.unpack(">H", frame[20:22])[0] == 1:          # ARP request we sent
            _pending_arp[socket.inet_ntoa(frame[38:42])] = ts
            if len(_pending_arp) > 4096:
                _prune(_pending_arp, ts)
    elif etype == 0x0800 and len(frame) >= 34 and frame[23] == 6:
        ihl = (frame[14] & 0x0F) * 4
        t = 14 + ihl
        if len(frame) < t + 14:
            return
        flags = frame[t + 13]
        if flags & 0x12 == 0x02:                                # SYN (no ACK) we sent
            sport, dport = struct.unpack(">HH", frame[t:t + 4])
            _pending_syn[(socket.inet_ntoa(frame[30:34]), dport, sport)] = ts
            if len(_pending_syn) > 20000:
                _prune(_pending_syn, ts)


def _prune(d, now):
    for k in [k for k, v in d.items() if now - v > 3]:
        d.pop(k, None)


def _local(ip):
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
        return any(a in net for net, _ in _local_nets)
    except ValueError:
        return False


def _rtt(r, ms, iface):
    if ms is None or ms < 0 or ms > 1000:
        return
    t = r["info"].setdefault("rtt", {"samples": []})
    t["samples"] = (t["samples"] + [round(ms, 3)])[-24:]
    t["iface"] = iface
    t["at"] = _now()


def _tcp_options(opts):
    out, mss, ws, ts = [], None, None, None
    i = 0
    while i < len(opts):
        k = opts[i]
        if k == 0:
            out.append("E")
            break
        if k == 1:
            out.append("N")
            i += 1
            continue
        if i + 1 >= len(opts):
            break
        ln = opts[i + 1]
        if ln < 2:
            break
        v = opts[i + 2:i + ln]
        if k == 2 and len(v) == 2:
            out.append("M")
            mss = struct.unpack(">H", v)[0]
        elif k == 3 and len(v) == 1:
            out.append("W")
            ws = v[0]
        elif k == 4:
            out.append("S")
        elif k == 8 and len(v) == 8:
            out.append("T")
            ts = struct.unpack(">I", v[:4])[0]
        else:
            out.append(str(k))
        i += ln
    return ",".join(out), mss, ws, ts


def _parse_tcp(frame, ihl, src_mac, src_ip, iface, ts):
    t = 14 + ihl
    if len(frame) < t + 20 or _skip_mac(src_mac) or not _local(src_ip):
        return                       # off-subnet: the MAC is the router's, not the sender's
    sport, dport = struct.unpack(">HH", frame[t:t + 4])
    off = (frame[t + 12] >> 4) * 4
    flags = frame[t + 13]
    win = struct.unpack(">H", frame[t + 14:t + 16])[0]
    opts, mss, ws, tsval = _tcp_options(frame[t + 20:t + off])
    ttl = frame[22]
    ipid = struct.unpack(">H", frame[18:20])[0]
    df = bool(frame[20] & 0x40)
    kind = "synack" if flags & 0x12 == 0x12 else "syn" if flags & 0x02 else None
    if not kind:
        return
    _count("tcp")
    r = _rec(src_mac, iface)
    _set_ip(r, src_ip, "tcp")
    st = r["info"].setdefault("stack", {})
    st["ttl"] = ttl
    st["ttl0"] = 64 if ttl <= 64 else 128 if ttl <= 128 else 255
    st["df"] = df
    st["ipids"] = (st.get("ipids", []) + [ipid])[-10:]
    st["at"] = _now()
    # A device's own SYN (it connected to the Pi) carries its full option
    # set: the most telling signature. Keep it once seen.
    if kind == "syn":
        st["syn"] = {"win": win, "opts": opts, "mss": mss, "ws": ws, "ts": tsval is not None}
    else:
        st["synack"] = {"win": win, "opts": opts, "mss": mss, "ws": ws, "ts": tsval is not None}
        sent = _pending_syn.pop((src_ip, sport, dport), None)
        if sent:
            _rtt(r, (ts - sent) * 1000, iface)


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

def _kernel_time(anc):
    for level, kind, data in anc or ():
        if level == socket.SOL_SOCKET and kind == SO_TIMESTAMPNS:
            if len(data) >= 16:
                sec, ns = struct.unpack("qq", data[:16])
            else:
                sec, ns = struct.unpack("ii", data[:8])
            return sec + ns / 1e9
    return None


def _load_own_macs():
    # also: which subnets are directly attached (fingerprints only make sense there)
    try:
        import ipaddress
        import scanner
        nets = []
        for i in scanner.list_interfaces():
            if i.get("ipv4"):
                nets.append((ipaddress.ip_interface(i["ipv4"]).network, i["name"]))
        _local_nets[:] = nets
    except Exception:
        pass
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
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
    except OSError:
        pass
    sock.settimeout(1.0)
    _state.update(running=True, error=None, started=_now())
    _load_own_macs()
    last_flush = last_macs = time.time()
    print("aliana passive: listening", flush=True)
    try:
        while not _stop.is_set():
            try:
                frame, anc, _, addr = sock.recvmsg(4096, 64)
                handle_frame(frame, addr[0], addr[2], _kernel_time(anc))
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
    ident["passive"] = {k: info[k] for k in ("dhcp", "mdns", "ssdp", "netbios", "arp", "stack", "rtt", "chatter")
                        if k in info}
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
