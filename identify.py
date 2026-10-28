"""
identify.py - works out *what* each device is and what it's called.

Runs after the port scan (and on Discovery scans too). Everything here is a
light, read-only lookup that ordinary devices on a LAN answer all day long:

  vendor   MAC prefix -> manufacturer, from the bundled IEEE database
           (data/oui.tsv.gz; newer than nmap's), plus "private / randomized
           MAC" detection (phones and laptops hide their real MAC)
  netbios  NetBIOS name query (UDP 137): Windows / Samba computer names,
           workgroup or domain
  mdns     mDNS / Bonjour (UDP 5353, unicast): hostname.local, advertised
           services (_airplay, _googlecast, _ipp, _hap...), friendly names
           and model strings
  ssdp     SSDP / UPnP (UDP 1900): friendly name, manufacturer, model and
           device type from the device's own description XML
  dns      reverse DNS against the gateway and the network's DNS servers
           (routers usually know their DHCP clients' names)
  http     the page title / server header / certificate name of web
           interfaces on ports already found open (never-probe ports and
           excluded hosts are skipped)

identify_hosts(hosts, ...) adds host["ident"] = {names, evidence...} and
fills in hostname / vendor where nmap had none.
"""
import concurrent.futures
import gzip
import html
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

OUI_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "oui.tsv.gz")
WEB_PORTS = {80, 81, 443, 591, 3000, 5000, 5001, 7080, 7443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9080, 9443}
TLS_PORTS = {443, 5001, 7443, 8443, 9443}

# ---------------------------------------------------------------- vendor database

_oui = None
_oui_lock = threading.Lock()


def _load_oui():
    global _oui
    with _oui_lock:
        if _oui is None:
            db = {}
            try:
                with gzip.open(OUI_PATH, "rt", encoding="utf-8") as f:
                    for line in f:
                        k, _, v = line.rstrip("\n").partition("\t")
                        if k and v:
                            db[k] = v
            except OSError:
                pass
            _oui = db
    return _oui


def reload_oui():
    global _oui
    with _oui_lock:
        _oui = None
    return len(_load_oui())


def update_oui():
    """Downloads the current IEEE registries and rebuilds data/oui.tsv.gz
    (needs internet on the Pi). Returns the number of prefixes."""
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "build_oui.py")
    spec = importlib.util.spec_from_file_location("aliana_build_oui", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    data = mod.from_ieee()
    if len(data) < 10000:
        raise RuntimeError(f"Only {len(data)} entries downloaded -- kept the existing database.")
    mod.write(data)
    return reload_oui()


def oui_info():
    try:
        st = os.stat(OUI_PATH)
        return {"entries": len(_load_oui()), "updated": time.strftime("%Y-%m-%d", time.localtime(st.st_mtime))}
    except OSError:
        return {"entries": 0, "updated": None}


def is_private_mac(mac):
    """Locally administered (randomized / 'private Wi-Fi address') MACs:
    second-lowest bit of the first byte set. Phones, tablets and laptops use
    them, so there's no manufacturer to look up."""
    try:
        return bool(int(str(mac).replace("-", ":").split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def vendor_for(mac):
    """Manufacturer for a MAC from the bundled IEEE database (longest prefix
    wins: 36, 28, then 24 bits), or None."""
    hexes = re.sub(r"[^0-9A-Fa-f]", "", str(mac or "")).upper()
    if len(hexes) != 12:
        return None
    db = _load_oui()
    for n in (9, 7, 6):
        v = db.get(hexes[:n])
        if v:
            return v
    return None


# ---------------------------------------------------------------- DNS wire format

def _encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        b = label.encode("utf-8")[:63]
        out += bytes([len(b)]) + b
    return out + b"\x00"


def _dns_query(questions, txid=None, unicast_response=False):
    """questions: [(name, qtype)]"""
    txid = random.randint(0, 0xFFFF) if txid is None else txid
    pkt = struct.pack(">HHHHHH", txid, 0, len(questions), 0, 0, 0)
    for name, qtype in questions:
        pkt += _encode_name(name) + struct.pack(">HH", qtype, 0x8001 if unicast_response else 1)
    return txid, pkt


def _read_name(data, off, depth=0):
    labels, jumped, end = [], False, off
    while depth < 20:
        if off >= len(data):
            raise ValueError("truncated")
        n = data[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = ((n & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            jumped, off, depth = True, ptr, depth + 1
            continue
        labels.append(data[off + 1:off + 1 + n].decode("utf-8", "replace"))
        off += 1 + n
    return ".".join(labels), (end if jumped else off)


def _parse_dns(data):
    """Returns a list of records (name, type, value) from all sections."""
    if len(data) < 12:
        return []
    _, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    off = 12
    for _ in range(qd):
        _, off = _read_name(data, off)
        off += 4
    recs = []
    for _ in range(an + ns + ar):
        name, off = _read_name(data, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rd = data[off:off + rdlen]
        val = None
        if rtype in (12, 5):            # PTR, CNAME
            val, _ = _read_name(data, off)
        elif rtype == 16:               # TXT
            val, i = [], 0
            while i < len(rd):
                ln = rd[i]
                val.append(rd[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                i += 1 + ln
        elif rtype == 1 and rdlen == 4:  # A
            val = socket.inet_ntoa(rd)
        elif rtype == 33:               # SRV
            val, _ = _read_name(data, off + 6)
        recs.append((name, rtype, val))
        off += rdlen
    return recs


def _udp_exchange(ip, port, payload, timeout, src_port=0, expect_from=None):
    """Sends one datagram, collects replies until timeout. Returns [bytes]."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.bind(("", src_port))
        s.sendto(payload, (ip, port))
        out, deadline = [], time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            s.settimeout(left)
            try:
                data, addr = s.recvfrom(9000)
            except socket.timeout:
                break
            if expect_from is None or addr[0] == expect_from:
                out.append(data)
        return out
    except OSError:
        return []
    finally:
        s.close()


def _rev(ip):
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


# ---------------------------------------------------------------- NetBIOS

def netbios(ip, timeout=1.0):
    """NetBIOS node status (the 'nbtstat -A' query). Returns
    {"name", "group", "server": bool, "mac"} or None."""
    txid = random.randint(0, 0xFFFF)
    encoded = b"".join(bytes([0x41 + (c >> 4), 0x41 + (c & 0x0F)]) for c in b"*" + b"\x00" * 15)
    pkt = struct.pack(">HHHHHH", txid, 0, 1, 0, 0, 0) + b"\x20" + encoded + b"\x00" + struct.pack(">HH", 0x21, 1)
    for data in _udp_exchange(ip, 137, pkt, timeout, expect_from=ip):
        try:
            if struct.unpack(">H", data[:2])[0] != txid:
                continue
            _, off = _read_name(data, 12)
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            if rtype != 0x21:
                continue
            n = data[off]
            off += 1
            name = group = None
            server = False
            for i in range(n):
                raw = data[off + i * 18: off + i * 18 + 18]
                nm = raw[:15].decode("ascii", "replace").strip()
                suffix, flags = raw[15], struct.unpack(">H", raw[16:18])[0]
                is_group = bool(flags & 0x8000)
                if suffix == 0x00 and not is_group and not name:
                    name = nm
                elif suffix == 0x00 and is_group and not group:
                    group = nm
                elif suffix == 0x20:
                    server = True
            macb = data[off + n * 18: off + n * 18 + 6]
            mac = ":".join(f"{b:02X}" for b in macb) if len(macb) == 6 and any(macb) else None
            if name:
                return {"name": name, "group": group, "server": server, "mac": mac}
        except (ValueError, IndexError, struct.error):
            continue
    return None


# ---------------------------------------------------------------- mDNS / Bonjour

_TXT_KEYS = ("md", "model", "fn", "ty", "product", "usb_MFG", "usb_MDL", "am", "manufacturer", "vendor",
             "deviceid", "name", "mdl", "mf", "osxvers", "integrator")


def mdns(ip, timeout=1.2):
    """Unicast mDNS queries to the device: its .local name, the services it
    advertises, and their instance names / TXT details."""
    res = {"name": None, "services": [], "instances": [], "txt": {}}
    _, q1 = _dns_query([(_rev(ip), 12), ("_services._dns-sd._udp.local", 12)], txid=0)
    replies = _udp_exchange(ip, 5353, q1, timeout, expect_from=ip)
    services = set()
    for data in replies:
        try:
            for name, rtype, val in _parse_dns(data):
                if rtype == 12 and name.endswith(".in-addr.arpa") and val:
                    res["name"] = res["name"] or val
                elif rtype == 12 and name == "_services._dns-sd._udp.local" and val:
                    services.add(val)
        except (ValueError, IndexError, struct.error):
            pass
    host_label = res["name"].split(".")[0] if res["name"] else None
    services = sorted(services)[:12]
    res["services"] = [s.replace(".local", "") for s in services]
    qs = [(s, 12) for s in services]
    if host_label:
        qs.append((f"{host_label}._device-info._tcp.local", 16))
    if qs:
        _, q2 = _dns_query(qs, txid=0)
        for data in _udp_exchange(ip, 5353, q2, timeout, expect_from=ip):
            try:
                for name, rtype, val in _parse_dns(data):
                    if rtype == 12 and val and name in services:
                        inst = val[: -len(name) - 1] if val.endswith("." + name) else val.split("._")[0]
                        if inst and inst not in res["instances"]:
                            res["instances"].append(inst)
                    elif rtype == 16 and isinstance(val, list):
                        for kv in val:
                            k, _, v = kv.partition("=")
                            if k in _TXT_KEYS and v and k not in res["txt"]:
                                res["txt"][k] = v[:120]
                    elif rtype == 1 and name.endswith(".local") and not res["name"]:
                        res["name"] = name
            except (ValueError, IndexError, struct.error):
                pass
    res["instances"] = res["instances"][:8]
    if not (res["name"] or res["services"] or res["instances"] or res["txt"]):
        return None
    return res


# ---------------------------------------------------------------- DNS (reverse)

def dns_servers(gateway=None):
    """Private DNS servers worth asking for PTR records: the gateway, then
    the servers this unit got from DHCP (public resolvers know nothing
    about LAN names, so they're skipped)."""
    found = []
    if gateway:
        found.append(gateway)
    for path in ("/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"):
        try:
            for line in open(path):
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    found.append(parts[1])
        except OSError:
            pass
    out = []
    for s in found:
        try:
            a = ipaddress.IPv4Address(s)
        except ValueError:
            continue
        if a.is_private and not a.is_loopback and s not in out:
            out.append(s)
    return out[:3]


def dns_ptr(ip, servers, timeout=1.0):
    for server in servers:
        txid, q = _dns_query([(_rev(ip), 12)])
        q = q[:2] + b"\x01\x00" + q[4:]   # recursion desired
        for data in _udp_exchange(server, 53, q, timeout, expect_from=server):
            try:
                if struct.unpack(">H", data[:2])[0] != txid:
                    continue
                for name, rtype, val in _parse_dns(data):
                    if rtype == 12 and val:
                        return {"name": val.rstrip("."), "server": server}
            except (ValueError, IndexError, struct.error):
                pass
    return None


# ---------------------------------------------------------------- SSDP / UPnP

def _xml_fields(xml_bytes):
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return {}
    want = {"friendlyName": "name", "manufacturer": "manufacturer", "modelName": "model",
            "modelNumber": "model_number", "modelDescription": "description", "deviceType": "device_type"}
    out = {}
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if tag in want and want[tag] not in out and (el.text or "").strip():
            out[want[tag]] = el.text.strip()[:120]
    return out


def _fetch(url, timeout=3.0, limit=65536):
    req = urllib.request.Request(url, headers={"User-Agent": "Aliana/1.0"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
    with opener.open(req, timeout=timeout) as r:
        return r.read(limit)


def ssdp(targets, iface_ip=None, unicast=False, timeout=3.0):
    """M-SEARCH for UPnP devices; returns {ip: {"server", "name",
    "manufacturer", "model", "device_type", ...}} for IPs in targets."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
           "MX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    found = {}
    try:
        s.bind((iface_ip or "", 0))
        if iface_ip:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(iface_ip))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if unicast:
            for ip in targets:
                s.sendto(msg, (ip, 1900))
        else:
            s.sendto(msg, ("239.255.255.250", 1900))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            s.settimeout(max(0.05, deadline - time.monotonic()))
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                break
            ip = addr[0]
            if ip not in targets:
                continue
            hdr = {}
            for line in data.decode("utf-8", "replace").split("\r\n")[1:]:
                k, _, v = line.partition(":")
                hdr[k.strip().lower()] = v.strip()
            e = found.setdefault(ip, {"locations": set()})
            if hdr.get("server"):
                e["server"] = hdr["server"][:120]
            loc = hdr.get("location")
            if loc and urllib.parse.urlparse(loc).hostname == ip:
                e["locations"].add(loc)
    except OSError:
        pass
    finally:
        s.close()
    out = {}
    for ip, e in found.items():
        info = {"server": e.get("server")} if e.get("server") else {}
        for loc in sorted(e["locations"])[:3]:
            try:
                fields = _xml_fields(_fetch(loc))
            except Exception:
                continue
            for k, v in fields.items():
                info.setdefault(k, v)
            if "name" in info:
                break
        if info:
            out[ip] = info
    return out


# ---------------------------------------------------------------- HTTP

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


def _cert_names(der):
    """Subject CN / O from a DER certificate without extra libraries."""
    out = {}
    for oid, key in ((b"\x55\x04\x03", "cn"), (b"\x55\x04\x0a", "org")):
        i = der.rfind(oid)   # rfind: subject comes after issuer
        if i < 0:
            continue
        j = i + 3
        if j + 2 > len(der):
            continue
        ln = der[j + 1]
        val = der[j + 2:j + 2 + ln].decode("utf-8", "replace").strip()
        if val:
            out[key] = val[:100]
    return out


def http_probe(ip, port, timeout=3.0):
    """GET / on an open web port: title, Server header, auth realm, and
    the TLS certificate's names."""
    tls = port in TLS_PORTS
    info = {}
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    try:
        sock = raw
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                sock = ctx.wrap_socket(raw, server_hostname=ip)
                der = sock.getpeercert(binary_form=True)
                if der:
                    info.update({f"cert_{k}": v for k, v in _cert_names(der).items()})
            except (ssl.SSLError, OSError):
                return info or None
        sock.settimeout(timeout)
        sock.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Aliana/1.0\r\nAccept: text/html\r\n"
                     f"Connection: close\r\n\r\n".encode())
        data = b""
        while len(data) < 65536:
            try:
                chunk = sock.recv(8192)
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1", "replace").split("\r\n")
        if lines and lines[0].startswith("HTTP/"):
            info["status"] = lines[0][9:12]
        for line in lines[1:]:
            k, _, v = line.partition(":")
            k = k.strip().lower()
            if k == "server":
                info["server"] = v.strip()[:100]
            elif k == "www-authenticate":
                m = re.search(r'realm="([^"]+)"', v)
                if m:
                    info["realm"] = m.group(1)[:100]
            elif k == "location":
                info["redirect"] = v.strip()[:150]
        m = _TITLE.search(body)
        if m:
            t = html.unescape(re.sub(r"\s+", " ", m.group(1).decode("utf-8", "replace"))).strip()
            if t:
                info["title"] = t[:120]
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return info or None


# ---------------------------------------------------------------- network helpers

def default_gateway():
    try:
        out = subprocess.run(["ip", "-4", "route", "show", "default"], capture_output=True, text=True,
                             timeout=5).stdout
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None
    except Exception:
        return None


# ---------------------------------------------------------------- putting it together

def _best_name(ident):
    """The most human name we found, and where it came from."""
    for key, src in (("netbios", "NetBIOS"), ("mdns_instance", "mDNS"), ("mdns", "mDNS"),
                     ("upnp", "UPnP"), ("dns", "DNS")):
        v = ident.get("names", {}).get(key)
        if v:
            return v, src
    return None, None


def _clean_host(name):
    if not name:
        return None
    n = name.rstrip(".")
    for suffix in (".local", ".lan", ".home", ".localdomain"):
        if n.lower().endswith(suffix):
            n = n[: -len(suffix)]
    return n or None


def identify_host(host, gateway=None, servers=(), no_probe=(), upnp=None, stop=None):
    """Runs the lookups for one host (dict from the scanner) and returns its ident dict."""
    ip = host["ip"]
    ident = {"names": {}, "sources": []}
    mac = host.get("mac")
    if mac:
        v = vendor_for(mac)
        if v:
            ident["vendor_db"] = v
        if is_private_mac(mac):
            ident["private_mac"] = True
    if gateway and ip == gateway:
        ident["gateway"] = True
    if stop is not None and stop.is_set():
        return ident

    nb = netbios(ip)
    if nb:
        ident["netbios"] = nb
        ident["names"]["netbios"] = nb["name"]
        ident["sources"].append("netbios")
    md = mdns(ip)
    if md:
        ident["mdns"] = md
        if md.get("name"):
            ident["names"]["mdns"] = _clean_host(md["name"])
        if md.get("instances"):
            ident["names"]["mdns_instance"] = md["instances"][0]
        ident["sources"].append("mdns")
    if upnp and upnp.get(ip):
        ident["upnp"] = upnp[ip]
        if upnp[ip].get("name"):
            ident["names"]["upnp"] = upnp[ip]["name"]
        ident["sources"].append("upnp")
    if servers and not host.get("hostname"):
        d = dns_ptr(ip, servers)
        if d:
            ident["names"]["dns"] = d["name"]
            ident["sources"].append("dns")
    web = {}
    for p in sorted({p["port"] for p in host.get("ports", []) if p.get("state") == "open"
                     and p.get("protocol", "tcp") == "tcp" and p["port"] in WEB_PORTS} - set(no_probe))[:3]:
        if stop is not None and stop.is_set():
            break
        r = http_probe(ip, p)
        if r:
            web[str(p)] = r
    if web:
        ident["http"] = web
        ident["sources"].append("http")
    name, src = _best_name(ident)
    if name:
        ident["name"], ident["name_source"] = name, src
    return ident


def identify_hosts(hosts, iface_ip=None, scope="subnet", no_probe=(), stop=None, progress=None, workers=16):
    """Fills host["ident"] for every host (in place) and fills in hostname /
    vendor where nmap didn't find one. Safe to call with an empty list."""
    if not hosts:
        return
    gateway = default_gateway()
    servers = dns_servers(gateway)
    targets = {h["ip"] for h in hosts}
    try:
        upnp = ssdp(targets, iface_ip=iface_ip, unicast=(scope == "host"))
    except Exception:
        upnp = {}
    done = [0]

    def one(h):
        try:
            h["ident"] = identify_host(h, gateway, servers, no_probe, upnp, stop)
        except Exception as e:   # never let identification break a scan
            h["ident"] = {"names": {}, "sources": [], "error": str(e)[:100]}
        done[0] += 1
        if progress:
            progress(done[0], len(hosts))

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(one, hosts))
    for h in hosts:
        ident = h.get("ident") or {}
        if not h.get("vendor") and ident.get("vendor_db"):
            h["vendor"] = ident["vendor_db"]
        if not h.get("vendor") and ident.get("private_mac"):
            h["vendor"] = None
        if not h.get("hostname") and ident.get("name"):
            h["hostname"] = ident["name"]


def ident_json(ident):
    try:
        s = json.dumps(ident, default=list, separators=(",", ":"))
    except (TypeError, ValueError):
        return None
    return s if len(s) <= 16000 else None
