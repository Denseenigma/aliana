"""
deep.py - the extra checks a Deep scan (one device at a time) runs, and how
their results are summarised.

Stage 2 of a Deep scan runs these nmap scripts on the TCP ports found open
(each script only runs where it applies -- RDP checks on 3389, SMB on 445...).
All are in nmap's "safe" set: they read what a service shows anyone who
connects; nothing logs in or changes anything.

  rdp-ntlm-info       computer name, domain and exact Windows build (no login)
  smb-protocols       SMB dialects offered (is the old SMBv1 still on?)
  smb2-security-mode  is SMB signing required?
  smb-os-discovery    OS / computer name the file server reports (SMBv1 hosts)
  ssl-cert            certificate: subject, issuer, expiry, key size
  ssh-hostkey         SSH host key types
  ssh2-enum-algos     SSH algorithms offered (weak ones?)
  http-title / http-server-header / http-security-headers
  ftp-anon            anonymous FTP login allowed?
  vnc-info            VNC security types (is "None" -- no password -- offered?)

Then a short UDP check of ports Standard never looks at (needs raw sockets):
  SNMP (does it answer to the default "public" community?), NTP, DNS, TFTP,
  NetBIOS, SSDP, IPMI (server management boards), BACnet (building
  controllers), SIP, IKE, MS-SQL browser, mDNS.
"""
import datetime
import re

TCP_SCRIPTS = ["rdp-ntlm-info", "smb-protocols", "smb2-security-mode", "smb-os-discovery", "ssl-cert",
               "ssh-hostkey", "ssh2-enum-algos", "http-title", "http-server-header", "http-security-headers",
               "ftp-anon", "vnc-info"]
UDP_PORTS = [53, 69, 123, 137, 161, 500, 623, 1434, 1900, 5060, 5353, 47808]
UDP_SCRIPTS = ["snmp-sysdescr", "snmp-info", "ntp-info", "ipmi-version", "bacnet-info", "nbstat", "upnp-info"]
SCRIPT_TIMEOUT = "30s"

_WEAK_SSH = {"diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1", "ssh-dss", "arcfour",
             "arcfour128", "arcfour256", "3des-cbc", "blowfish-cbc", "des-cbc", "hmac-md5", "hmac-md5-96",
             "hmac-sha1-96", "rsa-sha1"}
_SEC_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]

# Windows builds (rdp-ntlm-info Product_Version 10.0.<build>):
#   build -> (name, out of support as of late 2026)
_WIN_BUILDS = {
    7601: ("Windows 7 / Server 2008 R2", True), 9200: ("Windows 8 / Server 2012", True),
    9600: ("Windows 8.1 / Server 2012 R2", True),
    10240: ("Windows 10 1507", True), 10586: ("Windows 10 1511", True), 14393: ("Windows 10 1607 / Server 2016", False),
    15063: ("Windows 10 1703", True), 16299: ("Windows 10 1709", True), 17134: ("Windows 10 1803", True),
    17763: ("Windows 10 1809 / Server 2019", False), 18362: ("Windows 10 1903", True), 18363: ("Windows 10 1909", True),
    19041: ("Windows 10 2004", True), 19042: ("Windows 10 20H2", True), 19043: ("Windows 10 21H1", True),
    19044: ("Windows 10 21H2", True), 19045: ("Windows 10 22H2", True),
    20348: ("Windows Server 2022", False), 22000: ("Windows 11 21H2", True), 22621: ("Windows 11 22H2", True),
    22631: ("Windows 11 23H2", True), 26100: ("Windows 11 24H2 / Server 2025", False),
    26200: ("Windows 11 25H2", False),
}


def windows_build(version):
    """'10.0.19045' -> {"build", "name", "old"} or None."""
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version or "")
    if not m:
        return None
    b = int(m.group(3))
    name, old = _WIN_BUILDS.get(b, (None, None))
    if name is None:
        near = max((k for k in _WIN_BUILDS if k <= b), default=None)
        name, old = (f"Windows build {b}", _WIN_BUILDS[near][1] if near and b - near < 50 else False)
    if "Windows 10" in name and "Server" not in name:
        old = True        # Windows 10 left support in October 2025 (bar paid extended updates)
    return {"build": b, "version": version, "name": name, "old": bool(old)}


# ---------------------------------------------------------------- nmap XML <script> elements

def script_data(el):
    """An nmap <script>/<table> element -> dict (keyed) or list (unkeyed)."""
    keyed, items = {}, []
    for child in el:
        if child.tag == "elem":
            v = (child.text or "").strip()
            if child.get("key") is not None:
                keyed[child.get("key")] = v
            else:
                items.append(v)
        elif child.tag == "table":
            v = script_data(child)
            if child.get("key") is not None:
                keyed[child.get("key")] = v
            else:
                items.append(v)
    if keyed and items:
        keyed["_items"] = items
    return keyed if keyed else items


def parse_scripts(parent):
    """{script id: {"output": str, "data": ...}} for <script> children."""
    out = {}
    for s in parent.findall("script"):
        out[s.get("id")] = {"output": (s.get("output") or "")[:4000], "data": script_data(s)}
    return out


# ---------------------------------------------------------------- summary

def _cert(port, s):
    d = s.get("data") or {}
    if not isinstance(d, dict):
        return None
    subj, iss = d.get("subject") or {}, d.get("issuer") or {}
    val, key = d.get("validity") or {}, d.get("pubkey") or {}
    na = val.get("notAfter")
    expired = None
    try:
        expired = datetime.datetime.fromisoformat(na[:19]) < datetime.datetime.now() if na else None
    except ValueError:
        pass
    bits = None
    try:
        bits = int(key.get("bits")) if key.get("bits") else None
    except ValueError:
        pass
    kt = (key.get("type") or "").lower()
    return {"port": port, "cn": subj.get("commonName"), "org": subj.get("organizationName"),
            "issuer": iss.get("commonName") or iss.get("organizationName"),
            "self_signed": bool(subj) and subj == iss, "not_after": na, "expired": expired,
            "key": f"{kt.upper()} {bits}" if kt else None,
            "weak_key": bool(bits and ((kt == "rsa" and bits < 2048) or (kt in ("ec", "ecdsa") and bits < 224))),
            "sig": d.get("sig_algo")}


def summarize(host):
    """Everything worth keeping from a Deep scan's scripts (small: stored in
    hosts.ident["deep"])."""
    out = {"at": datetime.datetime.now().isoformat(timespec="seconds")}
    hs = host.get("hostscripts") or {}
    certs, http = [], {}
    for p in host.get("ports", []):
        sc = p.get("scripts") or {}
        port = p["port"]
        if "rdp-ntlm-info" in sc and isinstance(sc["rdp-ntlm-info"]["data"], dict):
            d = sc["rdp-ntlm-info"]["data"]
            out["rdp"] = {k: v for k, v in {
                "computer": d.get("DNS_Computer_Name") or d.get("NetBIOS_Computer_Name"),
                "netbios": d.get("NetBIOS_Computer_Name"), "domain": d.get("DNS_Domain_Name") or d.get("NetBIOS_Domain_Name"),
                "forest": d.get("DNS_Tree_Name"), "version": d.get("Product_Version")}.items() if v}
            wb = windows_build(d.get("Product_Version"))
            if wb:
                out["windows"] = wb
        if "ssl-cert" in sc:
            c = _cert(port, sc["ssl-cert"])
            if c:
                certs.append(c)
        if "ssh-hostkey" in sc:
            keys = sc["ssh-hostkey"]["data"]
            types = sorted({k.get("type") for k in keys if isinstance(k, dict) and k.get("type")}) if isinstance(keys, list) else []
            out.setdefault("ssh", {})["keys"] = types
            out["ssh"]["port"] = port
        if "ssh2-enum-algos" in sc and isinstance(sc["ssh2-enum-algos"]["data"], dict):
            algos = set()
            for v in sc["ssh2-enum-algos"]["data"].values():
                if isinstance(v, list):
                    algos |= {x for x in v if isinstance(x, str)}
            weak = sorted(a for a in algos if a in _WEAK_SSH or a.endswith("-cbc"))
            out.setdefault("ssh", {})["weak"] = weak
            out["ssh"]["port"] = port
        h = {}
        if "http-title" in sc:
            t = sc["http-title"]["data"]
            h["title"] = (t.get("title") if isinstance(t, dict) else None) or sc["http-title"]["output"].strip()[:100]
        if "http-server-header" in sc:
            h["server"] = sc["http-server-header"]["output"].strip()[:100]
        if "http-security-headers" in sc:
            o = sc["http-security-headers"]["output"].lower()
            h["missing"] = [x for x in _SEC_HEADERS if x.lower().replace("-", "_") not in o.replace("-", "_")]
        if h:
            http[str(port)] = h
        if "ftp-anon" in sc and "anonymous ftp login allowed" in sc["ftp-anon"]["output"].lower():
            out["ftp_anon"] = port
        if "vnc-info" in sc:
            o = sc["vnc-info"]["output"]
            out["vnc"] = {"port": port, "no_auth": bool(re.search(r"\bNone\b|No authentication", o)),
                          "info": " ".join(o.split())[:120]}
        # UDP
        if p.get("protocol") == "udp":
            if "snmp-sysdescr" in sc or "snmp-info" in sc:
                desc = (sc.get("snmp-sysdescr") or {}).get("output", "").strip()
                info = (sc.get("snmp-info") or {}).get("data") or {}
                out["snmp"] = {"public": True, "sysdescr": " ".join(desc.split())[:200] or None,
                               "engine": info.get("enterprise") if isinstance(info, dict) else None}
            if "ntp-info" in sc and isinstance(sc["ntp-info"]["data"], dict):
                d = sc["ntp-info"]["data"]
                out["ntp"] = {k: d.get(k) for k in ("version", "system", "stratum", "processor") if d.get(k)}
            if "ipmi-version" in sc:
                d = sc["ipmi-version"]["data"]
                out["ipmi"] = (d if isinstance(d, dict) else {}) | {"output": " ".join(sc["ipmi-version"]["output"].split())[:160]}
            if "bacnet-info" in sc and isinstance(sc["bacnet-info"]["data"], dict):
                d = sc["bacnet-info"]["data"]
                out["bacnet"] = {k: d.get(k) for k in ("Vendor Name", "Model Name", "Firmware", "Object-name",
                                                       "Application Software", "Description", "Location") if d.get(k)}
            if "upnp-info" in sc:
                out["upnp"] = " ".join(sc["upnp-info"]["output"].split())[:200]
            if "nbstat" in sc:
                out["nbstat"] = " ".join(sc["nbstat"]["output"].split())[:160]
    if certs:
        out["certs"] = certs[:6]
    if http:
        out["http"] = http
    udp = sorted(p["port"] for p in host.get("ports", []) if p.get("protocol") == "udp" and p.get("state") == "open")
    if udp:
        out["udp_open"] = udp
    if "smb-protocols" in hs:
        d = hs["smb-protocols"]["data"]
        dialects = d.get("dialects") if isinstance(d, dict) else None
        dialects = dialects if isinstance(dialects, list) else re.findall(r"^\s+(\S.*)$", hs["smb-protocols"]["output"], re.M)
        out.setdefault("smb", {})["dialects"] = [x for x in dialects if isinstance(x, str)][:8]
        out["smb"]["v1"] = any("SMBv1" in x or x.startswith("NT LM") for x in out["smb"]["dialects"])
    if "smb2-security-mode" in hs:
        o = hs["smb2-security-mode"]["output"].lower()
        out.setdefault("smb", {})["signing"] = "required" if "enabled and required" in o else \
            "not required" if "not required" in o else "disabled" if "disabled" in o else None
    if "smb-os-discovery" in hs and isinstance(hs["smb-os-discovery"]["data"], dict):
        d = hs["smb-os-discovery"]["data"]
        out.setdefault("smb", {})["os"] = d.get("os")
        out["smb"]["name"] = d.get("server") or d.get("fqdn")
        out["smb"]["domain"] = d.get("domain") or d.get("workgroup")
    return out


# ---------------------------------------------------------------- what it means

_SNMP_TYPES = [
    (re.compile(r"cisco|juniper|procurve|aruba|ubiquiti|edgeos|unifi|mikrotik|routeros|fortigate|fortios|sonicwall|meraki|netgear|tp-link", re.I), "network"),
    (re.compile(r"jetdirect|laserjet|officejet|brother|canon|ricoh|kyocera|xerox|lexmark|konica|epson|sharp mx", re.I), "printer"),
    (re.compile(r"\bapc\b|ups|eaton|cyberpower|vertiv|liebert", re.I), "power"),
    (re.compile(r"synology|qnap|diskstation|truenas|freenas|netapp", re.I), "nas"),
    (re.compile(r"axis|hikvision|dahua|hanwha|vivotek|camera", re.I), "camera"),
    (re.compile(r"windows", re.I), "windows"),
    (re.compile(r"linux|freebsd|unix", re.I), "unix"),
]


def clues(deep):
    """(scan clues, fingerprint clues, facts) from a deep summary."""
    if not deep:
        return [], [], []
    scan, fp, facts = [], [], []
    w = deep.get("windows")
    if w:
        t = "server" if "Server" in w["name"] and "Windows 1" not in w["name"] else "windows"
        fp.append((t, 96, f"exact Windows build {w['version']}: {w['name']}"))
        facts.append(f"Windows build {w['version']} ({w['name']}){' — OUT OF SUPPORT' if w['old'] else ''}")
    r = deep.get("rdp") or {}
    if r.get("domain"):
        facts.append(f"domain {r['domain']}" + (f" (forest {r['forest']})" if r.get("forest") and r["forest"] != r["domain"] else ""))
    smb = deep.get("smb") or {}
    if smb.get("os"):
        scan.append(("nas" if "samba" in smb["os"].lower() else "windows", 90, f"file server reports {smb['os']}"))
    s = deep.get("snmp") or {}
    if s.get("sysdescr"):
        for rx, t in _SNMP_TYPES:
            if rx.search(s["sysdescr"]):
                scan.append((t, 92, f"SNMP description: “{s['sysdescr'][:60]}”"))
                break
    if deep.get("bacnet"):
        b = deep["bacnet"]
        scan.append(("iot", 92, "BACnet building controller" + (f" ({b.get('Vendor Name')} {b.get('Model Name') or ''})".rstrip() if b.get("Vendor Name") else "")))
    if deep.get("ipmi"):
        scan.append(("server", 82, "IPMI management controller (server BMC)"))
    if deep.get("ntp", {}).get("system"):
        facts.append(f"NTP: {deep['ntp']['system']}")
    return scan, fp, facts


def flags(deep):
    """Exposure findings from a deep summary: [(key, level, label, detail)]."""
    if not deep:
        return []
    out = []
    smb = deep.get("smb") or {}
    if smb.get("v1"):
        out.append(("smbv1", "high", "SMBv1", "The old SMBv1 protocol is still enabled -- the one WannaCry spread through. "
                    "Turn it off unless something truly needs it."))
    if smb.get("signing") in ("not required", "disabled"):
        out.append(("smb-signing", "medium", "SMB signing off", "SMB signing isn't required, so connections to this "
                    "file share can be relayed / tampered with (NTLM relay)."))
    if (deep.get("snmp") or {}).get("public"):
        out.append(("snmp-public", "medium", "SNMP public", "Answers SNMP with the default 'public' community -- anyone "
                    "on the network can read its configuration details."))
    for c in deep.get("certs") or []:
        if c.get("expired"):
            out.append(("cert-expired", "medium", "Expired cert", f"The certificate on port {c['port']} expired "
                        f"({(c.get('not_after') or '')[:10]})."))
            break
    if any(c.get("weak_key") for c in deep.get("certs") or []):
        out.append(("cert-weak", "low", "Weak cert key", "A certificate uses a key shorter than 2048 bits."))
    if (deep.get("vnc") or {}).get("no_auth"):
        out.append(("vnc-noauth", "high", "VNC no password", "VNC offers access with no password at all."))
    if deep.get("ftp_anon"):
        out.append(("ftp-anon", "high", "Anonymous FTP", f"FTP on port {deep['ftp_anon']} lets anyone log in anonymously."))
    if (deep.get("ssh") or {}).get("weak"):
        out.append(("ssh-weak", "low", "Weak SSH crypto", "SSH still offers outdated algorithms: " +
                    ", ".join(deep["ssh"]["weak"][:4])))
    if deep.get("ipmi"):
        out.append(("ipmi", "medium", "IPMI exposed", "A server management controller (IPMI) answers on this network -- "
                    "these have a long history of serious flaws; keep them on a separate management network."))
    w = deep.get("windows") or {}
    if w.get("old"):
        out.append(("old-os", "medium", "Old OS", f"Reports Windows build {w['version']} ({w['name']}), which no longer "
                    "gets security updates."))
    return out
