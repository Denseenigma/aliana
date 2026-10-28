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
#
# classify_host() weighs every clue we have -- advertised services (mDNS /
# UPnP), names (NetBIOS, mDNS, DNS, UPnP), web page titles and certificates,
# open-port signatures, the MAC vendor, nmap's OS guess, a private MAC -- and
# picks the strongest. Each clue has a score; specific evidence ("advertises
# _ipp", "UPnP MediaRenderer", "page title HP LaserJet") beats a vendor guess.

import re as _re

import identify as _identify

# key -> (short code shown in the hex badge, label)
TYPES = {
    "access":  ("ACC", "Access control"),
    "camera":  ("CAM", "Camera / video"),
    "printer": ("PRN", "Printer / scanner"),
    "phone":   ("TEL", "IP phone / voice"),
    "network": ("NET", "Network equipment"),
    "nas":     ("NAS", "Storage (NAS)"),
    "server":  ("SRV", "Server / management"),
    "power":   ("PWR", "UPS / power"),
    "windows": ("WIN", "Windows computer"),
    "pc":      ("PC",  "Computer"),
    "apple":   ("MAC", "Apple computer"),
    "linux":   ("LNX", "Linux / Unix host"),
    "pi":      ("RPI", "Raspberry Pi"),
    "mobile":  ("MOB", "Phone / tablet"),
    "media":   ("TV",  "TV / media / speaker"),
    "iot":     ("IOT", "Smart home / IoT"),
    "vm":      ("VM",  "Virtual machine"),
    "unknown": ("?",   "Unknown device"),
}

# MAC vendor fragments -> (type, score). Ambiguous makers get low scores so
# any real evidence wins.
_VENDORS = [
    ("access", 70, ["paxton", "hid global", "lenel", "honeywell security", "genetec", "salto", "brivo",
                    "gallagher", "openpath", "verkada", "kisi", "assa abloy", "allegion", "s2 security"]),
    ("camera", 70, ["hikvision", "dahua", "axis communications", "hanwha", "vivotek", "uniview", "mobotix",
                    "avigilon", "reolink", "amcrest", "bosch security", "arlo", "wyze", "lorex", "swann"]),
    ("network", 65, ["cisco", "ubiquiti", "aruba", "juniper", "netgear", "mikrotik", "routerboard", "fortinet",
                     "palo alto", "meraki", "ruckus", "extreme networks", "zyxel", "d-link", "tp-link",
                     "sonicwall", "watchguard", "hewlett packard enterprise", "edgecore", "allied telesis",
                     "arista", "cambium", "eero", "linksys", "arris", "commscope", "sagemcom", "technicolor",
                     "calix", "adtran", "plume design", "draytek", "peplink", "cradlepoint", "sophos",
                     "barracuda", "space exploration", "huawei technologies", "h3c", "ruijie", "tenda",
                     "mercusys", "teltonika"]),
    ("printer", 55, ["hp inc", "hewlett packard", "brother", "canon", "seiko epson", "epson", "lexmark",
                     "xerox", "ricoh", "kyocera", "konica", "sharp corporation", "zebra", "oki electric",
                     "oki data", "fuji xerox", "fujifilm business"]),
    ("phone", 70, ["polycom", "yealink", "avaya", "grandstream", "snom", "mitel", "poly ", "plantronics",
                   "fanvil", "obihai", "htek", "algo communication", "cyberdata"]),
    ("nas", 70, ["synology", "qnap", "western digital", "buffalo", "asustor", "drobo", "terramaster",
                 "netapp", "infortrend"]),
    ("power", 75, ["american power conversion", "schneider electric", "eaton", "cyberpower", "tripp lite",
                   "vertiv", "liebert", "raritan", "server technology"]),
    ("server", 60, ["super micro", "supermicro", "inspur", "quanta"]),
    ("pi", 80, ["raspberry"]),
    ("iot", 65, ["espressif", "tuya", "sonoff", "itead", "shelly", "allterco", "lutron", "control4", "wirepath",
                 "crestron", "savant", "remote technologies", "nest labs", "ecobee", "rachio", "chamberlain",
                 "august home", "yale", "kwikset", "schlage", "eufy", "anker", "govee", "meross", "belkin",
                 "wemo", "philips lighting", "signify", "lifx", "wiz", "roborock", "ecovacs", "irobot",
                 "select comfort", "sleep number", "idevices", "simplisafe", "ring llc", "ring inc", "abode",
                 "ezviz", "xiaomi communications", "aqara", "lumi united", "silicon labs", "nordic semi",
                 "texas instruments", "particle industries", "hunter douglas", "somfy", "rheem", "carrier",
                 "trane", "honeywell home", "resideo", "emerson", "midea", "whirlpool", "ge appliances",
                 "haier", "miele", "bosch home", "sense labs", "rainbird", "orbit irrigation"]),
    ("media", 55, ["roku", "sonos", "bose", "sound united", "denon", "yamaha", "onkyo", "pioneer", "vizio",
                   "tcl", "hisense", "nvidia", "sling media", "tivo", "dish", "directv", "harman",
                   "bang & olufsen", "universal electronics", "logitech"]),
    ("mobile", 55, ["oneplus", "motorola mobility", "oppo", "vivo mobile", "realme", "hmd global", "fairphone",
                    "zte", "huawei device", "honor device", "xiaomi"]),
    ("vm", 75, ["vmware", "xensource", "parallels", "qemu", "virtualbox"]),
    ("apple", 45, ["apple"]),
    ("pc", 40, ["dell", "lenovo", "intel corporate", "intel", "asustek", "gigabyte", "micro-star",
                "hon hai", "liteon", "lite-on", "azurewave", "realtek", "framework computer", "acer",
                "microsoft corporation", "giga-byte", "elitegroup", "foxconn", "rivet networks", "killer"]),
    ("media", 35, ["samsung", "lg electronics", "sony", "panasonic", "sharp", "philips", "amazon technologies",
                   "google"]),
]

# Advertised mDNS services -> (type, score, what it means)
_MDNS = [
    (("_ipp.", "_ipps.", "_printer.", "_pdl-datastream.", "_fax-ipp.", "_scanner.", "_uscan.", "_uscans."),
     "printer", 95, "advertises printing/scanning"),
    (("_googlecast.",), "media", 92, "Google Cast / Chromecast"),
    (("_amzn-wplay.", "_amzn-alexa."), "media", 90, "Amazon Fire TV / Echo"),
    (("_androidtvremote", "_androidtvremote2."), "media", 90, "Android TV"),
    (("_sonos.", "_spotify-connect.", "_raop."), "media", 85, "audio streaming receiver"),
    (("_roku", "_dial."), "media", 80, "TV streaming (DIAL)"),
    (("_hap.", "_homekit.", "_matter.", "_matterc.", "_hue.", "_meshcop.", "_esphomelib.", "_shelly.",
      "_home-assistant.", "_hubitat.", "_lutron.", "_ecobee", "_nanoleafapi.", "_wled."),
     "iot", 92, "smart-home protocol (HomeKit / Matter / hub)"),
    (("_companion-link.", "_apple-mobdev2.", "_rdlink.", "_apple-pairable."), "apple", 70, "Apple device services"),
    (("_adisk.", "_afpovertcp.", "_timemachine"), "nas", 60, "network backup / file sharing"),
    (("_smb.",), "pc", 45, "file sharing"),
    (("_workstation.", "_ssh.", "_sftp-ssh."), "linux", 55, "Linux workstation services"),
    (("_nvstream.",), "pc", 60, "game streaming PC"),
    (("_axis-video.",), "camera", 95, "Axis video"),
    (("_rtsp.",), "camera", 70, "video stream"),
]

# UPnP deviceType fragments -> (type, score)
_UPNP = [
    ("internetgatewaydevice", "network", 92), ("wandevice", "network", 85), ("wlanaccesspoint", "network", 90),
    ("mediarenderer", "media", 85), ("printer", "printer", 92), ("scanner", "printer", 85),
    ("digitalsecuritycamera", "camera", 92), ("zoneplayer", "media", 92), ("dial", "media", 80),
    ("mediaserver", "media", 55), ("basic", None, 0),
]

# Keywords in web page titles / server headers / auth realms / certificates
_WEB = [
    ("printer", 88, r"laserjet|officejet|deskjet|pagewide|designjet|hp embedded web server|ews\b|brother|epson|"
                    r"canon|kyocera|ricoh|xerox|lexmark|konica|bizhub|sharp mx|zebra|printer|web image monitor|"
                    r"\bcups\b|imagerunner|workcentre|versalink|altalink|ecosys|taskalfa"),
    ("access", 92, r"paxton|net2|lenel|onguard|genetec|brivo|s2 netbox|verkada|access control"),
    ("camera", 88, r"hikvision|dahua|ip camera|network camera|\bnvr\b|\bdvr\b|axis|amcrest|reolink|vivotek|"
                   r"hanwha|wisenet|uniview|blue iris|milestone|unifi protect|webcam"),
    ("phone", 88, r"polycom|yealink|grandstream|cisco ip phone|avaya|snom|mitel|fanvil|3cx|poly "),
    ("nas", 88, r"synology|diskstation|qnap|truenas|freenas|unraid|readynas|my cloud|terramaster|asustor"),
    ("power", 90, r"\bapc\b|network management card|ups network|eaton|cyberpower|tripp ?lite|vertiv|liebert|"
                  r"\bpdu\b|powerchute"),
    ("server", 88, r"idrac|integrated lights-out|\bilo\b|ipmi|supermicro|xclarity|\bcimc\b|vmware esxi|"
                   r"vcenter|proxmox|hyper-v|ovirt|nutanix"),
    ("network", 85, r"unifi|ubiquiti|edgeos|edgerouter|mikrotik|routeros|pfsense|opnsense|fortigate|fortinet|"
                    r"sonicwall|meraki|cisco|aruba|netgear|tp-link|tplink|\bdeco\b|omada|asus ?wrt|asus router|"
                    r"linksys|draytek|zyxel|watchguard|juniper|openwrt|luci|dd-wrt|ruckus|eero|firewalla|"
                    r"velop|orbi|airos|switch|router|access point|gateway"),
    ("iot", 85, r"home assistant|hubitat|smartthings|philips hue|shelly|tasmota|esphome|wled|nest|ecobee|"
                r"control4|crestron|savant|lutron|rachio|myq|rti |sense monitor|octoprint"),
    ("media", 80, r"plex|jellyfin|emby|kodi|roku|sonos|bose|denon|heos|yamaha|onkyo|smart ?tv|webos|vizio|"
                  r"bravia|chromecast|apple tv"),
    ("linux", 55, r"pi-hole|ubuntu|debian|cockpit|webmin|raspberry|nextcloud|portainer|grafana"),
]
_WEB = [(t, sc, _re.compile(rx, _re.I)) for t, sc, rx in _WEB]

# Names (any source) -> type
_NAMES = [
    ("mobile", 75, r"iphone|ipad|ipod|galaxy|pixel|android|oneplus|redmi|moto[ -]?[gex]|\bsm-[a-z]\d|watch"),
    ("apple", 75, r"macbook|imac|mac-?mini|mac-?pro|mac-?studio|\bmbp\b"),
    ("windows", 70, r"^desktop-|^laptop-|^win-|^pc-|-pc$|^ws-|^wks|^lt-|^dt-|^nb-"),
    ("printer", 75, r"printer|^prn|mfp|laserjet|officejet|epson|brother|canon|kyocera|ricoh|xerox"),
    ("media", 72, r"\btv\b|-tv|roku|chromecast|fire-?tv|apple-?tv|appletv|sonos|homepod|shield|soundbar|"
                  r"speaker|living-?room|bedroom"),
    ("iot", 70, r"echo|alexa|\bnest\b|ecobee|thermostat|\bplug\b|bulb|light|switch-|esp[-_]?[0-9a-f]{4}|"
                r"tasmota|shelly|hue|doorbell|vacuum|roborock|robot|sleep ?number|simplisafe|garage"),
    ("camera", 72, r"\bcam\b|camera|-cam|cam-|nvr|dvr|doorbell"),
    ("network", 70, r"switch|router|gateway|firewall|^ap-|-ap$|unifi|\bdeco\b|^sw-|^rtr|^fw-"),
    ("nas", 72, r"\bnas\b|diskstation|synology|qnap"),
    ("pi", 75, r"raspberrypi|^pi-|-pi$"),
    ("server", 65, r"^srv|server|-dc\d*$|^dc\d|esxi|proxmox|hyperv|idrac|ilo"),
]
_NAMES = [(t, sc, _re.compile(rx, _re.I)) for t, sc, rx in _NAMES]

# Port signatures -> (type, score, why)
def _port_clues(ports):
    c = []
    if ports & {9100, 515, 631}:
        c.append(("printer", 90, "printing ports open"))
    if 554 in ports:
        c.append(("camera", 78, "video streaming (RTSP) port"))
    if ports & {5060, 5061}:
        c.append(("phone", 80, "SIP voice port"))
    if 62078 in ports:
        c.append(("mobile", 88, "iPhone/iPad sync port"))
    if ports & {8008, 8009} and 8443 in ports or {8008, 8009} <= ports:
        c.append(("media", 78, "Google Cast ports"))
    if 1400 in ports:
        c.append(("media", 80, "Sonos port"))
    if 8060 in ports:
        c.append(("media", 80, "Roku control port"))
    if 32400 in ports:
        c.append(("media", 65, "Plex media server"))
    if 8123 in ports:
        c.append(("iot", 80, "Home Assistant"))
    if ports & {1883, 8883}:
        c.append(("iot", 55, "MQTT broker/client"))
    if ports & {135, 3389, 5985, 5986} or {139, 445} <= ports:
        c.append(("windows", 76, "Windows services"))
    if 548 in ports:
        c.append(("apple", 60, "Apple file sharing"))
    if ports & {623, 664}:
        c.append(("server", 75, "server management (IPMI)"))
    if ports & {902, 9443} and 443 in ports and 902 in ports:
        c.append(("server", 75, "VMware ESXi"))
    if ports & {111, 2049}:
        c.append(("linux", 50, "NFS / RPC"))
    if ports == {22}:
        c.append(("linux", 45, "SSH only"))
    if ports & {161, 162} and len(ports) <= 3:
        c.append(("network", 40, "SNMP managed device"))
    return c


def _model_from(ident, host):
    """Best product / model string we have."""
    up = ident.get("upnp") or {}
    txt = (ident.get("mdns") or {}).get("txt") or {}
    for v in (" ".join(x for x in (up.get("manufacturer"), up.get("model")) if x) if up.get("model") else None,
              txt.get("md"), txt.get("usb_MDL") and " ".join(x for x in (txt.get("usb_MFG"), txt.get("usb_MDL")) if x),
              txt.get("ty"), txt.get("product"), txt.get("model"), txt.get("am")):
        if v:
            return v.strip("() ")[:80]
    prod = [p.get("product") for p in host.get("ports", []) if p.get("state") == "open" and p.get("product")]
    for t in (h.get("title") for h in (ident.get("http") or {}).values()):
        if t and len(t) > 3 and not _re.search(r"^(index|home|login|log in|welcome|redirect|loading|404|403)", t, _re.I):
            return t[:80]
    return None


def classify_host(host):
    """Returns {"type", "code", "label", "why", "model", "confidence", "evidence"}:
    a best guess at what the device is, from every clue available."""
    ident = host.get("ident") or {}
    vendor = (host.get("vendor") or ident.get("vendor_db") or "").lower()
    if not vendor and host.get("mac"):
        vendor = (_identify.vendor_for(host["mac"]) or "").lower()
    ports = {p["port"] for p in host.get("ports", []) if p.get("state") == "open"}
    services_txt = " ".join((p.get("service") or "") + " " + (p.get("product") or "")
                            for p in host.get("ports", []) if p.get("state") == "open").lower()
    os_name = (host.get("os_name") or "").lower()
    os_type = (host.get("os_type") or "").lower()
    names = [n for n in [host.get("hostname")] + list((ident.get("names") or {}).values()) if n]
    md = ident.get("mdns") or {}
    txt = md.get("txt") or {}
    up = ident.get("upnp") or {}
    nb = ident.get("netbios") or {}
    clues = []   # (score, type, why)

    def add(t, score, why):
        clues.append((score, t, why))

    # -- strongest: what the device says about itself
    if ident.get("gateway"):
        add("network", 96, "default gateway")
    svcs = " ".join(md.get("services") or []) + " "
    for keys, t, sc, why in _MDNS:
        if any(k in svcs for k in keys):
            add(t, sc, f"mDNS: {why}")
    model_hint = " ".join(str(txt.get(k, "")) for k in ("am", "model", "md")).lower()
    if _re.search(r"iphone|ipad|ipod|watch", model_hint):
        add("mobile", 94, f"Apple model {txt.get('model') or txt.get('am')}")
    elif _re.search(r"macbook|imac|macmini|macpro|mac\d|mac1|macstudio", model_hint):
        add("apple", 94, f"Apple model {txt.get('model') or txt.get('am')}")
    elif _re.search(r"appletv|audioaccessory|homepod", model_hint):
        add("media", 94, "Apple TV / HomePod")
    if txt.get("usb_MDL") or txt.get("ty"):
        add("printer", 93, f"printer model {txt.get('usb_MDL') or txt.get('ty')}")
    dt = (up.get("device_type") or "").lower()
    for frag, t, sc in _UPNP:
        if frag in dt and t:
            add(t, sc, f"UPnP {up.get('device_type', '').split(':')[-2] if ':' in up.get('device_type', '') else dt}")
            break
    web_blob = " ".join(" ".join(str(v) for k, v in h.items() if k in ("title", "server", "realm", "cert_cn", "cert_org"))
                        for h in (ident.get("http") or {}).values())
    up_blob = " ".join(str(up.get(k, "")) for k in ("manufacturer", "model", "description", "name", "server"))
    for t, sc, rx in _WEB:
        m = rx.search(web_blob)
        if m:
            add(t, sc, f"web page: “{m.group(0)}”")
            break
    for t, sc, rx in _WEB:
        m = rx.search(up_blob)
        if m:
            add(t, sc - 5, f"UPnP: “{m.group(0)}”")
            break
    if nb:
        if ports & {22} and not ports & {135, 445, 3389} and "linux" in os_name:
            add("linux", 70, "Samba (NetBIOS) on Linux")
        else:
            add("windows", 82 if not ident.get("private_mac") else 80, f"NetBIOS name {nb.get('name')}")
    # -- ports / OS / services
    for t, sc, why in _port_clues(ports):
        add(t, sc, why)
    if "printer" in services_txt or "jetdirect" in services_txt or "ipp" in services_txt.split():
        add("printer", 85, "printing service")
    if "rtsp" in services_txt:
        add("camera", 70, "RTSP service")
    if "printer" in os_type:
        add("printer", 70, "OS fingerprint")
    if any(k in os_type for k in ("switch", "router", "firewall", "wap", "broadband", "bridge")):
        add("network", 70, "OS fingerprint")
    if "webcam" in os_type or "camera" in os_type:
        add("camera", 70, "OS fingerprint")
    if "phone" in os_type and "voip" in os_type:
        add("phone", 70, "OS fingerprint")
    if "windows" in os_name:
        add("windows", 72, "OS fingerprint: Windows")
    if _re.search(r"mac os|macos|darwin", os_name):
        add("apple", 70, "OS fingerprint: macOS")
    if _re.search(r"\bios\b|iphone", os_name):
        add("mobile", 70, "OS fingerprint: iOS")
    if "android" in os_name:
        add("mobile", 70, "OS fingerprint: Android")
    if ("linux" in os_name or "unix" in os_name) and not clues:
        add("linux", 50, "OS fingerprint: Linux")
    # -- names
    for n in names:
        for t, sc, rx in _NAMES:
            if rx.search(n):
                add(t, sc, f"name “{n}”")
                break
    # -- vendor
    for t, sc, frags in _VENDORS:
        hit = next((f for f in frags if f in vendor), None)
        if hit:
            add(t, sc, f"maker {host.get('vendor') or ident.get('vendor_db')}")
            break
    mac_hex = _re.sub(r"[^0-9A-F]", "", (host.get("mac") or "").upper())
    if mac_hex[:6] in ("00155D",):
        add("vm", 85, "Hyper-V virtual network adapter")
    elif mac_hex[:6] in ("000C29", "005056", "000569"):
        add("vm", 85, "VMware virtual network adapter")
    elif mac_hex[:6] in ("080027", "0A0027"):
        add("vm", 85, "VirtualBox virtual network adapter")
    elif mac_hex[:6] in ("525400",):
        add("vm", 80, "KVM/QEMU virtual network adapter")
    if ident.get("private_mac") or (host.get("mac") and _identify.is_private_mac(host["mac"])):
        add("mobile", 48, "private (randomized) MAC — phones, tablets and laptops use these")

    model = _model_from(ident, host)
    if not clues:
        code, label = TYPES["unknown"]
        maker = host.get("vendor") or ident.get("vendor_db")
        if maker:
            label = f"{maker.split(',')[0].split(' Co')[0].strip()} device"
        return {"type": "unknown", "code": code, "label": label, "why": "not enough information",
                "model": model, "confidence": "none", "evidence": []}
    clues.sort(key=lambda c: -c[0])
    score, t, why = clues[0]
    # agreeing clues raise confidence
    agree = sum(1 for c in clues if c[1] == t)
    conf = "high" if score >= 85 or (score >= 70 and agree >= 2) else "medium" if score >= 55 else "low"
    code, label = TYPES[t]
    if t == "network" and ident.get("gateway"):
        label = "Router / gateway"
    if t == "mobile" and clues[0][2].startswith("private"):
        label = "Phone / tablet / laptop"
    seen, evidence = set(), []
    for sc, tt, w in clues:
        if w not in seen:
            seen.add(w)
            evidence.append({"type": tt, "score": sc, "why": w})
    return {"type": t, "code": code, "label": label, "why": why, "model": model, "confidence": conf,
            "evidence": evidence[:8]}


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
    prev = c.execute("SELECT * FROM scans WHERE " + scanner._BEFORE + " AND COALESCE(scope, 'subnet') = 'subnet' "
                     "AND subnet = ? ORDER BY finished_at DESC, id DESC LIMIT 1",
                     (cur["finished_at"], cur["finished_at"], cur["id"], cur["subnet"])).fetchone()
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


# ---------------------------------------------------------------- RMM

def rmm_check(host, device_type):
    """RMM match for a host (None when no RMM integration is set up)."""
    try:
        import rmm
        return rmm.match(host, device_type)
    except Exception:
        return None


def rmm_flag(m):
    return {"key": "rmm", "level": "medium", "label": "No RMM agent", "ports": [],
            "detail": f"Looks like a computer, but it isn't in {m['provider']} (no match by MAC or hostname)."}


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
    rmm_counts = {"managed": 0, "missing": 0, "na": 0}
    rmm_on = False
    for h in scan.get("hosts", []):
        h["device"] = classify_host(h)
        h["flags"] = host_flags(h)
        h["rmm"] = rmm_check(h, h["device"]["type"])
        if h["rmm"]:
            rmm_on = True
            rmm_counts[h["rmm"]["status"]] += 1
            if h["rmm"]["status"] == "missing":
                h["flags"].append(rmm_flag(h["rmm"]))
                h["flags"].sort(key=lambda f: LEVEL_ORDER[f["level"]])
        for f in h["flags"]:
            counts[f["level"]] += 1
        h["is_new"] = h["ip"] in new_ips
        for p in h.get("ports", []):
            p["is_new"] = (h["ip"], p["port"], p["protocol"]) in opened
    scan["flag_counts"] = counts
    scan["rmm"] = rmm_counts if rmm_on else None
    scan["flag_total"] = sum(counts.values())
    return scan
