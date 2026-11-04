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
import fpdb as _fpdb

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
    # broad families -- only the FINGERPRINT system votes these, so they
    # mostly confirm (or dispute) a more specific answer
    "unix":    ("NIX", "Unix-like (Linux / Apple / Android)"),
    "embedded": ("EMB", "Network gear / embedded"),
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


_DHCP_VENDORS = [   # (type, score, regex on the DHCP vendor class, label)
    ("windows", 84, _re.compile(r"^msft", _re.I), "Windows"),
    ("mobile", 88, _re.compile(r"^android-dhcp-?(\d*)", _re.I), "Android"),
    ("pi", 86, _re.compile(r"^dhcpcd.*(rpi|bcm27|bcm2835|bcm2711|raspberry)", _re.I), "Raspberry Pi"),
    ("linux", 70, _re.compile(r"^dhcpcd|^dhclient|systemd", _re.I), "Linux"),
    ("phone", 88, _re.compile(r"yealink|polycom|mitel|grandstream|avaya|snom|cisco.*phone|ip ?phone", _re.I), "IP phone"),
    ("printer", 85, _re.compile(r"jetdirect|hewlett|brother|epson|canon|lexmark|xerox|ricoh|kyocera|konica|sharp", _re.I), "printer"),
    ("camera", 85, _re.compile(r"axis|hikvision|dahua|hanwha|vivotek|reolink", _re.I), "camera"),
    ("network", 78, _re.compile(r"ubnt|ubiquiti|aruba|meraki|fortinet|cisco|juniper|mikrotik|tp-?link|netgear", _re.I), "network device"),
    ("iot", 55, _re.compile(r"^udhcp", _re.I), "embedded Linux"),
    ("pc", 45, _re.compile(r"^pxeclient", _re.I), "network boot"),
]


def _dhcp_clues(dh, host, ident):
    """Clues from the DHCP request a device broadcast (passive.py)."""
    if not dh:
        return []
    out = []
    vc = dh.get("vendor_class") or ""
    for t, sc, rx, label in _DHCP_VENDORS:
        m = rx.search(vc)
        if m:
            extra = f" {m.group(1)}" if label == "Android" and m.lastindex and m.group(1) else ""
            out.append((t, sc, f"DHCP: {label}{extra} (“{vc[:40]}”)"))
            break
    params = [p for p in (dh.get("params") or "").split(",") if p]
    if params and not vc:
        ps = set(params)
        private = ident.get("private_mac") or (host.get("mac") and _identify.is_private_mac(host["mac"]))
        if params[:2] == ["1", "121"] and {"108", "114"} & ps or params[:4] == ["1", "121", "3", "6"]:
            out.append(("mobile" if private else "apple", 80, "DHCP fingerprint: Apple (iOS / macOS)"))
        elif {"249", "252", "43"} <= ps:
            out.append(("windows", 72, "DHCP fingerprint: Windows"))
        elif {"26", "28", "51", "58", "59"} <= ps:
            out.append(("linux", 50, "DHCP fingerprint: Linux / Android"))
    return out


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


# ---------------------------------------------------------------- the triad
#
# Three independent systems each look at their own evidence and vote on what
# a device is. Two agreeing systems confirm the answer.
#
#   SCAN         what the device serves when asked: open ports, services,
#                web pages, the NetBIOS / mDNS / UPnP / DNS lookups Aliana
#                sent, and its scanned MAC (maker, virtual / random prefixes).
#   LISTEN       what it announced on its own, heard by passive.py: DHCP,
#                mDNS / UPnP / NetBIOS announcements.
#   FINGERPRINT  how it behaves: network-stack traits (TTL, IP ID, TCP
#                options), reply timing (wired / wireless), nmap's OS
#                fingerprint, and the RMM record when there is one.
#
# Your own label (labels.py) overrules all three.

SYSTEMS = [
    {"key": "scan", "name": "SCAN", "num": "1", "desc": "What it serves when asked: ports, services, web pages, name lookups, its MAC"},
    {"key": "listen", "name": "LISTEN", "num": "2", "desc": "What it announced on its own: DHCP, mDNS, UPnP, NetBIOS"},
    {"key": "fingerprint", "name": "FINGERPRINT", "num": "3",
     "desc": "How it behaves: network stack, timing, OS fingerprint, RMM record"},
]
MIN_VOTE = 40     # a system whose best clue scores below this abstains
DISSENT_MIN = 55  # weaker votes can confirm an answer but not dispute it

# Types that agree with each other: a broad answer ("a computer",
# "Unix-like") and a specific one ("a Mac") are the same answer.
_COMPAT = {
    "pc": {"windows", "linux", "apple", "vm", "server", "unix", "pi"},
    "unix": {"linux", "apple", "mobile", "pi", "nas", "media", "iot", "server", "camera", "printer", "phone",
             "access", "power", "network", "vm", "embedded"},
    "embedded": {"network", "printer", "access", "camera", "phone", "power", "iot", "media", "nas"},
    "linux": {"pi", "server", "nas", "vm"},
    "windows": {"vm", "server"},
    "server": {"linux", "vm"},
    "iot": {"camera", "media", "power", "access"},
}
_RANK = {"pc": 1, "unix": 1, "embedded": 1, "iot": 2, "linux": 2, "server": 4}


def _compatible(a, b):
    return a == b or b in _COMPAT.get(a, ()) or a in _COMPAT.get(b, ())


def _specific(a, b):
    """Of two compatible types, the more specific one."""
    return a if _RANK.get(a, 3) >= _RANK.get(b, 3) else b


def _median(xs):
    xs = sorted(xs)
    n = len(xs)
    return (xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2) if xs else None


def _fingerprint_clues(host, ident, private):
    """(clues [(type, score, why)], facts [str]) from the network stack and timing."""
    pv = ident.get("passive") or {}
    st = pv.get("stack") or {}
    rt = pv.get("rtt") or {}
    clues, facts = [], []
    ttl0 = st.get("ttl0")
    if ttl0 == 128:
        clues.append(("windows", 72, "network stack: starts at TTL 128 (Windows)"))
    elif ttl0 == 64:
        clues.append(("unix", 60, "network stack: starts at TTL 64 (Linux / Apple / Android / most appliances)"))
    elif ttl0 == 255:
        clues.append(("embedded", 62, "network stack: starts at TTL 255 (network gear / embedded)"))
    if ttl0:
        facts.append(f"TTL {st.get('ttl')} (starts {ttl0}){' · DF' if st.get('df') else ''}")
    ids = st.get("ipids") or []
    if len(ids) >= 3:
        diffs = [(b - a) % 65536 for a, b in zip(ids, ids[1:])]
        if all(i == 0 for i in ids):
            pat = "always 0"
            if ttl0 == 64:
                clues.append(("unix", 64, "IP ID always 0 (Linux / Android)"))
        elif all(0 < d < 2048 for d in diffs):
            pat = "counts up"
            if ttl0 == 128:
                clues.append(("windows", 76, "IP ID counts up with TTL 128 (Windows)"))
        else:
            pat = "random"
        facts.append(f"IP ID {pat}")
    syn = st.get("syn") or {}
    if syn.get("opts"):
        facts.append(f"its own connections: window {syn.get('win')}, options {syn['opts']}")
    sig = _fpdb.stack_signature(st)
    if sig:
        t = "mobile" if sig["type"] == "apple" and private else sig["type"]
        clues.append((t, sig["score"], f"looks like {sig['name']} ({sig['basis']})"))
        facts.insert(0, f"stack signature: {sig['name']}{' — OUT OF SUPPORT' if sig['old'] else ''}")
    cc, cf, old = _fpdb.chatter_clues(pv.get("chatter"))
    clues += cc
    facts += cf
    if old and not (sig and sig["old"]):
        facts.append(f"announces {old} — OUT OF SUPPORT")
    sa = st.get("synack") or {}
    mss = syn.get("mss") or sa.get("mss")
    if mss and mss < 1000:
        clues.append(("embedded", 58, f"tiny packet size (MSS {mss}): small embedded TCP stack"))
    elif mss and mss < 1400:
        facts.append(f"MSS {mss}: behind a VPN / tunnel")
    samples = rt.get("samples") or []
    iface = rt.get("iface") or ""
    if len(samples) >= 3:
        med = _median(samples)
        spread = max(samples) - min(samples)
        if iface.startswith("wl"):
            facts.append(f"replies in {med:.1f} ms (the Pi is on Wi-Fi, so wired vs wireless can't be told)")
        elif iface.startswith(("eth", "en")):
            if med < 1.2 and spread < 3:
                facts.append(f"wired: replies in {med:.2f} ms, steadily")
            elif med > 2.5 or spread > 8:
                facts.append(f"wireless: replies in {med:.1f} ms, varying by {spread:.0f} ms")
                clues.append(("mobile", 42, f"replies like a Wi-Fi device ({med:.1f} ms, jittery)"))
            else:
                facts.append(f"replies in {med:.1f} ms")
    return clues, facts


def _rmm_clues(host):
    try:
        import rmm
        m = rmm.match(host)
    except Exception:
        return []
    if not m or m.get("status") != "managed":
        return []
    d = m.get("device") or {}
    os_ = (d.get("os") or "").lower()
    cat = (d.get("category") or "").lower()
    src = f"{m.get('provider')}: {d.get('os') or d.get('category') or 'managed device'}"
    if "server" in os_ or "server" in cat or "esxi" in cat:
        return [("server", 90, src)]
    if "windows" in os_:
        return [("windows", 92, src)]
    if "mac" in os_ or "darwin" in os_:
        return [("apple", 92, src)]
    if "linux" in os_ or "ubuntu" in os_ or "debian" in os_:
        return [("linux", 88, src)]
    if "printer" in cat:
        return [("printer", 85, src)]
    if "network" in cat:
        return [("network", 85, src)]
    if cat in ("desktop", "laptop", "workstation"):
        return [("pc", 80, src)]
    return [("pc", 60, src)]


def classify_host(host):
    """Returns {"type", "code", "label", "why", "model", "confidence", "evidence",
    "consensus"}: each system's vote, and the decision."""
    ident = host.get("ident") or {}
    private = ident.get("private_mac") or (host.get("mac") and _identify.is_private_mac(host["mac"]))
    vendor = (host.get("vendor") or ident.get("vendor_db") or "").lower()
    if not vendor and host.get("mac") and not private:
        vendor = (_identify.vendor_for(host["mac"]) or "").lower()
    ports = {p["port"] for p in host.get("ports", []) if p.get("state") == "open"}
    services_txt = " ".join((p.get("service") or "") + " " + (p.get("product") or "")
                            for p in host.get("ports", []) if p.get("state") == "open").lower()
    os_name = (host.get("os_name") or "").lower()
    os_type = (host.get("os_type") or "").lower()
    md = ident.get("mdns") or {}
    txt = md.get("txt") or {}
    up = ident.get("upnp") or {}
    nb = ident.get("netbios") or {}
    md_sys = "listen" if md.get("passive") else "scan"
    up_sys = "listen" if up.get("passive") else "scan"
    nb_sys = "listen" if nb.get("passive") else "scan"
    clues = []   # (score, type, why, system)

    def add(t, score, why, sys):
        clues.append((score, t, why, sys))

    facts = []
    # -- LISTEN: the DHCP request it broadcast
    for t, sc, why in _dhcp_clues((ident.get("passive") or {}).get("dhcp") or {}, host, ident):
        add(t, sc, why, "listen")
    # -- SCAN: it's the address Aliana routes through
    if ident.get("gateway"):
        add("network", 96, "default gateway (routing table)", "scan")
    # -- FINGERPRINT: stack + timing, RMM
    fc, ff = _fingerprint_clues(host, ident, private)
    for t, sc, why in fc:
        add(t, sc, why, "fingerprint")
    facts += ff
    for t, sc, why in _rmm_clues(host):
        add(t, sc, why, "fingerprint")
        facts.append(why)
    # -- SCAN or LISTEN, depending on whether we asked or it announced
    svcs = " ".join(md.get("services") or []) + " "
    for keys, t, sc, why in _MDNS:
        if any(k in svcs for k in keys):
            add(t, sc, f"mDNS: {why}", md_sys)
    model_hint = " ".join(str(txt.get(k, "")) for k in ("am", "model", "md", "rpMd")).lower()
    if _re.search(r"iphone|ipad|ipod|watch", model_hint):
        add("mobile", 94, f"Apple model {txt.get('model') or txt.get('am') or txt.get('rpMd')}", md_sys)
    elif _re.search(r"macbook|imac|macmini|macpro|mac\d|mac1|macstudio", model_hint):
        add("apple", 94, f"Apple model {txt.get('model') or txt.get('am') or txt.get('rpMd')}", md_sys)
    elif _re.search(r"appletv|audioaccessory|homepod", model_hint):
        add("media", 94, "Apple TV / HomePod", md_sys)
    if txt.get("usb_MDL") or txt.get("ty"):
        add("printer", 93, f"printer model {txt.get('usb_MDL') or txt.get('ty')}", md_sys)
    dt = (up.get("device_type") or "").lower()
    for frag, t, sc in _UPNP:
        if frag in dt and t:
            add(t, sc, f"UPnP {up.get('device_type', '').split(':')[-2] if ':' in up.get('device_type', '') else dt}", up_sys)
            break
    web_blob = " ".join(" ".join(str(v) for k, v in h.items() if k in ("title", "server", "realm", "cert_cn", "cert_org"))
                        for h in (ident.get("http") or {}).values())
    up_blob = " ".join(str(up.get(k, "")) for k in ("manufacturer", "model", "description", "name", "server"))
    for t, sc, rx in _WEB:
        m = rx.search(web_blob)
        if m:
            add(t, sc, f"web page: “{m.group(0)}”", "scan")
            break
    for t, sc, rx in _WEB:
        m = rx.search(up_blob)
        if m:
            add(t, sc - 5, f"UPnP: “{m.group(0)}”", up_sys)
            break
    if nb:
        if ports & {22} and not ports & {135, 445, 3389} and "linux" in os_name:
            add("linux", 70, "Samba (NetBIOS) on Linux", nb_sys)
        else:
            add("windows", 82 if not private else 80, f"NetBIOS name {nb.get('name')}", nb_sys)
    # -- SCAN: ports / OS / services
    for t, sc, why in _port_clues(ports):
        add(t, sc, why, "scan")
    if "printer" in services_txt or "jetdirect" in services_txt or "ipp" in services_txt.split():
        add("printer", 85, "printing service", "scan")
    if "rtsp" in services_txt:
        add("camera", 70, "RTSP service", "scan")
    if "printer" in os_type:
        add("printer", 70, "nmap OS fingerprint", "fingerprint")
    if any(k in os_type for k in ("switch", "router", "firewall", "wap", "broadband", "bridge")):
        add("network", 70, "nmap OS fingerprint", "fingerprint")
    if "webcam" in os_type or "camera" in os_type:
        add("camera", 70, "nmap OS fingerprint", "fingerprint")
    if "phone" in os_type and "voip" in os_type:
        add("phone", 70, "nmap OS fingerprint", "fingerprint")
    if "windows" in os_name:
        add("windows", 72, "nmap OS fingerprint: Windows", "fingerprint")
    if _re.search(r"mac os|macos|darwin", os_name):
        add("apple", 70, "nmap OS fingerprint: macOS", "fingerprint")
    if _re.search(r"\bios\b|iphone", os_name):
        add("mobile", 70, "nmap OS fingerprint: iOS", "fingerprint")
    if "android" in os_name:
        add("mobile", 70, "nmap OS fingerprint: Android", "fingerprint")
    if ("linux" in os_name or "unix" in os_name) and not any(c[3] == "fingerprint" and c[0] >= 70 for c in clues):
        add("linux", 50, "nmap OS fingerprint: Linux", "fingerprint")
    # -- names, credited to whichever system learned them
    names = ident.get("names") or {}
    name_src = {"netbios": nb_sys, "mdns": md_sys, "mdns_instance": md_sys, "upnp": up_sys,
                "dns": "scan", "dhcp": "listen"}
    named = []
    for k, n in names.items():
        if n and (n, name_src.get(k, "scan")) not in named:
            named.append((n, name_src.get(k, "scan")))
    if host.get("hostname") and not any(n == host["hostname"] for n, _ in named):
        named.append((host["hostname"], "scan"))
    for n, sys_ in named:
        for t, sc, rx in _NAMES:
            if rx.search(n):
                add(t, sc, f"name “{n}”", sys_)
                break
    # -- SCAN: what its scanned MAC says (registries)
    for t, sc, frags in _VENDORS:
        hit = next((f for f in frags if f in vendor), None)
        if hit:
            add(t, sc, f"maker {host.get('vendor') or ident.get('vendor_db')}", "scan")
            break
    mac_hex = _re.sub(r"[^0-9A-F]", "", (host.get("mac") or "").upper())
    if mac_hex[:6] in ("00155D",):
        add("vm", 85, "Hyper-V virtual network adapter", "scan")
    elif mac_hex[:6] in ("000C29", "005056", "000569"):
        add("vm", 85, "VMware virtual network adapter", "scan")
    elif mac_hex[:6] in ("080027", "0A0027"):
        add("vm", 85, "VirtualBox virtual network adapter", "scan")
    elif mac_hex[:6] in ("525400",):
        add("vm", 80, "KVM/QEMU virtual network adapter", "scan")
    if private:
        add("mobile", 48, "private (randomized) MAC — phones, tablets and laptops use these", "scan")

    model = _model_from(ident, host)
    consensus = _decide(clues)
    vend = next(((c[1], c[0]) for c in clues if c[3] == "scan" and c[2].startswith("maker ") and c[0] >= 40), None)
    fpv = next((v for v in consensus["votes"] if v["system"] == "fingerprint" and not v["abstain"]), None)
    if vend and fpv:
        mm = _fpdb.mismatch(vend[0], host.get("vendor") or ident.get("vendor_db"), fpv["type"], fpv["score"], _compatible)
        if mm:
            consensus["mismatch"] = mm
    consensus["facts"] = facts
    try:
        import labels
        lab = labels.get(host.get("mac"))
    except Exception:
        lab = None
    if lab and lab.get("type") in TYPES:
        code, label = TYPES[lab["type"]]
        consensus["override"] = {"type": lab["type"], "code": code, "label": label, "name": lab.get("name"),
                                 "note": lab.get("note"), "at": lab.get("at"),
                                 "agrees": consensus.get("type") is not None and _compatible(consensus["type"], lab["type"])}
        ev = [{"type": lab["type"], "score": 100, "why": "set by you" + (f": {lab['note']}" if lab.get("note") else ""),
               "system": "you"}]
        for sc, tt, w, sy in sorted(clues, key=lambda c: -c[0])[:9]:
            ev.append({"type": tt, "score": sc, "why": w, "system": sy})
        return {"type": lab["type"], "code": code, "label": label, "why": "set by you", "model": model,
                "confidence": "high", "evidence": ev, "consensus": consensus, "name": lab.get("name")}
    if consensus["state"] == "none":
        code, label = TYPES["unknown"]
        maker = host.get("vendor") or ident.get("vendor_db")
        if maker:
            label = f"{maker.split(',')[0].split(' Co')[0].strip()} device"
        return {"type": "unknown", "code": code, "label": label, "why": "not enough information",
                "model": model, "confidence": "none", "evidence": [], "consensus": consensus}
    t, why, score = consensus["type"], consensus["why"], consensus["score"]
    state = consensus["state"]
    if state in ("unanimous", "confirmed"):
        conf = "high"
    elif state == "single":
        conf = "medium" if score >= 55 else "low"
    else:   # disputed
        conf = "medium" if score >= 85 else "low"
    code, label = TYPES[t]
    if t == "network" and ident.get("gateway"):
        label = "Router / gateway"
    if t == "mobile" and why.startswith("private"):
        label = "Phone / tablet / laptop"
    seen, evidence = set(), []
    for sc, tt, w, sy in sorted(clues, key=lambda c: -c[0]):
        if (w, sy) not in seen:
            seen.add((w, sy))
            evidence.append({"type": tt, "score": sc, "why": w, "system": sy})
    return {"type": t, "code": code, "label": label, "why": why, "model": model, "confidence": conf,
            "evidence": evidence[:10], "consensus": consensus}


def _decide(clues):
    """Each system votes for its best-supported type; then the vote."""
    votes = []
    for sysd in SYSTEMS:
        mine = sorted((c for c in clues if c[3] == sysd["key"]), key=lambda c: -c[0])
        if not mine or mine[0][0] < MIN_VOTE:
            votes.append({"system": sysd["key"], "name": sysd["name"], "num": sysd["num"], "type": None,
                          "abstain": True, "why": mine[0][2] if mine else None,
                          "score": mine[0][0] if mine else 0, "clues": len(mine)})
            continue
        # a system's own agreeing clues add a little weight
        t = mine[0][1]
        support = sum(1 for c in mine[1:] if _compatible(c[1], t) and c[0] >= MIN_VOTE)
        for c in mine[1:]:
            if _compatible(c[1], t):
                t = _specific(t, c[1])
        score = min(99, mine[0][0] + 4 * support)
        code, label = TYPES[t]
        votes.append({"system": sysd["key"], "name": sysd["name"], "num": sysd["num"], "type": t, "code": code,
                      "label": label, "score": score, "why": mine[0][2], "clues": len(mine), "abstain": False})
    cast = [v for v in votes if not v["abstain"]]
    if not cast:
        return {"state": "none", "votes": votes, "agree": 0, "voting": 0, "type": None, "why": None, "score": 0}
    # best group of mutually compatible votes
    best = None
    for v in cast:
        group = [w for w in cast if _compatible(w["type"], v["type"])]
        t = v["type"]
        for w in group:
            t = _specific(t, w["type"])
        key = (len(group), sum(w["score"] for w in group))
        if best is None or key > best[0]:
            best = (key, t, group)
    (n, _), t, group = best
    lead = max(group, key=lambda w: w["score"])
    # a weak dissent (e.g. just "private MAC") doesn't dispute a strong answer
    dissent = [w for w in cast if w not in group and w["score"] >= DISSENT_MIN]
    if n >= 2:
        state = "unanimous" if n == 3 else "confirmed"
    elif not dissent:
        state = "single"
    else:
        state = "disputed"
    for v in votes:
        v["agrees"] = (not v["abstain"]) and v in group
        v["dissents"] = (not v["abstain"]) and v not in group
    score = lead["score"] if n < 2 else min(99, max(w["score"] for w in group) + 5 * (n - 1))
    return {"state": state, "votes": votes, "agree": n, "voting": len(cast), "type": t,
            "code": TYPES[t][0], "label": TYPES[t][1], "why": lead["why"], "score": score}


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
    pv = (host.get("ident") or {}).get("passive") or {}
    sig = _fpdb.stack_signature(pv.get("stack"))
    _, _, old = _fpdb.chatter_clues(pv.get("chatter"))
    old = (sig["name"] if sig and sig["old"] else None) or old
    if old:
        flags.append({"key": "old-os", "level": "medium", "label": "Old OS",
                      "detail": f"Its network behaviour matches {old}, which no longer gets security updates.", "ports": []})
    if "BitTorrent" in ((pv.get("chatter") or {}).get("apps") or {}):
        flags.append({"key": "p2p", "level": "low", "label": "BitTorrent",
                      "detail": "A BitTorrent client is running on this device (peer-to-peer file sharing).", "ports": []})
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
    import passive
    for h in scan.get("hosts", []):
        if h.get("mac"):   # + what the device announced since (passive discovery)
            h["ident"] = passive.merge_into(h.get("ident") or {}, h["mac"])
            if not h.get("hostname") and h["ident"].get("name"):
                h["hostname"] = h["ident"]["name"]
        h["device"] = classify_host(h)
        if h["device"].get("name"):      # your label's name
            h["hostname"] = h["device"]["name"]
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
    tri = {}
    for h in scan.get("hosts", []):
        st = (h["device"].get("consensus") or {}).get("state", "none")
        tri[st] = tri.get(st, 0) + 1
    scan["triad"] = tri
    scan["rmm"] = rmm_counts if rmm_on else None
    scan["flag_total"] = sum(counts.values())
    return scan
