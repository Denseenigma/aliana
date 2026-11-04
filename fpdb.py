"""
fpdb.py - the FINGERPRINT system's signature library.

Turns the raw traits passive.py measures into named answers:

  stack_signature(stack)  network-stack traits -> "Windows 10 / 11",
                          "macOS / iOS", "Linux 5.x+", "Cisco IOS"...
  chatter_clues(chatter)  the background apps a device broadcasts for
                          (Dropbox, Steam, Spotify, WS-Discovery, SSDP
                          user agents, Windows browser announcements...)

Everything returns plain dicts / tuples; insights.py turns them into votes.
Signatures are best-effort: they name a family and era, not an exact build.
"""
import re

# ---------------------------------------------------------------- network stack
#
# A device's own SYN (when it connects to the Pi -- e.g. a laptop opening the
# dashboard) carries its full option set, the strongest signature. Replies
# to Aliana's scans (SYN-ACK) only echo the options nmap offered (MSS), so
# those signatures lean on TTL, window size, IP ID and DF.
#
# (ttl0, options, windows, window scales, name, type, score, old)
#   options / windows / scales: None = any

_SYN = [
    (128, "M,N,W,N,N,S", {64240, 65535}, {8}, "Windows 10 / 11 / Server 2016+", "windows", 88, False),
    (128, "M,N,W,N,N,S", {8192}, {2, 8}, "Windows 7 / 8 / Server 2008-2012", "windows", 86, True),
    (128, "M,N,W,N,N,S", None, None, "Windows (Vista or later)", "windows", 80, False),
    (128, "M,N,N,S", {65535, 64512, 16384}, None, "Windows XP / Server 2003", "windows", 84, True),
    (64, "M,N,W,N,N,T,S,E", {65535}, None, "macOS / iOS / iPadOS", "apple", 86, False),
    (64, "M,N,W,N,N,T,S", {65535}, None, "macOS / iOS / iPadOS", "apple", 82, False),
    (64, "M,S,T,N,W", {64240, 65535, 65160}, {7, 8, 9, 10}, "Linux 4.19+ / Android 9+", "unix", 80, False),
    (64, "M,S,T,N,W", {29200, 28800}, None, "Linux 3.x-4.x / Android", "unix", 78, False),
    (64, "M,S,T,N,W", {14600, 5840, 5720}, None, "Linux 2.6 (old)", "unix", 76, True),
    (64, "M,S,T,N,W", None, None, "Linux / Android", "unix", 72, False),
    (64, "M,N,W,S,T", {65535}, {6}, "FreeBSD (pfSense, OPNsense, TrueNAS...)", "unix", 78, False),
    (64, "M,N,W,N,N,S", None, None, "Unix-like with Windows-style options (BSD / embedded)", "unix", 60, False),
    (255, "M", None, None, "Embedded TCP stack", "embedded", 66, False),
    (64, "M", None, None, "Minimal TCP stack (embedded)", "embedded", 60, False),
]

# Replies to scans: (ttl0, ipid pattern, df, windows, mss, name, type, score, old)
_SYNACK = [
    (128, None, None, {64240}, None, "Windows 10 / 11 / Server 2016+", "windows", 78, False),
    (128, None, None, {65535}, None, "Windows (Server / 10+)", "windows", 74, False),
    (128, None, None, {8192}, None, "Windows 7 / 8 / Server 2008-2012", "windows", 74, True),
    (128, None, None, {16384, 64512}, None, "Windows XP / Server 2003", "windows", 72, True),
    (128, None, None, None, None, "Windows", "windows", 70, False),
    (64, "zero", True, {65160, 64240}, None, "Linux 4.19+", "unix", 74, False),
    (64, "zero", True, {28960, 29200}, None, "Linux 3.x-4.x", "unix", 72, False),
    (64, "zero", True, {14480, 14600, 5792, 5840}, None, "Linux 2.6 (old)", "unix", 72, True),
    (64, "zero", True, None, None, "Linux", "unix", 68, False),
    (64, "random", True, {65535}, None, "macOS / iOS / BSD", "unix", 70, False),
    (255, None, None, {4128}, None, "Cisco IOS", "network", 82, False),
    (255, None, None, None, 536, "Small embedded stack (lwIP / RTOS)", "embedded", 70, False),
    (64, None, None, None, 536, "Small embedded stack (lwIP / RTOS)", "embedded", 68, False),
    (255, None, None, None, None, "Network gear / embedded", "embedded", 64, False),
]


def ipid_pattern(ids):
    if not ids or len(ids) < 3:
        return None
    if all(i == 0 for i in ids):
        return "zero"
    diffs = [(b - a) % 65536 for a, b in zip(ids, ids[1:])]
    if all(0 < d < 2048 for d in diffs):
        return "incremental"
    return "random"


def stack_signature(stack):
    """-> {"name", "type", "score", "old", "basis"} or None."""
    if not stack or not stack.get("ttl0"):
        return None
    ttl0 = stack["ttl0"]
    syn = stack.get("syn") or {}
    if syn.get("opts"):
        o, win, ws = syn["opts"], syn.get("win"), syn.get("ws")
        for t, opts, wins, scales, name, typ, sc, old in _SYN:
            if t == ttl0 and o.startswith(opts) and (wins is None or win in wins) and \
                    (scales is None or ws in scales):
                return {"name": name, "type": typ, "score": sc, "old": old, "basis": "its own connection signature"}
    sa = stack.get("synack") or {}
    if sa:
        pat = ipid_pattern(stack.get("ipids"))
        for t, pp, df, wins, mss, name, typ, sc, old in _SYNACK:
            if t != ttl0 or (pp and pp != pat) or (df is not None and df != stack.get("df")):
                continue
            if (wins is None or sa.get("win") in wins) and (mss is None or sa.get("mss") == mss):
                return {"name": name, "type": typ, "score": sc, "old": old, "basis": "how it answers connections"}
    return None


# ---------------------------------------------------------------- background chatter
#
# UDP broadcast / multicast that apps send on their own. Port -> app.

CHATTER_PORTS = {
    17500: "Dropbox", 57621: "Spotify", 27036: "Steam", 21027: "Syncthing", 1716: "KDE Connect",
    6771: "BitTorrent", 10001: "Ubiquiti discovery", 5678: "MikroTik discovery", 32412: "Plex",
    32414: "Plex", 56700: "LIFX", 5355: "LLMNR", 3702: "WS-Discovery", 138: "Windows browser",
    3483: "Squeezebox", 9956: "AllJoyn", 6666: "Tuya", 6667: "Tuya", 20002: "Philips Hue",
    47808: "BACnet", 2222: "EtherNet/IP",
}

# app -> (type, score, why)
_APP_CLUES = {
    "Dropbox": ("pc", 72, "runs Dropbox (desktop app)"),
    "Steam": ("pc", 76, "runs Steam (gaming PC)"),
    "Spotify": ("pc", 52, "runs Spotify (desktop or phone app)"),
    "Syncthing": ("pc", 50, "runs Syncthing"),
    "BitTorrent": ("pc", 60, "runs a BitTorrent client"),
    "Ubiquiti discovery": ("network", 86, "Ubiquiti discovery broadcasts"),
    "MikroTik discovery": ("network", 88, "MikroTik neighbour discovery"),
    "LIFX": ("iot", 86, "LIFX smart bulb protocol"),
    "Tuya": ("iot", 84, "Tuya smart-home protocol"),
    "Philips Hue": ("iot", 70, "Philips Hue protocol"),
    "Squeezebox": ("media", 80, "Squeezebox / Logitech Media protocol"),
    "BACnet": ("iot", 84, "BACnet building-automation broadcasts"),
    "EtherNet/IP": ("iot", 80, "EtherNet/IP industrial broadcasts"),
    "LLMNR": ("windows", 52, "asks for names via LLMNR (Windows, or Linux with systemd)"),
}

_UA = [   # SSDP M-SEARCH user agents
    (re.compile(r"Microsoft-Windows/(\d+\.\d+)", re.I), "windows", 82, "Windows"),
    (re.compile(r"\biOS/(\d+[.\d]*)", re.I), "mobile", 86, "iOS"),
    (re.compile(r"\bAndroid/?\s?(\d+[.\d]*)", re.I), "mobile", 84, "Android"),
    (re.compile(r"Darwin/|Mac OS X|macOS/(\d+[.\d]*)?", re.I), "apple", 78, "macOS"),
    (re.compile(r"Xbox", re.I), "media", 86, "Xbox"),
    (re.compile(r"PlayStation|PS[45]", re.I), "media", 86, "PlayStation"),
    (re.compile(r"SEC_HHP|Tizen|webOS|Roku|BRAVIA|AppleTV", re.I), "media", 84, "smart TV"),
    (re.compile(r"Sonos", re.I), "media", 86, "Sonos"),
    (re.compile(r"Linux/(\d+[.\d]*)", re.I), "unix", 60, "Linux"),
]

_WSD_TYPES = [
    ("NetworkVideoTransmitter", "camera", 90, "ONVIF camera (WS-Discovery)"),
    ("PrintDeviceType", "printer", 88, "printer (WS-Discovery)"),
    ("ScanDeviceType", "printer", 82, "scanner (WS-Discovery)"),
    ("pub:Computer", "windows", 80, "Windows computer (WS-Discovery)"),
    ("Computer", "windows", 70, "computer (WS-Discovery)"),
]

_WIN_VERSIONS = {"10.0": ("Windows 10 / 11 / Server 2016+", False), "6.3": ("Windows 8.1 / Server 2012 R2", True),
                 "6.2": ("Windows 8 / Server 2012", True), "6.1": ("Windows 7 / Server 2008 R2", True),
                 "6.0": ("Windows Vista / Server 2008", True), "5.1": ("Windows XP", True),
                 "5.2": ("Windows XP x64 / Server 2003", True)}


def chatter_clues(ch):
    """-> (clues [(type, score, why)], facts [str], old_os name or None)"""
    if not ch:
        return [], [], None
    clues, facts, old = [], [], None
    apps = sorted((ch.get("apps") or {}).keys())
    for a in apps:
        if a in _APP_CLUES:
            clues.append(_APP_CLUES[a])
    shown = [a for a in apps if a not in ("WS-Discovery", "Windows browser", "LLMNR", "SSDP search")]
    if shown:
        facts.append("broadcasts for: " + ", ".join(shown))
    for ua in (ch.get("ua") or [])[:4]:
        for rx, t, sc, label in _UA:
            m = rx.search(ua)
            if m:
                ver = m.group(1) if m.lastindex and m.group(1) else ""
                if label == "Windows" and ver:
                    label = _WIN_VERSIONS.get(ver, (f"Windows {ver}", False))[0]
                    if _WIN_VERSIONS.get(ver, (None, False))[1]:
                        old = label
                clues.append((t, sc, f"app user agent: {label}{' ' + ver if ver and label in ('iOS', 'Android', 'macOS') else ''}"))
                break
    if ch.get("ua"):
        facts.append(f"user agent “{ch['ua'][0][:70]}”")
    wsd = ch.get("wsd") or {}
    for frag, t, sc, why in _WSD_TYPES:
        if any(frag in x for x in wsd.get("types", [])):
            clues.append((t, sc, why))
            break
    if wsd.get("types"):
        facts.append("WS-Discovery: " + " ".join(x.split(":")[-1] for x in wsd["types"][:4]))
    elif wsd.get("probes"):
        clues.append(("windows", 50, "searches for devices with WS-Discovery (Windows)"))
    if ch.get("ports"):
        facts.append("also broadcasts on UDP " + ", ".join(sorted(ch["ports"], key=int)[:6]))
    br = ch.get("browser") or {}
    if br.get("os"):
        stype = br.get("type") or 0
        if stype & 0x800:                       # SV_TYPE_SERVER_UNIX: Samba
            clues.append(("nas", 74, f"Samba file server announcing as “{br.get('name')}”"))
            facts.append("Samba (Unix file sharing) browser announcements")
        elif stype & 0x08:                      # SV_TYPE_DOMAIN_CTRL
            clues.append(("server", 92, "announces itself as a Windows domain controller"))
        else:
            name, is_old = _WIN_VERSIONS.get(br["os"], (f"Windows {br['os']}", False))
            clues.append(("server" if stype & 0x8000 and not stype & 0x1 else "windows", 84,
                          f"Windows browser announcement: {name}"))
            if is_old:
                old = name
        if br.get("comment"):
            facts.append(f"describes itself as “{br['comment'][:50]}”")
    for k in ("ubnt", "mndp"):
        d = ch.get(k) or {}
        bits = [d.get(x) for x in ("model", "platform", "name", "version") if d.get(x)]
        if bits:
            facts.append(("Ubiquiti: " if k == "ubnt" else "MikroTik: ") + " · ".join(bits))
    return clues, facts, old


# ---------------------------------------------------------------- mismatches

def mismatch(vendor_type, vendor, fp_type, fp_score, compatible):
    """A MAC maker that doesn't fit how the device behaves."""
    if not (vendor_type and fp_type and vendor) or fp_score < 60 or compatible(vendor_type, fp_type):
        return None
    v = vendor.split(",")[0]
    if vendor_type in ("apple", "mobile") and fp_type == "windows":
        return f"{v} hardware with a Windows network stack: Boot Camp, a virtual machine, or a changed MAC address"
    if vendor_type == "vm":
        return None
    return f"MAC maker {v} suggests {vendor_type}, but it behaves like {fp_type}: a changed MAC, a VM, or a re-purposed device"
