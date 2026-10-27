"""
wifi.py - Wi-Fi management for Aliana via NetworkManager's nmcli.

The aliana service runs as a normal user; setup.sh installs a polkit rule
that lets that user manage NetworkManager, so no sudo is needed here.
"""
import subprocess


class WifiError(Exception):
    pass


def _nmcli(args, timeout=20):
    try:
        r = subprocess.run(["nmcli"] + args, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise WifiError("nmcli not found -- is NetworkManager installed?")
    except subprocess.TimeoutExpired:
        raise WifiError("Timed out talking to NetworkManager.")
    if r.returncode != 0:
        msg = (r.stderr or r.stdout).strip().replace("Error: ", "")
        if "not authorized" in msg.lower() or "insufficient privileges" in msg.lower():
            msg = "Not authorized to change Wi-Fi. Re-run setup.sh on the Pi to grant Aliana permission."
        raise WifiError(msg or f"nmcli exited with code {r.returncode}")
    return r.stdout


def _fields(line):
    """Splits one line of `nmcli -t` output on unescaped colons."""
    out, cur, esc = [], [], False
    for ch in line:
        if esc:
            cur.append(ch)
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    return out


def _rows(text):
    return [_fields(l) for l in text.splitlines() if l.strip()]


def _wifi_device():
    for dev, typ, state, conn in _rows(_nmcli(["-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])):
        if typ == "wifi":
            return {"device": dev, "state": state, "connection": conn or None}
    return None


def _radio_on():
    return _nmcli(["radio", "wifi"]).strip() == "enabled"


def status():
    """Current Wi-Fi link: device, state, network name, signal %, IP."""
    dev = _wifi_device()
    if not dev:
        return {"available": False, "radio": False, "state": "no wifi device"}
    result = {
        "available": True,
        "radio": _radio_on(),
        "device": dev["device"],
        "state": dev["state"].split(" ")[0],  # e.g. "connected", "disconnected"
        "connection": dev["connection"],
        "ssid": None,
        "signal": None,
        "ip": None,
    }
    if result["state"] == "connected":
        for in_use, ssid, signal in _rows(_nmcli(
                ["-t", "-f", "IN-USE,SSID,SIGNAL", "device", "wifi", "list",
                 "ifname", dev["device"], "--rescan", "no"])):
            if in_use == "*":
                result["ssid"] = ssid
                result["signal"] = int(signal) if signal.isdigit() else None
                break
        ips = _nmcli(["-g", "IP4.ADDRESS", "device", "show", dev["device"]]).strip()
        if ips:
            result["ip"] = ips.split(" | ")[0].split("/")[0]
    return result


def saved():
    """Saved Wi-Fi connection profiles: name, ssid, active."""
    active = {name for name, typ in _rows(_nmcli(["-t", "-f", "NAME,TYPE", "connection", "show", "--active"]))}
    result = []
    for name, typ in _rows(_nmcli(["-t", "-f", "NAME,TYPE", "connection", "show"])):
        if typ != "802-11-wireless":
            continue
        ssid, mode = name, ""
        try:
            lines = _nmcli(["-g", "802-11-wireless.ssid,802-11-wireless.mode",
                            "connection", "show", "id", name]).splitlines()
            ssid = (lines[0].strip() if lines else "") or name
            mode = lines[1].strip() if len(lines) > 1 else ""
        except WifiError:
            pass
        if mode == "ap":
            continue  # hotspot profiles aren't networks to join
        result.append({"name": name, "ssid": ssid or name, "active": name in active})
    return result


def scan():
    """Visible networks, strongest first, one entry per network name."""
    dev = _wifi_device()
    if not dev:
        raise WifiError("No Wi-Fi device found.")
    if not _radio_on():
        _nmcli(["radio", "wifi", "on"])
    args = ["-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY", "device", "wifi", "list", "ifname", dev["device"]]
    try:
        out = _nmcli(args + ["--rescan", "yes"], timeout=30)
    except WifiError:
        out = _nmcli(args)  # rescans are rate-limited; fall back to the cached list
    saved_ssids = {s["ssid"] for s in saved()}
    best = {}
    for in_use, ssid, signal, security in _rows(out):
        if not ssid:
            continue  # hidden network
        sig = int(signal) if signal.isdigit() else 0
        security = security.strip()
        entry = {
            "ssid": ssid,
            "signal": sig,
            "secure": bool(security and security != "--"),
            "security": security if security != "--" else "",
            "in_use": in_use == "*",
            "saved": ssid in saved_ssids,
        }
        if ssid not in best or sig > best[ssid]["signal"] or entry["in_use"]:
            best[ssid] = entry
    return sorted(best.values(), key=lambda n: (not n["in_use"], -n["signal"]))


def connect(ssid, password=None):
    """Joins a network. Reuses a saved profile when no password is given."""
    dev = _wifi_device()
    if not dev:
        raise WifiError("No Wi-Fi device found.")
    if not _radio_on():
        _nmcli(["radio", "wifi", "on"])
    existing = [s for s in saved() if s["ssid"] == ssid]
    if existing and not password:
        _nmcli(["--wait", "30", "connection", "up", "id", existing[0]["name"]], timeout=40)
        return status()
    if existing:
        # New password for a saved network: replace the old profile
        for s in existing:
            _nmcli(["connection", "delete", "id", s["name"]])
    args = ["--wait", "30", "device", "wifi", "connect", ssid, "ifname", dev["device"]]
    if password:
        args += ["password", password]
    try:
        _nmcli(args, timeout=40)
    except WifiError as e:
        # A failed attempt leaves a half-made profile behind -- remove it
        for s in saved():
            if s["ssid"] == ssid and not s["active"]:
                try:
                    _nmcli(["connection", "delete", "id", s["name"]])
                except WifiError:
                    pass
        msg = str(e)
        if "secrets were required" in msg.lower() or "802-1x" in msg.lower():
            msg = "Wrong password (or the network rejected it)."
        raise WifiError(msg)
    return status()


def forget(name):
    _nmcli(["connection", "delete", "id", name])
