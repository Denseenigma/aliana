"""
wifi.py - Wi-Fi management for Aliana via NetworkManager's nmcli.

The aliana service runs as a normal user; setup.sh installs a polkit rule
that lets that user manage NetworkManager, so no sudo is needed here.
"""
import subprocess


class WifiError(Exception):
    pass


def _is_auth_error(msg):
    m = msg.lower()
    return "not authorized" in m or "insufficient privileges" in m or "not permitted" in m


def _run(cmd, timeout):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise WifiError(f"{cmd[0]} not found -- is NetworkManager installed?")
    except subprocess.TimeoutExpired:
        raise WifiError("Timed out talking to NetworkManager.")


def _nmcli(args, timeout=20):
    """Runs nmcli. If NetworkManager refuses (polkit didn't grant the service
    user access), retries through sudo -- setup.sh allows passwordless sudo
    for nmcli only."""
    r = _run(["nmcli"] + args, timeout)
    msg = (r.stderr or r.stdout).strip()
    if r.returncode != 0 and _is_auth_error(msg):
        r = _run(["sudo", "-n", "nmcli"] + args, timeout)
        msg = (r.stderr or r.stdout).strip()
        if r.returncode != 0 and ("password is required" in msg or "not allowed" in msg):
            raise WifiError("Not authorized to change Wi-Fi. Run `bash setup.sh` on the Pi, "
                            "then `sudo systemctl restart aliana`.")
    if r.returncode != 0:
        msg = msg.replace("Error: ", "")
        if "networkmanager is not running" in msg.lower():
            msg = "NetworkManager isn't running on the Pi, so Wi-Fi can't be managed from here yet."
        elif _is_auth_error(msg):
            msg = "Not authorized to change Wi-Fi. Run `bash setup.sh` on the Pi, then `sudo systemctl restart aliana`."
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


# ---------------------------------------------------------------- setup hotspot
#
# When the Pi has no network your phone can reach, the Pi screen's Wi-Fi panel
# can turn the Pi into a temporary Wi-Fi hotspot ("Aliana-Setup-XXXX", with a
# password shown only on the Pi's screen). Scan its QR code with a phone, the
# Wi-Fi page opens by itself (captive portal: every name resolves to the Pi,
# see setup.sh), pick the network for the Pi, and the hotspot closes while the
# Pi joins it. If that fails, the hotspot comes back with the error.
#
# The radio can't be a hotspot and scan / join at the same time, so the list
# of networks is scanned just before the hotspot starts.

import secrets
import socket
import threading
import time

HOTSPOT_CON = "aliana-setup"
HOTSPOT_IP = "10.42.0.1"          # NetworkManager's default for shared connections
HOTSPOT_MINUTES = 15

_hs = {"active": False, "ssid": None, "password": None, "until": 0, "networks": [], "result": None,
       "busy": None}
_hs_lock = threading.RLock()


def _hs_name():
    tail = "".join(ch for ch in socket.gethostname().upper() if ch.isalnum())[-4:] or secrets.token_hex(2).upper()
    return f"Aliana-Setup-{tail}"


def _qr_escape(s):
    specials = "\\;,:\""
    return "".join("\\" + ch if ch in specials else ch for ch in s)


def hotspot_info():
    with _hs_lock:
        info = {"active": _hs["active"], "busy": _hs["busy"], "result": _hs["result"]}
        if _hs["active"]:
            info.update(ssid=_hs["ssid"], password=_hs["password"], ip=HOTSPOT_IP,
                        url=f"http://{HOTSPOT_IP}:8080/wifi",
                        expires_in=max(0, int(_hs["until"] - time.time())),
                        join_qr=f"WIFI:T:WPA;S:{_qr_escape(_hs['ssid'])};P:{_qr_escape(_hs['password'])};;")
        return info


def hotspot_networks():
    return list(_hs["networks"])


def _start_ap():
    dev = _wifi_device()
    if not dev:
        raise WifiError("No Wi-Fi device found.")
    if not _radio_on():
        _nmcli(["radio", "wifi", "on"])
    try:
        _nmcli(["connection", "delete", "id", HOTSPOT_CON])
    except WifiError:
        pass
    _nmcli(["device", "wifi", "hotspot", "ifname", dev["device"], "con-name", HOTSPOT_CON,
            "ssid", _hs["ssid"], "password", _hs["password"]], timeout=40)
    try:   # never come back by itself after a reboot
        _nmcli(["connection", "modify", "id", HOTSPOT_CON, "connection.autoconnect", "no"])
    except WifiError:
        pass


def hotspot_start(minutes=HOTSPOT_MINUTES):
    """Scan, then become the setup hotspot. Returns hotspot_info()."""
    with _hs_lock:
        if _hs["active"]:
            _hs["until"] = time.time() + minutes * 60
            return hotspot_info()
        try:
            _hs["networks"] = [n for n in scan() if n["ssid"] != _hs.get("ssid")]
        except WifiError:
            _hs["networks"] = []
        _hs.update(ssid=_hs_name(), result=None,
                   password="".join(secrets.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(10)))
        _start_ap()
        _hs.update(active=True, until=time.time() + minutes * 60)
    print(f"aliana wifi: setup hotspot {_hs['ssid']} on", flush=True)
    threading.Thread(target=_hs_watch, daemon=True).start()
    return hotspot_info()


def _stop_ap():
    for args in (["connection", "down", "id", HOTSPOT_CON], ["connection", "delete", "id", HOTSPOT_CON]):
        try:
            _nmcli(args)
        except WifiError:
            pass


def hotspot_stop(result=None):
    with _hs_lock:
        was = _hs["active"]
        _stop_ap()
        _hs.update(active=False, result=result if result is not None else _hs["result"])
    if was:
        print("aliana wifi: setup hotspot off", flush=True)
    return hotspot_info()


def _hs_watch():
    while True:
        time.sleep(5)
        with _hs_lock:
            if not _hs["active"]:
                return
            if not _hs["busy"] and time.time() > _hs["until"]:
                break
    hotspot_stop({"ok": False, "message": "Setup hotspot timed out."})


def hotspot_connect(ssid, password=None):
    """Called from the phone on the hotspot: answer first, then (2 s later)
    close the hotspot and join `ssid`. On failure the hotspot comes back."""
    with _hs_lock:
        if not _hs["active"]:
            raise WifiError("The setup hotspot isn't running.")
        if _hs["busy"]:
            raise WifiError("Already switching networks.")
        _hs["busy"] = ssid

    def work():
        time.sleep(2)            # let the reply reach the phone first
        with _hs_lock:
            _stop_ap()
        try:
            st = connect(ssid, password)
            with _hs_lock:
                _hs.update(active=False, busy=None,
                           result={"ok": True, "ssid": ssid, "ip": st.get("ip"),
                                   "message": f"Connected to {ssid}" + (f" · {st['ip']}" if st.get("ip") else "")})
            print(f"aliana wifi: joined {ssid} from the setup hotspot", flush=True)
        except WifiError as e:
            with _hs_lock:
                _hs.update(busy=None, result={"ok": False, "ssid": ssid, "message": f"Couldn't join {ssid}: {e}"})
                try:
                    _start_ap()          # same name / password: the phone rejoins by itself
                    _hs["until"] = time.time() + HOTSPOT_MINUTES * 60
                except WifiError as e2:
                    _hs["active"] = False
                    _hs["result"]["message"] += f" (and the hotspot couldn't restart: {e2})"
    threading.Thread(target=work, daemon=True).start()
    return {"switching": True, "ssid": ssid}
