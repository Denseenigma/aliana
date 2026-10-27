"""
app.py - Aliana-lite: a small recon dashboard.
Runs nmap scans against a subnet (by default, whatever's on usb0) and
shows the results in a web UI, with history.
"""
import socket
import subprocess
import threading
import time
from flask import Flask, render_template, jsonify, redirect, url_for, request, Response

import scanner
import wifi
import qr

PORT = 8080

app = Flask(__name__)


@app.route("/")
def index():
    latest = scanner.get_latest_scan()
    status = scanner.get_status()
    history = scanner.get_scan_history(limit=10)
    interfaces = scanner.list_interfaces()
    return render_template(
        "index.html", scan=latest, status=status, history=history, interfaces=interfaces,
        profiles=scanner.PROFILES,
    )


@app.route("/scan/now", methods=["POST"])
def scan_now():
    # Run in a background thread so the request returns immediately
    threading.Thread(target=scanner.run_scan, daemon=True).start()
    return redirect(url_for("index"))


@app.route("/profile/set", methods=["POST"])
def set_profile():
    name = request.form.get("profile")
    if name in scanner.PROFILES and not scanner.get_status()["running"]:
        scanner.set_profile(name)
    return redirect(url_for("index"))


@app.route("/scan/stop", methods=["POST"])
def scan_stop():
    scanner.stop_scan()
    return redirect(url_for("index"))


@app.route("/interface/set", methods=["POST"])
def set_interface():
    name = request.form.get("interface")
    if name:
        scanner.set_current_interface(name)
    return redirect(url_for("index"))


@app.route("/kiosk")
def kiosk():
    """Condensed 480x320 control screen for the Pi's onboard display."""
    return render_template("kiosk.html")


_nmap_version = None


def _get_nmap_version():
    """nmap's version string, read once (shown in the kiosk boot sequence)."""
    global _nmap_version
    if _nmap_version is None:
        try:
            out = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=10).stdout
            _nmap_version = out.split("version", 1)[1].split()[0] if "version" in out else "unknown"
        except Exception:
            _nmap_version = "not found"
    return _nmap_version


def _scannable(interfaces, current):
    """Interfaces worth cycling through: ones with an IPv4 address (a
    subnet to scan), plus the current one so it's always in the list."""
    return [i["name"] for i in interfaces if i["ipv4"] or i["name"] == current]


def _kiosk_state():
    status = scanner.get_status()
    interfaces = scanner.list_interfaces()
    current = status["interface"]
    iface_ip = next((i["ipv4"] for i in interfaces if i["name"] == current), None)
    next_in = None
    if status.get("next_run") and not status["running"]:
        next_in = max(0, int(status["next_run"] - time.time()))
    return {
        "running": status["running"],
        "outcome": status.get("last_outcome"),
        "outcome_seq": status.get("outcome_seq", 0),
        "hostname": socket.gethostname(),
        "nmap_version": _get_nmap_version(),
        "profile": status["profile"],
        "profile_label": scanner.PROFILES[status["profile"]]["label"],
        "profiles": [{"key": k, "label": p["label"], "short": p["short"]}
                     for k, p in scanner.PROFILES.items()],
        "error": status["last_error"],
        "interface": current,
        "interface_ip": iface_ip,
        "interfaces": _scannable(interfaces, current),
        "next_in": next_in,
        "interval": status.get("next_total") or scanner.SCAN_INTERVAL_SECONDS,
        "progress": scanner.get_progress(),
        "latest": scanner.get_latest_summary(),
    }


@app.route("/api/kiosk")
def api_kiosk():
    return jsonify(_kiosk_state())


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Starts a scan. Optional JSON {"profile": ...}: runs that profile and
    remembers it as the default for automatic scans."""
    profile = (request.get_json(silent=True) or {}).get("profile")
    if not scanner.get_status()["running"]:
        if profile in scanner.PROFILES:
            scanner.set_profile(profile)
        threading.Thread(target=scanner.run_scan, daemon=True).start()
        time.sleep(0.2)  # let the scan flag flip so the response reflects it
    return jsonify(_kiosk_state())


@app.route("/api/profile/next", methods=["POST"])
def api_profile_next():
    """Cycles the scan profile (kiosk button). Ignored while scanning."""
    if not scanner.get_status()["running"]:
        names = list(scanner.PROFILES)
        current = scanner.get_profile()
        scanner.set_profile(names[(names.index(current) + 1) % len(names)])
    return jsonify(_kiosk_state())


@app.route("/api/scan/stop", methods=["POST"])
def api_scan_stop():
    scanner.stop_scan()
    return jsonify(_kiosk_state())


@app.route("/api/interface/next", methods=["POST"])
def api_interface_next():
    """Cycles the scan interface to the next one (kiosk button). Ignored
    while a scan is running -- stop it first."""
    current = scanner.get_current_interface()
    names = _scannable(scanner.list_interfaces(), current)
    if len(names) > 1 and not scanner.get_status()["running"]:
        idx = names.index(current) if current in names else -1
        scanner.set_current_interface(names[(idx + 1) % len(names)])
    return jsonify(_kiosk_state())


# ---------------------------------------------------------------- Wi-Fi

def _setup_url():
    """Address of the Wi-Fi page that a phone is most likely to reach:
    the Pi's Wi-Fi IP first, then wired, then the USB gadget link."""
    by_name = {i["name"]: i for i in scanner.list_interfaces() if i["ipv4"]}
    order = sorted(by_name, key=lambda n: (
        0 if n.startswith("wl") else 1 if n.startswith(("eth", "en")) else 3 if n.startswith("usb") else 2))
    if not order:
        return None
    ip = by_name[order[0]]["ipv4"].split("/")[0]
    return f"http://{ip}:{PORT}/wifi"


def _wifi_error(e):
    return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/wifi")
def wifi_page():
    return render_template("wifi.html")


@app.route("/api/wifi")
def api_wifi():
    # setup_url (and the QR code) don't depend on NetworkManager, so they're
    # always returned -- even when the Wi-Fi status itself can't be read.
    url = _setup_url()
    try:
        return jsonify({"ok": True, "status": wifi.status(), "saved": wifi.saved(), "setup_url": url})
    except wifi.WifiError as e:
        return jsonify({"ok": False, "error": str(e), "setup_url": url})


@app.route("/api/wifi/scan")
def api_wifi_scan():
    try:
        return jsonify({"ok": True, "networks": wifi.scan()})
    except wifi.WifiError as e:
        return _wifi_error(e)


@app.route("/api/wifi/connect", methods=["POST"])
def api_wifi_connect():
    data = request.get_json(silent=True) or {}
    ssid = (data.get("ssid") or "").strip()
    if not ssid:
        return _wifi_error("Network name is required.")
    try:
        return jsonify({"ok": True, "status": wifi.connect(ssid, data.get("password") or None)})
    except wifi.WifiError as e:
        return _wifi_error(e)


@app.route("/api/wifi/forget", methods=["POST"])
def api_wifi_forget():
    name = ((request.get_json(silent=True) or {}).get("name") or "").strip()
    if not name:
        return _wifi_error("Connection name is required.")
    try:
        wifi.forget(name)
        return jsonify({"ok": True})
    except wifi.WifiError as e:
        return _wifi_error(e)


@app.route("/api/wifi/qr.svg")
def api_wifi_qr():
    url = _setup_url()
    if not url:
        return Response(status=404)
    return Response(qr.svg(url), mimetype="image/svg+xml", headers={"Cache-Control": "no-store"})


@app.route("/api/interfaces")
def api_interfaces():
    return jsonify(scanner.list_interfaces())


@app.route("/api/latest")
def api_latest():
    return jsonify(scanner.get_latest_scan() or {})


@app.route("/api/status")
def api_status():
    return jsonify(scanner.get_status())


@app.route("/api/history")
def api_history():
    return jsonify(scanner.get_scan_history())


if __name__ == "__main__":
    scanner.init_db()
    # Kick off the periodic background scanner
    t = threading.Thread(target=scanner.background_loop, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=PORT)
