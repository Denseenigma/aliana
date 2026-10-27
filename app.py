"""
app.py - Aliana-lite: a small recon dashboard.
Runs nmap scans against a subnet (by default, whatever's on usb0) and
shows the results in a web UI, with history.
"""
import datetime
import re
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


@app.template_filter("when")
def when(iso):
    """'2026-10-26T21:13:41.8' -> 'Oct 26 · 21:13' (today: just '21:13')."""
    if not iso:
        return "never"
    try:
        t = datetime.datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        return iso
    if t.date() == datetime.date.today():
        return t.strftime("%H:%M")
    return f"{t.strftime('%b')} {t.day} \u00b7 {t.strftime('%H:%M')}"


@app.template_filter("ago")
def ago(iso):
    """'2026-10-26T21:13:41' -> '5 min ago'."""
    try:
        s = (datetime.datetime.now() - datetime.datetime.fromisoformat(iso)).total_seconds()
    except (TypeError, ValueError):
        return ""
    if s < 60:
        return "just now"
    if s < 3600:
        return f"{int(s // 60)} min ago"
    if s < 86400:
        return f"{int(s // 3600)} h ago"
    return f"{int(s // 86400)} d ago"


@app.route("/")
def index():
    return _dashboard(None)


@app.route("/scan/<int:scan_id>")
def view_scan(scan_id):
    """Dashboard showing an older scan (from the history list)."""
    return _dashboard(scan_id)


def _dashboard(scan_id):
    scan = scanner.get_scan(scan_id)
    if scan_id is not None and scan is None:
        return redirect(url_for("index"))
    latest_id = scanner.latest_subnet_scan_id()
    viewing_old = scan is not None and scan["id"] != latest_id
    status = scanner.get_status()
    history = scanner.get_scan_history(limit=10)
    interfaces = scanner.list_interfaces()
    return render_template(
        "index.html", scan=scan, status=status, history=history, interfaces=interfaces,
        viewing_old=viewing_old,
        profiles=scanner.PROFILES,
        intervals=[(sec, _interval_label(sec)) for sec in scanner.INTERVAL_CHOICES],
        own_ips={i["ipv4"].split("/")[0] for i in interfaces if i["ipv4"]},
    )


@app.route("/scan/now", methods=["POST"])
def scan_now():
    # Run in a background thread so the request returns immediately
    scanner.enqueue("subnet", source="manual")
    time.sleep(0.3)  # let the worker pick it up so the page shows it running
    return redirect(url_for("index"))


@app.route("/profile/set", methods=["POST"])
def set_profile():
    name = request.form.get("profile")
    if name in scanner.PROFILES and not scanner.get_status()["running"]:
        scanner.set_profile(name)
    return redirect(url_for("index"))


@app.route("/autoscan/set", methods=["POST"])
def set_autoscan():
    """Dashboard auto-scan select: "off" or an interval in seconds."""
    _apply_autoscan(request.form.get("autoscan"))
    return redirect(url_for("index"))


def _apply_autoscan(value):
    """'off' / 0 switches auto-scan off (the interval is kept); an interval
    in seconds switches it on at that interval."""
    if value in (None, ""):
        return
    if str(value).lower() in ("off", "0", "false"):
        scanner.set_auto_scan(enabled=False)
        return
    try:
        scanner.set_auto_scan(enabled=True, interval=int(value))
    except ValueError:
        pass


def _interval_label(sec):
    return f"{sec // 3600} h" if sec % 3600 == 0 else f"{sec // 60} min"


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
    if not status["running"]:
        next_in = scanner.next_scan_in()
    return {
        "running": status["running"],
        "outcome": status.get("last_outcome"),
        "outcome_seq": status.get("outcome_seq", 0),
        "last_job": status.get("last_job"),
        "queue": {k: status["queue"][k] for k in ("queued", "paused", "current")},
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
        "interval": status.get("next_total") or status["scan_interval"],
        "auto_scan": status["auto_scan"],
        "scan_interval": status["scan_interval"],
        "intervals": [{"seconds": sec, "label": _interval_label(sec)} for sec in scanner.INTERVAL_CHOICES],
        "mode": status["mode"],
        "notice": status.get("notice"),
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
        scanner.enqueue("subnet", source="manual")
        time.sleep(0.3)  # let the worker start it so the response reflects it
    return jsonify(_kiosk_state())


# ---------------------------------------------------------------- settings

def _settings_state():
    return {
        "auto_scan": scanner.get_auto_scan(),
        "scan_interval": scanner.get_scan_interval(),
        "intervals": [{"seconds": sec, "label": _interval_label(sec)} for sec in scanner.INTERVAL_CHOICES],
        "next_in": scanner.next_scan_in(),
        "no_probe_ports": scanner._format_port_list(scanner.get_no_probe_ports()),
        "no_probe_default": scanner._format_port_list(
            scanner._parse_port_list(scanner.NO_PROBE_PORTS_DEFAULT)),
        "profile": scanner.get_profile(),
        "profile_label": scanner.PROFILES[scanner.get_profile()]["label"],
        "mode": scanner.scan_mode(),
    }


_PORT_TOKEN = re.compile(r"^\d{1,5}(-\d{1,5})?$")


@app.route("/settings")
def settings_page():
    return render_template("settings.html", settings=_settings_state(), status=scanner.get_status())


@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    """GET: current settings. POST JSON with any of:
      {"auto_scan": true/false, "scan_interval": seconds,
       "no_probe_ports": ["9999", "10001-10003"]}"""
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        if "scan_interval" in data or "auto_scan" in data:
            try:
                scanner.set_auto_scan(
                    enabled=bool(data["auto_scan"]) if "auto_scan" in data else None,
                    interval=int(data["scan_interval"]) if data.get("scan_interval") is not None else None)
            except (TypeError, ValueError):
                return jsonify({"ok": False, "error": "Unsupported interval."}), 400
        if "no_probe_ports" in data:
            items = data["no_probe_ports"]
            if isinstance(items, str):
                items = items.split(",")
            bad = []
            for tok in (str(x).strip() for x in items):
                if not tok:
                    continue
                a, _, b = tok.partition("-")
                if (not _PORT_TOKEN.match(tok) or not 1 <= int(a) <= 65535
                        or (b and not int(a) <= int(b) <= 65535)):
                    bad.append(tok)
            if bad:
                return jsonify({"ok": False, "error": "Not a valid port or range: " + ", ".join(bad)}), 400
            scanner.set_no_probe_ports(items)
        time.sleep(0.1)  # let the auto-scan loop publish a new countdown
    return jsonify({"ok": True, "settings": _settings_state()})


# ---------------------------------------------------------------- job queue

@app.route("/queue")
def queue_page():
    status = scanner.get_status()
    return render_template("queue.html", status=status, profiles=scanner.PROFILES)


@app.route("/api/queue")
def api_queue():
    return jsonify(scanner.get_queue())


@app.route("/api/queue/host", methods=["POST"])
def api_queue_host():
    """JSON {"ip": "..."}: queue a Deep scan of that one host."""
    data = request.get_json(silent=True) or {}
    job, err = scanner.enqueue("host", target=data.get("ip"), profile=data.get("profile"),
                               source="host-card")
    if err:
        return jsonify({"ok": False, "error": err, "queue": scanner.queue_summary()}), 409
    return jsonify({"ok": True, "job": job, "queue": scanner.queue_summary()})


@app.route("/api/queue/subnet", methods=["POST"])
def api_queue_subnet():
    """JSON {"profile": ...}: queue a network scan (default: saved profile)."""
    data = request.get_json(silent=True) or {}
    job, err = scanner.enqueue("subnet", profile=data.get("profile"), source="manual")
    if err:
        return jsonify({"ok": False, "error": err}), 409
    return jsonify({"ok": True, "job": job})


@app.route("/api/queue/<int:job_id>/cancel", methods=["POST"])
def api_queue_cancel(job_id):
    return jsonify({"ok": scanner.cancel_job(job_id)})


@app.route("/api/queue/<int:job_id>/front", methods=["POST"])
def api_queue_front(job_id):
    scanner.move_job_to_front(job_id)
    return jsonify({"ok": True})


@app.route("/api/queue/pause", methods=["POST"])
def api_queue_pause():
    scanner.set_queue_paused(bool((request.get_json(silent=True) or {}).get("paused")))
    return jsonify({"ok": True, "paused": scanner.get_queue_paused()})


@app.route("/api/queue/cancel-all", methods=["POST"])
def api_queue_cancel_all():
    scanner.cancel_all_queued()
    return jsonify({"ok": True})


@app.route("/api/queue/clear", methods=["POST"])
def api_queue_clear():
    scanner.clear_finished_jobs()
    return jsonify({"ok": True})


@app.route("/api/profile/next", methods=["POST"])
def api_profile_next():
    """Cycles the scan profile (kiosk button). Ignored while scanning."""
    if not scanner.get_status()["running"]:
        names = list(scanner.PROFILES)
        current = scanner.get_profile()
        scanner.set_profile(names[(names.index(current) + 1) % len(names)])
    return jsonify(_kiosk_state())


@app.route("/api/autoscan", methods=["POST"])
def api_autoscan():
    """JSON {"interval": seconds} switches auto-scan on at that interval;
    {"interval": "off"} (or {"enabled": false}) switches it off."""
    data = request.get_json(silent=True) or {}
    if data.get("enabled") is False:
        _apply_autoscan("off")
    else:
        _apply_autoscan(data.get("interval"))
    time.sleep(0.1)  # let the auto-scan loop publish the new countdown
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


@app.route("/api/scan/<int:scan_id>")
def api_scan_detail(scan_id):
    return jsonify(scanner.get_scan(scan_id) or {})


@app.route("/api/status")
def api_status():
    return jsonify(scanner.get_status())


@app.route("/api/history")
def api_history():
    return jsonify(scanner.get_scan_history())


if __name__ == "__main__":
    scanner.init_db()
    # The queue worker runs every scan, one at a time; the auto-scan loop
    # adds a network scan to the queue whenever one is due
    threading.Thread(target=scanner.queue_worker, daemon=True).start()
    threading.Thread(target=scanner.background_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=PORT)
