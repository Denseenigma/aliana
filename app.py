"""
app.py - Aliana-lite: a small recon dashboard.
Runs nmap scans against a subnet (by default, whatever's on usb0) and
shows the results in a web UI, with history.
"""
import threading
import time
from flask import Flask, render_template, jsonify, redirect, url_for

import scanner

app = Flask(__name__)


@app.route("/")
def index():
    latest = scanner.get_latest_scan()
    status = scanner.get_status()
    history = scanner.get_scan_history(limit=10)
    interfaces = scanner.list_interfaces()
    return render_template(
        "index.html", scan=latest, status=status, history=history, interfaces=interfaces
    )


@app.route("/scan/now", methods=["POST"])
def scan_now():
    # Run in a background thread so the request returns immediately
    threading.Thread(target=scanner.run_scan, daemon=True).start()
    return redirect(url_for("index"))


@app.route("/interface/set", methods=["POST"])
def set_interface():
    from flask import request
    name = request.form.get("interface")
    if name:
        scanner.set_current_interface(name)
    return redirect(url_for("index"))


@app.route("/kiosk")
def kiosk():
    """Condensed 480x320 control screen for the Pi's onboard display."""
    return render_template("kiosk.html")


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
        "error": status["last_error"],
        "interface": current,
        "interface_ip": iface_ip,
        "interfaces": [i["name"] for i in interfaces],
        "next_in": next_in,
        "interval": scanner.SCAN_INTERVAL_SECONDS,
        "progress": scanner.get_progress(),
        "latest": scanner.get_latest_summary(),
    }


@app.route("/api/kiosk")
def api_kiosk():
    return jsonify(_kiosk_state())


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if not scanner.get_status()["running"]:
        threading.Thread(target=scanner.run_scan, daemon=True).start()
        time.sleep(0.2)  # let the scan flag flip so the response reflects it
    return jsonify(_kiosk_state())


@app.route("/api/interface/next", methods=["POST"])
def api_interface_next():
    """Cycles the scan interface to the next one (kiosk button)."""
    names = [i["name"] for i in scanner.list_interfaces()]
    if names:
        current = scanner.get_current_interface()
        idx = names.index(current) if current in names else -1
        scanner.set_current_interface(names[(idx + 1) % len(names)])
    return jsonify(_kiosk_state())


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
    app.run(host="0.0.0.0", port=8080)
