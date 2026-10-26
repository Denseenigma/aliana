"""
app.py - Aliana-lite: a small recon dashboard.
Runs nmap scans against a subnet (by default, whatever's on usb0) and
shows the results in a web UI, with history.
"""
import threading
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
