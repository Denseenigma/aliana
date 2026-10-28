"""
app.py - Aliana-lite: a small recon dashboard.
Runs nmap scans against a subnet (by default, whatever's on usb0) and
shows the results in a web UI, with history.
"""
import csv
import datetime
import io
import json
import re
import socket
import subprocess
import threading
import time
from flask import Flask, render_template, jsonify, redirect, url_for, request, Response

import scanner
import insights
import history
import identify
import rmm
import wifi
import qr

PORT = 8080

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024   # history imports


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
    scan = insights.annotate(scanner.get_scan(scan_id))
    if scan_id is not None and scan is None:
        return redirect(url_for("index"))
    latest_id = scanner.latest_subnet_scan_id()
    viewing_old = scan is not None and scan["id"] != latest_id
    status = scanner.get_status()
    history = scanner.get_scan_history(limit=10)
    interfaces = scanner.list_interfaces()
    card_ips = {h["ip"] for h in (scan or {}).get("hosts", [])} if not viewing_old else set()
    return render_template(
        "index.html", scan=scan, status=status, history=history, interfaces=interfaces,
        viewing_old=viewing_old,
        deep=_deep_tray(card_ips),
        ask_guard=request.args.get("guard") == "1",
        flash_error=request.args.get("err"),
        excluded={h["ip"]: scanner.is_excluded(h["ip"]) for h in (scan or {}).get("hosts", [])},
        profiles=scanner.PROFILES,
        network_profiles={k: scanner.PROFILES[k] for k in scanner.NETWORK_PROFILES},
        intervals=[(sec, _interval_label(sec)) for sec in scanner.INTERVAL_CHOICES],
        own_ips={i["ipv4"].split("/")[0] for i in interfaces if i["ipv4"]},
    )


def _deep_tray(card_ips):
    """Per-device Deep scans for the floating results tray: ones running or
    waiting, and ones finished in the last few hours (with a summary of what
    they found). "card" says whether that device has a card on this page."""
    q = scanner.get_queue(recent=0)
    active = []
    if q["running"] and q["running"]["kind"] == "host":
        active.append({"id": q["running"]["id"], "ip": q["running"]["target"], "state": "running",
                       "progress": q["running"].get("progress")})
    for j in q["queued"]:
        if j["kind"] == "host":
            active.append({"id": j["id"], "ip": j["target"], "state": "queued", "position": j["position"]})
    done = []
    for j in scanner.recent_host_jobs():
        item = {"id": j["id"], "ip": j["target"], "state": j["status"], "finished_at": j["finished_at"],
                "scan_id": j["scan_id"], "error": j["error"], "card": j["target"] in card_ips}
        if j["scan_id"]:
            s = insights.annotate(scanner.get_scan(j["scan_id"]))
            h = (s or {}).get("hosts", [None])[0] if s and s.get("hosts") else None
            if h:
                item.update(name=h.get("hostname"), mac=h.get("mac"), device=h["device"],
                            open=[p["port"] for p in h["ports"] if p["state"] == "open"],
                            flags=[{"label": f["label"], "level": f["level"]} for f in h["flags"]],
                            os=h.get("os_name"))
            else:
                item["no_response"] = True
        done.append(item)
    return {"active": active, "done": done}


@app.route("/api/deep-tray")
def api_deep_tray():
    return jsonify(_deep_tray(set(request.args.get("cards", "").split(","))))


@app.route("/scan/now", methods=["POST"])
def scan_now():
    # Run in a background thread so the request returns immediately
    confirm = request.form.get("confirm") == "1"
    g = scanner.current_subnet_guard()
    if g and g["level"] == "confirm" and not confirm:
        return redirect(url_for("index", guard=1))   # dashboard asks first
    job, err = scanner.enqueue("subnet", source="manual", confirm_large=confirm)
    if err:
        return redirect(url_for("index", err=err))
    time.sleep(0.3)  # let the worker pick it up so the page shows it running
    return redirect(url_for("index"))


@app.route("/profile/set", methods=["POST"])
def set_profile():
    name = request.form.get("profile")
    if name in scanner.NETWORK_PROFILES and not scanner.get_status()["running"]:
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
        "guard": status.get("guard"),
        "changes": insights.latest_changes_summary(),
        "queue": {k: status["queue"][k] for k in ("queued", "paused", "current")},
        "hostname": socket.gethostname(),
        "nmap_version": _get_nmap_version(),
        "profile": status["profile"],
        "profile_label": scanner.PROFILES[status["profile"]]["label"],
        "profiles": [{"key": k, "label": scanner.PROFILES[k]["label"], "short": scanner.PROFILES[k]["short"]}
                     for k in scanner.NETWORK_PROFILES],
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
    data = request.get_json(silent=True) or {}
    profile, confirm = data.get("profile"), bool(data.get("confirm"))
    extra = {}
    if not scanner.get_status()["running"]:
        g = scanner.current_subnet_guard()
        if g and g["level"] == "confirm" and not confirm:
            extra["needs_confirm"] = g      # Pi screen shows a confirm panel
        else:
            if profile in scanner.NETWORK_PROFILES:
                scanner.set_profile(profile)
            job, err = scanner.enqueue("subnet", source="manual", confirm_large=confirm)
            if err:
                extra["scan_error"] = err
            else:
                time.sleep(0.3)  # let the worker start it so the response reflects it
    state = _kiosk_state()
    state.update(extra)
    return jsonify(state)


# ---------------------------------------------------------------- export / report

def _scan_or_404(scan_id):
    scan = insights.annotate(scanner.get_scan(scan_id))
    if scan is None:
        return None
    return scan


def _export_name(scan, ext):
    t = (scan.get("finished_at") or "")[:16].replace(":", "").replace("T", "-")
    net = (scan.get("subnet") or "scan").replace("/", "_")
    return f"aliana-{net}-{t}.{ext}"


@app.route("/scan/<int:scan_id>/export.csv")
def export_csv(scan_id):
    """One row per open port (hosts with none get one row), with device
    type, flags and change markers."""
    scan = _scan_or_404(scan_id)
    if scan is None:
        return Response("No such scan", status=404)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["scan_id", "scan_finished", "subnet", "profile", "ip", "hostname", "mac", "vendor",
                "device_type", "os_guess", "os_accuracy", "new_host", "port", "protocol", "service",
                "product", "version", "identification", "new_port", "flags"])
    for h in scan["hosts"]:
        base = [scan["id"], scan["finished_at"], scan["subnet"], scan["profile"], h["ip"], h.get("hostname") or "",
                h.get("mac") or "", h.get("vendor") or "", h["device"]["label"], h.get("os_name") or "",
                h.get("os_accuracy") or "", "yes" if h["is_new"] else ""]
        flags = "; ".join(f"{f['label']} ({f['level']})" for f in h["flags"])
        ports = [p for p in h["ports"] if p["state"] == "open"]
        if not ports:
            w.writerow(base + ["", "", "", "", "", "", "", flags])
        for p in ports:
            ident = {"skipped": "not probed (skip list)", "timeout": "not identified"}.get(p.get("probe"), "")
            w.writerow(base + [p["port"], p["protocol"], p.get("service") or "", p.get("product") or "",
                               p.get("version") or "", ident, "yes" if p.get("is_new") else "", flags])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{_export_name(scan, "csv")}"'})


@app.route("/scan/<int:scan_id>/export.json")
def export_json(scan_id):
    """This one scan in Aliana's history format (importable)."""
    scan = scanner.get_scan(scan_id)
    if scan is None:
        return jsonify({}), 404
    return Response(json.dumps(history.export_bundle([scan_id]), indent=1), mimetype="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{_export_name(scan, "json")}"'})


# ---------------------------------------------------------------- history / devices

@app.route("/export/history.json")
def export_history():
    """Every scan this unit knows (its own and imported) -- import it on
    another day or another Aliana to keep building the same history."""
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    return Response(json.dumps(history.export_bundle(), indent=1), mimetype="application/json",
                    headers={"Content-Disposition":
                             f'attachment; filename="aliana-history-{socket.gethostname()}-{stamp}.json"'})


@app.route("/export/devices.csv")
def export_devices():
    data = history.list_devices()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["mac", "vendor", "hostname", "last_ip", "device_type", "first_seen", "last_seen", "times_seen",
                "in_latest_scan", "ips_seen", "hostnames_seen", "networks", "open_ports", "os_guess",
                "rmm_status", "rmm_hostname", "rmm_site", "flags"])
    for d in data["devices"]:
        m = rmm.match(d["_host"], d["device"]["type"])
        w.writerow([d["mac"], d["vendor"] or "", d["hostname"] or "", d["ip"], d["device"]["label"], d["first_seen"],
                    d["last_seen"], d["sightings"], "yes" if d["present"] else "no", " ".join(d["ips"]),
                    " ".join(d["hostnames"]), " ".join(d["networks"]),
                    " ".join(f"{p}/{pr}" for p, pr in d["open_ports"]), d["os_name"] or "",
                    (m or {}).get("status", ""), ((m or {}).get("device") or {}).get("hostname", ""),
                    ((m or {}).get("device") or {}).get("site", ""),
                    "; ".join(f["label"] for f in d["flags"])])
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M")
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="aliana-devices-{stamp}.csv"'})


@app.route("/api/import", methods=["POST"])
def api_import():
    """Multipart upload of one or more Aliana JSON exports."""
    files = request.files.getlist("files")
    if not files:
        return jsonify({"ok": False, "error": "Choose one or more Aliana .json export files."}), 400
    total = {"scans_added": 0, "scans_skipped": 0, "hosts_added": 0, "new_devices": 0, "errors": [], "files": []}
    for f in files:
        name = (f.filename or "file")[:80]
        try:
            data = json.loads(f.read().decode("utf-8"))
            r = history.import_bundle(data)
        except (ValueError, UnicodeDecodeError) as e:
            total["errors"].append(f"{name}: {e}" if isinstance(e, history.ImportFailed)
                                   else f"{name}: not a readable JSON file")
            continue
        total["files"].append({"name": name, **r})
        for k in ("scans_added", "scans_skipped", "hosts_added", "new_devices"):
            total[k] += r[k]
        total["errors"] += [f"{name}: {e}" for e in r["errors"]]
    insights._summary_cache.clear()
    return jsonify({"ok": not total["errors"] or total["scans_added"] > 0, **total})


def _device_view(d):
    d = dict(d)
    d["rmm"] = rmm.match(d["_host"], d["device"]["type"])
    if d["rmm"] and d["rmm"]["status"] == "missing":
        d["flags"] = sorted(d["flags"] + [insights.rmm_flag(d["rmm"])],
                            key=lambda f: insights.LEVEL_ORDER[f["level"]])
    d.pop("_host", None)
    return d


@app.route("/devices")
def devices_page():
    data = history.list_devices()
    devs = [_device_view(d) for d in data["devices"]]
    counts = {"total": len(devs), "present": sum(1 for d in devs if d["present"]),
              "managed": sum(1 for d in devs if d["rmm"] and d["rmm"]["status"] == "managed"),
              "missing": sum(1 for d in devs if d["rmm"] and d["rmm"]["status"] == "missing")}
    return render_template("devices.html", devices=devs, counts=counts, untracked=data["untracked_ips"],
                           span=data["scans"], status=scanner.get_status(), rmm_state=rmm.public_state())


@app.route("/device/<mac>")
def device_page(mac):
    h = history.device_history(mac)
    if not h:
        return redirect(url_for("devices_page"))
    return render_template("device.html", d=_device_view(h["device"]), timeline=h["timeline"],
                           profiles=scanner.PROFILES, status=scanner.get_status())


@app.route("/api/devices")
def api_devices():
    return jsonify([_device_view(d) for d in history.list_devices()["devices"]])


# ---------------------------------------------------------------- RMM integration

@app.route("/api/rmm")
def api_rmm():
    return jsonify(rmm.public_state())


@app.route("/api/rmm/save", methods=["POST"])
def api_rmm_save():
    data = request.get_json(silent=True) or {}
    try:
        rmm.save_config(data.get("provider") or "", data.get("values") or {},
                        data.get("sites"), data.get("site_names"))
    except rmm.RMMError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "state": rmm.public_state()})


@app.route("/api/rmm/test", methods=["POST"])
def api_rmm_test():
    data = request.get_json(silent=True) or {}
    try:
        r = rmm.test(data.get("provider") or None, data.get("values") or {})
    except rmm.RMMError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": f"Unexpected error: {e}"}), 500
    return jsonify(r)


@app.route("/api/rmm/sync", methods=["POST"])
def api_rmm_sync():
    if not rmm.get_provider_key():
        return jsonify({"ok": False, "error": "Set up an RMM first."}), 400
    started = rmm.sync_in_background()
    time.sleep(0.2)
    return jsonify({"ok": True, "started": started, "state": rmm.public_state()})


@app.route("/scan/<int:scan_id>/report")
def report(scan_id):
    """Printable one-page summary: totals, changes, findings, host list."""
    scan = _scan_or_404(scan_id)
    if scan is None:
        return redirect(url_for("index"))
    findings = []
    for h in scan["hosts"]:
        for f in h["flags"]:
            findings.append({"ip": h["ip"], "hostname": h.get("hostname"), "device": h["device"]["label"], **f})
    findings.sort(key=lambda f: (insights.LEVEL_ORDER[f["level"]], tuple(int(x) for x in f["ip"].split("."))))
    types = {}
    for h in scan["hosts"]:
        types[h["device"]["label"]] = types.get(h["device"]["label"], 0) + 1
    open_ports = sum(1 for h in scan["hosts"] for p in h["ports"] if p["state"] == "open")
    return render_template("report.html", scan=scan, findings=findings, profiles=scanner.PROFILES,
                           types=sorted(types.items(), key=lambda x: -x[1]), open_ports=open_ports,
                           generated=datetime.datetime.now().isoformat(), hostname=socket.gethostname(),
                           exclusions=scanner.get_exclusions(),
                           hosts_sorted=sorted(scan["hosts"], key=lambda h: tuple(int(x) for x in h["ip"].split("."))))


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
        "exclusions": scanner.get_exclusions(),
        "identify": scanner.get_identify_enabled(),
        "vendor_db": identify.oui_info(),
        "guard": _safe_guard(),
        "interface": scanner.get_current_interface(),
        "guard_levels": {"warn": scanner.GUARD_WARN_PREFIX, "confirm": scanner.GUARD_CONFIRM_PREFIX,
                         "max": scanner.GUARD_MAX_PREFIX},
    }


def _safe_guard():
    try:
        return scanner.current_subnet_guard()
    except ValueError:
        return None


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
        if "identify" in data:
            scanner.set_identify_enabled(bool(data["identify"]))
        if "exclusions" in data:
            try:
                scanner.set_exclusions(data["exclusions"])
            except ValueError as e:
                return jsonify({"ok": False, "error": str(e)}), 400
        time.sleep(0.1)  # let the auto-scan loop publish a new countdown
    return jsonify({"ok": True, "settings": _settings_state()})


@app.route("/api/vendor-db/update", methods=["POST"])
def api_vendor_db_update():
    """Refreshes the MAC vendor database from the IEEE (needs internet)."""
    try:
        n = identify.update_oui()
    except Exception as e:
        return jsonify({"ok": False, "error": f"Couldn't update the vendor database: {e}"}), 502
    return jsonify({"ok": True, "entries": n, "vendor_db": identify.oui_info()})


@app.route("/api/exclusions/add", methods=["POST"])
def api_exclusion_add():
    """JSON {"spec": ip/range/CIDR, "note": "..."} -- e.g. the host card's Exclude button."""
    data = request.get_json(silent=True) or {}
    try:
        items = scanner.add_exclusion(data.get("spec"), data.get("note") or "")
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "exclusions": items})


# ---------------------------------------------------------------- job queue

@app.route("/queue")
def queue_page():
    status = scanner.get_status()
    return render_template("queue.html", status=status, profiles=scanner.PROFILES,
                           network_profiles={k: scanner.PROFILES[k] for k in scanner.NETWORK_PROFILES})


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
    confirm = bool(data.get("confirm"))
    g = scanner.current_subnet_guard()
    if g and g["level"] == "confirm" and not confirm:
        return jsonify({"ok": False, "needs_confirm": True, "guard": g, "error": g["message"]}), 409
    job, err = scanner.enqueue("subnet", profile=data.get("profile"), source="manual", confirm_large=confirm)
    if err:
        return jsonify({"ok": False, "error": err}), 409
    return jsonify({"ok": True, "job": job, "guard": g})


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
        names = list(scanner.NETWORK_PROFILES)
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
    rmm.init_db()
    scanner.on_job_done.append(rmm.maybe_sync_after)
    # The queue worker runs every scan, one at a time; the auto-scan loop
    # adds a network scan to the queue whenever one is due
    threading.Thread(target=scanner.queue_worker, daemon=True).start()
    threading.Thread(target=scanner.background_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=PORT)
