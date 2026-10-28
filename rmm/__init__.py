"""
rmm - optional RMM integration: "is this device managed by our RMM?"

Aliana pulls the RMM's device list (read-only), keeps a copy in its
database, and matches scanned hosts to it by MAC address (then by
hostname). Providers live in this package; see rmm/base.py to add one.

Settings (stored in Aliana's database):
  rmm_provider  -- "" (off) or a provider key, e.g. "datto"
  rmm_config    -- JSON: provider fields (incl. secrets) + "sites": [uids]
  rmm_status    -- JSON: last sync time / count / error
"""
import datetime
import json
import sqlite3
import threading
import traceback

import scanner

from .base import RMMError, Provider  # noqa: F401  (re-exported for providers)
from .datto import Datto

PROVIDERS = {p.key: p for p in (Datto,)}

# Device types that should carry an RMM agent. Anything else (printers,
# cameras, door controllers, switches...) shows "no agent expected".
AGENT_TYPES = {"windows", "apple", "linux", "vm"}

AUTO_SYNC_MINUTES = 30   # after a network scan, re-sync if older than this

_sync_lock = threading.Lock()
_syncing = False


def _db():
    conn = sqlite3.connect(scanner.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rmm_devices (
            provider TEXT, uid TEXT, hostname TEXT, site TEXT, macs TEXT, ips TEXT,
            os TEXT, online INTEGER, last_seen TEXT, category TEXT, url TEXT,
            PRIMARY KEY (provider, uid))
    """)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------- settings

def get_provider_key():
    k = scanner._get_setting("rmm_provider", "") or ""
    return k if k in PROVIDERS else ""


def get_config():
    try:
        return json.loads(scanner._get_setting("rmm_config", "{}") or "{}")
    except ValueError:
        return {}


def get_status():
    try:
        st = json.loads(scanner._get_setting("rmm_status", "{}") or "{}")
    except ValueError:
        st = {}
    st["syncing"] = _syncing
    return st


def _set_status(**kw):
    st = get_status()
    st.pop("syncing", None)
    st.update(kw)
    scanner._set_setting("rmm_status", json.dumps(st))


def public_state():
    """Everything the Settings page needs -- with secrets blanked."""
    key = get_provider_key()
    cfg = get_config()
    providers = []
    for p in PROVIDERS.values():
        providers.append({"key": p.key, "label": p.label, "docs": p.docs, "has_sites": p.has_sites,
                          "fields": [{**f, "options": [list(o) for o in f.get("options", [])]} for f in p.fields]})
    safe = {}
    if key:
        for f in PROVIDERS[key].fields:
            v = cfg.get(f["name"])
            safe[f["name"]] = ("" if not v else "__saved__") if f["type"] == "password" else (v or "")
    conn = _db()
    count = conn.execute("SELECT COUNT(*) FROM rmm_devices WHERE provider = ?", (key,)).fetchone()[0] if key else 0
    conn.close()
    return {"provider": key, "label": PROVIDERS[key].label if key else None, "config": safe,
            "sites": cfg.get("sites") or [], "site_names": cfg.get("site_names") or {},
            "providers": providers, "status": get_status(), "device_count": count}


def save_config(provider, values, sites=None, site_names=None):
    """Saves provider + fields. A password field sent as "__saved__" or ""
    keeps the stored value. provider "" switches the integration off (and
    forgets the credentials)."""
    if not provider:
        scanner._set_setting("rmm_provider", "")
        scanner._set_setting("rmm_config", "{}")
        scanner._set_setting("rmm_status", "{}")
        conn = _db()
        conn.execute("DELETE FROM rmm_devices")
        conn.commit()
        conn.close()
        return
    if provider not in PROVIDERS:
        raise RMMError("Unknown RMM provider.")
    old = get_config() if get_provider_key() == provider else {}
    cfg = {}
    for f in PROVIDERS[provider].fields:
        v = (values or {}).get(f["name"])
        if f["type"] == "password" and v in (None, "", "__saved__"):
            v = old.get(f["name"])
        if isinstance(v, str):
            v = v.strip()
        if f["type"] == "select" and v not in [o[0] for o in f["options"]]:
            v = None
        cfg[f["name"]] = v
    cfg["sites"] = list(sites) if sites is not None else old.get("sites", [])
    cfg["site_names"] = dict(site_names) if site_names is not None else old.get("site_names", {})
    scanner._set_setting("rmm_provider", provider)
    scanner._set_setting("rmm_config", json.dumps(cfg))


def _instance(provider=None, values=None):
    key = provider or get_provider_key()
    if not key:
        raise RMMError("No RMM is set up.")
    cfg = get_config() if key == get_provider_key() else {}
    if values:   # testing unsaved values from the form
        merged = dict(cfg)
        for f in PROVIDERS[key].fields:
            v = values.get(f["name"])
            if f["type"] == "password" and v in (None, "", "__saved__"):
                continue
            merged[f["name"]] = v.strip() if isinstance(v, str) else v
        cfg = merged
    return PROVIDERS[key](cfg)


def test(provider=None, values=None):
    return _instance(provider, values).test()


# ---------------------------------------------------------------- sync

def sync():
    """Pulls the RMM's device list into rmm_devices. Returns a summary;
    errors are recorded in the status (and returned) rather than raised."""
    global _syncing
    key = get_provider_key()
    if not key:
        return {"ok": False, "error": "No RMM is set up."}
    if not _sync_lock.acquire(blocking=False):
        return {"ok": False, "error": "A sync is already running."}
    _syncing = True
    started = datetime.datetime.now().isoformat()
    try:
        cfg = get_config()
        devices = PROVIDERS[key](cfg).fetch(cfg.get("sites") or None)
        conn = _db()
        conn.execute("DELETE FROM rmm_devices WHERE provider = ?", (key,))
        conn.executemany(
            "INSERT OR REPLACE INTO rmm_devices (provider, uid, hostname, site, macs, ips, os, online, last_seen, "
            "category, url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(key, d["uid"], d["hostname"], d["site"], json.dumps(d["macs"]), json.dumps(d["ips"]), d["os"],
              None if d["online"] is None else int(bool(d["online"])), d["last_seen"], d["category"], d["url"])
             for d in devices])
        conn.commit()
        conn.close()
        _set_status(last_sync=datetime.datetime.now().isoformat(), started=started, count=len(devices),
                    with_mac=sum(1 for d in devices if d["macs"]), error=None)
        _cache.clear()
        return {"ok": True, "count": len(devices)}
    except RMMError as e:
        _set_status(error=str(e), last_attempt=started)
        return {"ok": False, "error": str(e)}
    except Exception as e:
        traceback.print_exc()
        _set_status(error=f"Unexpected error: {e}", last_attempt=started)
        return {"ok": False, "error": str(e)}
    finally:
        _syncing = False
        _sync_lock.release()


def sync_in_background():
    if get_provider_key() and not _syncing:
        threading.Thread(target=sync, daemon=True).start()
        return True
    return False


def maybe_sync_after(job):
    """scanner.on_job_done hook: refresh the RMM list after a network scan
    if it's older than AUTO_SYNC_MINUTES."""
    if job.get("kind") != "subnet" or job.get("status") != "done" or not get_provider_key():
        return
    last = get_status().get("last_sync")
    try:
        age = (datetime.datetime.now() - datetime.datetime.fromisoformat(last)).total_seconds() / 60
    except (TypeError, ValueError):
        age = None
    if age is None or age >= AUTO_SYNC_MINUTES:
        sync_in_background()


# ---------------------------------------------------------------- matching

_cache = {}


def _index():
    """(by_mac, by_hostname) for the active provider, cached until next sync."""
    key = get_provider_key()
    if not key:
        return None
    if key not in _cache:
        conn = _db()
        by_mac, by_name = {}, {}
        for r in conn.execute("SELECT * FROM rmm_devices WHERE provider = ?", (key,)):
            d = dict(r)
            d["macs"] = json.loads(d["macs"] or "[]")
            d["ips"] = json.loads(d["ips"] or "[]")
            for m in d["macs"]:
                by_mac.setdefault(m, d)
            n = _short(d["hostname"])
            if n:
                by_name.setdefault(n, []).append(d)
        conn.close()
        _cache.clear()
        _cache[key] = (by_mac, by_name)
    return _cache[key]


def _short(name):
    if not name:
        return None
    return str(name).split(".")[0].strip().lower() or None


def match(host, device_type=None):
    """None if no RMM is set up / synced; otherwise
    {"status": "managed" | "missing" | "na", "by": "mac" | "hostname", "device": {...}, "provider"}.
    "missing" = a computer-type device with no RMM record; "na" = no agent expected."""
    idx = _index()
    st = get_status()
    if idx is None or not st.get("last_sync"):
        return None
    by_mac, by_name = idx
    key = get_provider_key()
    mac = (host.get("mac") or "").upper()
    d = by_mac.get(mac) if mac else None
    if d:
        return {"status": "managed", "by": "mac", "device": d, "provider": PROVIDERS[key].label}
    n = _short(host.get("hostname"))
    if n and len(by_name.get(n, [])) == 1:
        return {"status": "managed", "by": "hostname", "device": by_name[n][0], "provider": PROVIDERS[key].label}
    return {"status": "missing" if device_type in AGENT_TYPES else "na", "provider": PROVIDERS[key].label}
