"""
labels.py - your own word on a device: set its type (and optionally a
name and a note) on the device page, and it overrules the triad's vote.
Stored per MAC address in aliana.db (table device_labels).
"""
import datetime
import sqlite3
import threading

import scanner

_lock = threading.Lock()
_cache = None


def _db():
    conn = sqlite3.connect(scanner.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _db()
    conn.execute("""CREATE TABLE IF NOT EXISTS device_labels (
        mac TEXT PRIMARY KEY, type TEXT, name TEXT, note TEXT, at TEXT)""")
    conn.commit()
    conn.close()


def _load():
    global _cache
    with _lock:
        if _cache is None:
            try:
                conn = _db()
                _cache = {r["mac"]: dict(r) for r in conn.execute("SELECT * FROM device_labels")}
                conn.close()
            except sqlite3.Error:
                _cache = {}
        return _cache


def get(mac):
    if not mac:
        return None
    return _load().get(mac.upper())


def set_label(mac, type_=None, name=None, note=None):
    """Empty type, name and note removes the label."""
    global _cache
    mac = mac.upper()
    type_ = (type_ or "").strip() or None
    name = (name or "").strip()[:80] or None
    note = (note or "").strip()[:300] or None
    conn = _db()
    if not (type_ or name or note):
        conn.execute("DELETE FROM device_labels WHERE mac = ?", (mac,))
    else:
        conn.execute("INSERT INTO device_labels (mac, type, name, note, at) VALUES (?, ?, ?, ?, ?) "
                     "ON CONFLICT(mac) DO UPDATE SET type = excluded.type, name = excluded.name, "
                     "note = excluded.note, at = excluded.at",
                     (mac, type_, name, note, datetime.datetime.now().isoformat(timespec="seconds")))
    conn.commit()
    conn.close()
    with _lock:
        _cache = None
    return get(mac)


def forget_all():
    global _cache
    with _lock:
        _cache = None
