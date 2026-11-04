"""
auth.py - Aliana's lock: an authenticator app (TOTP) instead of a password.

  * Sign in with the 6-digit code from an authenticator app (Google
    Authenticator, Microsoft Authenticator, Authy, 1Password, ...).
  * Lost the phone? Use one of the 10 single-use recovery codes.
  * Lost both? "Erase & reset" wipes the sensitive data (RMM credentials and
    their encryption key, scan history, device inventory) and lets you set up
    a new authenticator. Settings, exclusions and Wi-Fi networks are kept,
    so the Pi stays reachable.

Setting up an authenticator (first run, or after an erase) needs a 6-digit
pairing code that only appears on the Pi's own screen (and in
`journalctl -u aliana`). Someone else on the network can't claim the Pi,
or trigger an erase, without physical access to it.

The Pi's own screen (requests from 127.0.0.1) never needs to sign in.

Stored in ~/.config/aliana/ (owner-only, outside the repo):
  auth.json     -- TOTP secret, recovery-code hashes, session epoch
  session.key   -- signs the browser session cookie
Override the folder with ALIANA_CONFIG_DIR.

Locked out and no access to the Pi screen? Over SSH:
  cd ~/aliana && ./venv/bin/python3 auth.py --reset    (erases, like the button)
"""
import base64
import datetime
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import struct
import threading
import time
import urllib.parse

ISSUER = "Aliana"
DIGITS = 6
PERIOD = 30
RECOVERY_COUNT = 10
SESSION_HOURS = 12
PAIRING_TTL = 15 * 60          # an unused pairing code is replaced after this
PAIRING_TRIES = 5              # wrong pairing codes before a new one is drawn

_lock = threading.RLock()


class AuthError(Exception):
    pass


# ---------------------------------------------------------------- storage

def config_dir():
    return os.path.expanduser(os.environ.get("ALIANA_CONFIG_DIR") or "~/.config/aliana")


def _path(name):
    return os.path.join(config_dir(), name)


def _write_private(path, data):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _load():
    try:
        with open(_path("auth.json")) as f:
            d = json.load(f)
        return d if isinstance(d, dict) and d.get("secret") else None
    except (OSError, ValueError):
        return None


def _save(d):
    _write_private(_path("auth.json"), json.dumps(d, indent=1).encode())


def is_configured():
    return _load() is not None


def session_key():
    """Random key that signs Flask's session cookie (created on first use)."""
    path = _path("session.key")
    try:
        with open(path, "rb") as f:
            key = f.read().strip()
            if len(key) >= 32:
                return key
    except OSError:
        pass
    key = secrets.token_hex(32).encode()
    _write_private(path, key + b"\n")
    return key


def epoch():
    """Changes whenever the authenticator is replaced or reset, which signs
    every browser out."""
    d = _load()
    return d.get("epoch") if d else None


# ---------------------------------------------------------------- TOTP (RFC 6238)

def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret, counter):
    pad = "=" * (-len(secret) % 8)
    key = base64.b32decode(secret.upper() + pad)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return str(code).zfill(DIGITS)


def _match_step(secret, code, now=None, window=1):
    """Time step the code belongs to (allowing +/- one step of clock drift), or None."""
    code = "".join(ch for ch in str(code) if ch.isdigit())
    if len(code) != DIGITS:
        return None
    step = int((now or time.time()) // PERIOD)
    for s in range(step - window, step + window + 1):
        if hmac.compare_digest(_hotp(secret, s), code):
            return s
    return None


def otpauth_uri(secret, label):
    q = urllib.parse.urlencode({"secret": secret, "issuer": ISSUER, "digits": DIGITS, "period": PERIOD})
    return f"otpauth://totp/{urllib.parse.quote(ISSUER + ':' + label)}?{q}"


def pretty_secret(secret):
    return " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))


# ---------------------------------------------------------------- recovery codes

_RC_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"   # no 0/O, 1/I


def _norm_rc(code):
    return "".join(ch for ch in str(code).upper() if ch.isalnum())


def _hash_rc(code):
    return hashlib.sha256(("aliana-rc:" + _norm_rc(code)).encode()).hexdigest()


def _new_recovery_codes():
    codes = []
    for _ in range(RECOVERY_COUNT):
        raw = "".join(secrets.choice(_RC_ALPHABET) for _ in range(10))
        codes.append(raw[:5] + "-" + raw[5:])
    return codes


def looks_like_recovery(code):
    n = _norm_rc(code)
    return len(n) == 10 and not n.isdigit()


# ---------------------------------------------------------------- sign-in throttle

_fails = {}            # ip -> [count, locked_until]
_global_fails = []     # timestamps of recent failures from anywhere


def _throttle_check(ip):
    now = time.time()
    rec = _fails.get(ip)
    if rec and rec[1] > now:
        raise AuthError(f"Too many wrong codes. Try again in {int(rec[1] - now) + 1} s.")
    recent = [t for t in _global_fails if t > now - 60]
    _global_fails[:] = recent
    if len(recent) >= 30:
        raise AuthError("Too many wrong codes from this network. Try again in a minute.")


def _throttle_fail(ip):
    now = time.time()
    rec = _fails.setdefault(ip, [0, 0])
    rec[0] += 1
    if rec[0] >= 5:   # 5 wrong -> 30 s, then doubling, max 15 min
        rec[1] = now + min(900, 30 * 2 ** (rec[0] - 5))
    _global_fails.append(now)


def _throttle_ok(ip):
    _fails.pop(ip, None)


# ---------------------------------------------------------------- sign in

def login(code, ip):
    """Checks an authenticator code or a recovery code. Returns
    {"method": "totp"|"recovery", "recovery_left": n}. Raises AuthError."""
    with _lock:
        _throttle_check(ip)
        d = _load()
        if not d:
            raise AuthError("No authenticator is set up yet.")
        code = (code or "").strip()
        if looks_like_recovery(code):
            h = _hash_rc(code)
            left = [x for x in d.get("recovery", []) if not hmac.compare_digest(x, h)]
            if len(left) == len(d.get("recovery", [])):
                _throttle_fail(ip)
                raise AuthError("That recovery code isn't valid (or was already used).")
            d["recovery"] = left
            _save(d)
            _throttle_ok(ip)
            _log(f"signed in with a recovery code from {ip} ({len(left)} left)")
            return {"method": "recovery", "recovery_left": len(left)}
        step = _match_step(d["secret"], code)
        if step is None:
            _throttle_fail(ip)
            raise AuthError("Wrong code. Check the time on your phone and try the newest code.")
        if step <= d.get("last_step", 0):   # each code works once
            _throttle_fail(ip)
            raise AuthError("That code was already used. Wait for the next one.")
        d["last_step"] = step
        _save(d)
        _throttle_ok(ip)
        return {"method": "totp", "recovery_left": len(d.get("recovery", []))}


def verify_current(code, ip):
    """Re-check a fresh authenticator code before a sensitive change."""
    r = login(code, ip)
    if r["method"] != "totp":
        raise AuthError("Use a code from your authenticator app for this.")
    return r


def status():
    d = _load()
    if not d:
        return {"configured": False}
    return {"configured": True, "created": d.get("created"),
            "recovery_left": len(d.get("recovery", [])), "recovery_total": RECOVERY_COUNT}


# ---------------------------------------------------------------- pairing code (Pi screen)

_pairing = {"code": None, "expires": 0, "tries": 0, "reason": None, "requested": 0}


def _new_pairing(reason):
    _pairing.update(code="%06d" % secrets.randbelow(10 ** 6), expires=time.time() + PAIRING_TTL,
                    tries=0, reason=reason)
    _log(f"pairing code for {reason}: {_pairing['code']} (shown on the Pi screen)")


def request_pairing(reason):
    """Shows a pairing code on the Pi screen. reason: "setup" or "reset"."""
    with _lock:
        if not _pairing["code"] or _pairing["expires"] < time.time() or _pairing["reason"] != reason:
            _new_pairing(reason)
        _pairing["requested"] = time.time()


def pairing_display():
    """What the Pi screen shows: {"code", "reason", "expires_in"} or None.
    Setup codes show whenever nothing is set up; reset codes only for a few
    minutes after someone asks for one."""
    with _lock:
        now = time.time()
        if not is_configured():
            if not _pairing["code"] or _pairing["expires"] < now or _pairing["reason"] != "setup":
                _new_pairing("setup")
        elif _pairing["code"] and (_pairing["reason"] != "reset" or _pairing["expires"] < now):
            _pairing["code"] = None
        if not _pairing["code"]:
            return None
        return {"code": _pairing["code"], "reason": _pairing["reason"],
                "expires_in": int(_pairing["expires"] - now)}


def cancel_pairing(reason):
    with _lock:
        if _pairing["reason"] == reason:
            _pairing["code"] = None


def check_pairing(code, reason, ip):
    with _lock:
        _throttle_check(ip)
        if reason == "setup" and not is_configured():
            pairing_display()       # make sure a setup code exists
        if not _pairing["code"] or _pairing["reason"] != reason or _pairing["expires"] < time.time():
            raise AuthError("No pairing code is showing. Ask for a new one.")
        code = "".join(ch for ch in str(code or "") if ch.isdigit())
        if not hmac.compare_digest(code, _pairing["code"]):
            _pairing["tries"] += 1
            _throttle_fail(ip)
            if _pairing["tries"] >= PAIRING_TRIES:
                _new_pairing(reason)
                raise AuthError("Wrong pairing code. A new one is now showing on the Pi screen.")
            raise AuthError("Wrong pairing code. Check the Pi screen.")
        _pairing["code"] = None
        _throttle_ok(ip)
        return True


# ---------------------------------------------------------------- enrollment

_pending = {}     # token -> {"secret", "expires", "replace"}


def start_enrollment(replace=False):
    """A new secret waiting to be confirmed with a code. Returns a token."""
    with _lock:
        now = time.time()
        for t in [t for t, p in _pending.items() if p["expires"] < now]:
            _pending.pop(t, None)
        token = secrets.token_urlsafe(18)
        _pending[token] = {"secret": new_secret(), "expires": now + 15 * 60, "replace": replace}
        return token


def pending_secret(token):
    p = _pending.get(token or "")
    if not p or p["expires"] < time.time():
        return None
    return p["secret"]


def finish_enrollment(token, code, ip):
    """Confirms the new authenticator with its first code. Saves it, makes
    new recovery codes (returned once, in plain text) and a new session epoch."""
    with _lock:
        _throttle_check(ip)
        p = _pending.get(token or "")
        if not p or p["expires"] < time.time():
            raise AuthError("This setup expired. Start again.")
        if is_configured() and not p["replace"]:
            raise AuthError("An authenticator is already set up.")
        step = _match_step(p["secret"], code)
        if step is None:
            _throttle_fail(ip)
            raise AuthError("That code doesn't match. Make sure you scanned the new QR code, then try the newest code.")
        codes = _new_recovery_codes()
        _save({"secret": p["secret"], "created": _now(), "last_step": step,
               "recovery": [_hash_rc(c) for c in codes], "epoch": secrets.token_hex(8)})
        _pending.pop(token, None)
        _pairing["code"] = None
        _throttle_ok(ip)
        _log(("authenticator replaced" if p["replace"] else "authenticator set up") + f" from {ip}")
        return codes


def new_recovery_codes():
    with _lock:
        d = _load()
        if not d:
            raise AuthError("No authenticator is set up yet.")
        codes = _new_recovery_codes()
        d["recovery"] = [_hash_rc(c) for c in codes]
        _save(d)
        _log("new recovery codes made (the old ones no longer work)")
        return codes


# ---------------------------------------------------------------- erase & reset

def erase_sensitive(db_path, vault_key_path):
    """Lost the authenticator AND the recovery codes: wipe everything an
    intruder would want, then forget the authenticator.

    Erased: RMM provider/credentials/status and the synced RMM device list,
            the vault encryption key, all scans / hosts / ports / jobs
            (scan history, device inventory, identification results).
    Kept:   settings (profile, auto-scan, intervals, exclusions, never-probe
            ports, identification on/off), the vendor database, Wi-Fi."""
    with _lock:
        if os.path.exists(db_path):
            conn = sqlite3.connect(db_path)
            try:
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                for t in ("ports", "hosts", "scans", "jobs", "rmm_devices"):
                    if t in tables:
                        conn.execute(f"DELETE FROM {t}")
                if "settings" in tables:
                    conn.execute("DELETE FROM settings WHERE key LIKE 'rmm\\_%' ESCAPE '\\'")
                if "sqlite_sequence" in tables:
                    conn.execute("DELETE FROM sqlite_sequence")
                conn.commit()
                conn.execute("VACUUM")    # don't leave the old rows in free pages
            finally:
                conn.close()
        for path in (vault_key_path, _path("auth.json")):
            _shred(path)
        _pending.clear()
        _pairing["code"] = None
        _log("ERASED sensitive data and removed the authenticator (lost-access reset)")


def _shred(path):
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(secrets.token_bytes(max(size, 64)))
            f.flush()
            os.fsync(f.fileno())
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError as e:
        _log(f"couldn't remove {path}: {e}")


# ---------------------------------------------------------------- helpers

def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def _log(msg):
    print("aliana auth:", msg, flush=True)


if __name__ == "__main__":
    import sys
    if "--reset" in sys.argv:
        import scanner
        import vault
        ans = input("This erases RMM credentials, scan history and the device inventory,\n"
                    "and removes the authenticator. Type ERASE to continue: ")
        if ans.strip() != "ERASE":
            sys.exit("Cancelled.")
        erase_sensitive(scanner.DB_PATH, vault.key_path())
        print("Done. Restart Aliana (sudo systemctl restart aliana) and set up a new authenticator.")
    elif "--status" in sys.argv:
        print(json.dumps(status(), indent=1))
    else:
        print(__doc__)
