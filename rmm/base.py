"""
rmm/base.py - the interface every RMM provider implements.

A provider turns "credentials from the Settings page" into a list of the
devices that RMM manages, in one common shape. Aliana stores that list and
matches scanned hosts against it (by MAC address first, then hostname).

To add a provider (ConnectWise Automate, NinjaOne, N-able, Kaseya, ...):
subclass Provider in rmm/<name>.py, fill in key/label/fields, implement
test() and fetch(), and add it to PROVIDERS in rmm/__init__.py. Use only
read-only API calls -- Aliana never changes anything in the RMM.
"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request


class RMMError(Exception):
    """A problem talking to the RMM, with a message fit for the Settings page."""


def device(uid, hostname=None, site=None, macs=(), ips=(), os=None, online=None,
           last_seen=None, category=None, url=None):
    """The common device record every provider returns."""
    return {"uid": str(uid), "hostname": hostname, "site": site,
            "macs": sorted({m for m in macs if m}), "ips": sorted({i for i in ips if i}),
            "os": os, "online": online, "last_seen": last_seen, "category": category, "url": url}


class Provider:
    key = ""            # short id saved in settings, e.g. "datto"
    label = ""          # shown in the UI
    docs = ""           # one line: where to get credentials
    # Settings form fields: {"name", "label", "type": text|password|select,
    # "options": [(value, label)], "help", "required"}. Fields of type
    # "password" are never sent back to the browser once saved.
    fields = []
    # Whether the provider can be limited to some of its sites/companies
    has_sites = False

    def __init__(self, config):
        self.config = config or {}

    def test(self):
        """Checks the credentials. Returns {"ok": True, "message", "sites": [{"uid", "name"}]}
        or raises RMMError."""
        raise NotImplementedError

    def fetch(self, sites=None):
        """Returns [device(...)] -- every device the RMM manages (in the
        chosen sites, if any). Raises RMMError."""
        raise NotImplementedError

    # -- helpers for HTTP JSON APIs (stdlib only, no extra dependencies) --
    min_interval = 0.15     # seconds between requests (stay well under rate limits)
    _last = 0.0

    def http_json(self, method, url, headers=None, data=None, timeout=30):
        wait = self.min_interval - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
        body = None
        if data is not None:
            body = data if isinstance(data, bytes) else urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(url, data=body, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8") or "null")
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8", "ignore")[:200]
            except Exception:
                pass
            raise RMMError(self.http_error_message(e.code, detail))
        except urllib.error.URLError as e:
            raise RMMError(f"Can't reach {urllib.parse.urlparse(url).netloc}: {e.reason}. "
                           "Check the Pi has internet access and the API URL is right.")
        except (TimeoutError, OSError) as e:
            raise RMMError(f"Network error talking to the RMM: {e}")
        except ValueError:
            raise RMMError("The RMM returned something that isn't JSON -- is the API URL right?")

    def http_error_message(self, code, detail):
        if code in (400, 401):
            return "The RMM rejected the credentials (HTTP %d). Check the API key and secret." % code
        if code == 403:
            return "Access denied (HTTP 403). The API user may lack permission, or the IP is temporarily blocked."
        if code == 429:
            return "Rate limited by the RMM (HTTP 429). Wait a minute and try again."
        return f"RMM API error (HTTP {code}). {detail}".strip()
