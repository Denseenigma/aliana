"""
rmm/datto.py - Datto RMM provider (API v2, read-only).

Credentials: in Datto RMM, enable API access (Setup > Global Settings >
Access Control), then generate an API key + secret for a user (Setup >
Users > [user] > Generate API Keys). Use a dedicated user with view-only
permissions. The API URL is shown next to the keys, e.g.
https://merlot-api.centrastage.net.

Calls used (all GET apart from the token):
  POST /auth/oauth/token                                 (OAuth2 password grant)
  GET  /api/v2/account/sites                             (site list, paged)
  GET  /api/v2/site/{uid}/devices                        (hostname, OS, online, last seen)
  GET  /api/v2/site/{uid}/devices/network-interface      (NICs with MAC addresses)
Paging follows pageDetails.nextPageUrl. Datto allows 600 reads a minute per
account; requests here are spaced to stay well under that.
"""
import base64
import datetime
import os
import time
import urllib.parse

from .base import Provider, RMMError, device

PLATFORMS = ["pinotage", "merlot", "concord", "vidal", "zinfandel", "syrah"]


def _norm_mac(mac):
    hexes = "".join(ch for ch in str(mac or "") if ch in "0123456789abcdefABCDEF")
    if len(hexes) != 12 or hexes in ("000000000000", "FFFFFFFFFFFF"):
        return None
    return ":".join(hexes[i:i + 2] for i in range(0, 12, 2)).upper()


class Datto(Provider):
    key = "datto"
    label = "Datto RMM"
    docs = ("Datto RMM: Setup > Global Settings > Access Control (enable API), then Setup > Users > "
            "[user] > Generate API Keys. Use a view-only user.")
    has_sites = True
    fields = [
        {"name": "platform", "label": "Platform", "type": "select", "required": True,
         "options": [("auto", "Auto-detect")] +
                    [(p, p.capitalize() + f"  ({p}-api.centrastage.net)") for p in PLATFORMS],
         "help": "Datto shows it next to the API keys as the API URL, e.g. https://merlot-api.centrastage.net. "
                 "Auto-detect tries each platform."},
        {"name": "api_url", "label": "API URL (optional)", "type": "text",
         "help": "Paste the API URL from Datto to override the platform, e.g. for a new region."},
        {"name": "api_key", "label": "API key", "type": "password", "required": True},
        {"name": "api_secret", "label": "API secret key", "type": "password", "required": True},
    ]

    def __init__(self, config):
        super().__init__(config)
        self._token = None
        self._token_time = 0
        self._base = None
        self.learned = {}     # non-secret settings worked out here (detected platform), saved by rmm/__init__

    @staticmethod
    def clean_url(u):
        """'merlot-api.centrastage.net/api/' -> 'https://merlot-api.centrastage.net'."""
        u = (u or "").strip().rstrip("/")
        if not u:
            return ""
        if "://" not in u:
            u = "https://" + u
        for tail in ("/api/v2", "/api", "/auth/oauth/token"):
            if u.lower().endswith(tail):
                u = u[:-len(tail)]
        return u.rstrip("/")

    def _candidates(self):
        override = os.environ.get("ALIANA_DATTO_API_URL") or self.config.get("api_url")
        if override:
            return [(None, self.clean_url(override))]
        # The chosen platform first; the others after it, so keys from a
        # different platform than the one picked still work (and get learned)
        p = self.config.get("platform")
        order = ([p] if p in PLATFORMS else []) + [q for q in PLATFORMS if q != p]
        return [(q, f"https://{q}-api.centrastage.net") for q in order]

    @property
    def base(self):
        if self._base is None:
            self._auth()
        return self._base

    def where(self):
        return urllib.parse.urlparse(self._base or "").netloc or "Datto"

    def _auth(self):
        # Tokens last 100 hours; refresh well before that
        if self._token and time.monotonic() - self._token_time < 3600:
            return self._token
        key, secret = (self.config.get("api_key") or "").strip(), (self.config.get("api_secret") or "").strip()
        if not key or not secret:
            raise RMMError("Enter the Datto API key and secret.")
        basic = base64.b64encode(b"public-client:public").decode()
        cands = self._candidates()
        tried, last, first = [], None, None
        for plat, base in cands:
            try:
                r = self.http_json("POST", base + "/auth/oauth/token",
                                   headers={"Authorization": "Basic " + basic,
                                            "Content-Type": "application/x-www-form-urlencoded",
                                            "Accept": "application/json"},
                                   data={"grant_type": "password", "username": key, "password": secret})
            except RMMError as e:
                if len(cands) == 1:
                    raise RMMError("Signing in to Datto failed: " + str(e))
                st = getattr(e, "status", None)
                if st in (403, 429) and plat == cands[0][0]:
                    raise RMMError("Signing in to Datto failed: " + str(e))   # blocked/limited: don't hammer the rest
                tried.append(f"{plat} {st or 'unreachable'}")
                first = first or (e if getattr(e, "detail", None) else None)
                last = last if (last and getattr(last, "status", None)) else e
                continue
            tok = (r or {}).get("access_token")
            if not tok:
                raise RMMError(f"{urllib.parse.urlparse(base).netloc} didn't return an access token "
                               "-- is the API URL right?")
            self._token, self._token_time, self._base = tok, time.monotonic(), base
            if plat and self.config.get("platform") != plat:
                self.learned["platform"] = plat
                self.config["platform"] = plat
            return tok
        if all(t.endswith("unreachable") for t in tried):
            raise RMMError("Can't reach Datto RMM from the Pi: " + str(last))
        said = f" Datto said: {first.detail}." if first is not None else ""
        raise RMMError("No Datto platform accepted this API key and secret (" + ", ".join(tried) + ")." + said + " "
                       "Check the key and secret were copied in full (regenerating keys in Datto invalidates "
                       "the old pair), the user is active, and API access is on in Setup > Global Settings "
                       "> Access Control.")

    def http_error_message(self, code, detail, url=""):
        host = urllib.parse.urlparse(url).netloc or "Datto"
        why = f" Datto said: {detail}." if detail else ""
        if "/auth/oauth/token" in url:
            if code in (400, 401):
                return (f"{host} rejected the API key/secret (HTTP {code}).{why} Check: the platform matches the "
                        "API URL shown in Datto (or use Auto-detect), the key and secret were copied in full, the "
                        "user is active, and API access is enabled in Setup > Global Settings > Access Control.")
            if code == 403:
                return (f"{host} refused the sign-in (HTTP 403).{why} This usually means the Pi's IP is "
                        "temporarily blocked after too many requests -- wait 5 minutes.")
        else:
            if code == 401:
                return f"{host}: the sign-in token was refused (HTTP 401).{why} Try again; re-enter the keys if it persists."
            if code == 403:
                return (f"{host} denied access to {urllib.parse.urlparse(url).path} (HTTP 403).{why} Give the "
                        "API user a Security Level that can view Sites and Devices, or wait 5 minutes if it was "
                        "rate limited.")
            if code == 404:
                return f"{host}: {urllib.parse.urlparse(url).path} not found (HTTP 404) -- is the API URL right?"
        if code == 429:
            return "Datto rate limit hit (HTTP 429). Wait a minute and try again."
        return f"Datto API error from {host} (HTTP {code}).{why}"

    def _get_pages(self, path, item_key, max_pages=200):
        self._auth()
        url = self.base + "/api" + path + ("&" if "?" in path else "?") + "max=250"
        items = []
        for _ in range(max_pages):
            r = self.http_json("GET", url, headers={"Authorization": "Bearer " + self._auth(),
                                                    "Accept": "application/json"})
            items += (r or {}).get(item_key) or []
            nxt = ((r or {}).get("pageDetails") or {}).get("nextPageUrl")
            if not nxt:
                break
            url = nxt if nxt.startswith("http") else self.base + nxt
        return items

    def sites(self):
        return [{"uid": s.get("uid"), "name": s.get("name") or s.get("uid"),
                 "devices": ((s.get("devicesStatus") or {}).get("numberOfDevices"))}
                for s in self._get_pages("/v2/account/sites", "sites") if s.get("uid")]

    def test(self):
        sites = self.sites()
        return {"ok": True, "message": f"Connected to Datto RMM ({self.where()}) -- "
                                       f"{len(sites)} site{'s' if len(sites) != 1 else ''}.",
                "sites": sorted(sites, key=lambda s: (s["name"] or "").lower())}

    def fetch(self, sites=None):
        site_list = self.sites()
        if sites:
            wanted = set(sites)
            site_list = [s for s in site_list if s["uid"] in wanted]
        out = {}
        for s in site_list:
            uid = s["uid"]
            for d in self._get_pages(f"/v2/site/{uid}/devices", "devices"):
                if d.get("deleted"):
                    continue
                last = d.get("lastSeen")
                out[d.get("uid")] = {
                    "uid": d.get("uid"), "hostname": d.get("hostname"), "site": d.get("siteName") or s["name"],
                    "macs": set(), "ips": {d.get("intIpAddress")} if d.get("intIpAddress") else set(),
                    "os": d.get("operatingSystem"), "online": d.get("online"),
                    "last_seen": datetime.datetime.fromtimestamp(last / 1000).isoformat() if last else None,
                    "category": ((d.get("deviceType") or {}).get("category")),
                    "url": d.get("portalUrl")}
            for d in self._get_pages(f"/v2/site/{uid}/devices/network-interface", "devices"):
                rec = out.get(d.get("uid"))
                if rec is None:   # in the NIC list but not the device list: keep what we have
                    rec = out[d.get("uid")] = {
                        "uid": d.get("uid"), "hostname": d.get("hostname"), "site": d.get("siteName") or s["name"],
                        "macs": set(), "ips": set(), "os": None, "online": None, "last_seen": None,
                        "category": ((d.get("deviceType") or {}).get("category")), "url": None}
                for nic in d.get("nics") or []:
                    m = _norm_mac(nic.get("macAddress"))
                    if m:
                        rec["macs"].add(m)
                    if nic.get("ipv4"):
                        rec["ips"].add(nic["ipv4"])
        return [device(r["uid"], r["hostname"], r["site"], r["macs"], r["ips"], r["os"], r["online"],
                       r["last_seen"], r["category"], r["url"]) for r in out.values() if r["uid"]]
