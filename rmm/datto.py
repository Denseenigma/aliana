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
         "options": [(p, p.capitalize() + f"  ({p}-api.centrastage.net)") for p in PLATFORMS],
         "help": "Shown in Datto as the API URL, e.g. https://merlot-api.centrastage.net"},
        {"name": "api_key", "label": "API key", "type": "text", "required": True},
        {"name": "api_secret", "label": "API secret key", "type": "password", "required": True},
    ]

    def __init__(self, config):
        super().__init__(config)
        self._token = None
        self._token_time = 0

    @property
    def base(self):
        # ALIANA_DATTO_API_URL overrides the platform (new Datto regions, or testing)
        override = os.environ.get("ALIANA_DATTO_API_URL")
        if override:
            return override.rstrip("/")
        p = self.config.get("platform")
        if p not in PLATFORMS:
            raise RMMError("Choose your Datto RMM platform (from the API URL).")
        return f"https://{p}-api.centrastage.net"

    def _auth(self):
        # Tokens last 100 hours; refresh well before that
        if self._token and time.monotonic() - self._token_time < 3600:
            return self._token
        key, secret = self.config.get("api_key"), self.config.get("api_secret")
        if not key or not secret:
            raise RMMError("Enter the Datto API key and secret.")
        basic = base64.b64encode(b"public-client:public").decode()
        r = self.http_json("POST", self.base + "/auth/oauth/token",
                           headers={"Authorization": "Basic " + basic,
                                    "Content-Type": "application/x-www-form-urlencoded",
                                    "Accept": "application/json"},
                           data={"grant_type": "password", "username": key, "password": secret})
        tok = (r or {}).get("access_token")
        if not tok:
            raise RMMError("Datto didn't return an access token -- check the key and secret.")
        self._token, self._token_time = tok, time.monotonic()
        return tok

    def _get_pages(self, path, item_key, max_pages=200):
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
        return {"ok": True, "message": f"Connected to Datto RMM ({self.config.get('platform')}) -- "
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
