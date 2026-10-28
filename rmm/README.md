# RMM integrations

Aliana can check scanned devices against an RMM's device list ("is this
computer managed?"). It only **reads** from the RMM, and it matches hosts by
**MAC address** first, then by hostname. Computers (Windows / Mac / Linux /
VM by Aliana's device-type guess) with no match get a *No RMM agent*
finding; other device types show "no agent expected".

Set it up on the **Settings** page. Credentials are stored in Aliana's local
database (`aliana.db`) and are never sent back to the browser.

## Supported

| Provider  | Module         | Notes |
|-----------|----------------|-------|
| Datto RMM | `rmm/datto.py` | API v2. Enable API access (Setup > Global Settings > Access Control), generate keys for a view-only user (Setup > Users > user > Generate API Keys), pick your platform from the API URL. Uses `/v2/account/sites`, `/v2/site/{uid}/devices` and `/v2/site/{uid}/devices/network-interface`. |

## Adding a provider

1. Create `rmm/<name>.py` with a subclass of `rmm.base.Provider`:
   - `key`, `label`, `docs` (where to get credentials), `has_sites`
   - `fields`: the Settings form (`text`, `password`, `select`); password
     fields are write-only from the browser's point of view
   - `test()` -> `{"ok": True, "message": "...", "sites": [{"uid", "name"}]}`
   - `fetch(sites=None)` -> a list of `rmm.base.device(...)` records
     (`uid, hostname, site, macs, ips, os, online, last_seen, category, url`).
     MACs as `AA:BB:CC:DD:EE:FF`.
   - Raise `RMMError("message for the user")` on problems.
   - Use `self.http_json()` (stdlib only, spaced requests) and **read-only**
     endpoints.
2. Register it in `PROVIDERS` in `rmm/__init__.py`.

That's all -- the Settings form, sync, matching, dashboard tags, Devices
page column, findings and CSV export work for every provider.

For testing against a fake server, `ALIANA_DATTO_API_URL` overrides the
Datto API base URL.
