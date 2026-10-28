# RMM integrations

Aliana can check scanned devices against an RMM's device list ("is this
computer managed?"). It only **reads** from the RMM, and it matches hosts by
**MAC address** first, then by hostname. Computers (Windows / Mac / Linux /
VM by Aliana's device-type guess) with no match get a *No RMM agent*
finding; other device types show "no agent expected".

Set it up on the **Settings** page. Credentials never go into the repo and
are never sent back to the browser -- see *How credentials are stored* below.

## Datto RMM -- step by step

You need a Datto RMM **Administrator** login for steps 1-2.

1. **Turn on the API** (once per account): *Setup > Global Settings > Access
   Control* -> switch on **Enable API Access**.
2. **(Recommended) a dedicated user for Aliana.** *Setup > Security Levels*:
   make a level that can only **view** sites and devices (no jobs,
   components, remote takeover or edits). Then *Setup > Users*: add a user
   such as `aliana-readonly` on that level. Aliana only ever reads, so if
   the key leaks the damage is limited to someone *reading* your device list.
3. **Generate the keys**: *Setup > Users* -> click the user -> **Generate API
   Keys**. Set **API Security Level** to the read-only level and leave
   **API Component Level** as low as it goes. Copy three things:
   - **API URL** (e.g. `https://merlot-api.centrastage.net` -> the platform is *merlot*)
   - **API Key**
   - **API Secret Key** -- shown **once**; leave the page and it's gone (you'd
     have to regenerate, which kills the old pair).
   Click **Save User**.
4. **In Aliana**: open `http://<pi>/settings` -> *RMM integration*:
   - Provider: **Datto RMM**; Platform: the word from the API URL.
   - Paste the API key and API secret key.
   - **Test connection** -> you get "Connected ... N sites" and a site list.
   - Tick **All sites**, or only the sites for the network you're scanning.
   - **Save** -- this syncs straight away. After that Aliana re-syncs after a
     network scan whenever its copy is more than 30 minutes old (or press
     **Sync now**).
5. Run a scan. Host cards show *Datto RMM ✓ host · site* or *Not in Datto
   RMM*; the Devices page has a *No RMM agent* filter.

Troubleshooting: *HTTP 401* = wrong key/secret or wrong platform; *HTTP 403* =
API access not enabled, user inactive, or Datto's rate-limit block (wait 5
minutes); "missing encryption key" = see below. Datto allows 600 reads a
minute per account (shared with any other integrations you run); Aliana spaces
its requests well under that.

To revoke: *Disconnect* in Aliana wipes the stored keys; in Datto, **Delete
API Keys** on the user (or deactivate the user) kills them for good.

## How credentials are stored

- Password-type fields (for Datto: API key **and** secret) are encrypted
  with Fernet (AES + HMAC, `cryptography` package) before they are written to
  `aliana.db`, stored as `enc:v1:...`.
- The encryption key is a separate file **outside the repo**:
  `~/.config/aliana/secret.key` for the user the service runs as
  (`/home/admin/.config/aliana/secret.key`), mode `0600`, created on first
  save. `ALIANA_KEY_FILE` moves it.
- `aliana.db` is set to `0600` and is in `.gitignore` (as are `*.key`,
  `.env`, `*.pem`, SQLite journal files).
- Keys saved by an older version in plain text are encrypted automatically
  the next time Aliana starts.
- Lose or delete the key file and the saved keys can't be read -- Aliana
  says so and you re-enter them. Don't copy the key file and the database
  to the same place.
- Aliana never stores plain text as a fallback: without `cryptography`
  installed, saving keys fails with a message telling you to run `setup.sh`.
- The Settings page only ever receives `__saved__` for a stored secret.

Limits, honestly: anyone with a shell as the service user (or root) on the
Pi can read both files and decrypt the keys -- encryption at rest protects
against the repo, backups, a copied database or a pulled SD card's DB file,
not a compromised Pi. Hence the view-only Datto user, and the planned
portal login (backlog #8) so nobody on the LAN can reach Settings.

## Supported

| Provider  | Module         | Notes |
|-----------|----------------|-------|
| Datto RMM | `rmm/datto.py` | API v2, read-only. Setup steps above. Uses `/v2/account/sites`, `/v2/site/{uid}/devices` and `/v2/site/{uid}/devices/network-interface`. |

## Adding a provider

1. Create `rmm/<name>.py` with a subclass of `rmm.base.Provider`:
   - `key`, `label`, `docs` (where to get credentials), `has_sites`
   - `fields`: the Settings form (`text`, `password`, `select`); make every
     credential a `password` field -- those are encrypted at rest and
     write-only from the browser's point of view
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
