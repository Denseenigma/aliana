#!/usr/bin/env python3
"""
tools/build_oui.py - (re)builds data/oui.tsv.gz, Aliana's offline MAC vendor
database (IEEE MA-L / MA-M / MA-S assignments).

Sources, any of:
  * the IEEE registry CSVs  (https://standards-oui.ieee.org/oui/oui.csv,
    .../oui28/mam.csv, .../oui36/oui36.csv)   -- default, needs internet
  * Wireshark's generated epan/manuf-data.c   (--wireshark path)

Output: one line per prefix, "HEXPREFIX<TAB>Vendor", where the prefix is 6
(24-bit), 7 (28-bit) or 9 (36-bit) hex digits. Lookups try the longest
prefix first.

Usage:
  python3 tools/build_oui.py                      # download from IEEE
  python3 tools/build_oui.py --wireshark manuf-data.c
"""
import csv
import gzip
import io
import os
import re
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "data", "oui.tsv.gz")
IEEE = [
    "https://standards-oui.ieee.org/oui/oui.csv",
    "https://standards-oui.ieee.org/oui28/mam.csv",
    "https://standards-oui.ieee.org/oui36/oui36.csv",
]


def from_ieee():
    out = {}
    for url in IEEE:
        req = urllib.request.Request(url, headers={"User-Agent": "Aliana vendor database update"})
        with urllib.request.urlopen(req, timeout=120) as r:
            text = r.read().decode("utf-8", "replace")
        for row in csv.DictReader(io.StringIO(text)):
            hexp = (row.get("Assignment") or "").strip().upper()
            org = (row.get("Organization Name") or "").strip()
            if re.fullmatch(r"[0-9A-F]{6}|[0-9A-F]{7}|[0-9A-F]{9}", hexp) and org:
                out[hexp] = org
    return out


_WS = re.compile(r'\{\s*\{\s*((?:0x[0-9A-Fa-f]{2}\s*,?\s*){3,5})\}\s*,\s*"[^"]*"\s*,\s*"((?:[^"\\]|\\.)*)"\s*\}')


def from_wireshark(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    out = {}
    sections = [("oui24", 6), ("oui28", 7), ("oui36", 9)]
    for name, digits in sections:
        start = text.find(f"global_manuf_{name}_table[]")
        if start < 0:
            continue
        end = text.find("};", start)
        for m in _WS.finditer(text, start, end):
            hexp = "".join(b[2:] for b in re.findall(r"0x[0-9A-Fa-f]{2}", m.group(1))).upper()[:digits]
            out[hexp] = bytes(m.group(2), "utf-8").decode("unicode_escape").encode("latin-1").decode("utf-8", "replace")
    return out


def write(entries):
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    lines = "".join(f"{k}\t{v}\n" for k, v in sorted(entries.items()))
    with gzip.open(OUT + ".tmp", "wt", encoding="utf-8", compresslevel=9) as f:
        f.write(lines)
    os.replace(OUT + ".tmp", OUT)
    return len(entries)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--wireshark":
        data = from_wireshark(sys.argv[2])
    else:
        data = from_ieee()
    if len(data) < 10000:
        sys.exit(f"Only {len(data)} entries -- refusing to overwrite the database.")
    print(f"{write(data)} vendor prefixes written to {OUT}")
