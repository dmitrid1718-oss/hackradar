#!/usr/bin/env python3
"""HackRadar public-feed collector. Run via GitHub Actions; stdlib only."""
import datetime as dt
import json
import pathlib
import re
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEST = ROOT / "data" / "activity.json"
UA = {"User-Agent": "HackRadar/0.1 (+https://hackradar.org; public research)"}
errors = []

def get(url, timeout=25):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")

def previous():
    try: return json.loads(DEST.read_text())
    except (OSError, ValueError): return {}

old = previous()
points, network_events, advisory_events = [], [], []

# Static SANS feed; don't poll more than hourly.
try:
    raw = get("https://feeds.dshield.org/feeds/topips.txt")
    ips = []
    for line in raw.splitlines():
        if not line.strip() or line.startswith("#"): continue
        match = re.search(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", line)
        if match:
            ip = match.group()
            if ip not in ips and all(int(p) <= 255 for p in ip.split(".")):
                ips.append(ip)
    ips = ips[:18]
    if not ips:
        raise ValueError("No source IPs found in DShield feed")
    previous_geos = {p["ip"]: p for p in old.get("points", []) if "ip" in p}
    for ip in ips:
        network_events.append({
            "type": "network", "title": "Reported suspicious source: " + ip,
            "note": "Listed in SANS Internet Storm Center's recent top-source feed; not proof of attacker identity.",
            "date": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d"),
            "url": "https://www.dshield.org/ipinfo.html?ip=" + ip
        })
        cached = previous_geos.get(ip)
        if cached and "lat" in cached and "lon" in cached:
            points.append(cached)
            continue
        try:
            geo = json.loads(get("https://ipwho.is/" + ip, timeout=12))
            if geo.get("success") and isinstance(geo.get("latitude"), (float, int)) and isinstance(geo.get("longitude"), (float, int)):
                points.append({"ip": ip, "lat": geo["latitude"], "lon": geo["longitude"], "country": geo.get("country", "Unknown")})
        except Exception as exc:
            errors.append("Location lookup unavailable for some IPs")
        time.sleep(1.1)
except Exception as exc:
    errors.append("SANS source feed unavailable; network observations withheld")
    points = []
    network_events = []

try:
    kev = json.loads(get("https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"))
    vulns = kev["vulnerabilities"]
    vulns.sort(key=lambda x: (x.get("dateAdded", ""), x.get("cveID", "")), reverse=True)
    for v in vulns[:35]:
        cve = v.get("cveID", "")
        advisory_events.append({
            "type": "advisory",
            "title": cve + " · " + v.get("vendorProject", "Unknown vendor") + " / " + v.get("product", "Unknown product"),
            "note": v.get("vulnerabilityName") or v.get("shortDescription", "Known exploited vulnerability"),
            "date": v.get("dateAdded", ""),
            "url": "https://www.cve.org/CVERecord?id=" + cve
        })
except Exception:
    errors.append("CISA advisory source unavailable")
    advisory_events = []

# If both sources fail, do not overwrite previously good data.
if not network_events and not advisory_events:
    raise RuntimeError("No feeds returned usable data: " + "; ".join(errors))

now = dt.datetime.now(dt.timezone.utc).isoformat()
payload = {"updated_at": now, "points": points, "events": network_events + advisory_events, "errors": list(dict.fromkeys(errors)), "sources": ["SANS ISC DShield", "CISA KEV"]}
DEST.parent.mkdir(parents=True, exist_ok=True)
DEST.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
print("Updated:", len(points), "map points,", len(payload["events"]), "list records")
