#!/usr/bin/env python3
"""HackRadar V002 collector. Public source data; no invented incidents."""
import datetime as dt
import ipaddress
import json
import pathlib
import re
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEST = ROOT / "data" / "activity.json"
HISTORY = ROOT / "data" / "history.json"
NOW = dt.datetime.now(dt.timezone.utc)
UA = {"User-Agent": "HackRadar/0.2 (+https://hackradar.org)", "Accept": "*/*"}
errors, events, points = [], [], []

def get(url, timeout=23):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")

def read(path, default):
    try: return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError): return default

def add(kind, title, note, date, url, source):
    if title and date and url:
        events.append({"type":kind, "title":title, "note":note, "date":date, "url":url, "source":source, "sector":"unclassified", "importance":"unrated"})

old = read(DEST, {})
try:
    raw = get("https://feeds.dshield.org/feeds/topips.txt")
    ips = []
    for line in raw.splitlines():
        if line.lstrip().startswith("#"): continue
        m = re.search(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", line)
        if m:
            ip = m.group()
            try:
                if ipaddress.ip_address(ip).is_global and ip not in ips: ips.append(ip)
            except ValueError: pass
    ips = ips[:20]
    if not ips: raise ValueError("No parsable IPs")
    old_geo = {p.get("ip"):p for p in old.get("points", [])}
    for ip in ips:
        add("network", "Reported suspicious source · "+ip,
            "SANS ISC top-source snapshot; not an identified attacker, victim, or completed attack.",
            NOW.date().isoformat(), "https://www.dshield.org/ipinfo.html?ip="+ip, "SANS ISC DShield")
        if ip in old_geo: points.append(old_geo[ip]); continue
        try:
            g = json.loads(get("https://ipwho.is/"+ip, timeout=10))
            if g.get("success") and isinstance(g.get("latitude"),(int,float)) and isinstance(g.get("longitude"),(int,float)):
                points.append({"ip":ip,"lat":g["latitude"],"lon":g["longitude"],"country":g.get("country","Unknown")})
        except Exception:
            if "Some geolocations unavailable" not in errors: errors.append("Some geolocations unavailable")
        time.sleep(1.05)
except Exception as ex:
    errors.append("SANS ISC feed unavailable")
    print("SANS:",repr(ex))

try:
    raw = get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    vulns = json.loads(raw)["vulnerabilities"]
    vulns.sort(key=lambda v: (v.get("dateAdded",""),v.get("cveID","")), reverse=True)
    for v in vulns[:60]:
        cve=v.get("cveID","")
        add("advisory", cve+" · "+v.get("vendorProject","Unknown vendor")+" / "+v.get("product","Unknown product"),
            v.get("vulnerabilityName") or v.get("shortDescription") or "Known exploited vulnerability",
            v.get("dateAdded",""), "https://www.cve.org/CVERecord?id="+cve, "CISA KEV")
except Exception as ex:
    errors.append("CISA KEV feed unavailable")
    print("CISA:",repr(ex))

# An observed IP or a CVE cannot be reliably assigned to power, airlines, etc.
# Sector-specific incidents require a separate source with explicit target sector.
if not events: raise RuntimeError("All sources unavailable; preserving previous dataset")
events.sort(key=lambda e:(e["date"], e["type"]=="network"), reverse=True)
data = {"updated_at":NOW.isoformat(),"points":points,"events":events,
        "errors":errors,"sources":["SANS ISC DShield","CISA KEV"],
        "method":"Snapshots of public cyber observations and advisories; no verified sector-specific incident source."}
DEST.parent.mkdir(parents=True,exist_ok=True)
DEST.write_text(json.dumps(data,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")

# One durable record per successful retrieval; timestamped, genuine counts.
hist=read(HISTORY,{"snapshots":[]})
snapshots=hist.get("snapshots",[])
if not isinstance(snapshots,list): snapshots=[]
snapshots.append({"at":NOW.isoformat(),"network_records":sum(e["type"]=="network" for e in events),
                  "advisory_records":sum(e["type"]=="advisory" for e in events),
                  "mapped_sources":len(points),
                  "sources_available":{"sans":any(e["type"]=="network" for e in events),
                                       "cisa":any(e["type"]=="advisory" for e in events)}})
hist={"description":"Recorded feed snapshots; not attack totals or threat magnitudes.","snapshots":snapshots}
HISTORY.write_text(json.dumps(hist,indent=2)+"\n",encoding="utf-8")
print("Saved",len(events),"records,",len(points),"points,",len(snapshots),"history snapshots")
