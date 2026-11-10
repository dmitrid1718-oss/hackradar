"""Collect public incident headlines and render an archived, static reports page."""
import datetime as dt
import html
import json
import re
import urllib.request
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/incident-reports.json"
FEEDS = {
    "BleepingComputer": ("https://www.bleepingcomputer.com/feed/", "bleepingcomputer.com"),
    "SecurityWeek": ("https://www.securityweek.com/category/data-breaches/feed/", "securityweek.com"),
    "The Record": ("https://therecord.media/feed", "therecord.media"),
}
INCIDENT = re.compile(r"\b(?:cyber[- ]?attack|data breach|ransomware attack|wiper attack|data theft|data leak|hackers? (?:hit|steal|claim|breach)|breached|stolen data|systems? offline|disrupts?|disrupted|extortion attack)\b", re.I)
EXCLUDE = re.compile(r"\b(?:webinar|how to|proof.of.concept|exploit code|exploit chain|sponsored|roundup)\b", re.I)

def fetch_items(url, domain):
    req = urllib.request.Request(url, headers={"User-Agent": "HackRadar public news reader/1.0 (+https://hackradar.org)"})
    with urllib.request.urlopen(req, timeout=20) as response:
        root = ET.fromstring(response.read(4_000_000))
    items = root.findall(".//item")
    if not items:
        raise ValueError("Feed contains no RSS items")
    for item in items:
        title = " ".join((item.findtext("title") or "").split())
        link = (item.findtext("link") or "").strip()
        parts = urlsplit(link)
        if parts.scheme != "https" or (parts.hostname or "").removeprefix("www.") != domain:
            continue
        if not INCIDENT.search(title) or EXCLUDE.search(title):
            continue
        try:
            day = parsedate_to_datetime(item.findtext("pubDate")).date().isoformat()
        except (TypeError, ValueError, AttributeError):
            continue
        yield {"title": title, "url": link.split("#")[0].split("?")[0], "date": day}

def render(state):
    esc = html.escape
    rows = []
    for r in sorted(state["reports"], key=lambda r: r["date"], reverse=True):
        context = "<p>" + esc(r["note"]) + "</p>" if r.get("note") else ""
        rows.append(f'<article><small>{esc(r["date"])} · {esc(r["source"])} · {"Reviewed" if context else "Publisher report"}</small><h3><a href="{esc(r["url"], quote=True)}">{esc(r["title"])}</a></h3>{context}</article>')
    checks = []
    for name in FEEDS:
        check = state.get("feeds", {}).get(name, {})
        checks.append(esc(name) + " — " + ("last read " + esc(check["last_success"]) if check.get("last_success") else "awaiting first successful read") + (" (latest check unavailable)" if check.get("failed") else ""))
    template = (ROOT / "scripts/incident-page.html").read_text()
    (ROOT / "incident-reports.html").write_text(template.replace("<!--REPORTS-->", "\n".join(rows)).replace("<!--CHECKS-->", "<br>".join(checks)))

def main():
    state = json.loads(DATA.read_text())
    known = {r["url"] for r in state["reports"]}
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    for name, (url, domain) in FEEDS.items():
        check = state.setdefault("feeds", {}).setdefault(name, {})
        try:
            items = list(fetch_items(url, domain))
        except (OSError, ValueError, ET.ParseError) as exc:
            print(f"{name}: feed unavailable ({type(exc).__name__})")
            check["failed"] = True
            continue
        check.update(last_success=now, failed=False)
        for r in items:
            if r["url"] not in known:
                state["reports"].append(dict(r, source=name))
                known.add(r["url"])
    DATA.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n")
    render(state)

if __name__ == "__main__":
    main()
