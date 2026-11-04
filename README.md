# HackRadar™

**See the invisible internet.**

An open, static public cyber-observation dashboard with an interactive map and continuously refreshed list.

## Data

- **SANS Internet Storm Center / DShield:** public top-source-IP observations. Attribution: SANS Technology Institute, Internet Storm Center — https://isc.sans.edu. This is *reported suspicious network activity*, not an identification of attackers.
- **CISA KEV:** recently added known exploited vulnerabilities. They are advisories, not mapped incidents.
- **ipwho.is:** approximate IP geolocation. A dot does not identify a person's location, attack origin or destination.

## Run

Open `index.html` via a static web server (GitHub Pages, Vercel or similar). No keys needed for viewers.

Go to **Actions → Refresh public cyber feeds → Run workflow** for the initial dataset. The scheduled action then refreshes every 3 hours. Scheduled workflows sometimes run late. The page always displays the data age.

To enable GitHub Pages, choose **Settings → Pages → Deploy from a branch → main / root**; or connect the repository to your existing deployment. Configure `hackradar.org` with your host's domain instructions.

The dashboard deliberately shows no made-up data if the collector has not run or the feed is unavailable. The collector is best-effort; it never claims to show every cyberattack. If both feeds fail, it preserves the last successful saved data without changing the timestamp.

© Useless Instruments LLC.

## Version 002 and history

The primary view is a source-backed ongoing record list, with a secondary map and sector filters. **All sectors** includes general observations and vulnerability advisories; sector-specific filters intentionally remain empty until a trusted incident feed explicitly documents affected infrastructure sectors. No industry is inferred from an IP address, country, or vendor.

The collector writes `data/activity.json` and appends one timestamped sample per successful run to `data/history.json`. These observations are permanent repository history, but are **not** counts of cyberattacks or a continuous risk score. Missing collection periods are not interpolated. The chart displays the latest 40 saved samples while the JSON retains older snapshots.

If the site shows “Feed unavailable,” open **Actions → Refresh public cyber feeds → Run workflow** once and check whether the `data` files were committed. Scheduled runs occur every three hours; your web host must publish the new data files when the bot commits. GitHub Pages configured to deploy from a branch may not publish changes committed with the default `GITHUB_TOKEN`; use a GitHub Pages Actions-based deployment workflow or an external host that redeploys on the data commit.

## Install on a phone (PWA)

HackRadar is installable from the existing HTTPS website; there is no separate App Store / Google Play listing.

- **Android (Chrome/Edge):** visit https://hackradar.org, use **Install app** (or the browser's **Add to Home Screen** menu).
- **iPhone (Safari):** visit https://hackradar.org, tap **Share → Add to Home Screen**.
- The mobile app keeps the global and Ukraine/Russia source radar filters, public event list, and history.
- Offline opening shows an honest offline screen rather than outdated feeds. **Live data and map tiles require an internet connection.**
- No push alerts, account, native store publication, or background monitoring is included in this initial version.
- Files: `manifest.webmanifest`, `icon.svg`, `sw.js`, and `offline.html`.

A production HTTPS deployment must serve the manifest and service worker from the site root for installation to work.
