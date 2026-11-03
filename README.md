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
