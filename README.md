# SIGNAL — Threat Intel Feed Console

A static page that displays a cyber threat intel RSS feed, kept up to date by
a scheduled GitHub Action. No build step, no framework, no server.

## How it works

1. `.github/workflows/fetch-feed.yml` runs every 30 minutes (and on every push,
   and on demand from the Actions tab).
2. It runs `scripts/fetch_feed.py`, which pulls several public RSS feeds with
   `feedparser`, tags each entry with its source and a rough severity, merges
   and sorts everything by publish time, and writes the result to
   `data/threats.json`.
3. The workflow commits that file back to the repo if it changed.
4. `index.html` is a static page that fetches `data/threats.json` every 30
   seconds and re-renders the list — so it feels live, even though it's just
   polling a static file that occasionally changes underneath it. It also
   renders a small analytics strip (severity breakdown, volume per source,
   a 24-hour activity histogram) and lets you filter by severity, by source,
   and by a free-text search, with your filter choices remembered in the
   browser between visits.
5. GitHub Pages serves the repo as-is and redeploys automatically whenever
   `main` gets a new commit, including the bot's own commits.

## Setup

1. Push this folder to a new GitHub repo.
2. In the repo settings, go to **Pages** and set the source to **Deploy from
   a branch**, branch `main`, folder `/ (root)`.
3. In the repo settings, go to **Actions → General → Workflow permissions**
   and set it to **Read and write permissions**, so the workflow is allowed
   to commit `data/threats.json` back to the repo.
4. Go to the **Actions** tab, open "Fetch Threat Intel Feed", and click
   **Run workflow** to trigger the first pull manually rather than waiting
   for the schedule.
5. Once it's run once, visit your Pages URL — it should show live entries.

## Adding or swapping feeds

Edit the `FEEDS` list in `scripts/fetch_feed.py`, each entry just needs a
`name` and a `url`. Currently wired in:

- The Hacker News — `feeds.feedburner.com/TheHackersNews`
- Krebs on Security — `krebsonsecurity.com/feed/`
- BleepingComputer — `bleepingcomputer.com/feed/`
- Dark Reading — `darkreading.com/rss.xml`
- SecurityWeek — `securityweek.com/feed/`

A couple more worth adding if you want more volume or a different angle:

- Graham Cluley — `grahamcluley.com/feed/`
- Cisco Talos Blog — `blog.talosintelligence.com/rss/`

CISA retired its public RSS feeds in 2025 in favor of email/social
notifications, so it isn't used here — check
[CISA's advisories page](https://www.cisa.gov/news-events/cybersecurity-advisories)
if you want to look into their current subscription options.

If a feed fails to fetch (site down, URL changed), the script logs it and
skips that source rather than failing the whole run — check
`failed_sources` in `data/threats.json` if a source seems to have gone quiet.

## Notes

- The severity tagging in `fetch_feed.py` is a simple keyword match, not real
  threat scoring — treat it as a rough visual cue, not analysis.
- The workflow only commits when the data actually changed, so it won't spam
  your commit history if every feed is quiet.
- Filter state (severity toggles, selected source, search text) is saved in
  the browser's localStorage, so it's per-device, not shared or synced
  anywhere.
