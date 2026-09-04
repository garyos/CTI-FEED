# SIGNAL — Threat Intel Feed Console

A static page that displays a cyber threat intel RSS feed, kept up to date by
a scheduled GitHub Action. No build step, no framework, no server.

## How it works

1. `.github/workflows/fetch-feed.yml` runs every 30 minutes (and on every push,
   and on demand from the Actions tab).
2. It runs `scripts/fetch_feed.py`, which pulls a public RSS feed with
   `feedparser`, tags each entry with a rough severity, and writes the result
   to `data/threats.json`.
3. The workflow commits that file back to the repo if it changed.
4. `index.html` is a static page that fetches `data/threats.json` every 30
   seconds and re-renders the list — so it feels live, even though it's just
   polling a static file that occasionally changes underneath it.
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

## Swapping the feed

Edit `FEED_URL` in `scripts/fetch_feed.py`. Any RSS or Atom feed works, since
`feedparser` handles both. A few public cybersecurity feeds:

- The Hacker News — `https://feeds.feedburner.com/TheHackersNews`
- Krebs on Security — `https://krebsonsecurity.com/feed/`
- Bleeping Computer — `https://www.bleepingcomputer.com/feed/`

CISA retired its public RSS feeds in 2025 in favor of email/social
notifications, so it isn't used as the default here — check
[CISA's advisories page](https://www.cisa.gov/news-events/cybersecurity-advisories)
if you want to look into their current subscription options.

## Notes

- The severity tagging in `fetch_feed.py` is a simple keyword match, not real
  threat scoring — treat it as a rough visual cue, not analysis.
- The workflow only commits when the data actually changed, so it won't spam
  your commit history if the feed is quiet.
# CTI-FEED
# CTI-FEED
