#!/usr/bin/env python3
"""
Pulls entries from several public cyber threat intelligence / infosec news
RSS feeds and writes them to data/threats.json, which the static front end
(index.html) polls.

Add or remove feeds by editing FEEDS below. Each entry needs a short display
`name` (used for filtering in the UI) and the feed `url`. A few more public
options if you want to expand further:
  - Graham Cluley:     https://grahamcluley.com/feed/
  - Cisco Talos Blog:  https://blog.talosintelligence.com/rss/

CISA retired its public RSS feeds in 2025, so if you want CISA advisories
specifically, check https://www.cisa.gov/news-events/cybersecurity-advisories
for their current subscription options and add a feed here if one exists.
"""

import json
import hashlib
import re
from datetime import datetime, timezone
from html import unescape
from pathlib import Path

import feedparser

# WordPress-style RSS footer some feeds (e.g. SecurityWeek) append to every
# description: '<p>The post <a href="...">Title</a> appeared first on
# <a href="...">Site</a>.</p>'. Matched against the raw HTML before tags are
# stripped, since afterward it's indistinguishable from ordinary text.
WP_APPEARED_FIRST_RE = re.compile(r"<p>\s*The post .*?appeared first on .*?</p>", re.IGNORECASE | re.DOTALL)
HTML_TAG_RE = re.compile(r"<[^>]+>")
WHITESPACE_RE = re.compile(r"\s+")

FEEDS = [
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "Krebs on Security", "url": "https://krebsonsecurity.com/feed/"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml"},
    {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/"},
]

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "data" / "threats.json"
MAX_ENTRIES_PER_FEED = 25   # cap per source so one noisy feed can't drown the rest
MAX_TOTAL_ENTRIES = 150     # keep the overall file small


def entry_id(entry) -> str:
    """Build a stable id even if the feed has no guid."""
    raw = entry.get("id") or entry.get("link") or entry.get("title", "")
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:12]


def guess_severity(title: str, summary: str) -> str:
    """Very simple keyword-based severity tagging for the UI."""
    text = f"{title} {summary}".lower()
    if any(k in text for k in ["critical", "zero-day", "0-day", "actively exploited", "ransomware"]):
        return "critical"
    if any(k in text for k in ["high", "rce", "remote code execution", "exploit"]):
        return "high"
    if any(k in text for k in ["patch", "update", "advisory", "vulnerability"]):
        return "medium"
    return "info"


def clean_summary(raw: str, max_len: int = 400) -> str:
    """Some feeds (e.g. SecurityWeek) put raw HTML in the description — strip
    it down to plain text before truncating, so tags don't get chopped off
    mid-attribute and leak into the UI as literal '<p>'/'<a href=...' text."""
    if not raw:
        return ""
    text = WP_APPEARED_FIRST_RE.sub("", raw)
    text = HTML_TAG_RE.sub(" ", text)
    text = unescape(text)
    text = WHITESPACE_RE.sub(" ", text).strip()
    return text[:max_len]


def sort_key(entry):
    # feedparser gives a time.struct_time in published_parsed when it can
    # figure out the date; entries without one sort to the back.
    return entry.get("published_parsed") or (0,)


def main():
    all_entries = []
    sources_seen = []
    failures = []

    for feed_cfg in FEEDS:
        name, url = feed_cfg["name"], feed_cfg["url"]
        parsed = feedparser.parse(url)

        if parsed.bozo and not parsed.entries:
            print(f"Failed to fetch or parse {name}: {parsed.bozo_exception}")
            failures.append(name)
            continue

        sources_seen.append(name)
        raw_entries = sorted(parsed.entries, key=sort_key, reverse=True)

        for entry in raw_entries[:MAX_ENTRIES_PER_FEED]:
            title = entry.get("title", "Untitled")
            summary = clean_summary(entry.get("summary", ""))
            all_entries.append({
                "id": entry_id(entry),
                "source": name,
                "title": title,
                "summary": summary,
                "link": entry.get("link", ""),
                "published": entry.get("published", ""),
                "published_sort": list(sort_key(entry))[:6],  # for client-side sorting
                "severity": guess_severity(title, summary),
            })

    if not all_entries:
        # Every feed failed. Don't overwrite existing good data with an empty file.
        print("All feeds failed to fetch, leaving existing data/threats.json untouched.")
        return

    all_entries.sort(key=lambda e: e["published_sort"], reverse=True)
    all_entries = all_entries[:MAX_TOTAL_ENTRIES]

    payload = {
        "sources": sources_seen,
        "failed_sources": failures,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "entries": all_entries,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2))
    print(f"Wrote {len(all_entries)} entries from {len(sources_seen)} sources to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
