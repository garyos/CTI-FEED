#!/usr/bin/env python3
"""
Pulls entries from a public cyber threat intelligence RSS feed and writes
them to data/threats.json, which the static front end (index.html) polls.

Swap FEED_URL for any RSS/Atom feed you like. A few public options:
  - The Hacker News:  https://feeds.feedburner.com/TheHackersNews
  - Krebs on Security: https://krebsonsecurity.com/feed/
  - Bleeping Computer: https://www.bleepingcomputer.com/feed/

CISA retired its public RSS feeds in 2025, so if you want CISA advisories
specifically, check https://www.cisa.gov/news-events/cybersecurity-advisories
for their current subscription options and swap the URL below if a feed
is available.
"""

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

import feedparser

FEED_URL = "https://feeds.feedburner.com/TheHackersNews"
OUTPUT_PATH = Path(__file__).resolve().parent.parent / "data" / "threats.json"
MAX_ENTRIES = 40  # keep the file small; oldest entries drop off


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


def main():
    parsed = feedparser.parse(FEED_URL)

    if parsed.bozo and not parsed.entries:
        # Feed failed to fetch/parse. Don't wipe out existing good data.
        print(f"Failed to fetch or parse feed: {parsed.bozo_exception}")
        return

    entries = []
    for entry in parsed.entries[:MAX_ENTRIES]:
        title = entry.get("title", "Untitled")
        summary = entry.get("summary", "")
        entries.append({
            "id": entry_id(entry),
            "title": title,
            "summary": summary[:400],
            "link": entry.get("link", ""),
            "published": entry.get("published", ""),
            "severity": guess_severity(title, summary),
        })

    payload = {
        "source": parsed.feed.get("title", FEED_URL),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "entries": entries,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2))
    print(f"Wrote {len(entries)} entries to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
