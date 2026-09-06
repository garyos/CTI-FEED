#!/usr/bin/env python3
"""
Pulls publicly disclosed data breaches from Have I Been Pwned's public breach
list — the /api/v3/breaches endpoint is unauthenticated and keyless (only the
per-account "was this email in a breach" lookups need a paid key).

Unlike NVD's CVE API, HIBP doesn't offer a server-side "modified since X"
query on this endpoint. The whole catalog is small (~1000 entries, ~1MB
as of writing) so every run just re-fetches it in full and diffs locally
against what's already stored — the same shape as fetch_leaktracker.py's
groups.json refresh, just done every run instead of self-throttled weekly,
since a single request costs nothing.

Accumulates over time like fetch_cve.py / fetch_leaktracker.py's victims:
seeded from a recent window (not HIBP's full catalog back to 2007),
watermarked by HIBP's own AddedDate field, with the seed cutoff persisted
permanently in index.json so a later run can't silently backfill everything
the first run deliberately skipped (see fetch_leaktracker.py's get_seed_floor
for why that has to be permanent, not first-run-only).

Run manually with: python scripts/fetch_breaches.py
"""

import html
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "data" / "breaches"
BREACHES_PATH = OUTPUT_DIR / "breaches.json"
INDEX_PATH = OUTPUT_DIR / "index.json"
LATEST_PATH = OUTPUT_DIR / "latest.json"

SEED_DAYS = 180   # ~6 months — don't backfill HIBP's full catalog back to 2007
LATEST_COUNT = 20
DESCRIPTION_MAX_LEN = 600


def fetch_json(url: str, timeout: int = 60) -> object:
    req = urllib.request.Request(url, headers={"User-Agent": "cti-feed/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def clean_text(text: str, max_len: int = DESCRIPTION_MAX_LEN) -> str:
    """HIBP's Description field is HTML (it links out to Troy Hunt's writeups
    inline) — strip it the same way fetch_feed.py/fetch_leaktracker.py do,
    so it never leaks into the UI as literal tag text."""
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_len:
        text = text[:max_len].rsplit(" ", 1)[0] + "…"
    return text


def build_record(b: dict) -> dict:
    name = b.get("Name", "")
    return {
        "id": name,
        "title": b.get("Title") or name,
        "domain": b.get("Domain") or None,
        "breach_date": b.get("BreachDate"),
        "added_date": b.get("AddedDate"),
        "modified_date": b.get("ModifiedDate"),
        "pwn_count": b.get("PwnCount", 0),
        "description": clean_text(b.get("Description", "")),
        "data_classes": b.get("DataClasses") or [],
        "is_verified": bool(b.get("IsVerified")),
        "is_sensitive": bool(b.get("IsSensitive")),
        "is_malware": bool(b.get("IsMalware")),
        "is_stealer_log": bool(b.get("IsStealerLog")),
        "is_spam_list": bool(b.get("IsSpamList")),
        "logo_path": b.get("LogoPath"),
        # HIBP's breach detail "page" is really an anchor into the full list —
        # confirmed against the live page: <tr id="{Name}"> on /PwnedWebsites.
        "hibp_url": f"https://haveibeenpwned.com/PwnedWebsites#{name}",
    }


def load_existing() -> list:
    if BREACHES_PATH.exists():
        return json.loads(BREACHES_PATH.read_text()).get("breaches", [])
    return []


def get_seed_floor() -> str:
    if INDEX_PATH.exists():
        stored = json.loads(INDEX_PATH.read_text()).get("seed_floor")
        if stored:
            return stored
    return (datetime.now(timezone.utc) - timedelta(days=SEED_DAYS)).isoformat()


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    seed_floor = get_seed_floor()

    try:
        raw_breaches = fetch_json(BREACHES_URL)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"  breach fetch failed ({exc}); leaving existing data untouched.")
        return

    existing = load_existing()
    by_id = {b["id"]: b for b in existing}

    added = 0
    updated = 0
    for raw in raw_breaches:
        record = build_record(raw)
        if record["id"] in by_id:
            if record != by_id[record["id"]]:
                updated += 1
            by_id[record["id"]] = record
        else:
            added_date = record["added_date"] or ""
            if added_date < seed_floor:
                continue  # older than our seed window and never seen before — skip
            by_id[record["id"]] = record
            added += 1

    all_breaches = sorted(by_id.values(), key=lambda b: b["added_date"] or "", reverse=True)

    now = datetime.now(timezone.utc).isoformat()
    BREACHES_PATH.write_text(json.dumps({"generated_at": now, "breaches": all_breaches}, indent=2))
    INDEX_PATH.write_text(json.dumps({
        "generated_at": now,
        "last_fetched": now,
        "seed_floor": seed_floor,
        "count": len(all_breaches),
    }, indent=2))
    LATEST_PATH.write_text(json.dumps({"generated_at": now, "breaches": all_breaches[:LATEST_COUNT]}, indent=2))

    print(f"  breaches: {len(raw_breaches)} in source, {added} new since seed floor {seed_floor[:10]}, "
          f"{updated} updated, {len(all_breaches)} total on file")


if __name__ == "__main__":
    main()
