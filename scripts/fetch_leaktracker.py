#!/usr/bin/env python3
"""
Pulls ransomware leak-site victim postings and group profiles from
ransomware.live's public bulk data dumps (data.ransomware.live) — the
documented /v2/ REST API returns the site's own 404 page as of this writing,
so this uses the flat-file downloads instead, which are unauthenticated and
unrated-limited.

Two datasets, two different treatments:
  - victims.json is an event stream (one leak-site claim per record) that
    should accumulate over time, like data/cve/ — see fetch_cve.py for the
    same month-partitioned, upsert-by-derived-id pattern. There's no
    incremental query on the source (no lastModified-style filter), so every
    run downloads the full ~21MB file and diffs it locally against what's
    already stored.
  - groups.json is a slowly-changing reference/profile table (leak-site
    status, descriptions), not an event stream — it's refreshed in full,
    self-throttled to roughly once a week regardless of how often this script
    runs, the same way fetch_attack.py's data changes slowly compared to the
    daily CVE pull.

Run manually with: python scripts/fetch_leaktracker.py
"""

import hashlib
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

GROUPS_URL = "https://data.ransomware.live/groups.json"
VICTIMS_URL = "https://data.ransomware.live/victims.json"

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "data" / "leaktracker"
GROUPS_PATH = OUTPUT_DIR / "groups.json"
INDEX_PATH = OUTPUT_DIR / "index.json"
LATEST_PATH = OUTPUT_DIR / "latest.json"

GROUPS_REFRESH_DAYS = 7   # groups.json is a slow-moving profile table, not an event stream
SEED_DAYS = 60            # first run: don't backfill all 31k+ historical victims, just recent ones
LATEST_COUNT = 40
DESCRIPTION_MAX_LEN = 500


def fetch_json(url: str, timeout: int = 120) -> object:
    req = urllib.request.Request(url, headers={"User-Agent": "cti-feed/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def clean_text(text: str, max_len: int = DESCRIPTION_MAX_LEN) -> str:
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_len:
        text = text[:max_len].rsplit(" ", 1)[0] + "…"
    return text


# ---------- groups (weekly, full replace) ----------

def refresh_groups():
    if GROUPS_PATH.exists():
        existing = json.loads(GROUPS_PATH.read_text())
        fetched_at = datetime.fromisoformat(existing["fetched_at"])
        if datetime.now(timezone.utc) - fetched_at < timedelta(days=GROUPS_REFRESH_DAYS):
            print(f"  groups.json is {(datetime.now(timezone.utc) - fetched_at).days}d old, "
                  f"skipping (refreshes every {GROUPS_REFRESH_DAYS}d)")
            return

    try:
        raw_groups = fetch_json(GROUPS_URL)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"  groups fetch failed ({exc}); leaving existing groups.json untouched.")
        return

    groups = []
    for g in raw_groups:
        locations = g.get("locations") or []
        active = sum(1 for loc in locations if loc.get("available"))
        groups.append({
            "name": g.get("name", ""),
            "altname": g.get("altname"),
            "description": clean_text(g.get("description", "")),
            "raas": bool((g.get("type") or {}).get("raas")),
            "first_seen": g.get("date"),
            "active_sites": active,
            "total_sites": len(locations),
        })
    groups.sort(key=lambda g: g["name"].lower())

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    GROUPS_PATH.write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "groups": groups,
    }, indent=2))
    print(f"  wrote {GROUPS_PATH} — {len(groups)} groups")


# ---------- victims (daily, accumulate) ----------

def derive_victim_id(v: dict) -> str:
    """No stable id field on a victim record — derive one. Posts are
    immutable historical events (a leak-site claim doesn't get 'updated'
    the way a CVE does), so once seen an id is just a dedup key, never
    something we need to re-fetch and overwrite."""
    raw = f"{v.get('group_name', '')}|{v.get('post_title', '')}|{v.get('published', '')}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def victim_month_key(v: dict) -> str:
    date = v.get("published") or v.get("discovered") or ""
    return date[:7] or "unknown"


def build_record(v: dict) -> dict:
    return {
        "id": derive_victim_id(v),
        "victim": v.get("post_title", "Unknown"),
        "group": v.get("group_name", "unknown"),
        "published": v.get("published") or v.get("discovered"),
        "discovered": v.get("discovered"),
        "country": v.get("country") or None,
        "sector": v.get("activity") or None,
        "website": v.get("website") or None,
        "description": clean_text(v.get("description", "")),
        "post_url": v.get("post_url") or None,
    }


def load_month(month: str) -> dict:
    path = OUTPUT_DIR / "victims" / f"{month}.json"
    if path.exists():
        return json.loads(path.read_text())
    return {"month": month, "victims": []}


def save_month(month: str, doc: dict) -> None:
    doc["victims"].sort(key=lambda v: v.get("published") or "", reverse=True)
    doc["updated_at"] = datetime.now(timezone.utc).isoformat()
    path = OUTPUT_DIR / "victims" / f"{month}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2))


def known_victim_ids() -> set:
    seen = set()
    victims_dir = OUTPUT_DIR / "victims"
    if not victims_dir.exists():
        return seen
    for path in victims_dir.glob("*.json"):
        doc = json.loads(path.read_text())
        seen.update(v["id"] for v in doc.get("victims", []))
    return seen


def get_seed_floor() -> str:
    """The 'don't backfill the full 2013-onward archive' cutoff must be a
    permanent floor, not a first-run-only check — otherwise every run after
    the first has nothing stopping it from ingesting everything the first
    run deliberately skipped (this was a real bug: the second run alone
    pulled in 29,646 historical records once the first-run guard no longer
    applied). The floor is computed once and persisted in index.json."""
    if INDEX_PATH.exists():
        stored = json.loads(INDEX_PATH.read_text()).get("seed_floor")
        if stored:
            return stored
    return (datetime.now(timezone.utc) - timedelta(days=SEED_DAYS)).isoformat()


def refresh_victims(seed_floor: str):
    try:
        raw_victims = fetch_json(VICTIMS_URL)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"  victims fetch failed ({exc}); leaving existing ransomware data untouched.")
        return False

    seen_ids = known_victim_ids()

    new_by_month = {}
    for v in raw_victims:
        record = build_record(v)
        if record["id"] in seen_ids:
            continue
        if (record["published"] or "") < seed_floor:
            continue
        new_by_month.setdefault(victim_month_key(v), []).append(record)

    for month, records in new_by_month.items():
        doc = load_month(month)
        doc["victims"].extend(records)
        save_month(month, doc)

    added = sum(len(r) for r in new_by_month.values())
    print(f"  victims: {len(raw_victims)} in source, {added} new since seed floor {seed_floor[:10]}, "
          f"{len(new_by_month)} month file(s) touched")
    return True


def rebuild_index_and_latest(seed_floor: str):
    victims_dir = OUTPUT_DIR / "victims"
    month_files = sorted(victims_dir.glob("????-??.json"), reverse=True) if victims_dir.exists() else []

    months_meta = []
    recent_pool = []
    for path in month_files:
        doc = json.loads(path.read_text())
        victims = doc.get("victims", [])
        months_meta.append({
            "key": doc["month"], "count": len(victims),
            "latest_published": max((v.get("published") or "" for v in victims), default=""),
        })
        if len(recent_pool) < LATEST_COUNT * 3:
            recent_pool.extend(victims)

    recent_pool.sort(key=lambda v: v.get("published") or "", reverse=True)

    index = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "last_fetched": datetime.now(timezone.utc).isoformat(),
        "seed_floor": seed_floor,
        "months": months_meta,
    }
    INDEX_PATH.write_text(json.dumps(index, indent=2))
    LATEST_PATH.write_text(json.dumps({
        "generated_at": index["generated_at"],
        "victims": recent_pool[:LATEST_COUNT],
    }, indent=2))


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print("Refreshing ransomware group profiles…")
    refresh_groups()
    print("Refreshing ransomware victim postings…")
    seed_floor = get_seed_floor()
    if refresh_victims(seed_floor):
        rebuild_index_and_latest(seed_floor)
        print(f"  wrote {INDEX_PATH} and {LATEST_PATH}")


if __name__ == "__main__":
    main()
