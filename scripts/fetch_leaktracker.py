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
from html import unescape
from pathlib import Path

GROUPS_URL = "https://data.ransomware.live/groups.json"
VICTIMS_URL = "https://data.ransomware.live/victims.json"

# Public archive of leaked ransomware negotiation chat transcripts, indexed by
# group. Refreshed alongside groups.json (same weekly cadence) since it's a
# similarly slow-moving reference dataset, not an event stream.
CHAT_INDEX_URL = "https://raw.githubusercontent.com/Casualtek/Ransomchats/refs/heads/main/chat_index.json"

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "data" / "leaktracker"
GROUPS_PATH = OUTPUT_DIR / "groups.json"
INDEX_PATH = OUTPUT_DIR / "index.json"
LATEST_PATH = OUTPUT_DIR / "latest.json"

GROUPS_REFRESH_DAYS = 7   # groups.json is a slow-moving profile table, not an event stream
SEED_DAYS = 60            # first run: don't backfill all 31k+ historical victims, just recent ones
LATEST_COUNT = 40
DESCRIPTION_MAX_LEN = 500

# ---------- origin-country inference (ported from fetch_attack.py) ----------
# Same conservative demonym + attribution-word approach used for ATT&CK
# groups: bare country names are never enough on their own (ransomware group
# profiles frequently name countries they *refuse* to target, e.g. "we do not
# allow CIS, Cuba, North Korea and China to be targeted" — that must not read
# as the group's own origin).

DEMONYMS = [
    ("North Korean", "KP", "North Korea"),
    ("South Korean", "KR", "South Korea"),
    ("Russian", "RU", "Russia"),
    ("Chinese", "CN", "China"),
    ("Iranian", "IR", "Iran"),
    ("Vietnamese", "VN", "Vietnam"),
    ("Indian", "IN", "India"),
    ("Pakistani", "PK", "Pakistan"),
    ("Israeli", "IL", "Israel"),
    ("Turkish", "TR", "Turkey"),
    ("Belarusian", "BY", "Belarus"),
    ("Syrian", "SY", "Syria"),
    ("Lebanese", "LB", "Lebanon"),
    ("Ukrainian", "UA", "Ukraine"),
    ("American", "US", "United States"),
    ("British", "GB", "United Kingdom"),
    ("French", "FR", "France"),
    ("German", "DE", "Germany"),
]

ATTRIBUTION_WORDS = re.compile(
    r"state[- ]sponsored|state[- ]affiliated|threat group|threat actor|"
    r"intelligence (?:service|agency)|military intelligence|"
    r"government-sponsored|cyber ?espionage|espionage actor",
    re.IGNORECASE,
)

SPONSOR_VERBS = [
    "associated with", "linked to", "nexus to", "on behalf of", "backed by",
    "sponsored by", "tied to", "overlap with", "works for", "attributed to",
]
_demonym_alt = "|".join(re.escape(d) for d, _, _ in DEMONYMS)
SPONSOR_GOVERNMENT_PATTERN = re.compile(
    r"(?:" + "|".join(re.escape(v) for v in SPONSOR_VERBS) + r")"
    r"(?:\s+\S+){0,4}\s+(" + _demonym_alt + r")\s+government",
    re.IGNORECASE,
)

COUNTRY_NOUNS = [
    ("North Korea", "KP", "North Korea"),
    ("South Korea", "KR", "South Korea"),
    ("Russia", "RU", "Russia"),
    ("China", "CN", "China"),
    ("Iran", "IR", "Iran"),
    ("Vietnam", "VN", "Vietnam"),
    ("India", "IN", "India"),
    ("Pakistan", "PK", "Pakistan"),
    ("Israel", "IL", "Israel"),
    ("Turkey", "TR", "Turkey"),
    ("Belarus", "BY", "Belarus"),
    ("Syria", "SY", "Syria"),
    ("Lebanon", "LB", "Lebanon"),
    ("Ukraine", "UA", "Ukraine"),
]
BASED_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(n) for n, _, _ in COUNTRY_NOUNS) + r")[- ]based\b",
    re.IGNORECASE,
)

AGENCY_TO_COUNTRY = {
    "GRU": ("RU", "Russia"),
    "FSB": ("RU", "Russia"),
    "SVR": ("RU", "Russia"),
    "MSS": ("CN", "China"),
    "PLA": ("CN", "China"),
    "RGB": ("KP", "North Korea"),
    "Reconnaissance General Bureau": ("KP", "North Korea"),
    "IRGC": ("IR", "Iran"),
    "MOIS": ("IR", "Iran"),
}


def guess_countries(description: str) -> list:
    """Best-effort origin attribution from free text — same heuristic as
    fetch_attack.py's guess_countries(). Group profiles rarely state this
    outright, so coverage will be modest; that's expected."""
    if not description:
        return []

    found = {}
    for noun_match in BASED_PATTERN.finditer(description):
        noun = noun_match.group(1)
        for n, code, name in COUNTRY_NOUNS:
            if n.lower() == noun.lower():
                found[code] = name
                break

    demonym_to_country = {d.lower(): (code, name) for d, code, name in DEMONYMS}
    for m in SPONSOR_GOVERNMENT_PATTERN.finditer(description):
        code, name = demonym_to_country[m.group(1).lower()]
        found[code] = name

    for demonym, code, name in DEMONYMS:
        for m in re.finditer(re.escape(demonym), description):
            window = description[max(0, m.start() - 40): m.end() + 40]
            if ATTRIBUTION_WORDS.search(window):
                found[code] = name
                break

    if not found:
        for agency, (code, name) in AGENCY_TO_COUNTRY.items():
            if re.search(rf"\b{re.escape(agency)}\b", description):
                found[code] = name

    return [{"code": code, "name": name} for code, name in sorted(found.items(), key=lambda kv: kv[1])]


# ---------- ransomchat negotiation matching ----------

def normalize_group_name(name: str) -> str:
    """Lowercase, alnum-only, with a trailing '.0' version suffix dropped
    first (Ransomchats' "lockbit3.0" vs. ransomware.live's "lockbit3")."""
    name = re.sub(r"\.0\b", "", name or "")
    return re.sub(r"[^a-z0-9]", "", name.lower())


def parse_chat_date(chat_id: str) -> str | None:
    """Chat ids are usually a YYYYMMDD date, sometimes with a suffix
    ('20250425b', '20250203 - from @user') or, for a minority, an opaque
    UUID/hex id with no date at all — those return None rather than a
    guess."""
    m = re.match(r"^(\d{4})(\d{2})(\d{2})", chat_id or "")
    if not m:
        return None
    try:
        datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None
    return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"


def fetch_chat_index() -> dict | None:
    try:
        return fetch_json(CHAT_INDEX_URL)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"  ransomchat index fetch failed ({exc}); negotiation data will be unavailable this run.")
        return None


def build_negotiation_lookup(chat_index: dict) -> dict:
    """Ransomchats' display name -> negotiation summary, computed once from
    the index. message_count comes straight from the index (no need to
    download every individual chat just to measure it)."""
    lookup = {}
    for chat_name, gdata in (chat_index.get("groups") or {}).items():
        chats = gdata.get("chats") or []
        if not chats:
            continue
        dated = [(parse_chat_date(c["chat_id"]), c) for c in chats]
        dated = [(d, c) for d, c in dated if d]
        latest = max(dated, key=lambda dc: dc[0]) if dated else None
        longest = max(chats, key=lambda c: c.get("message_count") or 0)
        lookup[chat_name] = {
            "chat_count": len(chats),
            "latest_chat_date": latest[0] if latest else None,
            "latest_chat_url": latest[1]["raw_url"] if latest else None,
            "longest_chat_url": longest["raw_url"],
            "longest_chat_message_count": longest.get("message_count"),
        }
    return lookup


EMPTY_NEGOTIATION = {
    "available": False, "chat_count": None, "latest_chat_date": None,
    "latest_chat_url": None, "longest_chat_url": None, "longest_chat_message_count": None,
}


def match_negotiation(name: str, altname: str, description: str, chat_lookup: dict) -> dict:
    """Match a ransomware.live group against the Ransomchats index. Tries an
    exact normalized name/altname match first; if that fails, falls back to
    the group's own description naming it — but only among candidates whose
    normalized name is itself a substring/superstring of the Ransomchats
    name (e.g. our 'hunters' vs. their 'Hunters International'), not a blind
    full-corpus text search. That distinction matters: a corpus-wide search
    for "Hunters International" also hits an unrelated group's description
    that merely mentions Hunters International as a third party using their
    tooling — the name-relation guard rules that false match out while still
    catching genuine aliasing."""
    if not chat_lookup:
        return dict(EMPTY_NEGOTIATION)

    norm_name = normalize_group_name(name)
    norm_alt = normalize_group_name(altname) if altname else None

    for chat_name, summary in chat_lookup.items():
        if normalize_group_name(chat_name) in (norm_name, norm_alt):
            return {"available": True, **summary}

    if description and len(norm_name) >= 3:
        desc_lower = description.lower()
        for chat_name, summary in chat_lookup.items():
            cn_norm = normalize_group_name(chat_name)
            if len(cn_norm) < 3:
                continue
            if (norm_name in cn_norm or cn_norm in norm_name) and chat_name.lower() in desc_lower:
                return {"available": True, **summary}

    return dict(EMPTY_NEGOTIATION)


def fetch_json(url: str, timeout: int = 120) -> object:
    req = urllib.request.Request(url, headers={"User-Agent": "cti-feed/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def clean_text(text: str, max_len: int = DESCRIPTION_MAX_LEN) -> str:
    """Some group/victim descriptions in the source have raw HTML in them
    (<br> tags, entities) — strip it the same way fetch_feed.py does for
    RSS summaries, so it never leaks into the UI as literal tag text."""
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = unescape(text)
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

    chat_index = fetch_chat_index()
    chat_lookup = build_negotiation_lookup(chat_index) if chat_index else {}
    if chat_lookup:
        print(f"  ransomchat index: {len(chat_lookup)} groups with negotiation transcripts")

    groups = []
    for g in raw_groups:
        locations = g.get("locations") or []
        active = sum(1 for loc in locations if loc.get("available"))
        name = g.get("name", "")
        altname = g.get("altname")
        description = clean_text(g.get("description", ""))
        groups.append({
            "name": name,
            "altname": altname,
            "description": description,
            "raas": bool((g.get("type") or {}).get("raas")),
            "first_seen": g.get("date"),
            "active_sites": active,
            "total_sites": len(locations),
            "is_active": active > 0,
            "total_victims": g.get("_victim_count"),
            "countries": guess_countries(description),
            "negotiation": match_negotiation(name, altname, description, chat_lookup),
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
