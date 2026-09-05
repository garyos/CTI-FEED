#!/usr/bin/env python3
"""
Pulls new/changed CVE records from the NVD CVE API 2.0, cross-references them
against CISA's Known Exploited Vulnerabilities (KEV) catalog, and accumulates
them into month-partitioned files under data/cve/ — unlike data/threats.json
(replaced every run) or data/attack/*.json (fully regenerated snapshots), this
feed is meant to build up over time.

Incremental, no-duplicate-pulls design:
  - data/cve/index.json tracks `last_fetched`, the end of the last successful
    query window.
  - Each run queries NVD for everything with lastModified in
    (last_fetched, run_start], where run_start is captured *before* the query
    runs — so anything modified mid-run is simply picked up again next run
    (safe overlap, never a silent gap), and last_fetched only advances after
    a successful fetch.
  - Records are upserted by CVE id into their published-month file, so a CVE
    that gets rescored/updated later replaces its existing entry instead of
    duplicating.

Volume control: NVD publishes ~800 new/modified CVEs a day, most Low/Medium or
not yet scored. Storing all of them forever isn't sustainable for a static
site, so only Critical/High severity CVEs are kept — plus, unconditionally,
anything CISA's KEV catalog lists as actively exploited, regardless of its
CVSS score, since that's arguably the single most actionable signal here.

Run manually with: python scripts/fetch_cve.py
"""

import json
import re
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "data" / "cve"
SEED_DAYS = 3          # first-run window — don't try to backfill NVD's full history
MAX_WINDOW_DAYS = 120  # NVD's own cap on lastMod date-range width
PAGE_SIZE = 2000
REQUEST_SLEEP = 6      # seconds between NVD requests, well under the 5-req/30s unauthenticated limit
LATEST_COUNT = 40
DESCRIPTION_MAX_LEN = 500

KEPT_SEVERITIES = {"CRITICAL", "HIGH"}

# A curated subset of the most commonly-seen CWE categories in NVD data.
# Anything not listed here falls back to showing the raw CWE id.
CWE_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-59": "Link Following",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-88": "Argument Injection",
    "CWE-89": "SQL Injection",
    "CWE-91": "XML Injection",
    "CWE-94": "Code Injection",
    "CWE-99": "Improper Control of Resource Identifiers",
    "CWE-119": "Memory Buffer Boundary Violation",
    "CWE-120": "Buffer Overflow",
    "CWE-125": "Out-of-Bounds Read",
    "CWE-190": "Integer Overflow / Wraparound",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-269": "Improper Privilege Management",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Race Condition",
    "CWE-367": "Time-of-Check Time-of-Use Race Condition",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-401": "Memory Leak",
    "CWE-416": "Use After Free",
    "CWE-427": "Uncontrolled Search Path Element",
    "CWE-434": "Unrestricted Dangerous File Upload",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity Reference (XXE)",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-770": "Allocation of Resources Without Limits",
    "CWE-787": "Out-of-Bounds Write",
    "CWE-798": "Use of Hard-Coded Credentials",
    "CWE-843": "Type Confusion",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1321": "Prototype Pollution",
    "NVD-CWE-Other": "Other / Not Yet Mapped",
    "NVD-CWE-noinfo": "Insufficient Information",
}


def http_get_json(url: str, headers: dict | None = None) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "cti-feed/1.0", **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.load(resp)


def nvd_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def fetch_kev() -> dict:
    try:
        data = http_get_json(KEV_URL)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"Warning: couldn't fetch CISA KEV catalog ({exc}); continuing without it.")
        return {}
    return {v["cveID"]: v for v in data.get("vulnerabilities", [])}


def fetch_nvd_window(start: datetime, end: datetime) -> list[dict]:
    results = []
    start_index = 0
    while True:
        url = (
            f"{NVD_API}?lastModStartDate={nvd_dt(start)}&lastModEndDate={nvd_dt(end)}"
            f"&resultsPerPage={PAGE_SIZE}&startIndex={start_index}"
        )
        page = http_get_json(url)
        vulns = page.get("vulnerabilities", [])
        results.extend(v["cve"] for v in vulns if "cve" in v)
        total = page.get("totalResults", 0)
        start_index += len(vulns)
        if start_index >= total or not vulns:
            break
        time.sleep(REQUEST_SLEEP)
    return results


def fetch_nvd_range(start: datetime, end: datetime) -> list[dict]:
    """Chunk into <=120-day windows (NVD's own cap) and dedupe across chunks."""
    by_id = {}
    window_start = start
    while window_start < end:
        window_end = min(end, window_start + timedelta(days=MAX_WINDOW_DAYS))
        for cve in fetch_nvd_window(window_start, window_end):
            by_id[cve["id"]] = cve
        window_start = window_end
        if window_start < end:
            time.sleep(REQUEST_SLEEP)
    return list(by_id.values())


def best_cvss(metrics: dict) -> dict | None:
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key)
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = primary["cvssData"]
        score = data["baseScore"]
        severity = data.get("baseSeverity") or primary.get("baseSeverity")
        if not severity:
            # CVSS v2 has no baseSeverity field and no "Critical" tier.
            severity = "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
        return {"score": score, "version": version, "severity": severity}
    return None


def extract_cwes(weaknesses: list) -> list[dict]:
    seen = []
    for w in weaknesses or []:
        for d in w.get("description", []):
            if d.get("lang") != "en":
                continue
            cwe_id = d["value"]
            if any(c["id"] == cwe_id for c in seen):
                continue
            seen.append({"id": cwe_id, "name": CWE_NAMES.get(cwe_id, cwe_id)})
    return seen


def extract_vendors(affected: list, limit: int = 5) -> list[str]:
    seen = []
    for a in affected or []:
        for ad in a.get("affectedData", []):
            label = f"{ad.get('vendor', '')} {ad.get('product', '')}".strip()
            if label and label not in seen:
                seen.append(label)
            if len(seen) >= limit:
                return seen
    return seen


def extract_references(references: list, limit: int = 4) -> list[str]:
    urls = [r["url"] for r in (references or []) if r.get("url")]
    seen = []
    for u in urls:
        if u not in seen:
            seen.append(u)
        if len(seen) >= limit:
            break
    return seen


def build_record(cve: dict, kev_lookup: dict) -> dict | None:
    if cve.get("vulnStatus") == "Rejected":
        return None

    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    description = re.sub(r"\s+", " ", description).strip()[:DESCRIPTION_MAX_LEN]

    cvss = best_cvss(cve.get("metrics", {}))
    kev = kev_lookup.get(cve["id"])

    severity = cvss["severity"] if cvss else None
    if severity not in KEPT_SEVERITIES and not kev:
        return None

    return {
        "id": cve["id"],
        "published": cve.get("published"),
        "lastModified": cve.get("lastModified"),
        "vulnStatus": cve.get("vulnStatus"),
        "description": description or "No description available.",
        "cvss": cvss,
        "cwes": extract_cwes(cve.get("weaknesses", [])),
        "vendors": extract_vendors(cve.get("affected", [])),
        "references": extract_references(cve.get("references", [])),
        "kev": {
            "in_kev": True,
            "date_added": kev["dateAdded"],
            "required_action": kev.get("requiredAction", ""),
            "known_ransomware": kev.get("knownRansomwareCampaignUse", "Unknown"),
        } if kev else {"in_kev": False},
    }


def month_key(published: str) -> str:
    return (published or "")[:7] or "unknown"


def load_month(month: str) -> dict:
    path = OUTPUT_DIR / f"{month}.json"
    if path.exists():
        return json.loads(path.read_text())
    return {"month": month, "cves": []}


def save_month(month: str, doc: dict) -> None:
    doc["cves"].sort(key=lambda c: c.get("published") or "", reverse=True)
    doc["updated_at"] = datetime.now(timezone.utc).isoformat()
    (OUTPUT_DIR / f"{month}.json").write_text(json.dumps(doc, indent=2))


def upsert_records(records: list[dict]) -> set[str]:
    by_month = {}
    for r in records:
        by_month.setdefault(month_key(r["published"]), []).append(r)

    touched = set()
    for month, month_records in by_month.items():
        doc = load_month(month)
        by_id = {c["id"]: c for c in doc["cves"]}
        for r in month_records:
            by_id[r["id"]] = r
        doc["cves"] = list(by_id.values())
        save_month(month, doc)
        touched.add(month)
    return touched


def rebuild_index_and_latest() -> None:
    month_files = sorted(OUTPUT_DIR.glob("????-??.json"), reverse=True)
    months_meta = []
    all_recent = []

    for path in month_files:
        doc = json.loads(path.read_text())
        cves = doc.get("cves", [])
        critical = sum(1 for c in cves if c.get("cvss", {}) and c["cvss"]["severity"] == "CRITICAL")
        high = sum(1 for c in cves if c.get("cvss", {}) and c["cvss"]["severity"] == "HIGH")
        kev_count = sum(1 for c in cves if c.get("kev", {}).get("in_kev"))
        latest_published = max((c.get("published") or "" for c in cves), default="")
        months_meta.append({
            "key": doc["month"], "count": len(cves), "critical": critical, "high": high,
            "kev": kev_count, "latest_published": latest_published,
        })
        if len(all_recent) < LATEST_COUNT * 3:  # a few months' worth is plenty to pick the top N from
            all_recent.extend(cves)

    def sort_key(c):
        sev_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}.get((c.get("cvss") or {}).get("severity"), 0)
        kev_rank = 1 if c.get("kev", {}).get("in_kev") else 0
        return (kev_rank, sev_rank, c.get("published") or "")

    all_recent.sort(key=sort_key, reverse=True)

    index = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "last_fetched": LAST_FETCHED_HOLDER["value"],
        "months": months_meta,
    }
    (OUTPUT_DIR / "index.json").write_text(json.dumps(index, indent=2))
    (OUTPUT_DIR / "latest.json").write_text(json.dumps({
        "generated_at": index["generated_at"],
        "cves": all_recent[:LATEST_COUNT],
    }, indent=2))


LAST_FETCHED_HOLDER = {"value": None}  # populated in main(), read by rebuild_index_and_latest()


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    index_path = OUTPUT_DIR / "index.json"

    if index_path.exists():
        last_fetched = datetime.fromisoformat(json.loads(index_path.read_text())["last_fetched"])
    else:
        last_fetched = datetime.now(timezone.utc) - timedelta(days=SEED_DAYS)

    run_start = datetime.now(timezone.utc)
    print(f"Fetching CVEs modified between {last_fetched.isoformat()} and {run_start.isoformat()}…")

    try:
        kev_lookup = fetch_kev()
        print(f"  CISA KEV catalog: {len(kev_lookup)} entries")
        raw_cves = fetch_nvd_range(last_fetched, run_start)
        print(f"  NVD returned {len(raw_cves)} new/modified CVEs")
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError) as exc:
        print(f"Fetch failed ({exc}); leaving existing data/cve/ untouched so next run retries this window.")
        return

    records = [r for r in (build_record(c, kev_lookup) for c in raw_cves) if r]
    print(f"  kept {len(records)} (Critical/High or KEV-listed)")

    touched = upsert_records(records)
    LAST_FETCHED_HOLDER["value"] = run_start.isoformat()
    rebuild_index_and_latest()

    print(f"  wrote {len(touched)} month file(s): {', '.join(sorted(touched)) or '(none)'}")
    print(f"  last_fetched advanced to {run_start.isoformat()}")


if __name__ == "__main__":
    main()
