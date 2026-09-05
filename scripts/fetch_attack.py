#!/usr/bin/env python3
"""
Pulls the MITRE ATT&CK STIX 2.1 bundles (Enterprise, Mobile, ICS) from the
official mitre-attack/attack-stix-data GitHub repo and compacts each one down
to just what the front end needs: tactics, techniques, groups (APT actors),
software (malware/tools), campaigns, and mitigations, with the relationships
between them ("uses", "mitigates", "attributed-to") resolved into plain
ATT&CK IDs.

Groups also get a best-effort `countries` tag inferred from their free-text
description (MITRE's STIX data has no structured nationality field) — see
guess_countries() below. Treat it as a rough lead, not an attribution claim;
many groups are financially motivated or simply undetermined and will come
back with countries: [].

The raw bundles are large (Enterprise alone is ~50MB of STIX, mostly citation
metadata) so this never commits them as-is — it writes one small JSON file
per domain to data/attack/.

Run manually with: python scripts/fetch_attack.py
"""

import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DOMAINS = [
    {
        "key": "enterprise",
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        "kill_chain": "mitre-attack",
    },
    {
        "key": "mobile",
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
        "kill_chain": "mitre-mobile-attack",
    },
    {
        "key": "ics",
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
        "kill_chain": "mitre-ics-attack",
    },
]

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "data" / "attack"
SUMMARY_MAX_LEN = 420

# Demonym -> (ISO code, display name), longest phrase first so "North Korean"
# matches before a hypothetical bare "Korean" would.
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

# Bare "government" is deliberately NOT in ATTRIBUTION_WORDS above — MITRE
# descriptions use it constantly for *targets* too ("attacks against Ukrainian
# government agencies"), which would misread a victim's nationality as the
# actor's origin. It's only trustworthy when a sponsor-relation verb sits
# directly in front of "<Demonym> government", e.g. "associated with the
# Chinese government" / "on behalf of the Iranian government".
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

# Country noun (not demonym) immediately before "-based" — MITRE's other very
# common phrasing, e.g. "APT3 is a China-based threat group".
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

# Fallback when the demonym+attribution-word pattern doesn't fire but a named
# sponsoring agency does, e.g. "attributed to Russia's GRU".
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


def clean_full(text: str) -> str:
    """Strip MITRE's citation markers and markdown links, keep full length."""
    if not text:
        return ""
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    return text.strip()


def clean_summary(text: str, max_len: int = SUMMARY_MAX_LEN) -> str:
    """Short card-friendly blurb: first paragraph of the cleaned text, trimmed."""
    cleaned = clean_full(text)
    paragraph = cleaned.split("\n\n")[0].strip()
    if len(paragraph) > max_len:
        paragraph = paragraph[:max_len].rsplit(" ", 1)[0] + "…"
    return paragraph


def guess_countries(description: str) -> list[dict]:
    """Best-effort nation attribution from free text. Deliberately scoped to
    demonym + attribution-word pairs (not bare country-name matching) so a
    mention of a *targeted* country doesn't get mistaken for the actor's
    origin."""
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


def attack_id(obj) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in ("mitre-attack", "mitre-ics-attack", "mitre-mobile-attack"):
            return ref.get("external_id")
    return None


def is_live(obj) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def fetch_bundle(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "cti-feed/1.0"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.load(resp)


def compact_domain(domain_cfg: dict) -> dict:
    bundle = fetch_bundle(domain_cfg["url"])
    objects = bundle.get("objects", [])
    kill_chain = domain_cfg["kill_chain"]

    tactics_by_stix_id = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic" and is_live(obj):
            aid = attack_id(obj)
            if aid:
                tactics_by_stix_id[obj["id"]] = {
                    "id": aid,
                    "name": obj.get("name", ""),
                    "shortname": obj.get("x_mitre_shortname", ""),
                    "description": clean_full(obj.get("description", "")),
                }

    matrix = next((o for o in objects if o.get("type") == "x-mitre-matrix" and is_live(o)), None)
    if matrix:
        tactics = [tactics_by_stix_id[ref] for ref in matrix.get("tactic_refs", []) if ref in tactics_by_stix_id]
        matrix_name = matrix.get("name", domain_cfg["key"])
    else:
        tactics = list(tactics_by_stix_id.values())
        matrix_name = domain_cfg["key"]

    shortname_to_tactic_id = {t["shortname"]: t["id"] for t in tactics}

    techniques = {}    # attack_id -> record
    software = {}       # attack_id -> record
    groups = {}          # attack_id -> record
    campaigns = {}        # attack_id -> record
    mitigations = {}       # attack_id -> record
    id_to_attack_id = {}     # stix id -> attack id, for resolving relationships
    stix_id_to_kind = {}      # stix id -> "technique" | "software" | "group" | "campaign" | "mitigation"

    for obj in objects:
        if not is_live(obj):
            continue
        otype = obj.get("type")
        aid = attack_id(obj)
        if not aid:
            continue

        if otype == "attack-pattern":
            phases = [p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == kill_chain]
            tactic_ids = [shortname_to_tactic_id[p] for p in phases if p in shortname_to_tactic_id]
            is_sub = bool(obj.get("x_mitre_is_subtechnique"))
            techniques[aid] = {
                "id": aid,
                "name": obj.get("name", ""),
                "description": clean_full(obj.get("description", "")),
                "tactics": tactic_ids,
                "platforms": obj.get("x_mitre_platforms", []),
                "is_subtechnique": is_sub,
                "parent": aid.split(".")[0] if is_sub and "." in aid else None,
                "groups": [],
                "software": [],
                "campaigns": [],
                "mitigations": [],
            }
            id_to_attack_id[obj["id"]] = aid
            stix_id_to_kind[obj["id"]] = "technique"

        elif otype in ("malware", "tool"):
            software[aid] = {
                "id": aid,
                "name": obj.get("name", ""),
                "type": otype,
                "description": clean_full(obj.get("description", "")),
                "aliases": obj.get("x_mitre_aliases", []),
                "platforms": obj.get("x_mitre_platforms", []),
                "techniques": [],
                "campaigns": [],
            }
            id_to_attack_id[obj["id"]] = aid
            stix_id_to_kind[obj["id"]] = "software"

        elif otype == "intrusion-set":
            description = obj.get("description", "")
            groups[aid] = {
                "id": aid,
                "name": obj.get("name", ""),
                "aliases": obj.get("aliases", []),
                "summary": clean_summary(description),
                "description": clean_full(description),
                "countries": guess_countries(clean_full(description)),
                "techniques": [],
                "software": [],
                "campaigns": [],
            }
            id_to_attack_id[obj["id"]] = aid
            stix_id_to_kind[obj["id"]] = "group"

        elif otype == "campaign":
            campaigns[aid] = {
                "id": aid,
                "name": obj.get("name", ""),
                "description": clean_full(obj.get("description", "")),
                "first_seen": obj.get("first_seen"),
                "last_seen": obj.get("last_seen"),
                "groups": [],
                "techniques": [],
                "software": [],
            }
            id_to_attack_id[obj["id"]] = aid
            stix_id_to_kind[obj["id"]] = "campaign"

        elif otype == "course-of-action":
            mitigations[aid] = {
                "id": aid,
                "name": obj.get("name", ""),
                "description": clean_full(obj.get("description", "")),
                "techniques": [],
            }
            id_to_attack_id[obj["id"]] = aid
            stix_id_to_kind[obj["id"]] = "mitigation"

    for obj in objects:
        if obj.get("type") != "relationship" or not is_live(obj):
            continue
        rel = obj.get("relationship_type")
        src_stix, dst_stix = obj.get("source_ref"), obj.get("target_ref")
        src_kind, dst_kind = stix_id_to_kind.get(src_stix), stix_id_to_kind.get(dst_stix)
        src_id, dst_id = id_to_attack_id.get(src_stix), id_to_attack_id.get(dst_stix)
        if not src_id or not dst_id:
            continue

        if rel == "uses":
            if src_kind == "group" and dst_kind == "technique":
                groups[src_id]["techniques"].append(dst_id)
                techniques[dst_id]["groups"].append(src_id)
            elif src_kind == "group" and dst_kind == "software":
                groups[src_id]["software"].append(dst_id)
            elif src_kind == "software" and dst_kind == "technique":
                software[src_id]["techniques"].append(dst_id)
                techniques[dst_id]["software"].append(src_id)
            elif src_kind == "campaign" and dst_kind == "technique":
                campaigns[src_id]["techniques"].append(dst_id)
                techniques[dst_id]["campaigns"].append(src_id)
            elif src_kind == "campaign" and dst_kind == "software":
                campaigns[src_id]["software"].append(dst_id)
                software[dst_id]["campaigns"].append(src_id)
        elif rel == "attributed-to" and src_kind == "campaign" and dst_kind == "group":
            campaigns[src_id]["groups"].append(dst_id)
            groups[dst_id]["campaigns"].append(src_id)
        elif rel == "mitigates" and src_kind == "mitigation" and dst_kind == "technique":
            mitigations[src_id]["techniques"].append(dst_id)
            techniques[dst_id]["mitigations"].append(src_id)

    for g in groups.values():
        g["techniques"] = sorted(set(g["techniques"]))
        g["software"] = sorted(set(g["software"]))
        g["campaigns"] = sorted(set(g["campaigns"]))
    for s in software.values():
        s["techniques"] = sorted(set(s["techniques"]))
        s["campaigns"] = sorted(set(s["campaigns"]))
    for t in techniques.values():
        t["groups"] = sorted(set(t["groups"]))
        t["software"] = sorted(set(t["software"]))
        t["campaigns"] = sorted(set(t["campaigns"]))
        t["mitigations"] = sorted(set(t["mitigations"]))
    for c in campaigns.values():
        c["groups"] = sorted(set(c["groups"]))
        c["techniques"] = sorted(set(c["techniques"]))
        c["software"] = sorted(set(c["software"]))
    for m in mitigations.values():
        m["techniques"] = sorted(set(m["techniques"]))

    return {
        "domain": domain_cfg["key"],
        "name": matrix_name,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "tactics": tactics,
        "techniques": sorted(techniques.values(), key=lambda t: t["id"]),
        "groups": sorted(groups.values(), key=lambda g: g["name"].lower()),
        "software": sorted(software.values(), key=lambda s: s["name"].lower()),
        "campaigns": sorted(campaigns.values(), key=lambda c: c["name"].lower()),
        "mitigations": sorted(mitigations.values(), key=lambda m: m["name"].lower()),
    }


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for domain_cfg in DOMAINS:
        key = domain_cfg["key"]
        print(f"Fetching {key} ATT&CK bundle…")
        data = compact_domain(domain_cfg)
        out_path = OUTPUT_DIR / f"{key}.json"
        out_path.write_text(json.dumps(data, indent=2))
        attributed = sum(1 for g in data["groups"] if g["countries"])
        print(
            f"  wrote {out_path} — {len(data['groups'])} groups ({attributed} with an inferred country), "
            f"{len(data['software'])} software, {len(data['techniques'])} techniques, "
            f"{len(data['campaigns'])} campaigns, {len(data['mitigations'])} mitigations, "
            f"{len(data['tactics'])} tactics"
        )


if __name__ == "__main__":
    main()
