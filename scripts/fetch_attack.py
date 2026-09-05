#!/usr/bin/env python3
"""
Pulls the MITRE ATT&CK STIX 2.1 bundles (Enterprise, Mobile, ICS) from the
official mitre-attack/attack-stix-data GitHub repo and compacts each one down
to just what the front end needs: tactics, techniques, groups (APT actors),
and software (malware/tools), with the "uses" relationships between them
resolved into plain ATT&CK IDs.

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
DESCRIPTION_MAX_LEN = 420


def clean_text(text: str) -> str:
    """Strip MITRE's markdown links and citation markers, trim to one short blurb."""
    if not text:
        return ""
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)
    paragraph = text.strip().split("\n\n")[0].strip()
    if len(paragraph) > DESCRIPTION_MAX_LEN:
        paragraph = paragraph[:DESCRIPTION_MAX_LEN].rsplit(" ", 1)[0] + "…"
    return paragraph


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

    by_stix_id = {o["id"]: o for o in objects if "id" in o}

    tactics_by_stix_id = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic" and is_live(obj):
            aid = attack_id(obj)
            if aid:
                tactics_by_stix_id[obj["id"]] = {
                    "id": aid,
                    "name": obj.get("name", ""),
                    "shortname": obj.get("x_mitre_shortname", ""),
                }

    matrix = next((o for o in objects if o.get("type") == "x-mitre-matrix" and is_live(o)), None)
    if matrix:
        tactics = [tactics_by_stix_id[ref] for ref in matrix.get("tactic_refs", []) if ref in tactics_by_stix_id]
        matrix_name = matrix.get("name", domain_cfg["key"])
    else:
        tactics = list(tactics_by_stix_id.values())
        matrix_name = domain_cfg["key"]

    shortname_to_tactic_id = {t["shortname"]: t["id"] for t in tactics}

    techniques = {}       # attack_id -> record
    software = {}         # attack_id -> record
    groups = {}           # attack_id -> record
    id_to_attack_id = {}  # stix id -> attack id, for resolving relationships
    stix_id_to_kind = {}  # stix id -> "technique" | "software" | "group"

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
                "tactics": tactic_ids,
                "platforms": obj.get("x_mitre_platforms", []),
                "is_subtechnique": is_sub,
                "parent": aid.split(".")[0] if is_sub and "." in aid else None,
                "groups": [],
                "software": [],
            }
            id_to_attack_id[obj["id"]] = aid
            stix_id_to_kind[obj["id"]] = "technique"

        elif otype in ("malware", "tool"):
            software[aid] = {
                "id": aid,
                "name": obj.get("name", ""),
                "type": otype,
                "aliases": obj.get("x_mitre_aliases", []),
                "platforms": obj.get("x_mitre_platforms", []),
                "techniques": [],
            }
            id_to_attack_id[obj["id"]] = aid
            stix_id_to_kind[obj["id"]] = "software"

        elif otype == "intrusion-set":
            groups[aid] = {
                "id": aid,
                "name": obj.get("name", ""),
                "aliases": obj.get("aliases", []),
                "summary": clean_text(obj.get("description", "")),
                "techniques": [],
                "software": [],
            }
            id_to_attack_id[obj["id"]] = aid
            stix_id_to_kind[obj["id"]] = "group"

    for obj in objects:
        if obj.get("type") != "relationship" or not is_live(obj):
            continue
        rel = obj.get("relationship_type")
        src_stix, dst_stix = obj.get("source_ref"), obj.get("target_ref")
        src_kind, dst_kind = stix_id_to_kind.get(src_stix), stix_id_to_kind.get(dst_stix)
        src_id, dst_id = id_to_attack_id.get(src_stix), id_to_attack_id.get(dst_stix)
        if rel != "uses" or not src_id or not dst_id:
            continue

        if src_kind == "group" and dst_kind == "technique":
            groups[src_id]["techniques"].append(dst_id)
            techniques[dst_id]["groups"].append(src_id)
        elif src_kind == "group" and dst_kind == "software":
            groups[src_id]["software"].append(dst_id)
        elif src_kind == "software" and dst_kind == "technique":
            software[src_id]["techniques"].append(dst_id)
            techniques[dst_id]["software"].append(src_id)

    for g in groups.values():
        g["techniques"] = sorted(set(g["techniques"]))
        g["software"] = sorted(set(g["software"]))
    for s in software.values():
        s["techniques"] = sorted(set(s["techniques"]))
    for t in techniques.values():
        t["groups"] = sorted(set(t["groups"]))
        t["software"] = sorted(set(t["software"]))

    return {
        "domain": domain_cfg["key"],
        "name": matrix_name,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "tactics": tactics,
        "techniques": sorted(techniques.values(), key=lambda t: t["id"]),
        "groups": sorted(groups.values(), key=lambda g: g["name"].lower()),
        "software": sorted(software.values(), key=lambda s: s["name"].lower()),
    }


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for domain_cfg in DOMAINS:
        key = domain_cfg["key"]
        print(f"Fetching {key} ATT&CK bundle…")
        data = compact_domain(domain_cfg)
        out_path = OUTPUT_DIR / f"{key}.json"
        out_path.write_text(json.dumps(data, indent=2))
        print(
            f"  wrote {out_path} — {len(data['groups'])} groups, "
            f"{len(data['software'])} software, {len(data['techniques'])} techniques, "
            f"{len(data['tactics'])} tactics"
        )


if __name__ == "__main__":
    main()
