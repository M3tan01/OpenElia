"""
core/stix_ingest.py — runtime STIX 2.x bundle parser (no stix2 dependency).

An org's CTI bundle is just JSON. We extract the parts useful for a threat
hunt — IOCs (from indicator patterns), ATT&CK techniques (from attack-pattern
external refs), and actor/malware context — using only the stdlib, keeping the
runtime free of the heavy `stix2` library (the only stix2 import in the repo is
the offline maintainer script scripts/extract_actor_ttps.py).
"""

from __future__ import annotations

import json
import re

# Capture `<stix-object-type>:<path> = 'value'` tokens inside indicator patterns,
# e.g. [ipv4-addr:value = '1.2.3.4'] or [file:hashes.'SHA-256' = 'abc'].
_TOKEN_RE = re.compile(r"([a-z0-9-]+):([^\s=]+)\s*=\s*'([^']+)'", re.IGNORECASE)

# STIX object type → normalized IOC type.
_IOC_TYPE = {
    "ipv4-addr": "ip",
    "ipv6-addr": "ip",
    "domain-name": "domain",
    "url": "url",
    "email-addr": "email",
    "file": "hash",
    "windows-registry-key": "registry",
    "mac-addr": "mac",
}


def _iocs_from_pattern(pattern: str) -> list[dict]:
    """Extract normalized IOCs from a STIX indicator `pattern` string."""
    out: list[dict] = []
    for obj_type, _path, value in _TOKEN_RE.findall(pattern or ""):
        ioc_type = _IOC_TYPE.get(obj_type.lower(), obj_type.lower())
        out.append({"type": ioc_type, "value": value})
    return out


def parse_stix(content: str | bytes | dict) -> dict:
    """Parse a STIX bundle into a hunt brief.

    Accepts raw JSON text/bytes or an already-decoded dict/list. Returns
    {iocs, ttps, actors, malware, counts}. Raises ValueError on invalid JSON
    or a structure with no STIX objects. Malformed individual objects are
    skipped, never fatal.
    """
    if isinstance(content, (str, bytes)):
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"not valid JSON: {exc}") from exc
    else:
        data = content

    if isinstance(data, dict):
        objects = data.get("objects")
        if objects is None:
            # a single SDO passed without a bundle wrapper
            t = data.get("type")
            objects = [data] if t and t != "bundle" else None
    elif isinstance(data, list):
        objects = data
    else:
        objects = None

    if objects is None:
        raise ValueError("no STIX objects found (expected a bundle with 'objects')")

    iocs: list[dict] = []
    ttps: list[str] = []
    actors: list[str] = []
    malware: list[str] = []
    seen_ioc: set[tuple[str, str]] = set()

    for obj in objects:
        if not isinstance(obj, dict):
            continue
        otype = obj.get("type")
        if otype == "indicator":
            for ioc in _iocs_from_pattern(obj.get("pattern", "")):
                key = (ioc["type"], ioc["value"])
                if key not in seen_ioc:
                    seen_ioc.add(key)
                    iocs.append(ioc)
        elif otype == "attack-pattern":
            for ref in obj.get("external_references", []):
                if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
                    ext = ref.get("external_id")
                    if ext and ext not in ttps:
                        ttps.append(ext)
        elif otype in ("intrusion-set", "threat-actor", "campaign"):
            name = obj.get("name")
            if name and name not in actors:
                actors.append(name)
        elif otype in ("malware", "tool"):
            name = obj.get("name")
            if name and name not in malware:
                malware.append(name)

    return {
        "iocs": iocs,
        "ttps": ttps,
        "actors": actors,
        "malware": malware,
        "counts": {
            "iocs": len(iocs),
            "ttps": len(ttps),
            "actors": len(actors),
            "malware": len(malware),
        },
    }


def compose_hunt_task(brief: dict, max_iocs: int = 200) -> str:
    """Build a readable defensive hunt objective from a parsed STIX brief."""
    lines = ["Threat hunt seeded from uploaded STIX CTI. Search logs/endpoints for the"
             " following indicators and ATT&CK techniques; report any matches."]
    if brief.get("actors"):
        lines.append(f"Attributed actor(s): {', '.join(brief['actors'])}")
    if brief.get("malware"):
        lines.append(f"Associated malware/tools: {', '.join(brief['malware'])}")
    iocs = brief.get("iocs", [])
    if iocs:
        lines.append("IOCs to hunt:")
        for ioc in iocs[:max_iocs]:
            lines.append(f"  - {ioc['type']}: {ioc['value']}")
        if len(iocs) > max_iocs:
            lines.append(f"  … and {len(iocs) - max_iocs} more")
    if brief.get("ttps"):
        lines.append(f"ATT&CK techniques: {', '.join(brief['ttps'])}")
    return "\n".join(lines)
