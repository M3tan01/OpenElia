"""
core/stix_ingest.py — runtime STIX 2.x bundle parser (no stix2 dependency).

An org's CTI bundle is just JSON. We extract the parts useful for a threat
hunt — IOCs (from indicator patterns), ATT&CK techniques (from attack-pattern
external refs), and actor/malware context — using only the stdlib, keeping the
runtime free of the heavy `stix2` library (the only stix2 import in the repo is
the offline maintainer script scripts/extract_actor_ttps.py).
"""

from __future__ import annotations

import ipaddress
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

# ---------------------------------------------------------------------------
# Refang / validation helpers
# ---------------------------------------------------------------------------

# Substitution rules applied in order (most-specific first).
# NOTE: Assumes input is a single IOC token, not free prose — space-delimited
# rules (' dot ', ' at ') and substring rules ('hxxp') would over-match plain text.
_REFANG_SUBS: list[tuple[re.Pattern[str], object]] = [
    # scheme-level: hxxp / hxxps (case-insensitive)
    (re.compile(r'hxxps?', re.IGNORECASE), lambda m: m.group().lower().replace('hxxps', 'https').replace('hxxp', 'http')),
    # [://] → ://
    (re.compile(r'\[://\]'), '://'),
    # [:] → :
    (re.compile(r'\[:\]'), ':'),
    # [at] → @  (must precede the generic bracket-strip rule)
    (re.compile(r'\[at\]', re.IGNORECASE), '@'),
    # [dot] → .  (must precede the generic bracket-strip rule)
    (re.compile(r'\[dot\]', re.IGNORECASE), '.'),
    # [.] (.)  (dot)  <space>dot<space>  →  .
    (re.compile(r'\[\.\]|\(\.\)|\(dot\)| dot ', re.IGNORECASE), '.'),
    # [@] (at) <space>at<space>  →  @
    (re.compile(r'\[@\]|\(at\)| at ', re.IGNORECASE), '@'),
    # strip stray surrounding brackets used for fanging: [text] → text
    # only when the bracket wraps an alnum-only string (avoids stomping [://])
    (re.compile(r'\[([a-zA-Z0-9]+)\]'), r'\1'),
]


def refang(value: str) -> str:
    """Normalize defanged IOC notation back to its canonical form.

    Handles: hxxp/hxxps, [.] (.) (dot) ' dot ', [//] [:] [@] (at) ' at ',
    [at] → @, [dot] → .  (bracket-word forms; resolved before generic strip).
    Does NOT handle free-text prose — input must be a single IOC token.
    Pure stdlib (re only). Returns the refanged string unchanged when no
    defanging notation is present.
    """
    for pattern, repl in _REFANG_SUBS:
        value = pattern.sub(repl, value)  # re.sub handles callable and str uniformly
    return value


# Pre-compiled validators ------------------------------------------------

_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
_DOMAIN_LABEL_RE = re.compile(r'^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$')
_MAC_RE = re.compile(r'^[0-9a-fA-F]{2}([:\-])[0-9a-fA-F]{2}(\1[0-9a-fA-F]{2}){4}$')


def is_valid_ioc(ioc_type: str, value: str) -> bool:
    """Return True when *value* is a well-formed IOC of *ioc_type*.

    Types with active validation: ip, hash, url, domain, email, mac.
    Any other type (registry, unknown passthrough) always returns True.
    """
    if ioc_type == "ip":
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    if ioc_type == "hash":
        if len(value) not in (32, 40, 64):
            return False
        return bool(_HEX_RE.match(value))

    if ioc_type == "url":
        if not (value.startswith("http://") or value.startswith("https://")):
            return False
        # host is the part between :// and the first / (or end of string)
        after_scheme = value.split("://", 1)[1]
        host = after_scheme.split("/")[0]
        return len(host) > 0

    if ioc_type == "domain":
        labels = value.rstrip(".").split(".")
        if len(labels) < 2:
            return False
        return all(_DOMAIN_LABEL_RE.match(label) for label in labels)

    if ioc_type == "email":
        parts = value.split("@")
        if len(parts) != 2:
            return False
        local, domain = parts
        if not local:
            return False
        domain_labels = domain.rstrip(".").split(".")
        if len(domain_labels) < 2:
            return False
        return all(_DOMAIN_LABEL_RE.match(label) for label in domain_labels)

    if ioc_type == "mac":
        return bool(_MAC_RE.match(value))

    # registry, unknown passthrough types — keep as-is
    return True


def _iocs_from_pattern(pattern: str) -> list[dict]:
    """Extract normalized IOCs from a STIX indicator `pattern` string.

    Each extracted value is refanged, then validated by type. Invalid IOCs
    are silently dropped.
    """
    out: list[dict] = []
    for obj_type, _path, value in _TOKEN_RE.findall(pattern or ""):
        ioc_type = _IOC_TYPE.get(obj_type.lower(), obj_type.lower())
        value = refang(value)
        if is_valid_ioc(ioc_type, value):
            # Canonicalize IP addresses so equivalent forms (expanded vs compressed
            # IPv6) deduplicate correctly in parse_stix's seen_ioc set.
            if ioc_type == "ip":
                value = str(ipaddress.ip_address(value))
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
