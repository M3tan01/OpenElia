#!/usr/bin/env python3
"""IOC enrichment — vendored from cybersec-skills
`analyzing-indicators-of-compromise/scripts/agent.py` and ported to httpx.

Changes from the source:
  * requests.get/post -> httpx (already an OpenElia dependency; avoids a new install)
  * API keys read from SecretStore (keyring) with env fallback, instead of bare params
  * pure functions (classify/defang/refang/is_private_ip/score) are byte-for-byte equivalent

The pure functions never touch the network and are the unit-test surface.
"""
import datetime
import os
import re
import sys

import httpx

# Import SecretStore from the OpenElia root (same pattern as
# mcp_servers/threat_intel/server.py:13).
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
try:
    from secret_store import SecretStore

    def _key(name: str) -> str | None:
        return SecretStore.get_secret(name)
except Exception:  # pragma: no cover - keyring unavailable in some CI contexts
    def _key(name: str) -> str | None:
        return os.getenv(name)


_HTTP_TIMEOUT = httpx.Timeout(30.0)


# --------------------------------------------------------------------------- #
# Pure classification / formatting helpers (no network)                       #
# --------------------------------------------------------------------------- #

def classify_ioc(value: str) -> str:
    """Classify an IOC by type: ipv4, domain, url, sha256, sha1, md5, email."""
    value = value.strip()
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
        return "ipv4"
    if re.match(r"^[a-fA-F0-9]{64}$", value):
        return "sha256"
    if re.match(r"^[a-fA-F0-9]{40}$", value):
        return "sha1"
    if re.match(r"^[a-fA-F0-9]{32}$", value):
        return "md5"
    if re.match(r"^https?://", value):
        return "url"
    if re.match(r"^[^@]+@[^@]+\.[^@]+$", value):
        return "email"
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", value):
        return "domain"
    return "unknown"


def defang_ioc(value: str) -> str:
    """Defang an IOC for safe documentation."""
    value = value.replace("http://", "hxxp://")
    value = value.replace("https://", "hxxps://")
    value = re.sub(r"\.(?=\w)", "[.]", value)
    return value


def refang_ioc(value: str) -> str:
    """Refang a defanged IOC for querying APIs."""
    value = value.replace("hxxp://", "http://")
    value = value.replace("hxxps://", "https://")
    value = value.replace("[.]", ".")
    value = value.replace("[://]", "://")
    return value


def is_private_ip(ip: str) -> bool:
    """Check if an IP is RFC 1918 private (or loopback)."""
    octets = [int(o) for o in ip.split(".")]
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    return False


def score_ioc(vt_result=None, abuse_result=None, mb_result=None) -> dict:
    """Assign a confidence score and disposition to an IOC."""
    score = 0
    reasons = []
    if vt_result:
        malicious = vt_result.get("malicious", 0)
        if malicious >= 15:
            score += 40
            reasons.append(f"VT: {malicious} detections (high)")
        elif malicious >= 5:
            score += 20
            reasons.append(f"VT: {malicious} detections (moderate)")
        elif malicious > 0:
            score += 5
            reasons.append(f"VT: {malicious} detections (low)")
    if abuse_result:
        abuse_score = abuse_result.get("abuse_confidence", 0)
        if abuse_score >= 70:
            score += 30
            reasons.append(f"AbuseIPDB: {abuse_score}% confidence")
        elif abuse_score >= 30:
            score += 15
            reasons.append(f"AbuseIPDB: {abuse_score}% confidence")
    if mb_result:
        score += 30
        reasons.append(f"MalwareBazaar: {mb_result.get('signature', 'known malware')}")

    if score >= 70:
        disposition = "BLOCK"
    elif score >= 40:
        disposition = "MONITOR"
    else:
        disposition = "INVESTIGATE"

    return {"score": score, "disposition": disposition, "reasons": reasons}


# --------------------------------------------------------------------------- #
# Live API queries (httpx) — only reached in --mode live                      #
# --------------------------------------------------------------------------- #

def query_virustotal_hash(sha256: str, api_key: str):
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    resp = httpx.get(url, headers={"x-apikey": api_key}, timeout=_HTTP_TIMEOUT)
    if resp.status_code == 200:
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "sha256": sha256,
            "malicious": stats.get("malicious", 0),
            "total": sum(stats.values()),
            "type_description": data.get("type_description", ""),
            "popular_threat_name": data.get("popular_threat_classification", {}).get(
                "suggested_threat_label", ""),
            "tags": data.get("tags", []),
        }
    return None


def query_virustotal_domain(domain: str, api_key: str):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    resp = httpx.get(url, headers={"x-apikey": api_key}, timeout=_HTTP_TIMEOUT)
    if resp.status_code == 200:
        data = resp.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        return {
            "domain": domain,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "reputation": data.get("reputation", 0),
            "registrar": data.get("registrar", ""),
            "creation_date": data.get("creation_date", ""),
        }
    return None


def query_abuseipdb(ip: str, api_key: str, max_age_days: int = 90):
    url = "https://api.abuseipdb.com/api/v2/check"
    resp = httpx.get(
        url,
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": max_age_days},
        timeout=_HTTP_TIMEOUT,
    )
    if resp.status_code == 200:
        data = resp.json().get("data", {})
        return {
            "ip": ip,
            "abuse_confidence": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "is_tor": data.get("isTor", False),
        }
    return None


def query_malwarebazaar(sha256: str):
    url = "https://mb-api.abuse.ch/api/v1/"
    resp = httpx.post(url, data={"query": "get_info", "hash": sha256}, timeout=_HTTP_TIMEOUT)
    if resp.status_code == 200:
        result = resp.json()
        if result.get("query_status") == "ok" and result.get("data"):
            entry = result["data"][0]
            return {
                "sha256": sha256,
                "signature": entry.get("signature", ""),
                "tags": entry.get("tags", []),
                "file_type": entry.get("file_type", ""),
                "reporter": entry.get("reporter", ""),
                "first_seen": entry.get("first_seen", ""),
            }
    return None


# --------------------------------------------------------------------------- #
# Orchestration                                                                #
# --------------------------------------------------------------------------- #

def enrich_ioc(value: str, live: bool = False) -> dict:
    """Enrich a single IOC.

    Always classifies/defangs/scores. Network calls only happen when
    ``live=True`` and the relevant API key is present in keyring/env.
    """
    ioc_type = classify_ioc(value)
    result = {
        "ioc": value,
        "type": ioc_type,
        "defanged": defang_ioc(value),
        "enrichment": {},
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    if ioc_type == "ipv4" and is_private_ip(value):
        result["note"] = "RFC 1918 private IP - skipping external enrichment"
        result.update(score_ioc())
        return result

    if live:
        vt_key = _key("VT_API_KEY")
        abuse_key = _key("ABUSEIPDB_API_KEY")
        try:
            if ioc_type in ("sha256", "sha1", "md5") and vt_key:
                result["enrichment"]["virustotal"] = query_virustotal_hash(value, vt_key)
                result["enrichment"]["malwarebazaar"] = query_malwarebazaar(value)
            elif ioc_type == "ipv4":
                if abuse_key:
                    result["enrichment"]["abuseipdb"] = query_abuseipdb(value, abuse_key)
                if vt_key:
                    result["enrichment"]["virustotal"] = query_virustotal_domain(value, vt_key)
            elif ioc_type == "domain" and vt_key:
                result["enrichment"]["virustotal"] = query_virustotal_domain(value, vt_key)
        except httpx.HTTPError as exc:
            result["error"] = f"enrichment HTTP error: {exc}"

    scoring = score_ioc(
        result["enrichment"].get("virustotal"),
        result["enrichment"].get("abuseipdb"),
        result["enrichment"].get("malwarebazaar"),
    )
    result["score"] = scoring["score"]
    result["disposition"] = scoring["disposition"]
    result["reasons"] = scoring["reasons"]
    return result
