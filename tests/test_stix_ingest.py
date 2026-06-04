"""Tests for core.stix_ingest — runtime STIX bundle parsing for threat hunting."""
from __future__ import annotations

import json

import pytest

from core.stix_ingest import compose_hunt_task, is_valid_ioc, parse_stix, refang


def _bundle(objects: list[dict]) -> str:
    return json.dumps({"type": "bundle", "id": "bundle--x", "objects": objects})


def test_extracts_ip_domain_url_hash_iocs():
    objs = [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.100.7']"},
        {"type": "indicator", "pattern": "[domain-name:value = 'evil.example']"},
        {"type": "indicator", "pattern": "[url:value = 'http://evil.example/a']"},
        {"type": "indicator", "pattern": "[file:hashes.'SHA-256' = '" + "d" * 64 + "']"},
    ]
    brief = parse_stix(_bundle(objs))
    kinds = {i["type"] for i in brief["iocs"]}
    assert {"ip", "domain", "url", "hash"} <= kinds
    assert brief["counts"]["iocs"] == 4


def test_extracts_attack_pattern_ttps():
    objs = [
        {"type": "attack-pattern", "name": "OS Cred Dumping",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1003"}]},
        {"type": "attack-pattern", "name": "Cmd",
         "external_references": [{"source_name": "mitre-attack", "external_id": "T1059"}]},
    ]
    brief = parse_stix(_bundle(objs))
    assert brief["ttps"] == ["T1003", "T1059"]


def test_extracts_actor_and_malware_names():
    objs = [
        {"type": "intrusion-set", "name": "APT-Test"},
        {"type": "malware", "name": "EvilRAT"},
    ]
    brief = parse_stix(_bundle(objs))
    assert "APT-Test" in brief["actors"]
    assert "EvilRAT" in brief["malware"]


def test_dedupes_repeated_iocs():
    objs = [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '10.0.0.9']"},
        {"type": "indicator", "pattern": "[ipv4-addr:value = '10.0.0.9']"},
    ]
    brief = parse_stix(_bundle(objs))
    assert brief["counts"]["iocs"] == 1


def test_accepts_bare_object_list():
    objs = [{"type": "indicator", "pattern": "[domain-name:value = 'x.test']"}]
    brief = parse_stix(json.dumps(objs))
    assert brief["counts"]["iocs"] == 1


def test_malformed_objects_skipped_not_fatal():
    objs = ["not-a-dict", {"type": "indicator"}, {"type": "indicator", "pattern": "[ipv4-addr:value = '1.1.1.1']"}]
    brief = parse_stix(_bundle(objs))
    assert brief["counts"]["iocs"] == 1


def test_invalid_json_raises_valueerror():
    with pytest.raises(ValueError):
        parse_stix("{not json")


def test_no_objects_raises_valueerror():
    with pytest.raises(ValueError):
        parse_stix(json.dumps({"type": "bundle"}))


def test_compose_hunt_task_includes_iocs_and_ttps():
    brief = parse_stix(_bundle([
        {"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.5']"},
        {"type": "attack-pattern", "external_references": [{"source_name": "mitre-attack", "external_id": "T1071"}]},
        {"type": "intrusion-set", "name": "APT-Z"},
    ]))
    task = compose_hunt_task(brief)
    assert "203.0.113.5" in task
    assert "T1071" in task
    assert "APT-Z" in task


def test_compose_hunt_task_caps_ioc_list():
    objs = [{"type": "indicator", "pattern": f"[ipv4-addr:value = '10.0.0.{i}']"} for i in range(10)]
    brief = parse_stix(_bundle(objs))
    task = compose_hunt_task(brief, max_iocs=3)
    assert "and 7 more" in task


# ---------------------------------------------------------------------------
# refang() unit tests
# ---------------------------------------------------------------------------

def test_refang_dotted_brackets():
    assert refang("1[.]2[.]3[.]4") == "1.2.3.4"


def test_refang_hxxp_scheme_and_dotted_brackets():
    assert refang("hxxp://evil[.]com/x") == "http://evil.com/x"


def test_refang_hxxps_scheme():
    assert refang("hxxps://safe[.]example") == "https://safe.example"


def test_refang_paren_at_and_paren_dot():
    assert refang("bad(at)evil(dot)com") == "bad@evil.com"


def test_refang_space_dot_space():
    assert refang("example dot com") == "example.com"


def test_refang_space_at_space():
    assert refang("user at example dot com") == "user@example.com"


def test_refang_bracket_colon():
    assert refang("http[:]//example.com") == "http://example.com"


def test_refang_bracket_scheme():
    assert refang("http[://]example.com") == "http://example.com"


def test_refang_no_change_plain():
    assert refang("192.168.1.1") == "192.168.1.1"


# ---------------------------------------------------------------------------
# is_valid_ioc() unit tests
# ---------------------------------------------------------------------------

def test_is_valid_ioc_ip_valid_v4():
    assert is_valid_ioc("ip", "192.0.2.1") is True


def test_is_valid_ioc_ip_valid_v6():
    assert is_valid_ioc("ip", "2001:db8::1") is True


def test_is_valid_ioc_ip_invalid():
    assert is_valid_ioc("ip", "999.999.0.1") is False


def test_is_valid_ioc_ip_garbage():
    assert is_valid_ioc("ip", "not-an-ip") is False


def test_is_valid_ioc_hash_md5():
    assert is_valid_ioc("hash", "a" * 32) is True


def test_is_valid_ioc_hash_sha1():
    assert is_valid_ioc("hash", "b" * 40) is True


def test_is_valid_ioc_hash_sha256():
    assert is_valid_ioc("hash", "c" * 64) is True


def test_is_valid_ioc_hash_wrong_length():
    assert is_valid_ioc("hash", "a" * 10) is False


def test_is_valid_ioc_hash_non_hex():
    assert is_valid_ioc("hash", "z" * 32) is False


def test_is_valid_ioc_url_valid():
    assert is_valid_ioc("url", "https://evil.example/path") is True


def test_is_valid_ioc_url_no_scheme():
    assert is_valid_ioc("url", "evil.example/path") is False


def test_is_valid_ioc_url_empty_host():
    assert is_valid_ioc("url", "http:///path") is False


def test_is_valid_ioc_domain_valid():
    assert is_valid_ioc("domain", "evil.example.com") is True


def test_is_valid_ioc_domain_invalid_leading_hyphen():
    assert is_valid_ioc("domain", "-evil.example.com") is False


def test_is_valid_ioc_domain_no_tld():
    assert is_valid_ioc("domain", "localhost") is False


def test_is_valid_ioc_email_valid():
    assert is_valid_ioc("email", "user@evil.example.com") is True


def test_is_valid_ioc_email_missing_at():
    assert is_valid_ioc("email", "userevilexample.com") is False


def test_is_valid_ioc_mac_colon():
    assert is_valid_ioc("mac", "aa:bb:cc:dd:ee:ff") is True


def test_is_valid_ioc_mac_dash():
    assert is_valid_ioc("mac", "AA-BB-CC-DD-EE-FF") is True


def test_is_valid_ioc_mac_invalid():
    assert is_valid_ioc("mac", "zz:gg:hh:ii:jj:kk") is False


def test_is_valid_ioc_registry_passthrough():
    assert is_valid_ioc("registry", r"HKLM\Software\Bad") is True


def test_is_valid_ioc_unknown_type_passthrough():
    assert is_valid_ioc("unknown-thing", "whatever") is True


# ---------------------------------------------------------------------------
# Integration: refang + validation wired into parse_stix
# ---------------------------------------------------------------------------

def test_parse_stix_refangs_defanged_ip():
    """Defanged IP in indicator pattern is refanged and stored as plain IP."""
    objs = [{"type": "indicator", "pattern": "[ipv4-addr:value = '1[.]2[.]3[.]4']"}]
    brief = parse_stix(_bundle(objs))
    values = [i["value"] for i in brief["iocs"]]
    assert "1.2.3.4" in values
    assert not any("[" in v for v in values)


def test_parse_stix_drops_malformed_ip():
    """An indicator with a syntactically invalid IP is silently dropped."""
    objs = [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '999.999.0.1']"},
        {"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.5']"},
    ]
    brief = parse_stix(_bundle(objs))
    values = [i["value"] for i in brief["iocs"]]
    assert "203.0.113.5" in values
    assert "999.999.0.1" not in values
    assert brief["counts"]["iocs"] == 1


def test_parse_stix_defanged_and_plain_deduped():
    """Defanged + plain versions of the same IOC collapse to a single entry."""
    objs = [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '1[.]2[.]3[.]4']"},
        {"type": "indicator", "pattern": "[ipv4-addr:value = '1.2.3.4']"},
    ]
    brief = parse_stix(_bundle(objs))
    assert brief["counts"]["iocs"] == 1
    assert brief["iocs"][0]["value"] == "1.2.3.4"


def test_parse_stix_refangs_defanged_url():
    """hxxps indicator pattern is refanged to https."""
    objs = [{"type": "indicator", "pattern": "[url:value = 'hxxps://evil[.]example/c2']"}]
    brief = parse_stix(_bundle(objs))
    values = [i["value"] for i in brief["iocs"]]
    assert "https://evil.example/c2" in values


# ---------------------------------------------------------------------------
# Fix 1 — [at] / [dot] bracket-word refanging
# ---------------------------------------------------------------------------

def test_refang_bracket_at_dot():
    """[at] and [dot] bracket-word forms are converted to @ and . respectively."""
    assert refang("user[at]evil[dot]com") == "user@evil.com"


def test_parse_stix_bracket_at_dot_email_addr():
    """[at]/[dot] indicator survives parse_stix for an email-addr STIX object."""
    objs = [{"type": "indicator", "pattern": "[email-addr:value = 'user[at]evil[dot]com']"}]
    brief = parse_stix(_bundle(objs))
    values = [i["value"] for i in brief["iocs"]]
    assert "user@evil.com" in values
    assert brief["counts"]["iocs"] == 1


# ---------------------------------------------------------------------------
# Fix 3 — IPv6 canonicalization collapses equivalent forms to one IOC
# ---------------------------------------------------------------------------

def test_parse_stix_ipv6_canonical_dedup():
    """Expanded and compressed IPv6 representations collapse to a single IOC."""
    objs = [
        {"type": "indicator", "pattern": "[ipv6-addr:value = '2001:0db8:0000:0000:0000:0000:0000:0001']"},
        {"type": "indicator", "pattern": "[ipv6-addr:value = '2001:db8::1']"},
    ]
    brief = parse_stix(_bundle(objs))
    assert brief["counts"]["iocs"] == 1


# ---------------------------------------------------------------------------
# parse_ioc_list() + detect_ioc_type() tests
# ---------------------------------------------------------------------------

from core.stix_ingest import detect_ioc_type, parse_ioc_list  # noqa: E402


def test_detect_ioc_type_ip():
    assert detect_ioc_type("192.168.1.1") == "ip"


def test_detect_ioc_type_url():
    assert detect_ioc_type("http://evil.example/path") == "url"
    assert detect_ioc_type("https://evil.example/path") == "url"


def test_detect_ioc_type_hash_md5():
    assert detect_ioc_type("a" * 32) == "hash"


def test_detect_ioc_type_hash_sha1():
    assert detect_ioc_type("b" * 40) == "hash"


def test_detect_ioc_type_hash_sha256():
    assert detect_ioc_type("c" * 64) == "hash"


def test_detect_ioc_type_email():
    assert detect_ioc_type("user@evil.example.com") == "email"


def test_detect_ioc_type_domain():
    assert detect_ioc_type("evil.example.com") == "domain"


def test_detect_ioc_type_unknown():
    assert detect_ioc_type("not-an-ioc") is None
    assert detect_ioc_type("999.999.0.1") is None


def test_parse_ioc_list_mixed_types():
    """All five IOC types detected from a mixed newline list."""
    content = "\n".join([
        "198.51.100.1",
        "https://evil.example/c2",
        "d" * 64,
        "attacker@evil.example.com",
        "evil.example.com",
    ])
    brief = parse_ioc_list(content)
    types = {ioc["type"] for ioc in brief["iocs"]}
    assert types == {"ip", "url", "hash", "email", "domain"}
    assert brief["counts"]["iocs"] == 5
    assert brief["counts"]["ttps"] == 0
    assert brief["counts"]["actors"] == 0
    assert brief["counts"]["malware"] == 0
    assert brief["ttps"] == []
    assert brief["actors"] == []
    assert brief["malware"] == []


def test_parse_ioc_list_skips_blanks_and_comments():
    content = "\n".join([
        "",
        "# this is a comment",
        "10.0.0.1",
        "",
        "# another comment",
        "evil.example.org",
    ])
    brief = parse_ioc_list(content)
    assert brief["counts"]["iocs"] == 2


def test_parse_ioc_list_csv_first_field():
    """CSV line: first non-empty comma-separated field is used as IOC."""
    content = "1.2.3.4,first-seen,2024"
    brief = parse_ioc_list(content)
    values = [ioc["value"] for ioc in brief["iocs"]]
    assert "1.2.3.4" in values


def test_parse_ioc_list_csv_header_skipped():
    """A CSV header line (contains ioc/indicator/value/type) is skipped."""
    content = "\n".join([
        "value,note",
        "10.0.0.1,some note",
        "evil.example.org,another note",
    ])
    brief = parse_ioc_list(content)
    values = [ioc["value"] for ioc in brief["iocs"]]
    assert "10.0.0.1" in values
    assert "evil.example.org" in values
    # The header row itself must not appear as an IOC value
    assert "value" not in values


def test_parse_ioc_list_defanged_entry_refanged():
    """Defanged domain evil[.]com is refanged to evil.com."""
    content = "evil[.]com"
    brief = parse_ioc_list(content)
    values = [ioc["value"] for ioc in brief["iocs"]]
    assert "evil.com" in values


def test_parse_ioc_list_malformed_ip_dropped():
    """999.999.0.1 fails validation and is silently dropped."""
    content = "\n".join(["999.999.0.1", "10.0.0.1"])
    brief = parse_ioc_list(content)
    values = [ioc["value"] for ioc in brief["iocs"]]
    assert "999.999.0.1" not in values
    assert "10.0.0.1" in values
    assert brief["counts"]["iocs"] == 1


def test_parse_ioc_list_dedup():
    """Duplicate (type, value) pairs collapsed to one entry."""
    content = "\n".join(["10.0.0.1", "10.0.0.1"])
    brief = parse_ioc_list(content)
    assert brief["counts"]["iocs"] == 1


def test_parse_ioc_list_empty_raises():
    with pytest.raises(ValueError, match="no valid IOCs found"):
        parse_ioc_list("")


def test_parse_ioc_list_all_invalid_raises():
    with pytest.raises(ValueError, match="no valid IOCs found"):
        parse_ioc_list("# only a comment\n\n999.999.0.1")
