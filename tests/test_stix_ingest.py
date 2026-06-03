"""Tests for core.stix_ingest — runtime STIX bundle parsing for threat hunting."""
from __future__ import annotations

import json

import pytest

from core.stix_ingest import compose_hunt_task, parse_stix


def _bundle(objects: list[dict]) -> str:
    return json.dumps({"type": "bundle", "id": "bundle--x", "objects": objects})


def test_extracts_ip_domain_url_hash_iocs():
    objs = [
        {"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.100.7']"},
        {"type": "indicator", "pattern": "[domain-name:value = 'evil.example']"},
        {"type": "indicator", "pattern": "[url:value = 'http://evil.example/a']"},
        {"type": "indicator", "pattern": "[file:hashes.'SHA-256' = 'deadbeef']"},
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
