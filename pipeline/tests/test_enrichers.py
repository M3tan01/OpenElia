"""Unit tests for the pure (no-network) enricher surface."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import enrichers  # noqa: E402


def test_classify_ioc_types():
    assert enrichers.classify_ioc("185.220.101.42") == "ipv4"
    assert enrichers.classify_ioc("evil-domain.com") == "domain"
    assert enrichers.classify_ioc("http://x.com/a.exe") == "url"
    assert enrichers.classify_ioc("a@b.com") == "email"
    assert enrichers.classify_ioc("e" * 64) == "sha256"
    assert enrichers.classify_ioc("a" * 40) == "sha1"
    assert enrichers.classify_ioc("b" * 32) == "md5"
    assert enrichers.classify_ioc("???") == "unknown"


def test_defang_refang_roundtrip():
    original = "http://malicious-site.com/payload.exe"
    defanged = enrichers.defang_ioc(original)
    assert "hxxp://" in defanged and "[.]" in defanged
    assert enrichers.refang_ioc(defanged) == original


def test_is_private_ip():
    assert enrichers.is_private_ip("192.168.1.100")
    assert enrichers.is_private_ip("10.0.0.5")
    assert enrichers.is_private_ip("172.16.0.1")
    assert enrichers.is_private_ip("127.0.0.1")
    assert not enrichers.is_private_ip("185.220.101.42")


def test_score_ioc_dispositions():
    assert enrichers.score_ioc({"malicious": 20})["disposition"] == "MONITOR"
    block = enrichers.score_ioc({"malicious": 20}, {"abuse_confidence": 80})
    assert block["disposition"] == "BLOCK"
    assert block["score"] >= 70
    assert enrichers.score_ioc()["disposition"] == "INVESTIGATE"


def test_enrich_ioc_private_skips_network():
    rec = enrichers.enrich_ioc("192.168.1.100", live=True)
    assert rec["type"] == "ipv4"
    assert "private" in rec["note"].lower()
    assert rec["disposition"] == "INVESTIGATE"
    assert rec["enrichment"] == {}


def test_enrich_ioc_mock_offline_shape():
    rec = enrichers.enrich_ioc("evil-domain.com", live=False)
    for field in ("ioc", "type", "defanged", "enrichment", "timestamp",
                  "score", "disposition", "reasons"):
        assert field in rec
    assert rec["enrichment"] == {}  # offline = no network calls
