"""
tests/test_security.py — Unit tests for security components.

Covers: PrivacyGuard PII redaction (including new patterns), ScopeValidator,
adversary_manager path traversal prevention, and artifact_manager filename sanitization.
"""
import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from security_manager import PrivacyGuard, ScopeValidator
from adversary_manager import AdversaryManager


# ---------------------------------------------------------------------------
# PrivacyGuard — existing patterns
# ---------------------------------------------------------------------------

class TestPrivacyGuardExisting:
    def test_redacts_email(self):
        result = PrivacyGuard.redact("Contact admin@corp.com for access")
        assert "admin@corp.com" not in result
        assert "[REDACTED_EMAIL]" in result

    def test_redacts_private_key(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nABCDEF==\n-----END RSA PRIVATE KEY-----"
        result = PrivacyGuard.redact(pem)
        assert "ABCDEF" not in result

    def test_redacts_ssn(self):
        result = PrivacyGuard.redact("SSN: 123-45-6789")
        assert "123-45-6789" not in result
        assert "[REDACTED_SSN]" in result

    def test_benign_text_unchanged(self):
        text = "nmap scan completed on 10.0.0.1 port 80"
        assert PrivacyGuard.redact(text) == text

    def test_recursive_dict_redaction(self):
        data = {"email": "test@example.com", "host": "10.0.0.1"}
        result = PrivacyGuard.redact(data)
        assert "test@example.com" not in result["email"]
        assert result["host"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# PrivacyGuard — new patterns (T1)
# ---------------------------------------------------------------------------

class TestPrivacyGuardNewPatterns:
    def test_redacts_aws_access_key(self):
        result = PrivacyGuard.redact("key=AKIAIOSFODNN7EXAMPLE")
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_redacts_bearer_token(self):
        result = PrivacyGuard.redact("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig")
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result

    def test_redacts_db_connection_string(self):
        result = PrivacyGuard.redact("dsn=postgresql://user:pass@db.corp.com:5432/prod")
        assert "user:pass@db.corp.com" not in result

    def test_redacts_slack_webhook(self):
        url = "https://hooks.slack.com/services/T01234567/B01234567/AbcDefGhiJklMnoPqr"
        result = PrivacyGuard.redact(url)
        assert "AbcDefGhiJklMnoPqr" not in result

    def test_redacts_anthropic_key(self):
        result = PrivacyGuard.redact("api_key=sk-ant-api03-AAABBBCCCDDDEEEFFFGGG")
        assert "sk-ant-api03-AAABBBCCCDDDEEEFFFGGG" not in result


# ---------------------------------------------------------------------------
# ScopeValidator
# ---------------------------------------------------------------------------

class TestScopeValidator:
    def test_no_roe_file_blocks_all(self, tmp_path):
        sv = ScopeValidator(roe_path=str(tmp_path / "missing.json"))
        assert sv.is_allowed("10.0.0.1") is False

    def test_authorized_ip_allowed(self, tmp_path):
        roe = tmp_path / "roe.json"
        roe.write_text('{"authorized_subnets": ["10.0.0.0/24"], "blacklisted_ips": []}')
        sv = ScopeValidator(roe_path=str(roe))
        assert sv.is_allowed("10.0.0.50") is True

    def test_out_of_scope_ip_blocked(self, tmp_path):
        roe = tmp_path / "roe.json"
        roe.write_text('{"authorized_subnets": ["10.0.0.0/24"], "blacklisted_ips": []}')
        sv = ScopeValidator(roe_path=str(roe))
        assert sv.is_allowed("192.168.1.1") is False

    def test_blacklisted_ip_blocked(self, tmp_path):
        roe = tmp_path / "roe.json"
        roe.write_text('{"authorized_subnets": ["10.0.0.0/24"], "blacklisted_ips": ["10.0.0.1"]}')
        sv = ScopeValidator(roe_path=str(roe))
        assert sv.is_allowed("10.0.0.1") is False

    def test_invalid_json_blocks_all(self, tmp_path):
        roe = tmp_path / "roe.json"
        roe.write_text("{not valid json}")
        sv = ScopeValidator(roe_path=str(roe))
        assert sv.is_allowed("10.0.0.1") is False


# ---------------------------------------------------------------------------
# AdversaryManager — path traversal prevention (C4)
# ---------------------------------------------------------------------------

class TestAdversaryManagerSecurity:
    def test_valid_name_loads_or_returns_empty(self, tmp_path):
        am = AdversaryManager(adversaries_dir=str(tmp_path))
        result = am.load_profile("apt29")
        assert isinstance(result, dict)

    def test_path_traversal_raises(self, tmp_path):
        am = AdversaryManager(adversaries_dir=str(tmp_path))
        with pytest.raises(ValueError):
            am.load_profile("../etc/passwd")

    def test_dotdot_in_name_raises(self, tmp_path):
        am = AdversaryManager(adversaries_dir=str(tmp_path))
        with pytest.raises(ValueError):
            am.load_profile("..%2Fetc%2Fpasswd")

    def test_special_chars_raise(self, tmp_path):
        am = AdversaryManager(adversaries_dir=str(tmp_path))
        with pytest.raises(ValueError):
            am.load_profile("apt29; rm -rf /")

    def test_name_too_long_raises(self, tmp_path):
        am = AdversaryManager(adversaries_dir=str(tmp_path))
        with pytest.raises(ValueError):
            am.load_profile("a" * 33)

    def test_valid_profile_loaded(self, tmp_path):
        import json
        profile = {"name": "APT29", "alias": "Cozy Bear", "description": "test",
                   "rationale": "espionage", "preferred_ttps": ["T1078"], "tools": ["mimikatz"]}
        (tmp_path / "apt29.json").write_text(json.dumps(profile))
        am = AdversaryManager(adversaries_dir=str(tmp_path))
        result = am.load_profile("APT29")
        assert result["name"] == "APT29"


# ---------------------------------------------------------------------------
# AuditLogger — delegates to core.audit_chain
# ---------------------------------------------------------------------------

from unittest.mock import patch
from security_manager import AuditLogger


class TestAuditLogger:
    def _make_logger(self, tmp_path):
        return AuditLogger(log_path=str(tmp_path / "audit.log"))

    def test_log_event_creates_file(self, tmp_path):
        logger = self._make_logger(tmp_path)
        logger.log_event("agent", "10.0.0.1", "nmap scan", "ALLOWED")
        assert (tmp_path / "audit.log").exists()

    def test_log_event_record_has_chain_hash(self, tmp_path):
        import json
        logger = self._make_logger(tmp_path)
        logger.log_event("agent", "10.0.0.1", "nmap scan", "ALLOWED", "scope ok")
        entry = json.loads((tmp_path / "audit.log").read_text().strip())
        assert "chain_hash" in entry
        assert len(entry["chain_hash"]) == 64

    def test_log_event_redacts_pii(self, tmp_path):
        import json
        logger = self._make_logger(tmp_path)
        logger.log_event("agent", "10.0.0.1", "user admin@corp.com accessed", "ALLOWED")
        entry = json.loads((tmp_path / "audit.log").read_text().strip())
        assert "admin@corp.com" not in entry["payload"]
        assert "[REDACTED_EMAIL]" in entry["payload"]

    def test_verify_chain_clean(self, tmp_path):
        logger = self._make_logger(tmp_path)
        logger.log_event("a", "t", "p", "ALLOWED")
        logger.log_event("a", "t", "p2", "BLOCKED")
        assert logger.verify_chain() is True

    def test_verify_chain_detects_tamper(self, tmp_path):
        import json
        logger = self._make_logger(tmp_path)
        logger.log_event("a", "t", "p", "ALLOWED")
        log = tmp_path / "audit.log"
        entry = json.loads(log.read_text().strip())
        entry["status"] = "BLOCKED"
        log.write_text(json.dumps(entry) + "\n")
        assert logger.verify_chain() is False

    def test_log_event_raises_on_unwritable_path(self, tmp_path):
        log = tmp_path / "sub" / "audit.log"
        # Make parent a file so mkdir fails
        (tmp_path / "sub").write_text("not a dir")
        logger = AuditLogger(log_path=str(log))
        with pytest.raises(RuntimeError, match="AUDIT FAILURE"):
            logger.log_event("a", "t", "p", "ALLOWED")
