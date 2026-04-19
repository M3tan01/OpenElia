"""
tests/test_rbac_manager.py — RBAC sign/verify IdP session and RBACManager.

Covers: sign_idp_session adds _sig, verify_idp_session accepts valid,
        verify_idp_session rejects tampered, is_os_admin returns bool,
        verify_idp_claims with missing/present/tampered session files.
"""
import json
import pytest
from unittest.mock import patch, MagicMock

# Stub out SecretStore keyring calls before importing rbac_manager
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


@pytest.fixture(autouse=True)
def stub_keyring(monkeypatch):
    """Prevent real keyring calls; return a deterministic HMAC key."""
    _KEY = "test-rbac-hmac-key-1234567890abcdef"
    monkeypatch.setenv("IDP_HMAC_KEY", _KEY)
    with patch("rbac_manager._get_hmac_key", return_value=_KEY.encode()):
        yield


from rbac_manager import sign_idp_session, verify_idp_session, RBACManager


# ---------------------------------------------------------------------------
# sign / verify
# ---------------------------------------------------------------------------

class TestSignVerify:
    def test_sign_adds_sig_field(self):
        claims = {"user": "alice", "roles": ["admin"]}
        signed = sign_idp_session(claims)
        assert "_sig" in signed
        assert len(signed["_sig"]) == 64  # SHA-256 hex

    def test_sign_does_not_mutate_original(self):
        claims = {"user": "alice", "roles": ["admin"]}
        sign_idp_session(claims)
        assert "_sig" not in claims

    def test_verify_valid_session_returns_true(self):
        claims = {"user": "alice", "roles": ["admin"]}
        signed = sign_idp_session(claims)
        assert verify_idp_session(signed) is True

    def test_verify_tampered_field_returns_false(self):
        signed = sign_idp_session({"user": "alice", "roles": ["viewer"]})
        signed["roles"] = ["admin"]  # tamper
        assert verify_idp_session(signed) is False

    def test_verify_missing_sig_returns_false(self):
        assert verify_idp_session({"user": "alice", "roles": ["admin"]}) is False

    def test_verify_empty_dict_returns_false(self):
        assert verify_idp_session({}) is False


# ---------------------------------------------------------------------------
# RBACManager.is_os_admin
# ---------------------------------------------------------------------------

class TestIsOsAdmin:
    def test_returns_bool(self):
        result = RBACManager.is_os_admin()
        assert isinstance(result, bool)

    def test_non_root_returns_false(self):
        with patch("os.getuid", return_value=1000):
            assert RBACManager.is_os_admin() is False


# ---------------------------------------------------------------------------
# RBACManager.verify_idp_claims
# ---------------------------------------------------------------------------

class TestVerifyIdpClaims:
    def test_no_session_file_returns_false(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        assert RBACManager.verify_idp_claims(["admin"]) is False

    def test_valid_session_with_matching_role_returns_true(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "state").mkdir()
        claims = sign_idp_session({"user": "bob", "roles": ["admin"]})
        (tmp_path / "state" / "idp_session.json").write_text(json.dumps(claims))
        assert RBACManager.verify_idp_claims(["admin"]) is True

    def test_valid_session_without_required_role_returns_false(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "state").mkdir()
        claims = sign_idp_session({"user": "bob", "roles": ["viewer"]})
        (tmp_path / "state" / "idp_session.json").write_text(json.dumps(claims))
        assert RBACManager.verify_idp_claims(["admin"]) is False

    def test_tampered_session_returns_false(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "state").mkdir()
        claims = sign_idp_session({"user": "bob", "roles": ["viewer"]})
        claims["roles"] = ["admin"]  # tamper after signing
        (tmp_path / "state" / "idp_session.json").write_text(json.dumps(claims))
        assert RBACManager.verify_idp_claims(["admin"]) is False

    def test_invalid_json_returns_false(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / "state").mkdir()
        (tmp_path / "state" / "idp_session.json").write_text("{not valid json")
        assert RBACManager.verify_idp_claims(["admin"]) is False
