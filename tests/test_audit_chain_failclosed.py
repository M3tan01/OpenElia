"""
tests/test_audit_chain_failclosed.py — fail-closed HMAC key derivation +
tamper-detection coverage.

The audit chain must refuse to sign with the forgeable public fallback key
when AUDIT_HMAC_KEY is unset, unless the operator explicitly opts in via
OPENELIA_ALLOW_INSECURE_AUDIT_KEY=1. This file deliberately does NOT use the
fixed_key fixture from test_audit_chain.py so it exercises the real _hmac_key().

TestChainTamperDetection then proves the HMAC chain actually detects the tamper
classes it claims to: mid-chain content mutation, record reorder, verification
under the wrong key, and a stripped chain_hash. It also documents the ONE class
the hash chain cannot detect on its own — trailing-record truncation — so no one
mistakes that gap for coverage.
"""
import json

import pytest

import core.audit_chain as ac
import secret_store


def _no_secret(monkeypatch):
    # audit_chain imports SecretStore lazily from the secret_store module, so
    # patch the class there (ac has no SecretStore attribute at module level).
    monkeypatch.setattr(secret_store.SecretStore, "get_secret", staticmethod(lambda k: None))


class TestHmacKeyFailClosed:
    def test_raises_when_key_unset_and_no_optin(self, monkeypatch):
        """No key + no opt-in → RuntimeError, not a silent forgeable fallback."""
        monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
        monkeypatch.delenv("OPENELIA_ALLOW_INSECURE_AUDIT_KEY", raising=False)
        _no_secret(monkeypatch)
        with pytest.raises(RuntimeError, match="AUDIT_HMAC_KEY is not set"):
            ac._hmac_key()

    def test_append_raises_when_key_unset(self, tmp_path, monkeypatch):
        """The fail-closed contract must propagate through the public append()."""
        monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
        monkeypatch.delenv("OPENELIA_ALLOW_INSECURE_AUDIT_KEY", raising=False)
        _no_secret(monkeypatch)
        with pytest.raises(RuntimeError, match="AUDIT_HMAC_KEY is not set"):
            ac.append(tmp_path / "audit.log", {"event": "should-not-write"})

    def test_uses_key_when_set(self, monkeypatch):
        monkeypatch.setattr(secret_store.SecretStore, "get_secret", staticmethod(lambda k: "real-key"))
        assert ac._hmac_key() == b"real-key"

    def test_fallback_only_with_explicit_optin(self, monkeypatch):
        """The insecure fallback is reachable ONLY behind the explicit danger flag."""
        monkeypatch.delenv("AUDIT_HMAC_KEY", raising=False)
        monkeypatch.setenv("OPENELIA_ALLOW_INSECURE_AUDIT_KEY", "1")
        _no_secret(monkeypatch)
        assert ac._hmac_key() == ac._FALLBACK_KEY


def _use_key(monkeypatch, key: str):
    """Pin _hmac_key() to a deterministic value for the current phase."""
    monkeypatch.setattr(
        secret_store.SecretStore, "get_secret", staticmethod(lambda k: key)
    )


def _seed_chain(path, n=3):
    """Append n well-formed records and return their chain_hashes."""
    return [ac.append(path, {"event": "op", "seq": i, "target": "10.0.0.5"})
            for i in range(n)]


class TestChainTamperDetection:
    """The HMAC chain's whole point is detecting after-the-fact edits. These
    tests exercise each tamper class end-to-end: write a real chain via
    ac.append, corrupt the on-disk log, then assert ac.verify flags it.

    conftest's autouse fixture supplies AUDIT_HMAC_KEY, so the default path
    signs and verifies under one real key; the wrong-key test overrides it.
    """

    def test_midchain_content_mutation_detected(self, tmp_path, monkeypatch):
        """Editing a record's content (keeping its stored hash) breaks that line."""
        path = tmp_path / "audit.log"
        _seed_chain(path, 3)

        lines = path.read_text().splitlines()
        rec = json.loads(lines[1])
        rec["target"] = "8.8.8.8"          # attacker rewrites the target, keeps chain_hash
        lines[1] = json.dumps(rec, sort_keys=True)
        path.write_text("\n".join(lines) + "\n")

        ok, reason = ac.verify(path)
        assert ok is False
        assert "Line 2" in reason and "mismatch" in reason

    def test_record_reorder_detected(self, tmp_path, monkeypatch):
        """Swapping two records breaks the chain — each hash binds its predecessor."""
        path = tmp_path / "audit.log"
        _seed_chain(path, 3)

        lines = path.read_text().splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        path.write_text("\n".join(lines) + "\n")

        ok, reason = ac.verify(path)
        assert ok is False
        assert "Line 1" in reason and "mismatch" in reason

    def test_wrong_key_fails_verification(self, tmp_path, monkeypatch):
        """A log signed under key A does not verify under key B — from line 1."""
        path = tmp_path / "audit.log"
        _use_key(monkeypatch, "key-A-original")
        _seed_chain(path, 3)

        _use_key(monkeypatch, "key-B-attacker")
        ok, reason = ac.verify(path)
        assert ok is False
        assert "Line 1" in reason and "mismatch" in reason

    def test_stripped_chain_hash_detected(self, tmp_path, monkeypatch):
        """A record with its chain_hash field removed is rejected, not skipped."""
        path = tmp_path / "audit.log"
        _seed_chain(path, 2)

        lines = path.read_text().splitlines()
        rec = json.loads(lines[1])
        rec.pop("chain_hash")
        lines[1] = json.dumps(rec, sort_keys=True)
        path.write_text("\n".join(lines) + "\n")

        ok, reason = ac.verify(path)
        assert ok is False
        assert "missing chain_hash" in reason

    def test_trailing_truncation_is_UNDETECTABLE(self, tmp_path, monkeypatch):
        """DOCUMENTED LIMITATION — not a passing feature.

        A bare hash chain cannot detect that trailing records were lopped off:
        the remaining prefix is still a valid chain from genesis. verify()
        therefore returns OK on a truncated log. Detecting this needs an
        out-of-band signed head/length anchor (e.g. periodically signing the
        latest chain_hash + record count to a separate store). This test pins
        the gap so a future reader does not mistake it for coverage.
        """
        path = tmp_path / "audit.log"
        _seed_chain(path, 3)

        lines = path.read_text().splitlines()
        path.write_text("\n".join(lines[:-1]) + "\n")   # drop the last record

        ok, reason = ac.verify(path)
        assert ok is True                                # <-- the gap, asserted intentionally
        assert reason == "OK"
