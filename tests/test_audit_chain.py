"""
tests/test_audit_chain.py — HMAC-SHA256 tamper-evident audit chain.

Covers: append creates file, chain_hash present, chain verifies OK,
        single-entry tamper detected, mid-chain tamper detected,
        missing chain_hash detected.
"""
import json
import pytest
from pathlib import Path
from unittest.mock import patch

# Use a fixed key so tests are deterministic and independent of SecretStore
_TEST_KEY = b"test-hmac-key-for-unit-tests-only"


@pytest.fixture(autouse=True)
def fixed_key(monkeypatch):
    """Pin the HMAC key for all tests in this module."""
    monkeypatch.setattr("core.audit_chain._hmac_key", lambda: _TEST_KEY)


from core.audit_chain import append, verify


# ---------------------------------------------------------------------------
# append()
# ---------------------------------------------------------------------------

class TestAppend:
    def test_creates_file(self, tmp_path):
        log = tmp_path / "audit.log"
        append(log, {"event": "test"})
        assert log.exists()

    def test_record_contains_chain_hash(self, tmp_path):
        log = tmp_path / "audit.log"
        append(log, {"event": "test"})
        entry = json.loads(log.read_text().strip())
        assert "chain_hash" in entry
        assert len(entry["chain_hash"]) == 64  # SHA-256 hex digest

    def test_chain_hash_not_in_original_record(self, tmp_path):
        log = tmp_path / "audit.log"
        record = {"task_id": "abc", "status": "success"}
        append(log, record)
        # Original dict is not mutated
        assert "chain_hash" not in record

    def test_multiple_entries_have_different_hashes(self, tmp_path):
        log = tmp_path / "audit.log"
        append(log, {"event": "first"})
        append(log, {"event": "second"})
        lines = [json.loads(l) for l in log.read_text().strip().splitlines()]
        assert lines[0]["chain_hash"] != lines[1]["chain_hash"]

    def test_creates_parent_dirs(self, tmp_path):
        log = tmp_path / "deep" / "nested" / "audit.log"
        append(log, {"x": 1})
        assert log.exists()


# ---------------------------------------------------------------------------
# verify() — clean chain
# ---------------------------------------------------------------------------

class TestVerifyClean:
    def test_empty_log_ok(self, tmp_path):
        log = tmp_path / "audit.log"
        ok, msg = verify(log)
        assert ok
        assert "OK" in msg

    def test_nonexistent_file_ok(self, tmp_path):
        ok, msg = verify(tmp_path / "missing.log")
        assert ok

    def test_single_entry_verifies(self, tmp_path):
        log = tmp_path / "audit.log"
        append(log, {"event": "boot"})
        ok, msg = verify(log)
        assert ok, msg

    def test_ten_entries_verify(self, tmp_path):
        log = tmp_path / "audit.log"
        for i in range(10):
            append(log, {"seq": i, "data": f"record-{i}"})
        ok, msg = verify(log)
        assert ok, msg


# ---------------------------------------------------------------------------
# verify() — tamper detection
# ---------------------------------------------------------------------------

class TestVerifyTampered:
    def test_modified_field_detected(self, tmp_path):
        log = tmp_path / "audit.log"
        append(log, {"task_id": "t1", "status": "success"})
        append(log, {"task_id": "t2", "status": "success"})

        # Tamper: change status of first entry
        lines = log.read_text().splitlines()
        entry = json.loads(lines[0])
        entry["status"] = "error"          # flip to something else
        lines[0] = json.dumps(entry)
        log.write_text("\n".join(lines) + "\n")

        ok, msg = verify(log)
        assert not ok
        assert "tampered" in msg.lower() or "mismatch" in msg.lower()

    def test_deleted_entry_breaks_chain(self, tmp_path):
        log = tmp_path / "audit.log"
        for i in range(3):
            append(log, {"seq": i})

        # Remove the middle entry
        lines = log.read_text().splitlines()
        del lines[1]
        log.write_text("\n".join(lines) + "\n")

        ok, msg = verify(log)
        assert not ok

    def test_missing_chain_hash_detected(self, tmp_path):
        log = tmp_path / "audit.log"
        append(log, {"event": "a"})

        # Strip the chain_hash from the entry
        entry = json.loads(log.read_text().strip())
        del entry["chain_hash"]
        log.write_text(json.dumps(entry) + "\n")

        ok, msg = verify(log)
        assert not ok
        assert "missing" in msg.lower()

    def test_injected_entry_breaks_chain(self, tmp_path):
        log = tmp_path / "audit.log"
        append(log, {"seq": 0})
        append(log, {"seq": 2})

        # Inject a fabricated entry in the middle (without valid chain_hash)
        lines = log.read_text().splitlines()
        fake = json.dumps({"seq": 1, "chain_hash": "a" * 64})
        lines.insert(1, fake)
        log.write_text("\n".join(lines) + "\n")

        ok, msg = verify(log)
        assert not ok
