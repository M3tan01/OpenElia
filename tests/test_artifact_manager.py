"""
tests/test_artifact_manager.py — ArtifactManager store, retrieve, chain of custody.

Covers: store_artifact creates encrypted file, SHA-256 in CoC, path traversal
        in filename is stripped, get_chain_of_custody returns entries,
        audit log written per store, list_artifacts reflects stored files.
"""
import hashlib
import json
import os
import pytest
from pathlib import Path
from unittest.mock import patch
from cryptography.fernet import Fernet


@pytest.fixture()
def fernet_key():
    return Fernet.generate_key().decode()


@pytest.fixture()
def manager(tmp_path, fernet_key):
    """ArtifactManager with all external deps stubbed."""
    with patch("artifact_manager.SecretStore") as mock_ss, \
         patch("secret_store.SecretStore") as mock_ss2:
        mock_ss.get_secret.return_value = fernet_key
        mock_ss.set_secret.return_value = None
        yield _make_manager(tmp_path, fernet_key)


def _make_manager(tmp_path, fernet_key):
    from cryptography.fernet import Fernet as _Fernet
    with patch("artifact_manager.SecretStore") as mock_ss:
        mock_ss.get_secret.return_value = fernet_key
        mock_ss.set_secret.return_value = None
        from artifact_manager import ArtifactManager
        return ArtifactManager(
            base_dir=str(tmp_path / "artifacts"),
            audit_log_path=str(tmp_path / "audit.log"),
            db_path=str(tmp_path / "forensic.db"),
        )


@pytest.fixture()
def am(tmp_path, fernet_key):
    return _make_manager(tmp_path, fernet_key)


class TestStoreArtifact:
    def test_creates_encrypted_file(self, am, tmp_path):
        result = am.store_artifact("agent_recon", "scan.txt", "nmap output here")
        assert os.path.exists(result["path"])

    def test_stored_file_is_not_plaintext(self, am, fernet_key):
        result = am.store_artifact("agent_recon", "scan.txt", "sensitive data")
        raw = open(result["path"], "rb").read()
        assert b"sensitive data" not in raw

    def test_returns_correct_sha256(self, am):
        content = "hello artifact"
        result = am.store_artifact("agent_recon", "hello.txt", content)
        expected = hashlib.sha256(content.encode()).hexdigest()
        assert result["sha256"] == expected

    def test_path_traversal_in_filename_is_stripped(self, am):
        result = am.store_artifact("agent", "../../../etc/passwd", "evil")
        # The stored filename must not contain directory components
        stored_filename = os.path.basename(result["path"])
        assert "etc" not in stored_filename
        assert ".." not in stored_filename

    def test_status_is_stored(self, am):
        result = am.store_artifact("agent_recon", "scan.txt", "data")
        assert result["status"] == "stored"


class TestChainOfCustody:
    def test_empty_on_init(self, am):
        assert am.get_chain_of_custody() == []

    def test_entry_added_after_store(self, am):
        am.store_artifact("agent_recon", "scan.txt", "data")
        coc = am.get_chain_of_custody()
        assert len(coc) == 1

    def test_coc_entry_has_expected_fields(self, am):
        am.store_artifact("agent_recon", "scan.txt", "data", metadata={"target": "10.0.0.1"})
        entry = am.get_chain_of_custody()[0]
        assert entry["source_agent"] == "agent_recon"
        assert entry["status"] == "ACQUIRED"
        assert len(entry["sha256"]) == 64

    def test_multiple_artifacts_all_appear(self, am):
        am.store_artifact("recon", "a.txt", "aaa")
        am.store_artifact("exploit", "b.txt", "bbb")
        assert len(am.get_chain_of_custody()) == 2


class TestAuditLog:
    def test_store_writes_to_audit_log(self, am, tmp_path):
        am.store_artifact("agent", "scan.txt", "data")
        log = tmp_path / "audit.log"
        assert log.exists()
        entry = json.loads(log.read_text().strip().splitlines()[0])
        assert "chain_hash" in entry  # core.audit_chain format


class TestListArtifacts:
    def test_lists_stored_files(self, am):
        am.store_artifact("agent", "a.txt", "aaa")
        am.store_artifact("agent", "b.txt", "bbb")
        listing = am.list_artifacts()
        assert len(listing) == 2
