"""Unit tests for core/archive.py — the data-returning case-archive builder.

build_case_archive() is the shared core the CLI `archive` command and the
webdash POST /api/archive route both call. It is pure of the ReporterAgent
synthesis run and of stdout: it zips engagement state + artifacts and returns
metadata (archive path, sha256, engagement id).
"""

from __future__ import annotations

import hashlib
import os
import zipfile

from core.archive import build_case_archive


def test_build_case_archive_returns_metadata_and_packages_state(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / "engagement.db").write_bytes(b"sqlite-bytes")
    (state_dir / "audit.log").write_text("audit line\n")
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    (artifacts_dir / "loot.txt").write_text("evidence")
    (artifacts_dir / ".gitkeep").write_text("")

    state = {"engagement": {"id": "ENG-123", "target": "10.0.0.5"}}
    result = build_case_archive(
        state, state_dir=str(state_dir), artifacts_dir=str(artifacts_dir)
    )

    assert result["engagement_id"] == "ENG-123"
    assert os.path.exists(result["archive_path"])
    assert len(result["sha256"]) == 64

    with zipfile.ZipFile(result["archive_path"]) as z:
        names = z.namelist()
    assert "engagement.db" in names
    assert "audit.log" in names
    assert "Case_Summary.md" in names
    assert os.path.join("evidence", "loot.txt") in names
    # .gitkeep placeholder is excluded from the evidence bundle
    assert not any(".gitkeep" in n for n in names)


def test_build_case_archive_sha256_matches_written_file(tmp_path):
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / "engagement.db").write_bytes(b"x")

    state = {"engagement": {"id": "E1", "target": "t"}}
    result = build_case_archive(
        state, state_dir=str(state_dir), artifacts_dir=str(tmp_path / "absent")
    )

    h = hashlib.sha256()
    with open(result["archive_path"], "rb") as f:
        h.update(f.read())
    assert result["sha256"] == h.hexdigest()


def test_build_case_archive_tolerates_missing_optional_files(tmp_path):
    """No audit.log / bom.json / artifacts dir — still produces a valid archive."""
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / "engagement.db").write_bytes(b"only-db")

    state = {"engagement": {"id": "E2", "target": "t"}}
    result = build_case_archive(
        state, state_dir=str(state_dir), artifacts_dir=str(tmp_path / "absent")
    )

    with zipfile.ZipFile(result["archive_path"]) as z:
        names = z.namelist()
    assert "engagement.db" in names
    assert "Case_Summary.md" in names
    assert "audit.log" not in names
