"""core/archive.py — engagement case-archive builder, data-returning core.

`build_case_archive()` packages the engagement state files and recovered
artifacts into a single forensic zip and returns metadata (path, SHA-256,
engagement id). It is pure of the ReporterAgent synthesis run and of stdout:
the caller supplies the already-generated `summary` text, and presentation
(printing, HTTP serialization) stays in the CLI / route.

The CLI (`main.py cmd_archive`) and the webdash `POST /api/archive` route both
call this with their own `state_dir`, so the same logic packages the correct
(env-configured / test tmp) directory rather than a hardcoded `state/`.
"""

from __future__ import annotations

import hashlib
import os
import zipfile

# State files packaged at the archive root when present (source -> arcname).
_STATE_FILES = ("engagement.db", "audit.log", "bom.json")
_ARTIFACT_SKIP = {".gitkeep"}
_SHA256_BLOCK = 4096


def build_case_archive(
    state: dict,
    state_dir: str = "state",
    artifacts_dir: str = "artifacts",
    summary: str | None = None,
) -> dict:
    """Package engagement state + artifacts into a zip and return metadata.

    Args:
        state: the engagement state dict; ``state["engagement"]["id"]`` and
            ``["target"]`` name the case.
        state_dir: directory holding ``engagement.db`` / ``audit.log`` /
            ``bom.json`` and the archive's write destination.
        artifacts_dir: directory of recovered artifacts, bundled under
            ``evidence/`` (``.gitkeep`` placeholders excluded).
        summary: pre-generated case-summary markdown; a minimal header is
            synthesized when omitted so the core needs no ReporterAgent.

    Returns:
        ``{"engagement_id": str, "archive_path": str, "sha256": str}``.
    """
    engagement = state["engagement"]
    eng_id = engagement["id"]

    archive_path = os.path.join(state_dir, f"OpenElia_Case_{eng_id}.zip")

    if summary is None:
        summary = (
            f"# OpenElia Case Summary\n"
            f"ID: {eng_id}\n"
            f"Target: {engagement.get('target', 'unknown')}\n"
        )

    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for name in _STATE_FILES:
            src = os.path.join(state_dir, name)
            if os.path.exists(src):
                zipf.write(src, name)

        if os.path.isdir(artifacts_dir):
            for root, _dirs, files in os.walk(artifacts_dir):
                for fname in files:
                    if fname in _ARTIFACT_SKIP:
                        continue
                    src = os.path.join(root, fname)
                    rel = os.path.relpath(src, artifacts_dir)
                    zipf.write(src, os.path.join("evidence", rel))

        zipf.writestr("Case_Summary.md", summary)

    sha256 = hashlib.sha256()
    with open(archive_path, "rb") as f:
        for block in iter(lambda: f.read(_SHA256_BLOCK), b""):
            sha256.update(block)

    return {
        "engagement_id": eng_id,
        "archive_path": archive_path,
        "sha256": sha256.hexdigest(),
    }
