"""
Unit tests for core/sbom.py — the data-returning SBOM core.

`build_sbom()` must be pure: return a JSON-serializable dict, never touch the
filesystem or stdout. These tests pin the dict shape the CLI and the
`GET /api/sbom` route both depend on, and mock the dependency-collection
helpers so the result doesn't vary with the host's installed packages.
"""
from __future__ import annotations

import core.sbom as sbom
from core.sbom import build_sbom


def test_build_sbom_top_level_shape():
    result = build_sbom()
    assert set(result.keys()) == {
        "project",
        "version",
        "timestamp",
        "components",
        "integrity",
    }
    assert result["project"] == "OpenElia"
    assert result["version"] == "1.0.0-Platinum"


def test_build_sbom_components_shape():
    result = build_sbom()
    components = result["components"]
    assert set(components.keys()) == {"engine", "platform", "sterile_environment"}
    assert components["engine"]["language"] == "Python 3.11+"
    assert isinstance(components["engine"]["dependencies"], list)
    assert components["platform"]["language"] == "TypeScript / Node.js"
    assert isinstance(components["platform"]["dependencies"], (list, dict))


def test_build_sbom_integrity_paths():
    result = build_sbom()
    integrity = result["integrity"]
    assert integrity["audit_trail"] == "state/audit.log"
    assert integrity["forensic_db"] == "state/forensic_timeline.db"


def test_build_sbom_is_json_serializable():
    import json

    # Round-trips without raising — proves no non-serializable objects leak in.
    payload = json.dumps(build_sbom())
    assert '"OpenElia"' in payload


def test_build_sbom_mocks_dependency_helpers(monkeypatch):
    """With both dep collectors stubbed, the shape is stable and host-independent."""
    monkeypatch.setattr(sbom, "_python_dependencies", lambda: ["fastapi==0.110.0"])
    monkeypatch.setattr(sbom, "_node_dependencies", lambda: {"react": "18.2.0"})
    result = build_sbom()
    assert result["components"]["engine"]["dependencies"] == ["fastapi==0.110.0"]
    assert result["components"]["platform"]["dependencies"] == {"react": "18.2.0"}
