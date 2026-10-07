"""core/sbom.py — Software Bill of Materials builder, data-returning core.

`build_sbom()` returns the SBOM as a plain dict. The CLI (`main.py cmd_sbom`)
writes it to `state/bom.json` and prints a component count; the webdash
`GET /api/sbom` route serializes the same dict to JSON. Pure: no file write,
no stdout — presentation stays in the callers.
"""

from __future__ import annotations

import json
import os
from datetime import datetime

_NODE_PACKAGE_JSON = "src/package.json"
_STERILE_DOCKERFILE = "Dockerfile.offensive"


def _python_dependencies() -> list[str]:
    """Installed Python distributions as ``name==version`` strings.

    Uses stdlib ``importlib.metadata`` (Python 3.8+). ``pkg_resources`` is
    deprecated and absent on modern setuptools/Python, so relying on it made
    both the CLI ``sbom`` command and ``GET /api/sbom`` crash.
    """
    from importlib.metadata import distributions

    return sorted(
        f"{d.metadata['Name']}=={d.version}"
        for d in distributions()
        if d.metadata["Name"]
    )


def _node_dependencies() -> dict:
    """Node dependencies from ``src/package.json``, or empty when absent."""
    if not os.path.exists(_NODE_PACKAGE_JSON):
        return {}
    with open(_NODE_PACKAGE_JSON, "r") as f:
        return json.load(f).get("dependencies", {})


def build_sbom() -> dict:
    """Assemble the OpenElia SBOM as a JSON-serializable dict."""
    python_deps = _python_dependencies()
    node_deps = _node_dependencies()

    docker_info = "Local Fallback"
    if os.path.exists(_STERILE_DOCKERFILE):
        docker_info = "cyber-ops-recon:strict (Debian Bookworm + Metasploit)"

    return {
        "project": "OpenElia",
        "version": "1.0.0-Platinum",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "engine": {
                "language": "Python 3.11+",
                "dependencies": python_deps,
            },
            "platform": {
                "language": "TypeScript / Node.js",
                "dependencies": node_deps,
            },
            "sterile_environment": docker_info,
        },
        "integrity": {
            "audit_trail": "state/audit.log",
            "forensic_db": "state/forensic_timeline.db",
        },
    }
