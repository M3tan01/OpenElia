"""core/checks.py — operational readiness probes, data-returning core.

The CLI (`main.py cmd_check`) renders a `ReadinessReport` to the terminal;
the webdash `GET /api/check` route serializes the same report to JSON. One
capability, one home: neither surface duplicates the probe logic.

This module must NOT import `main` — `main` is the CLI entrypoint and would
create a circular import. The URL/Ollama probe helpers live here; `main`
re-imports them.
"""

from __future__ import annotations

import http.client
import os
import subprocess  # nosec: B404
import sys
from dataclasses import dataclass
from urllib.parse import urlparse

from secret_store import SecretStore

# Directories that must be writable for the engine to persist state.
_WRITABLE_PATHS = ("state", "artifacts", "mcp_servers")
# CVE intel endpoint probed for outbound connectivity.
_INTEL_URL = "https://cve.circl.lu/api/browse"
# Docker image the sterile offensive environment runs in.
_STERILE_IMAGE = "cyber-ops-recon:strict"


def is_safe_url(url: str) -> bool:
    """True when *url* is an http(s) URL with a non-empty netloc (SSRF guard)."""
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def check_ollama() -> bool:
    """Probe the local Ollama OpenAI-compat endpoint; True if it answers 2xx/3xx."""
    from model_manager import ModelManager, DEFAULT_OLLAMA_URL

    # Stored OLLAMA_BASE_URL may lack the /v1 suffix (e.g. "http://localhost:11434").
    # _sanitize_url appends /v1 for :11434 hosts so we hit the OpenAI-compat
    # /v1/models endpoint (200) instead of the native /models path (404).
    base_url = ModelManager._sanitize_url(
        SecretStore.get_secret("OLLAMA_BASE_URL") or DEFAULT_OLLAMA_URL
    )
    try:
        url = f"{base_url}/models"
        if not is_safe_url(url):
            return False

        parsed = urlparse(url)
        conn = (
            http.client.HTTPConnection(parsed.netloc, timeout=3)
            if parsed.scheme == "http"
            else http.client.HTTPSConnection(parsed.netloc, timeout=3)
        )
        conn.request("GET", parsed.path or "/")
        response = conn.getresponse()
        return 200 <= response.status < 400
    except Exception:
        return False


@dataclass(frozen=True)
class CheckItem:
    """One readiness probe result.

    ``sub`` marks a nested/indented item (e.g. the sterile image under Docker).
    ``informational`` marks a result that is reported but never gates readiness
    (RBAC status, macOS hardware).
    """

    name: str
    label: str
    passed: bool
    detail: str
    sub: bool = False
    informational: bool = False


@dataclass(frozen=True)
class ReadinessReport:
    """Aggregate readiness verdict plus every individual probe result."""

    overall_pass: bool
    checks: tuple[CheckItem, ...]

    def as_dict(self) -> dict:
        """JSON-serializable form for the API route."""
        return {
            "overall_pass": self.overall_pass,
            "checks": [
                {
                    "name": c.name,
                    "label": c.label,
                    "passed": c.passed,
                    "detail": c.detail,
                    "sub": c.sub,
                    "informational": c.informational,
                }
                for c in self.checks
            ],
        }


def _check_docker() -> list[CheckItem]:
    """Docker daemon reachability + sterile image presence. Both gate readiness."""
    try:
        import docker

        client = docker.from_env()
        client.ping()
        items = [CheckItem("docker", "Docker", True, "Running")]
        try:
            client.images.get(_STERILE_IMAGE)
            items.append(
                CheckItem(
                    "docker_image",
                    f"Image '{_STERILE_IMAGE}'",
                    True,
                    "Found",
                    sub=True,
                )
            )
        except docker.errors.ImageNotFound:
            items.append(
                CheckItem(
                    "docker_image",
                    f"Image '{_STERILE_IMAGE}'",
                    False,
                    "Not found (Run: python main.py doctor)",
                    sub=True,
                )
            )
        return items
    except Exception as e:  # noqa: BLE001 — surface any docker init failure as not-ready
        return [CheckItem("docker", "Docker", False, f"Error ({str(e)})")]


def _check_intel() -> CheckItem:
    """Outbound CVE intel connectivity. A non-2xx/3xx or unsafe URL gates readiness.

    A bare exception (network down) is reported as failed but deliberately does
    NOT gate — matches the original CLI semantics where the connectivity probe
    exception path left overall_pass untouched.
    """
    try:
        if not is_safe_url(_INTEL_URL):
            return CheckItem("intel_api", "Intel API", False, "Unsafe URL detected")
        parsed = urlparse(_INTEL_URL)
        conn = http.client.HTTPSConnection(parsed.netloc, timeout=5)
        conn.request("GET", parsed.path or "/")
        response = conn.getresponse()
        if 200 <= response.status < 400:
            return CheckItem("intel_api", "Intel API", True, "Reachable (cve.circl.lu)")
        return CheckItem("intel_api", "Intel API", False, "Not reachable")
    except Exception:
        # Non-gating: connectivity failure reported but does not block readiness.
        return CheckItem(
            "intel_api", "Intel API", False, "Not reachable", informational=True
        )


def _check_macos_hardware() -> CheckItem:
    """macOS Touch ID / autofill posture. Informational — never gates readiness."""
    try:
        # macOS system binaries, no user input.
        bioutil_proc = subprocess.run(  # nosec B603 B607
            ["bioutil", "-read", "-type", "fingerprint"],
            capture_output=True,
            text=True,
        )
        touch_id_enabled = (
            "total: 0" not in bioutil_proc.stdout and bioutil_proc.returncode == 0
        )
        autofill_proc = subprocess.run(  # nosec B603 B607
            ["defaults", "read", "com.apple.TouchID", "AllowPasswordAutofill"],
            capture_output=True,
            text=True,
        )
        autofill_enabled = autofill_proc.stdout.strip() == "1"
        detail = (
            f"TouchID={'Active' if touch_id_enabled else 'No Fingerprints'} | "
            f"Autofill={'Enabled' if autofill_enabled else 'Disabled'}"
        )
        return CheckItem("macos_hardware", "macOS Hardware", True, detail, informational=True)
    except Exception:
        return CheckItem(
            "macos_hardware",
            "macOS Hardware",
            False,
            "Failed to query bioutil/defaults",
            informational=True,
        )


async def run_readiness_check() -> ReadinessReport:
    """Run every readiness probe and return an immutable report.

    Gating probes (Docker, sterile image, Ollama, write permissions, intel
    non-2xx/unsafe-URL) drive ``overall_pass``. RBAC and macOS hardware are
    informational; a bare intel-connectivity exception is non-gating.
    """
    checks: list[CheckItem] = []
    overall_pass = True

    # 1. Docker daemon + sterile image (gating).
    docker_items = _check_docker()
    checks.extend(docker_items)
    if any(not c.passed for c in docker_items):
        overall_pass = False

    # 2. Ollama reachability (gating).
    if check_ollama():
        from model_manager import ModelManager

        model = (
            ModelManager.get_config().get("local_model")
            or "not set — run: model set local <model>"
        )
        checks.append(
            CheckItem("ollama", "Ollama", True, f"Reachable (Target Model: {model})")
        )
    else:
        target = SecretStore.get_secret("OLLAMA_BASE_URL") or "localhost"
        checks.append(
            CheckItem("ollama", "Ollama", False, f"Not reachable at {target}")
        )
        overall_pass = False

    # 3. CVE intel connectivity (non-2xx/unsafe gates; bare exception does not).
    intel = _check_intel()
    checks.append(intel)
    if not intel.passed and not intel.informational:
        overall_pass = False

    # 4. Write permissions on core directories (gating).
    denied = [p for p in _WRITABLE_PATHS if not os.access(p, os.W_OK)]
    if denied:
        overall_pass = False
        checks.append(
            CheckItem(
                "permissions",
                "Permissions",
                False,
                "Write access denied: " + ", ".join(denied),
            )
        )
    else:
        checks.append(
            CheckItem(
                "permissions",
                "Permissions",
                True,
                "Write access confirmed for core directories",
            )
        )

    # 5. RBAC status (informational).
    from rbac_manager import RBACManager

    is_admin = RBACManager.is_os_admin()
    has_idp = os.path.exists(
        os.path.join(os.getenv("OPENELIA_STATE_DIR", "state"), "idp_session.json")
    )
    allow_unpriv = os.getenv("OPENELIA_ALLOW_UNPRIV_RED") == "1"
    status = "Admin" if is_admin else ("User+unpriv-red" if allow_unpriv else "User")
    checks.append(
        CheckItem(
            "rbac",
            "RBAC",
            True,
            f"Running as {status} | IdP Session: {'Found' if has_idp else 'Missing'}",
            informational=True,
        )
    )

    # 6. macOS hardware posture (informational, darwin only).
    if sys.platform == "darwin":
        checks.append(_check_macos_hardware())

    return ReadinessReport(overall_pass, tuple(checks))
