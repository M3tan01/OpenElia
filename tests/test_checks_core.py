"""
Unit tests for core/checks.py — the data-returning readiness core.

Mocks the probe-helper boundary (Docker, Ollama, intel, RBAC, write access)
so the tests exercise the gating logic in `run_readiness_check`, not the host
environment. Also pins `sys.platform` off darwin so the macOS hardware probe
never shells out during CI.
"""
from __future__ import annotations

import pytest

import core.checks as checks
from core.checks import CheckItem, ReadinessReport, is_safe_url


# --- is_safe_url ------------------------------------------------------------ #

@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://localhost:11434/v1/models", True),
        ("https://cve.circl.lu/api/browse", True),
        ("ftp://example.com/file", False),
        ("file:///etc/passwd", False),
        ("http://", False),
        ("not-a-url", False),
    ],
)
def test_is_safe_url(url, expected):
    assert is_safe_url(url) is expected


# --- CheckItem / ReadinessReport shape -------------------------------------- #

def test_readiness_report_as_dict_shape():
    report = ReadinessReport(
        overall_pass=True,
        checks=(
            CheckItem("docker", "Docker", True, "Running"),
            CheckItem("rbac", "RBAC", True, "Admin", informational=True),
        ),
    )
    d = report.as_dict()
    assert d["overall_pass"] is True
    assert isinstance(d["checks"], list)
    first = d["checks"][0]
    assert set(first.keys()) == {"name", "label", "passed", "detail", "sub", "informational"}
    assert first["name"] == "docker"
    assert d["checks"][1]["informational"] is True


def test_checkitem_is_frozen():
    item = CheckItem("docker", "Docker", True, "Running")
    with pytest.raises((AttributeError, TypeError)):
        item.passed = False  # type: ignore[misc]


# --- run_readiness_check gating --------------------------------------------- #

@pytest.fixture
def all_green(monkeypatch):
    """Force every gating probe to pass; caller overrides individual ones."""
    monkeypatch.setattr(checks, "_check_docker",
                        lambda: [CheckItem("docker", "Docker", True, "Running")])
    monkeypatch.setattr(checks, "check_ollama", lambda: True)
    monkeypatch.setattr(checks, "_check_intel",
                        lambda: CheckItem("intel_api", "Intel API", True, "Reachable"))
    # os.access → all writable
    monkeypatch.setattr(checks.os, "access", lambda p, m: True)
    # RBAC probe imports rbac_manager; stub to avoid OS calls.
    import rbac_manager
    monkeypatch.setattr(rbac_manager.RBACManager, "is_os_admin", staticmethod(lambda: True))
    # model_manager.get_config used on the ollama-pass branch.
    import model_manager
    monkeypatch.setattr(model_manager.ModelManager, "get_config",
                        staticmethod(lambda: {"local_model": "qwen3.5:2b"}))
    # Skip the darwin-only hardware probe.
    monkeypatch.setattr(checks.sys, "platform", "linux")


@pytest.mark.asyncio
async def test_all_probes_pass_overall_true(all_green):
    report = await checks.run_readiness_check()
    assert report.overall_pass is True
    names = {c.name for c in report.checks}
    assert {"docker", "ollama", "intel_api", "permissions", "rbac"} <= names


@pytest.mark.asyncio
async def test_docker_failure_gates(all_green, monkeypatch):
    monkeypatch.setattr(checks, "_check_docker",
                        lambda: [CheckItem("docker", "Docker", False, "Error")])
    report = await checks.run_readiness_check()
    assert report.overall_pass is False


@pytest.mark.asyncio
async def test_ollama_failure_gates(all_green, monkeypatch):
    monkeypatch.setattr(checks, "check_ollama", lambda: False)
    report = await checks.run_readiness_check()
    assert report.overall_pass is False
    ollama = next(c for c in report.checks if c.name == "ollama")
    assert ollama.passed is False


@pytest.mark.asyncio
async def test_write_permission_denied_gates(all_green, monkeypatch):
    monkeypatch.setattr(checks.os, "access", lambda p, m: False)
    report = await checks.run_readiness_check()
    assert report.overall_pass is False
    perms = next(c for c in report.checks if c.name == "permissions")
    assert perms.passed is False


@pytest.mark.asyncio
async def test_intel_non2xx_gates(all_green, monkeypatch):
    """A reachable-but-non-2xx intel probe (informational=False) gates."""
    monkeypatch.setattr(checks, "_check_intel",
                        lambda: CheckItem("intel_api", "Intel API", False, "Not reachable"))
    report = await checks.run_readiness_check()
    assert report.overall_pass is False


@pytest.mark.asyncio
async def test_intel_connectivity_exception_non_gating(all_green, monkeypatch):
    """A bare intel connectivity failure (informational=True) does NOT gate."""
    monkeypatch.setattr(
        checks, "_check_intel",
        lambda: CheckItem("intel_api", "Intel API", False, "Not reachable", informational=True),
    )
    report = await checks.run_readiness_check()
    assert report.overall_pass is True  # informational failure does not block


@pytest.mark.asyncio
async def test_rbac_is_informational(all_green):
    report = await checks.run_readiness_check()
    rbac = next(c for c in report.checks if c.name == "rbac")
    assert rbac.informational is True
