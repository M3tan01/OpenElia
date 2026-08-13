"""
Read-only GET /api/n8n/status endpoint tests: confirm allowlist config reporting
and security constraint (no hostnames leaked to browser).
"""
from __future__ import annotations

from unittest.mock import patch

from tests.conftest_webdash import auth, client, token  # noqa: F401


def test_status_reports_configured_when_allowlist_set(client, auth):
    with patch("webdash.api.n8n.load_webhook_allowlist", return_value=["n8n.corp.local", "hooks.corp.local"]):
        r = client.get("/api/n8n/status", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["allowlist_configured"] is True
    assert body["allowlist_count"] == 2
    assert body["trigger_path"] == "/api/n8n/trigger"
    assert body["domains"] == ["red", "blue", "purple"]
    # HARD CONSTRAINT: hostnames must never be echoed back to the browser.
    assert "n8n.corp.local" not in r.text
    assert "hooks.corp.local" not in r.text


def test_status_reports_unconfigured_when_allowlist_empty(client, auth):
    with patch("webdash.api.n8n.load_webhook_allowlist", return_value=[]):
        r = client.get("/api/n8n/status", headers=auth)
    assert r.status_code == 200
    body = r.json()
    assert body["allowlist_configured"] is False
    assert body["allowlist_count"] == 0
