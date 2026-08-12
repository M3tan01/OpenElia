"""
Tests for the sync_audit_log tool in mcp_servers/siem/server.py.
"""
import json
import os
import sys
import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# Ensure repo root is importable
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import mcp_servers.siem.server as siem_module


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_http_client(status_code: int = 200):
    """Return a patched httpx.AsyncClient context-manager whose post() is an AsyncMock."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.raise_for_status = MagicMock()  # no-op on success

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_response)

    # Support `async with httpx.AsyncClient() as client:`
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_client)
    cm.__aexit__ = AsyncMock(return_value=False)

    return cm, mock_client


GOOD_URL = "https://siem.internal/ingest"

# ---------------------------------------------------------------------------
# Test A: 3 log lines (one malformed) → count == 2, POSTs correctly
# ---------------------------------------------------------------------------

async def test_sync_audit_log_skips_malformed_and_posts_count_2(tmp_path):
    # Write 3 lines: 2 valid JSON, 1 malformed
    audit_log = tmp_path / "audit.log"
    audit_log.write_text(
        '{"timestamp": "2026-01-01T00:00:00Z", "source": "agent", "target": "host1", "status": "OK"}\n'
        'NOT VALID JSON {\n'
        '{"timestamp": "2026-01-02T00:00:00Z", "source": "agent", "target": "host2", "status": "OK"}\n',
        encoding="utf-8",
    )

    cm, mock_client = _make_mock_http_client(200)

    with patch.dict(os.environ, {"OPENELIA_STATE_DIR": str(tmp_path)}), \
         patch("httpx.AsyncClient", return_value=cm), \
         patch.object(siem_module, "_validate_webhook_url", return_value=GOOD_URL), \
         patch.object(siem_module, "_audit_log_path", return_value=str(audit_log)):

        result = await siem_module.handle_call_tool(
            "sync_audit_log", {"webhook_url": GOOD_URL, "limit": 100}
        )

    text = result[0].text
    assert "SUCCESS" in text, f"Expected SUCCESS in result, got: {text!r}"
    assert "2" in text, f"Expected count 2 in result, got: {text!r}"

    # Verify the POSTed payload has count == 2
    call_args = mock_client.post.call_args
    posted_json = call_args.kwargs.get("json") if call_args.kwargs else None
    if posted_json is None and call_args.args and len(call_args.args) > 1:
        posted_json = call_args.args[1]
    if posted_json is None:
        # fall back: inspect keyword args
        posted_json = call_args[1].get("json") if len(call_args) > 1 else None
    assert posted_json is not None, "No json argument found on POST call"
    assert posted_json["count"] == 2, f"Expected count=2 in POST body, got {posted_json['count']}"
    assert len(posted_json["events"]) == 2


# ---------------------------------------------------------------------------
# Test B: absent audit log → graceful message, no HTTP POST
# ---------------------------------------------------------------------------

async def test_sync_audit_log_absent_file_no_post(tmp_path):
    # tmp_path exists but audit.log does NOT — no file at all
    absent_path = str(tmp_path / "audit.log")

    cm, mock_client = _make_mock_http_client(200)

    with patch("httpx.AsyncClient", return_value=cm), \
         patch.object(siem_module, "_validate_webhook_url", return_value=GOOD_URL), \
         patch.object(siem_module, "_audit_log_path", return_value=absent_path):

        result = await siem_module.handle_call_tool(
            "sync_audit_log", {"webhook_url": GOOD_URL}
        )

    text = result[0].text
    assert "no audit log" in text.lower(), f"Expected graceful message, got: {text!r}"
    mock_client.post.assert_not_called()


# ---------------------------------------------------------------------------
# Test C: SSRF guard fires before any file I/O
# ---------------------------------------------------------------------------

async def test_sync_audit_log_ssrf_guard_blocks_bad_url(tmp_path):
    audit_log = tmp_path / "audit.log"
    audit_log.write_text('{"status": "OK"}\n', encoding="utf-8")

    cm, mock_client = _make_mock_http_client(200)

    with patch("httpx.AsyncClient", return_value=cm), \
         patch.object(
             siem_module,
             "_validate_webhook_url",
             side_effect=ValueError("Webhook hostname 'evil.com' is not in the approved SIEM allowlist."),
         ), \
         patch.object(siem_module, "_audit_log_path", return_value=str(audit_log)):

        result = await siem_module.handle_call_tool(
            "sync_audit_log", {"webhook_url": "https://evil.com/steal"}
        )

    text = result[0].text
    assert "SSRF Guard" in text
    mock_client.post.assert_not_called()


# ---------------------------------------------------------------------------
# Test D: SIEM returns 4xx/5xx (raise_for_status raises) → non-fatal error string
# ---------------------------------------------------------------------------

async def test_sync_audit_log_http_error_returns_error_string(tmp_path):
    import httpx

    audit_log = tmp_path / "audit.log"
    audit_log.write_text('{"status": "OK"}\n', encoding="utf-8")

    cm, mock_client = _make_mock_http_client(500)
    # POST returns, but raise_for_status raises an HTTP status error.
    mock_response = await mock_client.post()  # the AsyncMock return value
    mock_response.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError(
            "500 Server Error", request=MagicMock(), response=MagicMock()
        )
    )

    with patch("httpx.AsyncClient", return_value=cm), \
         patch.object(siem_module, "_validate_webhook_url", return_value=GOOD_URL), \
         patch.object(siem_module, "_audit_log_path", return_value=str(audit_log)):

        result = await siem_module.handle_call_tool(
            "sync_audit_log", {"webhook_url": GOOD_URL}
        )

    text = result[0].text
    assert "SIEM Sync Error" in text, f"Expected error string, got: {text!r}"
