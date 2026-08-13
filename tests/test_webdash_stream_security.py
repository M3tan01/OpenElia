"""
Unit tests for webdash.stream._read_new, the live WS tail loop, the token
helpers in webdash.security, and the server localhost guard.
"""
from __future__ import annotations

import json

import pytest

from tests.conftest_webdash import client, state_dir, token  # noqa: F401
from webdash import security
from webdash.stream import _read_new


# --- _read_new --------------------------------------------------------------- #

def test_read_new_reads_from_offset(tmp_path):
    p = tmp_path / "log.jsonl"
    p.write_text(json.dumps({"a": 1}) + "\n")
    recs, off = _read_new(p, 0)
    assert recs == [{"a": 1}]
    assert off == p.stat().st_size


def test_read_new_only_returns_appended(tmp_path):
    p = tmp_path / "log.jsonl"
    p.write_text(json.dumps({"a": 1}) + "\n")
    _, off = _read_new(p, 0)
    p.write_text(p.read_text() + json.dumps({"b": 2}) + "\n")
    recs, _ = _read_new(p, off)
    assert recs == [{"b": 2}]


def test_read_new_resets_on_truncation(tmp_path):
    p = tmp_path / "log.jsonl"
    p.write_text(json.dumps({"a": 1}) + "\n")
    recs, _ = _read_new(p, 9999)  # offset past EOF → rotation/truncation
    assert recs == [{"a": 1}]


def test_read_new_missing_file(tmp_path):
    recs, off = _read_new(tmp_path / "nope.jsonl", 0)
    assert recs == [] and off == 0


def test_read_new_skips_bad_json(tmp_path):
    p = tmp_path / "log.jsonl"
    p.write_text("not json\n" + json.dumps({"ok": 1}) + "\n")
    recs, _ = _read_new(p, 0)
    assert recs == [{"ok": 1}]


# --- live WS tail ------------------------------------------------------------ #

def test_websocket_auth_via_subprotocol(client, state_dir, token):
    # token in Sec-WebSocket-Protocol, NOT in the URL
    with client.websocket_connect("/api/stream", subprotocols=[token]) as ws:
        assert ws.receive_json()["type"] == "snapshot"


def test_websocket_bad_subprotocol_rejected(client, state_dir, token):
    import pytest as _pytest
    from starlette.websockets import WebSocketDisconnect

    with _pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/api/stream", subprotocols=["wrong-token"]) as ws:
            ws.receive_json()


def test_websocket_pushes_new_audit_event(client, state_dir, token):
    from security_manager import AuditLogger

    with client.websocket_connect(f"/api/stream?token={token}") as ws:
        assert ws.receive_json()["type"] == "snapshot"
        # Append a new audit event; the tail loop should push it.
        AuditLogger(log_path=str(state_dir / "audit.log")).log_event(
            "defender_mon", "10.0.0.5", "new event", "LOOP_DETECTED", "live-test"
        )
        msg = ws.receive_json()
        assert msg["type"] == "audit"
        assert msg["event"]["status"] == "LOOP_DETECTED"


# --- token helpers ----------------------------------------------------------- #

def test_generate_and_verify_token(monkeypatch):
    store: dict[str, str] = {}
    monkeypatch.setattr(security.SecretStore, "set_secret", classmethod(lambda cls, k, v: store.__setitem__(k, v)))
    monkeypatch.setattr(security.SecretStore, "get_secret", classmethod(lambda cls, k: store.get(k)))

    tok = security.generate_token()
    assert len(tok) > 20
    assert security.verify(tok) is True
    assert security.verify("wrong") is False
    # get_or_create returns the existing one, doesn't mint a new value
    assert security.get_or_create_token() == tok


def test_get_or_create_mints_when_absent(monkeypatch):
    store: dict[str, str] = {}
    monkeypatch.setattr(security.SecretStore, "set_secret", classmethod(lambda cls, k, v: store.__setitem__(k, v)))
    monkeypatch.setattr(security.SecretStore, "get_secret", classmethod(lambda cls, k: store.get(k)))
    tok = security.get_or_create_token()
    # Stored as a JSON record {token, issued}, not a bare string (TTL support).
    import json as _json
    assert _json.loads(store["WEBDASH_TOKEN"])["token"] == tok


def test_verify_false_when_no_token(monkeypatch):
    monkeypatch.setattr(security, "current_token", lambda: None)
    assert security.verify("anything") is False


# --- server localhost guard -------------------------------------------------- #

def test_run_refuses_non_localhost():
    from webdash import server

    with pytest.raises(ValueError):
        server.run(host="0.0.0.0", port=8765)  # nosec B104 — asserting it is REFUSED
