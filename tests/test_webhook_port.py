"""Unit tests for core.webhook port-aware allowlist (finding #2)."""
from __future__ import annotations

from core.webhook import _parse_allowlist_entry


def test_bare_host_means_any_port():
    assert _parse_allowlist_entry("localhost") == ("localhost", None)


def test_host_port_restricts_to_that_port():
    assert _parse_allowlist_entry("localhost:5678") == ("localhost", 5678)


def test_non_integer_port_is_unmatchable():
    # Fail-closed: a malformed entry must never allow-all. Host becomes ""
    # (no real hostname equals ""), so no URL can match it.
    assert _parse_allowlist_entry("localhost:notaport") == ("", None)


import core.webhook
from core.webhook import validate_webhook_url


def _set_allowlist(monkeypatch, value: str):
    monkeypatch.setattr(
        core.webhook.SecretStore, "get_secret",
        lambda key, _v=value: _v if key == "WH_ALLOW" else None,
    )


def test_bare_host_entry_allows_any_port(monkeypatch):
    _set_allowlist(monkeypatch, "localhost")
    assert validate_webhook_url("http://localhost:5678/hook", "WH_ALLOW") == "http://localhost:5678/hook"
    assert validate_webhook_url("http://localhost:9999/hook", "WH_ALLOW") == "http://localhost:9999/hook"


def test_host_port_entry_allows_matching_port(monkeypatch):
    _set_allowlist(monkeypatch, "localhost:5678")
    assert validate_webhook_url("http://localhost:5678/hook", "WH_ALLOW") == "http://localhost:5678/hook"


def test_host_port_entry_rejects_other_port(monkeypatch):
    import pytest
    _set_allowlist(monkeypatch, "localhost:5678")
    with pytest.raises(ValueError):
        validate_webhook_url("http://localhost:22/hook", "WH_ALLOW")


def test_host_port_entry_rejects_default_port_when_url_has_none(monkeypatch):
    # entry demands :5678; bare http URL resolves to :80 -> reject
    import pytest
    _set_allowlist(monkeypatch, "localhost:5678")
    with pytest.raises(ValueError):
        validate_webhook_url("http://localhost/hook", "WH_ALLOW")


def test_bare_host_entry_matches_scheme_default_port(monkeypatch):
    # entry "localhost" (any port); http URL with no explicit port -> :80, still matches
    _set_allowlist(monkeypatch, "localhost")
    assert validate_webhook_url("http://localhost/hook", "WH_ALLOW") == "http://localhost/hook"


def test_unparseable_url_port_is_rejected(monkeypatch):
    import pytest
    _set_allowlist(monkeypatch, "localhost")
    with pytest.raises(ValueError):
        validate_webhook_url("http://localhost:99999/hook", "WH_ALLOW")  # port out of range
