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


# --- RFC1918 private-range scope (webhook allowlist broadening) --------------

import socket as _socket

from core.webhook import _is_rfc1918_host


def test_rfc1918_literal_ips_accepted():
    assert _is_rfc1918_host("10.0.0.5")
    assert _is_rfc1918_host("172.16.0.1")
    assert _is_rfc1918_host("172.31.255.254")  # top of 172.16.0.0/12
    assert _is_rfc1918_host("192.168.1.10")


def test_public_and_reserved_ips_rejected():
    assert not _is_rfc1918_host("8.8.8.8")            # public
    assert not _is_rfc1918_host("172.32.0.1")         # just outside 172.16.0.0/12
    assert not _is_rfc1918_host("127.0.0.1")          # loopback — not RFC1918
    assert not _is_rfc1918_host("169.254.169.254")    # link-local metadata — not RFC1918


def _patch_getaddrinfo(monkeypatch, ip):
    monkeypatch.setattr(
        core.webhook.socket, "getaddrinfo",
        lambda host, *a, **k: [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", (ip, 0))],
    )


def test_hostname_resolving_to_private_accepted(monkeypatch):
    _patch_getaddrinfo(monkeypatch, "10.1.2.3")
    assert _is_rfc1918_host("n8n.internal")


def test_hostname_resolving_to_public_rejected(monkeypatch):
    _patch_getaddrinfo(monkeypatch, "93.184.216.34")
    assert not _is_rfc1918_host("evil.example.com")


def test_hostname_resolution_failure_is_failclosed(monkeypatch):
    def _boom(*a, **k):
        raise OSError("no such host")
    monkeypatch.setattr(core.webhook.socket, "getaddrinfo", _boom)
    assert not _is_rfc1918_host("nonexistent.invalid")


def test_rfc1918_target_accepted_with_empty_allowlist(monkeypatch):
    _set_allowlist(monkeypatch, "")  # allowlist unset — RFC1918 still passes
    assert validate_webhook_url("http://10.0.0.5:5678/hook", "WH_ALLOW") == "http://10.0.0.5:5678/hook"


def test_rfc1918_target_accepted_on_any_port(monkeypatch):
    _set_allowlist(monkeypatch, "")
    assert validate_webhook_url("https://192.168.1.9:8443/x", "WH_ALLOW") == "https://192.168.1.9:8443/x"


def test_public_target_rejected_with_empty_allowlist(monkeypatch):
    import pytest
    _set_allowlist(monkeypatch, "")
    with pytest.raises(ValueError):
        validate_webhook_url("http://8.8.8.8/hook", "WH_ALLOW")


def test_metadata_endpoint_rejected(monkeypatch):
    import pytest
    _set_allowlist(monkeypatch, "")
    with pytest.raises(ValueError):
        validate_webhook_url("http://169.254.169.254/latest/meta-data", "WH_ALLOW")


def test_rfc1918_accepted_even_when_allowlist_lists_other_host(monkeypatch):
    _set_allowlist(monkeypatch, "splunk.corp:8088")
    assert validate_webhook_url("http://10.5.5.5:9999/hook", "WH_ALLOW") == "http://10.5.5.5:9999/hook"
