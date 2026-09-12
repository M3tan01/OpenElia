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
