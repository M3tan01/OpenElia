"""Unit tests for core/remediation.py — execute-remediation request validation.

validate_action_id is the single implementation shared by the CLI
`execute-remediation` command and the webdash POST /api/execute-remediation
route (boundary 400 before a background run launches). It is the boundary check
that the DB row id is a usable positive integer before the (dangerous, Tier 4)
allowlisted response action is dispatched. The command-execution allowlist
itself lives in DefenderRes and still gates the actual subprocess.
"""

from __future__ import annotations

import pytest

from core.remediation import validate_action_id


def test_valid_int_accepted():
    assert validate_action_id(5) == 5


def test_numeric_string_coerced():
    assert validate_action_id("5") == 5


def test_zero_rejected():
    with pytest.raises(ValueError):
        validate_action_id(0)


def test_negative_rejected():
    with pytest.raises(ValueError):
        validate_action_id(-1)


def test_non_numeric_rejected():
    with pytest.raises(ValueError):
        validate_action_id("abc")


def test_none_rejected():
    with pytest.raises(ValueError):
        validate_action_id(None)
