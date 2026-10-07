"""Unit tests for core/grant.py — the data-returning IdP-session mint/revoke core.

mint_grant_session() / revoke_grant_session() are the shared core the CLI `grant`
command and the webdash POST /api/grant route both call. They are pure of stdout
and of the CLI's root-gate advisory: they sign + write (or unlink) the
state/idp_session.json bearer credential and return metadata.
"""

from __future__ import annotations

import json
import time

import pytest

from core.grant import mint_grant_session, revoke_grant_session
from rbac_manager import verify_idp_session


def test_mint_writes_valid_signed_session_and_returns_metadata(tmp_path):
    state_dir = tmp_path / "state"

    before = int(time.time())
    result = mint_grant_session(
        user="alice", role="red_team_lead", ttl_hours=2, state_dir=str(state_dir)
    )

    # Metadata the callers serialize / print.
    assert result["user"] == "alice"
    assert result["role"] == "red_team_lead"
    assert result["chmod_ok"] is True
    idp_path = state_dir / "idp_session.json"
    assert result["idp_path"] == str(idp_path)

    # exp is now + ttl (2h = 7200s), within a small clock tolerance.
    assert before + 7200 <= result["expires_epoch"] <= int(time.time()) + 7200

    # The file on disk is a validly HMAC-signed session carrying the role.
    session = json.loads(idp_path.read_text())
    assert verify_idp_session(session) is True
    assert session["roles"] == ["red_team_lead"]
    assert session["user"] == "alice"
    assert session["exp"] == result["expires_epoch"]


def test_mint_tightens_file_permissions_to_owner_only(tmp_path):
    state_dir = tmp_path / "state"
    mint_grant_session(user="op", role="admin", ttl_hours=1, state_dir=str(state_dir))

    import os
    import stat

    mode = stat.S_IMODE(os.stat(state_dir / "idp_session.json").st_mode)
    assert mode == 0o600  # bearer credential — not readable by other local users


def test_mint_rejects_role_outside_allowlist(tmp_path):
    """An attacker-controlled role must not be HMAC-signed into a valid session."""
    with pytest.raises(ValueError):
        mint_grant_session(
            user="op", role="superadmin", ttl_hours=1, state_dir=str(tmp_path / "state")
        )
    assert not (tmp_path / "state" / "idp_session.json").exists()


def test_revoke_removes_existing_session(tmp_path):
    state_dir = tmp_path / "state"
    mint_grant_session(user="op", role="admin", ttl_hours=1, state_dir=str(state_dir))

    result = revoke_grant_session(state_dir=str(state_dir))

    assert result["revoked"] is True
    assert not (state_dir / "idp_session.json").exists()


def test_revoke_is_idempotent_when_no_session(tmp_path):
    result = revoke_grant_session(state_dir=str(tmp_path / "state"))
    assert result["revoked"] is False
