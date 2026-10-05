"""core/grant.py — mint/revoke the signed IdP session authorizing red/purple ops.

Shared by the `grant` CLI command (main.py) and POST /api/grant (webdash). The
logic — sign the claims, write the file, tighten permissions, or unlink — lives
here; presentation (CLI prints, the root-gate advisory) stays in the callers.

SECURITY — credential-injection residual risk (per the Tier 3 mandate):
  grant mints a *bearer credential* (state/idp_session.json) that authorizes
  offensive red/purple operations. The residual risks a reviewer must keep in view:

  * Bearer, not bound. enforce_red_team_auth verifies only the HMAC signature and
    that an allowed role is present — the session is NOT bound to a host, process,
    or OS user. Whoever can reach this function can self-mint red/purple authority:
    the CLI path is a local operator; the HTTP path is *any holder of the webdash
    bearer token*. The route therefore stays token + confirm gated and must be
    treated as a privilege-bootstrap surface, not a benign config write.

  * role is attacker-controllable and gets HMAC-signed into the claims. If an
    arbitrary string were accepted, a caller would obtain a validly-signed session
    carrying a role of their choosing and bypass the verifier's role check. We
    therefore validate `role` against _ALLOWED_ROLES here (defense in depth behind
    the route's Pydantic Literal). `user` is a free-form audit label — it drives no
    trust decision — so it is intentionally left unconstrained.

  * chmod 0600/0700 stops *other local users* copying the file into their own
    OPENELIA_STATE_DIR and inheriting the grant. It does NOT constrain the minting
    caller. The OS-root gate still applies at red/purple *execution*, not at mint.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

# Must stay in sync with the roles enforce_red_team_auth accepts and the CLI
# `grant --role` choices (main.py).
_ALLOWED_ROLES: tuple[str, ...] = ("admin", "security_lead", "red_team_lead")
_IDP_FILENAME = "idp_session.json"


def mint_grant_session(
    user: str, role: str, ttl_hours: float, state_dir: str = "state"
) -> dict:
    """Sign and persist an IdP session authorizing `role` for `ttl_hours`.

    Returns metadata the callers serialize/print. Raises ValueError if `role` is
    not in the allowlist (credential-injection guard — see module docstring).
    """
    if role not in _ALLOWED_ROLES:
        raise ValueError(f"role must be one of {_ALLOWED_ROLES}, got {role!r}")

    from rbac_manager import sign_idp_session

    sdir = Path(state_dir)
    sdir.mkdir(parents=True, exist_ok=True)
    idp_path = sdir / _IDP_FILENAME

    exp = int(time.time()) + int(ttl_hours * 3600)
    claims = {"user": user, "roles": [role], "exp": exp}
    signed = sign_idp_session(claims)
    idp_path.write_text(json.dumps(signed, indent=2))

    chmod_ok = True
    chmod_error: str | None = None
    try:
        os.chmod(idp_path, 0o600)
        os.chmod(sdir, 0o700)
    except OSError as exc:  # os.chmod is a near no-op on Windows; POSIX is the threat
        chmod_ok = False
        chmod_error = str(exc)

    return {
        "user": user,
        "role": role,
        "expires_epoch": exp,
        "idp_path": str(idp_path),
        "chmod_ok": chmod_ok,
        "chmod_error": chmod_error,
    }


def revoke_grant_session(state_dir: str = "state") -> dict:
    """Remove the IdP session if present. Idempotent."""
    idp_path = Path(state_dir) / _IDP_FILENAME
    existed = idp_path.exists()
    if existed:
        idp_path.unlink()
    return {"revoked": existed, "idp_path": str(idp_path)}
