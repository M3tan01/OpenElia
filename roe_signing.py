#!/usr/bin/env python3
"""
roe_signing.py — HMAC-SHA256 signing + engagement-binding for Rules of Engagement.

A raw roe.json only names subnets/tools/quiet-hours; nothing ties it to a
specific, time-boxed engagement, so a stale or copied file silently authorizes
the wrong scope. This module binds the RoE to an engagement:

    signature = HMAC-SHA256(ROE_SIGNING_KEY, canonical_json(doc without "signature"))

plus required `engagement_id` and `expires_at` fields that are inside the signed
body — they cannot be changed without invalidating the signature.

Signing key lives in SecretStore("ROE_SIGNING_KEY"), auto-generated and persisted
on first `sign` (mirrors rbac_manager._get_hmac_key). Verification refuses to run
without a key — it never mints one — so a missing key fails closed.

CLI:
    python roe_signing.py sign roe.json --engagement-id ENG-2026-014 --ttl-days 7
    python roe_signing.py verify roe.json
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

_ROE_KEY_NAME = "ROE_SIGNING_KEY"
_SIGNATURE_FIELD = "signature"


def _roe_key(create: bool = False) -> bytes:
    """Return the RoE signing key.

    create=True (sign path) auto-generates and persists a key if absent.
    create=False (verify path) refuses to mint one — a missing key fails closed.
    """
    sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
    from secret_store import SecretStore
    key = SecretStore.get_secret(_ROE_KEY_NAME)
    if not key:
        if not create:
            raise RuntimeError(
                f"{_ROE_KEY_NAME} is not set — cannot verify RoE signature. "
                f"Sign a RoE with 'python roe_signing.py sign' (which provisions the "
                f"key) or set {_ROE_KEY_NAME} in the keychain / environment."
            )
        import secrets as _sec
        key = _sec.token_hex(32)
        SecretStore.set_secret(_ROE_KEY_NAME, key)
    return key.encode() if isinstance(key, str) else key


def _canonical(doc: dict) -> bytes:
    """Canonical JSON over the doc minus the signature field — sorted, tight."""
    body = {k: v for k, v in doc.items() if k != _SIGNATURE_FIELD}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign_roe(doc: dict, *, engagement_id: str | None = None,
             ttl_days: float = 7.0) -> dict:
    """Return a copy of `doc` bound to an engagement and HMAC-signed.

    Injects engagement_id (generated if not supplied), issued_at, and expires_at,
    then signs the whole body. Does not mutate the input dict.
    """
    now = datetime.now(timezone.utc)
    bound = {k: v for k, v in doc.items() if k != _SIGNATURE_FIELD}
    bound["engagement_id"] = engagement_id or bound.get("engagement_id") or f"ENG-{uuid.uuid4().hex[:12]}"
    bound["issued_at"] = now.isoformat()
    bound["expires_at"] = (now + timedelta(days=ttl_days)).isoformat()
    sig = hmac.new(_roe_key(create=True), _canonical(bound), hashlib.sha256).hexdigest()
    return {**bound, _SIGNATURE_FIELD: sig}


def verify_roe(doc: dict) -> tuple[bool, str]:
    """Verify a RoE document's signature and engagement binding.

    Returns (True, "ok") only when the signature matches, the required binding
    fields are present, and the RoE has not expired. Every other outcome is a
    fail-closed (False, reason).
    """
    sig = doc.get(_SIGNATURE_FIELD)
    if not sig:
        return False, "unsigned RoE (no signature field)"
    if not doc.get("engagement_id"):
        return False, "RoE missing engagement_id"
    expires_at = doc.get("expires_at")
    if not expires_at:
        return False, "RoE missing expires_at"

    try:
        key = _roe_key(create=False)
    except RuntimeError as e:
        return False, str(e)

    expected = hmac.new(key, _canonical(doc), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False, "signature mismatch — RoE tampered or signed with a different key"

    try:
        exp = datetime.fromisoformat(expires_at)
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return False, f"malformed expires_at: {expires_at!r}"
    if exp < datetime.now(timezone.utc):
        return False, f"RoE expired at {expires_at}"

    return True, "ok"


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _cli(argv: list[str]) -> int:
    if len(argv) < 2 or argv[0] not in {"sign", "verify"}:
        print(__doc__)
        return 2

    action, path = argv[0], argv[1]
    try:
        with open(path, "r") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[roe_signing] cannot read {path}: {e}", file=sys.stderr)
        return 1

    if action == "verify":
        ok, reason = verify_roe(doc)
        print(f"{'OK' if ok else 'INVALID'}: {reason}")
        return 0 if ok else 1

    # sign
    engagement_id = None
    ttl_days = 7.0
    rest = argv[2:]
    for i, tok in enumerate(rest):
        if tok == "--engagement-id" and i + 1 < len(rest):
            engagement_id = rest[i + 1]
        if tok == "--ttl-days" and i + 1 < len(rest):
            ttl_days = float(rest[i + 1])
    signed = sign_roe(doc, engagement_id=engagement_id, ttl_days=ttl_days)
    with open(path, "w") as f:
        json.dump(signed, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"Signed {path}: engagement_id={signed['engagement_id']} "
          f"expires_at={signed['expires_at']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
