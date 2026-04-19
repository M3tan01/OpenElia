"""
core/audit_chain.py — HMAC-SHA256 tamper-evident audit log.

Each record written to the chain includes a `chain_hash` field:

    chain_hash = HMAC-SHA256(prev_chain_hash | canonical_json(record))

where `|` denotes concatenation and `prev_chain_hash` for the first entry
is the genesis value (64 hex zeros). This makes any tampering with a
historical entry detectable: the hash chain breaks at the modified record.

The HMAC key is sourced from SecretStore("AUDIT_HMAC_KEY"). If not set,
a deterministic fallback key is used so the chain always functions — but
operators should set a real key in production (openelia lock --set-hmac-key).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

_GENESIS_HASH = "0" * 64
_FALLBACK_KEY = b"openelia-audit-default-key-change-in-prod"


def _hmac_key() -> bytes:
    from secret_store import SecretStore
    raw = SecretStore.get_secret("AUDIT_HMAC_KEY")
    return raw.encode() if raw else _FALLBACK_KEY


def _canonical(record: dict) -> bytes:
    """Stable JSON serialisation — sorted keys, no extra whitespace."""
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()


def _compute_hash(prev_hash: str, record: dict) -> str:
    key = _hmac_key()
    msg = prev_hash.encode() + _canonical(record)
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _last_hash(log_path: Path) -> str:
    """Return the chain_hash of the last record in the log, or genesis."""
    if not log_path.exists():
        return _GENESIS_HASH
    last_line = ""
    with log_path.open() as fh:
        for line in fh:
            stripped = line.strip()
            if stripped:
                last_line = stripped
    if not last_line:
        return _GENESIS_HASH
    try:
        return json.loads(last_line).get("chain_hash", _GENESIS_HASH)
    except (json.JSONDecodeError, KeyError):
        return _GENESIS_HASH


def append(log_path: Path, record: dict[str, Any]) -> str:
    """
    Append `record` to `log_path` with an HMAC chain_hash field added.

    Returns the chain_hash of the appended entry.
    The `chain_hash` key must not already exist in `record` — it is
    injected here to ensure it is always computed over the canonical
    record content.
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)

    record_copy = {k: v for k, v in record.items() if k != "chain_hash"}
    prev = _last_hash(log_path)
    chain_hash = _compute_hash(prev, record_copy)
    record_copy["chain_hash"] = chain_hash

    with log_path.open("a") as fh:
        fh.write(json.dumps(record_copy, sort_keys=True) + "\n")

    return chain_hash


def verify(log_path: Path) -> tuple[bool, str]:
    """
    Verify the integrity of the entire audit log.

    Returns:
        (True, "OK") if the chain is intact.
        (False, "<reason>") if any entry has been tampered with.
    """
    if not log_path.exists():
        return True, "OK (empty log)"

    key = _hmac_key()
    prev = _GENESIS_HASH

    with log_path.open() as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False, f"Line {lineno}: invalid JSON"

            stored_hash = entry.pop("chain_hash", None)
            if stored_hash is None:
                return False, f"Line {lineno}: missing chain_hash"

            expected = hmac.new(key, prev.encode() + _canonical(entry), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(stored_hash, expected):
                return False, f"Line {lineno}: chain_hash mismatch — log has been tampered"

            prev = stored_hash

    return True, "OK"
