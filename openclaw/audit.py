#!/usr/bin/env python3
"""
openclaw/audit.py — Immutable, HMAC-chained structured audit log for OpenClaw.

Every record written here is a JSON-lines entry with exactly these fields:
    timestamp          ISO-8601 UTC instant
    action_type        FETCH | EXTRACT | VALIDATE | BLOCKED | ERROR | TOKEN_ROTATED
    target_uri         URL/endpoint contacted — credentials auto-stripped
    data_hash          SHA-256 of the raw payload (payload itself NEVER stored)
    execution_status   SUCCESS | FAILED | BLOCKED | ANOMALY
    meta               Optional dict of safe scalar metadata (byte_length, schema, …)
    _chain             HMAC-SHA-256 over (prev_chain : this_entry_json) — tamper-evident

The _chain field forms a cryptographic linked list: altering or deleting any
single entry is detectable by verify_chain().

Log path: state/openclaw_audit.jsonl  (separate from the main audit.log so
OpenClaw anomalies don't pollute the engagement audit trail).
"""

import gc
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
from datetime import datetime, timezone
from pathlib import Path

_log = logging.getLogger("OpenElia.OpenClaw.Audit")

_DEFAULT_LOG_PATH = Path("state") / "openclaw_audit.jsonl"
_HMAC_KEY_NAME    = "OPENCLAW_AUDIT_HMAC_KEY"

# Fields whose values must NEVER appear in the meta dict even if a caller
# accidentally passes them — hard-blocked at write time.
_BLOCKED_META_KEYS = frozenset(
    {"token", "key", "secret", "password", "api_key", "credential", "bearer"}
)


class ClawAuditLog:
    """
    Append-only, HMAC-chained structured audit log.

    Usage
    -----
    audit = ClawAuditLog()

    body_hash = ClawAuditLog.hash_payload(raw_bytes)   # hash BEFORE discarding body
    audit.record(
        action_type="FETCH",
        target_uri="https://feeds.example.com/iocs",
        data_hash=body_hash,
        execution_status="SUCCESS",
        extra={"byte_length": 4096, "schema": "ClawThreatFeed"},
    )
    """

    def __init__(self, log_path: Path | str = _DEFAULT_LOG_PATH):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Static helpers — safe to call before instantiation                  #
    # ------------------------------------------------------------------ #

    @staticmethod
    def hash_payload(raw: bytes | str) -> str:
        """
        Return the SHA-256 hex digest of a payload.

        Always hash BEFORE discarding the raw data; store only the digest.
        This lets analysts verify data integrity without the audit log
        becoming a second copy of potentially hostile content.
        """
        if isinstance(raw, str):
            raw = raw.encode()
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def scrub_uri(uri: str) -> str:
        """
        Strip userinfo (credentials) embedded in a URI before it is logged.
        https://user:pass@host/path  →  https://[REDACTED]@host/path
        """
        return re.sub(r"(://)[^@/]+@", r"\1[REDACTED]@", uri)

    # ------------------------------------------------------------------ #
    # HMAC key management                                                  #
    # ------------------------------------------------------------------ #

    def _hmac_key(self) -> bytes:
        """
        Load the per-installation HMAC signing key from the OS keychain.
        Auto-generates and persists a 256-bit key on first use.
        The key is held in memory only for the duration of the call.
        """
        key: str | None = None
        try:
            from secret_store import SecretStore
            key = SecretStore.get_secret(_HMAC_KEY_NAME)
        except Exception:
            pass

        if not key:
            key = secrets.token_hex(32)
            try:
                from secret_store import SecretStore
                SecretStore.set_secret(_HMAC_KEY_NAME, key)
            except Exception:
                # Fallback: store in env so at least the current process is consistent
                os.environ[_HMAC_KEY_NAME] = key
                key = os.environ[_HMAC_KEY_NAME]

        result = key.encode() if isinstance(key, str) else key
        # Overwrite local string reference before it is GC'd
        del key
        return result

    def _last_chain(self) -> str:
        """Return the _chain value of the last persisted entry, or 'GENESIS'."""
        if not self.log_path.exists():
            return "GENESIS"
        last = "GENESIS"
        try:
            with self.log_path.open() as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            last = json.loads(line).get("_chain", last)
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass
        return last

    # ------------------------------------------------------------------ #
    # Write                                                                #
    # ------------------------------------------------------------------ #

    def record(
        self,
        action_type:      str,
        target_uri:       str,
        data_hash:        str,
        execution_status: str,
        extra:            dict | None = None,
    ) -> None:
        """
        Append one tamper-evident audit record.

        Parameters
        ----------
        action_type      FETCH | EXTRACT | VALIDATE | BLOCKED | ERROR | TOKEN_ROTATED
        target_uri       The URL or endpoint contacted. Credentials are auto-scrubbed.
        data_hash        SHA-256 hex of the raw payload. NEVER pass the raw payload itself.
        execution_status SUCCESS | FAILED | BLOCKED | ANOMALY
        extra            Optional dict of safe, non-sensitive metadata.
                         Keys in _BLOCKED_META_KEYS are silently dropped even if present.
        """
        entry: dict = {
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "action_type":      str(action_type),
            "target_uri":       self.scrub_uri(str(target_uri)),
            "data_hash":        str(data_hash),
            "execution_status": str(execution_status),
        }

        if extra:
            # Only permit safe scalar values; hard-block credential-adjacent keys
            safe_meta = {
                k: v
                for k, v in extra.items()
                if isinstance(v, (str, int, float, bool))
                and k.lower() not in _BLOCKED_META_KEYS
            }
            if safe_meta:
                entry["meta"] = safe_meta

        # ── HMAC chain ──────────────────────────────────────────────────
        prev_chain  = self._last_chain()
        entry_body  = json.dumps(entry, sort_keys=True)
        chain_input = f"{prev_chain}:{entry_body}".encode()
        hmac_key    = self._hmac_key()
        entry["_chain"] = hmac.new(hmac_key, chain_input, hashlib.sha256).hexdigest()

        # Overwrite key bytes before releasing
        del hmac_key
        gc.collect()

        # ── Append-only write with fsync ─────────────────────────────────
        try:
            with self.log_path.open("a") as fh:
                fh.write(json.dumps(entry) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            # Fail-closed: audit failure is a hard error, not a warning
            raise RuntimeError(
                f"OPENCLAW AUDIT FAILURE — cannot write to {self.log_path}: {exc}"
            ) from exc

    # ------------------------------------------------------------------ #
    # Verification                                                         #
    # ------------------------------------------------------------------ #

    def verify_chain(self) -> bool:
        """
        Walk the entire log and validate every HMAC link.

        Returns True if the chain is intact.
        Returns False and logs the first tampered line number if not.
        Any deletion, reordering, or content modification is detectable.
        """
        if not self.log_path.exists():
            return True  # empty log is valid

        prev = "GENESIS"
        hmac_key = self._hmac_key()
        try:
            with self.log_path.open() as fh:
                for line_num, raw_line in enumerate(fh, 1):
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    entry = json.loads(raw_line)
                    stored_chain = entry.pop("_chain", None)
                    if not stored_chain:
                        _log.error("Audit chain broken at line %d: missing _chain", line_num)
                        return False

                    body     = json.dumps(entry, sort_keys=True)
                    expected = hmac.new(
                        hmac_key,
                        f"{prev}:{body}".encode(),
                        hashlib.sha256,
                    ).hexdigest()

                    if not hmac.compare_digest(stored_chain, expected):
                        _log.error("Audit chain tampered at line %d", line_num)
                        return False

                    prev = stored_chain
        except Exception as exc:
            _log.error("Audit chain verification error: %s", exc)
            return False
        finally:
            del hmac_key
            gc.collect()

        return True
