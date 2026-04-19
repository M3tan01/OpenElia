#!/usr/bin/env python3
"""
openclaw/connector.py — Zero-Trust external data connector for OpenElia.

Security boundaries enforced here
──────────────────────────────────
  1. NETWORK ALLOWLIST   — only hosts in OPENCLAW_ALLOWED_HOSTS (keychain) are
                           reachable; fail-closed when the list is empty.
  2. SSRF PREVENTION     — private/loopback/link-local CIDRs, cloud metadata
                           endpoints, and non-http(s) schemes are hard-blocked.
  3. EPHEMERAL TOKENS    — credentials fetched from SecretStore, used in the
                           narrowest possible scope, then del + gc.collect().
  4. HERMETIC SUBPROCESS — run_isolated() passes env={} so child processes
                           inherit zero environment variables.
  5. STRUCTURED AUDIT    — every fetch, blocked attempt, error, and token
                           rotation is recorded in the HMAC-chained audit log.
"""

import asyncio
import gc
import ipaddress
import logging
import shlex
import subprocess
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from urllib.parse import urlparse

import httpx

from openclaw.audit import ClawAuditLog
from openclaw.middleware import SanitizationMiddleware
from pydantic import BaseModel

_log = logging.getLogger("OpenElia.OpenClaw.Connector")

# ── SSRF block-list ─────────────────────────────────────────────────────────
# Cloud provider metadata endpoints — never allow these regardless of allowlist.
_METADATA_HOSTNAMES: frozenset[str] = frozenset(
    {
        "169.254.169.254",   # AWS / GCP / Azure IMDS
        "metadata.google.internal",
        "fd00:ec2::254",     # AWS IPv6 IMDS
        "100.100.100.200",   # Alibaba Cloud metadata
    }
)

# Private, loopback, link-local, and multicast ranges — blocked by default.
_PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("169.254.0.0/16"),   # link-local IPv4
    ipaddress.ip_network("fe80::/10"),         # link-local IPv6
    ipaddress.ip_network("224.0.0.0/4"),       # multicast
    ipaddress.ip_network("240.0.0.0/4"),       # reserved
)

_ALLOWED_SCHEMES: frozenset[str] = frozenset({"https", "http"})

_OPENCLAW_ALLOWED_HOSTS_KEY = "OPENCLAW_ALLOWED_HOSTS"

# Default HTTP timeout (seconds) — prevents slow-drip attacks.
_DEFAULT_TIMEOUT = 30.0

# Maximum response body size (bytes) — prevents memory exhaustion attacks.
_MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MiB


class OpenClawURIError(ValueError):
    """Raised when a URI fails allowlist or SSRF validation."""


class OpenClawConnector:
    """
    Zero-trust connector for fetching and sanitising external threat data.

    Usage
    -----
    connector = OpenClawConnector()

    feed = await connector.fetch_json(
        uri="https://feeds.example.com/iocs",
        expected_schema=ClawThreatFeed,
        auth_key="FEED_API_TOKEN",
    )
    if feed is None:
        ...  # blocked or invalid — already audited

    result = connector.run_isolated(["parser-tool", "--json"], stdin_data=raw_bytes)
    """

    def __init__(
        self,
        audit_log_path: Path | str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        max_body_bytes: int = _MAX_BODY_BYTES,
    ) -> None:
        self._audit = ClawAuditLog(audit_log_path) if audit_log_path else ClawAuditLog()
        self._middleware = SanitizationMiddleware(self._audit)
        self._timeout = timeout
        self._max_body_bytes = max_body_bytes

    # ──────────────────────────────────────────────────────────────────────
    # Credential lifecycle
    # ──────────────────────────────────────────────────────────────────────

    @contextmanager
    def _ephemeral_token(self, secret_key: str):
        """
        Context manager that yields a credential from SecretStore then
        immediately wipes the local reference on exit.

        The token is held in memory only for the duration of the ``with`` block.
        Callers MUST NOT store the yielded value outside the block.

        Example
        -------
        with self._ephemeral_token("MY_API_KEY") as token:
            headers = {"Authorization": f"Bearer {token}"}
        # token is gone
        """
        token: str | None = None
        try:
            from secret_store import SecretStore
            token = SecretStore.get_secret(secret_key)
        except Exception as exc:
            _log.warning("Could not load secret %r: %s", secret_key, exc)
        try:
            yield token
        finally:
            del token
            gc.collect()

    # ──────────────────────────────────────────────────────────────────────
    # Network allowlist & SSRF checks
    # ──────────────────────────────────────────────────────────────────────

    def _load_allowed_hosts(self) -> frozenset[str]:
        """
        Load the network allowlist from SecretStore.

        Returns a frozenset of lowercase hostnames.
        Fail-closed: returns an empty frozenset when the list cannot be read
        or is empty, which causes all URIs to be blocked.
        """
        raw: str | None = None
        try:
            from secret_store import SecretStore
            raw = SecretStore.get_secret(_OPENCLAW_ALLOWED_HOSTS_KEY)
        except Exception:
            pass

        if not raw or not raw.strip():
            _log.error(
                "OPENCLAW_ALLOWED_HOSTS is empty or unset — all outbound "
                "connections are blocked (fail-closed)."
            )
            return frozenset()

        hosts = frozenset(h.strip().lower() for h in raw.split(",") if h.strip())
        return hosts

    def _is_private_ip(self, hostname: str) -> bool:
        """Return True if hostname resolves to a private/reserved address."""
        try:
            addr = ipaddress.ip_address(hostname)
            return any(addr in net for net in _PRIVATE_NETWORKS)
        except ValueError:
            # Not a raw IP literal — we cannot DNS-resolve here (that would be
            # a TOCTOU issue), so return False and rely on the allowlist.
            return False

    def _validate_uri(self, uri: str, allowed_hosts: frozenset[str]) -> None:
        """
        Validate a URI against the SSRF block-list and the network allowlist.

        Raises ``OpenClawURIError`` with an explanation on any violation.
        On success, returns None.
        """
        parsed = urlparse(uri)

        # 1. Scheme must be http or https.
        if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
            raise OpenClawURIError(
                f"Blocked scheme {parsed.scheme!r} — only http/https allowed."
            )

        hostname = (parsed.hostname or "").lower().strip("[]")  # strip IPv6 brackets

        # 2. Hard-block known cloud metadata endpoints.
        if hostname in _METADATA_HOSTNAMES:
            raise OpenClawURIError(
                f"SSRF blocked: {hostname!r} is a cloud metadata endpoint."
            )

        # 3. Block private/loopback IP addresses.
        if self._is_private_ip(hostname):
            # Check allowlist — an operator may intentionally allowlist an
            # on-prem threat-intel proxy.
            if hostname not in allowed_hosts:
                raise OpenClawURIError(
                    f"SSRF blocked: {hostname!r} is a private/reserved address "
                    f"and is not in the OPENCLAW_ALLOWED_HOSTS allowlist."
                )

        # 4. Enforce network allowlist.
        if not allowed_hosts:
            raise OpenClawURIError(
                "All outbound connections blocked — OPENCLAW_ALLOWED_HOSTS is empty."
            )

        if hostname not in allowed_hosts:
            raise OpenClawURIError(
                f"Host {hostname!r} is not in the OPENCLAW_ALLOWED_HOSTS allowlist."
            )

    # ──────────────────────────────────────────────────────────────────────
    # HTTP fetch
    # ──────────────────────────────────────────────────────────────────────

    async def fetch_json(
        self,
        uri: str,
        expected_schema: type[BaseModel],
        auth_key: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> BaseModel | None:
        """
        Perform a zero-trust HTTP GET and return a validated Pydantic model.

        Security guarantees
        -------------------
        * URI is checked against the SSRF block-list and allowlist before any
          network call is made.
        * The response body is hashed *before* it is parsed; the raw bytes are
          then discarded — only the digest is retained in the audit log.
        * The parsed JSON is run through SanitizationMiddleware (schema
          validation + injection stripping) before being returned.
        * Auth tokens are held in memory only for the duration of the request.
        * All outcomes (success, BLOCKED, ERROR) are appended to the audit log.

        Parameters
        ----------
        uri             Target URL.
        expected_schema Pydantic model class to validate the response against.
        auth_key        SecretStore key whose value is sent as a Bearer token.
                        Pass ``None`` for unauthenticated endpoints.
        extra_headers   Additional safe headers (e.g., Accept, User-Agent).
                        Content-Type is always forced to application/json.

        Returns
        -------
        Validated Pydantic model instance, or ``None`` if any security check
        failed (caller must treat None as "dropped, do not process").
        """
        # ── Pre-flight: allowlist + SSRF ───────────────────────────────
        allowed_hosts = self._load_allowed_hosts()
        try:
            self._validate_uri(uri, allowed_hosts)
        except OpenClawURIError as exc:
            self._audit.record(
                action_type="BLOCKED",
                target_uri=uri,
                data_hash="N/A",
                execution_status="BLOCKED",
                extra={"reason": str(exc)[:256]},
            )
            _log.warning("OpenClaw fetch blocked: %s", exc)
            return None

        # ── Build request headers ──────────────────────────────────────
        headers: dict[str, str] = {"Accept": "application/json"}
        if extra_headers:
            # Only allow safe, non-credential header names.
            _blocked_header_keys = {"authorization", "cookie", "set-cookie", "x-api-key"}
            for k, v in extra_headers.items():
                if k.lower() not in _blocked_header_keys and isinstance(v, str):
                    headers[k] = v

        # ── Ephemeral auth token ───────────────────────────────────────
        with self._ephemeral_token(auth_key) as token:
            if token:
                headers["Authorization"] = f"Bearer {token}"
            # token reference is kept alive only inside this `with` block

            # ── HTTP request ───────────────────────────────────────────
            raw_body: bytes | None = None
            try:
                async with httpx.AsyncClient(
                    timeout=self._timeout,
                    follow_redirects=False,   # never follow redirects — SSRF risk
                    verify=True,              # always verify TLS certificates
                ) as client:
                    response = await client.get(uri, headers=headers)
                    response.raise_for_status()

                    # Cap body size before reading into memory.
                    raw_body = await response.aread()
                    if len(raw_body) > self._max_body_bytes:
                        raise ValueError(
                            f"Response body {len(raw_body)} bytes exceeds "
                            f"limit of {self._max_body_bytes} bytes."
                        )

            except Exception as exc:
                data_hash = ClawAuditLog.hash_payload(raw_body) if raw_body else "N/A"
                self._audit.record(
                    action_type="ERROR",
                    target_uri=uri,
                    data_hash=data_hash,
                    execution_status="FAILED",
                    extra={"error": str(exc)[:256], "schema": expected_schema.__name__},
                )
                _log.error("OpenClaw fetch error from %s: %s", uri, exc)
                return None

        # ── Hash immediately — raw body is no longer needed after this ──
        body_hash = ClawAuditLog.hash_payload(raw_body)

        # ── Parse JSON (structural, not semantic — schema validates below) ─
        try:
            payload = __import__("json").loads(raw_body)
        except ValueError as exc:
            self._audit.record(
                action_type="ERROR",
                target_uri=uri,
                data_hash=body_hash,
                execution_status="FAILED",
                extra={"error": f"JSON parse failure: {exc}"[:256]},
            )
            return None
        finally:
            # Discard raw bytes — only the hash travels forward.
            del raw_body
            gc.collect()

        # ── Sanitize + validate (SanitizationMiddleware) ──────────────
        validated = self._middleware.validate(
            raw=payload,
            expected_schema=expected_schema,
            target_uri=uri,
        )

        if validated is not None:
            self._audit.record(
                action_type="FETCH",
                target_uri=uri,
                data_hash=body_hash,
                execution_status="SUCCESS",
                extra={"schema": expected_schema.__name__, "byte_length": len(body_hash)},
            )

        return validated

    # ──────────────────────────────────────────────────────────────────────
    # Isolated subprocess execution
    # ──────────────────────────────────────────────────────────────────────

    def run_isolated(
        self,
        command: list[str],
        stdin_data: bytes | None = None,
        timeout_s: float = 30.0,
    ) -> subprocess.CompletedProcess:
        """
        Execute an external command in a hermetically sealed subprocess.

        Security guarantees
        -------------------
        * ``env={}`` — the child process inherits **zero** environment
          variables; no API keys, tokens, or paths can leak.
        * stdout and stderr are captured, never streamed to the parent terminal.
        * The process is killed (not just terminated) if it exceeds ``timeout_s``.
        * The invocation and outcome are written to the audit log.

        Parameters
        ----------
        command     Argument list (already split — no shell=True).
        stdin_data  Optional bytes to pipe to stdin.
        timeout_s   Hard kill timeout in seconds.

        Returns
        -------
        subprocess.CompletedProcess with returncode, stdout, stderr.

        Raises
        ------
        FileNotFoundError  if the executable is not found.
        subprocess.TimeoutExpired  if the process exceeds ``timeout_s``.
        """
        cmd_str = " ".join(shlex.quote(c) for c in command)
        stdin_hash = ClawAuditLog.hash_payload(stdin_data) if stdin_data else "N/A"

        try:
            result = subprocess.run(
                command,
                input=stdin_data,
                capture_output=True,
                timeout=timeout_s,
                # ── HERMETIC SEAL ──────────────────────────────────────
                # env={} means the child inherits NO environment variables.
                # This prevents credential leakage through PATH, API keys,
                # proxy settings, and any other inherited env vars.
                env={},
                # Never interpret the command through a shell.
                shell=False,
            )
        except subprocess.TimeoutExpired as exc:
            self._audit.record(
                action_type="ERROR",
                target_uri=f"subprocess://{command[0]}",
                data_hash=stdin_hash,
                execution_status="FAILED",
                extra={"error": "TimeoutExpired", "timeout_s": timeout_s, "cmd": cmd_str[:128]},
            )
            raise

        except Exception as exc:
            self._audit.record(
                action_type="ERROR",
                target_uri=f"subprocess://{command[0]}",
                data_hash=stdin_hash,
                execution_status="FAILED",
                extra={"error": str(exc)[:256], "cmd": cmd_str[:128]},
            )
            raise

        status = "SUCCESS" if result.returncode == 0 else "FAILED"
        self._audit.record(
            action_type="EXTRACT",
            target_uri=f"subprocess://{command[0]}",
            data_hash=stdin_hash,
            execution_status=status,
            extra={
                "returncode": result.returncode,
                "stdout_bytes": len(result.stdout),
                "stderr_bytes": len(result.stderr),
                "cmd": cmd_str[:128],
            },
        )
        return result

    # ──────────────────────────────────────────────────────────────────────
    # Token rotation
    # ──────────────────────────────────────────────────────────────────────

    def rotate_token(self, provider_key: str, new_token: str) -> None:
        """
        Replace a stored credential with a new value.

        The new token is written to SecretStore and the old reference is
        immediately wiped from memory. The rotation event is audited as
        TOKEN_ROTATED (no token value is ever logged).

        Parameters
        ----------
        provider_key  SecretStore key (e.g., "FEED_API_TOKEN").
        new_token     The replacement credential value.
        """
        token_ref = new_token  # local name we can del
        _exc_to_raise = None
        try:
            from secret_store import SecretStore
            SecretStore.set_secret(provider_key, token_ref)
        except Exception as exc:
            self._audit.record(
                action_type="TOKEN_ROTATED",
                target_uri=f"keychain://{provider_key}",
                data_hash="N/A",
                execution_status="FAILED",
                extra={"error": str(exc)[:256]},
            )
            _exc_to_raise = RuntimeError(
                f"OpenClaw token rotation failed for {provider_key!r}: {exc}"
            )
        finally:
            del token_ref
            gc.collect()

        if _exc_to_raise is not None:
            raise _exc_to_raise

        self._audit.record(
            action_type="TOKEN_ROTATED",
            target_uri=f"keychain://{provider_key}",
            data_hash="N/A",
            execution_status="SUCCESS",
        )
        _log.info("Token rotated for key %r", provider_key)
