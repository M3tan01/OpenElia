#!/usr/bin/env python3
import json
import ipaddress
import re
import os
from datetime import datetime, timezone

class ScopeValidator:
    _resolution_cache = {}  # Static cache across instances

    def __init__(self, roe_path: str | None = None):
        # An explicit path (even unusual) wins; only None falls back to env.
        # `""` is intentionally NOT treated as "use env" — it fails closed in
        # _load_roe (the file "" does not exist) rather than silently switching.
        self.roe_path = roe_path if roe_path is not None else os.getenv("OPENELIA_ROE_PATH", "roe.json")
        self.authorized_subnets = []
        self.blacklisted_ips = []
        self.prohibited_tools = []
        self.quiet_hours = {}
        self.roe_loaded = False
        self._roe_mtime = None  # mtime of roe_path at last successful/attempted load
        self._load_roe()

    def _load_roe(self):
        self._roe_mtime = None
        if not os.path.exists(self.roe_path):
            return  # roe_loaded stays False → fail-closed
        try:
            self._roe_mtime = os.path.getmtime(self.roe_path)
            with open(self.roe_path, "r") as f:
                roe = json.load(f)
            # Fail-closed: the RoE must be HMAC-signed and bound to a live
            # engagement, so a copied/edited/stale roe.json cannot silently
            # re-scope an engagement. Dev/test/migration bypass via the explicit
            # OPENELIA_ALLOW_UNSIGNED_ROE=1 danger flag (mirrors the audit-key idiom).
            if os.getenv("OPENELIA_ALLOW_UNSIGNED_ROE") != "1":
                from roe_signing import verify_roe
                ok, reason = verify_roe(roe)
                if not ok:
                    import sys
                    print(
                        f"[ScopeValidator] REJECTED {self.roe_path}: {reason} (fail-closed). "
                        f"Sign it with 'python roe_signing.py sign {self.roe_path}' or set "
                        f"OPENELIA_ALLOW_UNSIGNED_ROE=1 for dev.",
                        file=sys.stderr,
                    )
                    return  # roe_loaded stays False → block all
            self.authorized_subnets = [
                ipaddress.ip_network(s, strict=False)
                for s in roe.get("authorized_subnets", [])
            ]
            self.blacklisted_ips = [
                ipaddress.ip_address(ip)
                for ip in roe.get("blacklisted_ips", [])
            ]
            self.prohibited_tools = roe.get("prohibited_tools", [])
            self.quiet_hours = roe.get("quiet_hours", {})
            self.roe_loaded = True
        except Exception as e:
            import sys
            print(f"[ScopeValidator] ERROR: Failed to parse {self.roe_path}: {e}", file=sys.stderr)
            # roe_loaded stays False → fail-closed

    def _purge_cache_for_path(self):
        """Drop all cached decisions tied to this validator's roe_path."""
        for k in [k for k in self._resolution_cache if k[0] == self.roe_path]:
            del self._resolution_cache[k]

    def _refresh_if_changed(self):
        """Hot-reload the RoE if its file changed since load, so a scope-NARROWING
        edit takes effect without a process restart. Fail-closed on stat errors."""
        try:
            current = os.path.getmtime(self.roe_path)
        except OSError:
            # File vanished after load → fail closed and drop stale cache entries.
            if self.roe_loaded:
                self.roe_loaded = False
                self.authorized_subnets = []
                self._purge_cache_for_path()
            return
        if current != self._roe_mtime:
            self._purge_cache_for_path()
            self._load_roe()

    def is_allowed(self, target: str) -> bool:
        # Fail closed: no roe.json or empty authorized_subnets → block all
        if not self.roe_loaded or not self.authorized_subnets:
            return False

        # Pick up a live RoE edit (esp. scope narrowing) before serving cache.
        self._refresh_if_changed()
        if not self.roe_loaded or not self.authorized_subnets:
            return False

        if (self.roe_path, target) in self._resolution_cache:
            return self._resolution_cache[(self.roe_path, target)]

        try:
            target_ip = ipaddress.ip_address(target)

            if target_ip in self.blacklisted_ips:
                self._resolution_cache[(self.roe_path, target)] = False
                return False

            for subnet in self.authorized_subnets:
                if target_ip in subnet:
                    self._resolution_cache[(self.roe_path, target)] = True
                    return True

            self._resolution_cache[(self.roe_path, target)] = False
            return False
        except ValueError:
            # target is a hostname, not a literal IP. Resolve EVERY A/AAAA
            # record and require ALL of them to be in scope — a single in-scope
            # record is not enough. Round-robin DNS and DNS-rebinding mean the
            # address the tool ultimately connects to may be any record in the
            # set, so if even one resolves out of scope we must fail closed.
            #
            # Do NOT cache the hostname->bool decision: DNS is time-varying, and
            # a cached allow would pin a stale (or attacker-flipped) answer for
            # the life of the process, defeating the RoE boundary. Only literal
            # IP decisions (the recursive calls below) are cached, and those are
            # deterministic. Residual: an attacker who flips DNS at the exact
            # connect() moment can still rebind after this check — closing that
            # fully requires IP-pinning at the socket layer, which is downstream
            # of this gate. This narrows the window to the connect race only.
            import socket
            try:
                infos = socket.getaddrinfo(target, None)
            except Exception:
                return False
            resolved = {info[4][0] for info in infos}
            if not resolved:
                return False
            return all(self.is_allowed(ip) for ip in resolved)

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check if a specific tool is prohibited by the RoE."""
        if not self.roe_loaded:
            return False
        return tool_name not in self.prohibited_tools

    def is_within_quiet_hours(self) -> tuple[bool, str]:
        """
        Check if current time is within quiet hours.
        Returns (is_quiet, message).
        """
        if not self.roe_loaded or not self.quiet_hours.get("enabled"):
            return False, ""

        now = datetime.now().time()
        try:
            start_time = datetime.strptime(self.quiet_hours["start"], "%H:%M").time()
            end_time = datetime.strptime(self.quiet_hours["end"], "%H:%M").time()
            
            # Handle overnight ranges (e.g. 22:00 to 06:00)
            if start_time <= end_time:
                is_quiet = start_time <= now <= end_time
            else:
                is_quiet = now >= start_time or now <= end_time
            
            return is_quiet, self.quiet_hours.get("message", "Quiet hours active.")
        except Exception:
            return False, ""

class SemanticFirewall:
    """Defense-in-depth denylist for obviously-destructive payloads.

    IMPORTANT: this is NOT the primary safety control and must never be relied
    on as one. A regex denylist can never be complete — an attacker with control
    of the payload can always encode, obfuscate, or find an un-listed equivalent.
    The enforceable boundary is the RoE scope check (ScopeValidator.is_allowed):
    it decides *where* an action may run. This firewall only catches a few
    well-known "wipe the box" commands so a fat-fingered or obviously-malicious
    payload is stopped even when the target happens to be in scope.

    Patterns below cover common destructive families and their obvious flag
    variants (e.g. `rm -rf` and `rm -fr`). Over-matching is acceptable here:
    a false positive costs one extra confirmation, a false negative could wipe
    an authorized host.
    """

    DESTRUCTIVE_PATTERNS = [
        r"\brm\s+-[a-z]*r[a-z]*f[a-z]*",     # rm -rf, -Rf, -rfv ...
        r"\brm\s+-[a-z]*f[a-z]*r[a-z]*",     # rm -fr (flags reversed)
        r"\bshred\b",
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:",  # bash fork bomb
        r"vssadmin\s+delete\s+shadows",
        r"wmic\s+shadowcopy\s+delete",
        r">\s*/dev/sd[a-z]",
        r"\bmkfs(\.\w+)?\b",
        r"dd\s+if=/dev/(zero|random|urandom)",
        r"Format-Volume",
        r"Remove-Item\s+.*-Recurse\s+.*-Force",  # any flag order
        r"Clear-Content\b",
        r"\bdel\s+/[fsq]",                   # del /f /s /q
        r"cipher\s+/w:",                     # secure-wipe free space
        r"wevtutil\s+cl",                    # clear Windows event logs
    ]

    @classmethod
    def is_safe(cls, payload: str) -> bool:
        for pattern in cls.DESTRUCTIVE_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                return False
        return True

class AuditLogger:
    """
    Thin wrapper around core.audit_chain that adds security-event schema
    (source, target, payload, status, reason) and PII redaction.

    Delegates all HMAC chaining to core.audit_chain so there is a single
    canonical chain implementation across the entire codebase.
    """

    def __init__(self, log_path=None):
        import os
        from pathlib import Path
        # Default resolves the state dir at call time so tests (and any operator
        # override) can redirect the audit trail via OPENELIA_STATE_DIR — matching
        # webdash/guards.py and mcp_servers/siem which resolve the same var. A
        # hardcoded "state/audit.log" here bypassed that and leaked test-run
        # security events into the live HMAC-chained forensic log.
        if log_path is None:
            log_path = Path(os.getenv("OPENELIA_STATE_DIR", "state")) / "audit.log"
        self.log_path = Path(log_path)

    def verify_chain(self) -> bool:
        """Delegate chain verification to core.audit_chain.verify()."""
        from core.audit_chain import verify
        ok, msg = verify(self.log_path)
        if not ok:
            print(f"[!] Audit Failure: {msg}")
        return ok

    def log_event(self, source: str, target: str, payload: str, status: str, reason: str = ""):
        """
        Log a security event with PII redaction and HMAC chaining.
        Appended via core.audit_chain so the chain is consistent with
        task-result entries written by core.hooks.
        """
        from core.audit_chain import append
        redacted_payload = PrivacyGuard.redact(payload)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "target": target,
            "payload": redacted_payload,
            "status": status,
            "reason": reason,
        }
        try:
            append(self.log_path, record)
        except Exception as e:
            raise RuntimeError(f"AUDIT FAILURE: Unable to write to forensic log. Error: {e}")

class PrivacyGuard:
    # Common PII and sensitive credential patterns
    PII_PATTERNS = {
        "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
        "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "PRIVATE_KEY": r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----",
        "AWS_ACCESS_KEY": r"\bAKIA[0-9A-Z]{16}\b",
        "AWS_SECRET_KEY": r"(?i)aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key[\s:=]+[A-Za-z0-9/+=]{40}",
        "BEARER_TOKEN": r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}",
        "DB_CONN_STRING": r"(?i)(?:postgres(?:ql)?|mysql|mssql|mongodb|redis|oracle)://[^\s\"']+",
        "SLACK_WEBHOOK": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        "ANTHROPIC_KEY": r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b",
        "GENERIC_API_KEY": r"(?i)(?:api[_\-]?key|api[_\-]?secret|access[_\-]?token)[\s:=]+['\"]?[A-Za-z0-9\-_\.]{16,}['\"]?",
    }

    @classmethod
    def redact(cls, data: any) -> any:
        """
        Recursively redact PII from strings, dictionaries, and lists.
        """
        if isinstance(data, dict):
            return {k: cls.redact(v) for k, v in data.items()}
        if isinstance(data, list):
            return [cls.redact(i) for i in data]
        if not isinstance(data, str):
            return data

        redacted = data
        for label, pattern in cls.PII_PATTERNS.items():
            redacted = re.sub(pattern, f"[REDACTED_{label}]", redacted)
        return redacted

def enforce_security_gate(source: str, target: str, payload: str):
    validator = ScopeValidator()
    firewall = SemanticFirewall()
    logger = AuditLogger()

    # 1. Target Validation (Mathematical Boundary)
    # The `target and` guard is intentional: some legitimate operations have no
    # network target (e.g. local cleanup-rollback undos registered via
    # cleanup_registry, which pass an empty target). Forcing scope validation on
    # an empty target would fail-closed every such call and deadlock the
    # kill-switch's own rollback path. An empty target has no destination to be
    # out-of-scope; the quiet-hours, prohibited-tool, and semantic-firewall rails
    # below still run unconditionally on the payload, so a destructive no-target
    # payload is still caught. Only the two agent/MCP callers reach this with a
    # real (always non-empty) IP, so this guard does not widen the attack surface.
    if target and not validator.is_allowed(target):
        logger.log_event(source, target, payload, "BLOCKED", "Mathematical Boundary Breach")
        raise PermissionError("Mathematical Boundary Breach: Target is not in authorized scope.")

    # 2. Quiet Hours Check
    is_quiet, quiet_msg = validator.is_within_quiet_hours()
    if is_quiet:
        logger.log_event(source, target, payload, "BLOCKED", "Quiet Hours Breach")
        raise PermissionError(f"Rules of Engagement Breach: {quiet_msg}")

    # 3. Tool Prohibition Check
    if not validator.is_tool_allowed(source):
        logger.log_event(source, target, payload, "BLOCKED", "Prohibited Tool Usage")
        raise PermissionError(f"Rules of Engagement Breach: Tool '{source}' is prohibited by policy.")

    # 4. Semantic Firewall (Destructive Pattern Check)
    if not firewall.is_safe(payload):
        logger.log_event(source, target, payload, "BLOCKED", "Destructive Payload Detected")
        raise PermissionError("Semantic Firewall Breach: Destructive Payload Detected.")

    # Log successful validation before execution
    logger.log_event(source, target, payload, "AUTHORIZED", "Passed security checks")
    return True
