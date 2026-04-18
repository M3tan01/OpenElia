#!/usr/bin/env python3
import hashlib
import hmac
import json
import ipaddress
import re
import os
from datetime import datetime, timezone

class ScopeValidator:
    _resolution_cache = {}  # Static cache across instances

    def __init__(self, roe_path="roe.json"):
        self.roe_path = roe_path
        self.authorized_subnets = []
        self.blacklisted_ips = []
        self.prohibited_tools = []
        self.quiet_hours = {}
        self.roe_loaded = False
        self._load_roe()

    def _load_roe(self):
        if not os.path.exists(self.roe_path):
            return  # roe_loaded stays False → fail-closed
        try:
            with open(self.roe_path, "r") as f:
                roe = json.load(f)
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

    def is_allowed(self, target: str) -> bool:
        # Fail closed: no roe.json or empty authorized_subnets → block all
        if not self.roe_loaded or not self.authorized_subnets:
            return False

        if target in self._resolution_cache:
            return self._resolution_cache[target]

        try:
            target_ip = ipaddress.ip_address(target)

            if target_ip in self.blacklisted_ips:
                self._resolution_cache[target] = False
                return False

            for subnet in self.authorized_subnets:
                if target_ip in subnet:
                    self._resolution_cache[target] = True
                    return True

            self._resolution_cache[target] = False
            return False
        except ValueError:
            import socket
            try:
                resolved_ip = socket.gethostbyname(target)
                result = self.is_allowed(resolved_ip)
                self._resolution_cache[target] = result
                return result
            except Exception:
                return False

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
    DESTRUCTIVE_PATTERNS = [
        r"rm\s+-rf\s+/*",
        r"vssadmin\s+delete\s+shadows",
        r">\s*/dev/sda",
        r"mkfs",
        r"dd\s+if=/dev/zero",
        r"Format-Volume",
        r"Remove-Item\s+-Recurse\s+-Force\s+C:\\"
    ]

    @classmethod
    def is_safe(cls, payload: str) -> bool:
        for pattern in cls.DESTRUCTIVE_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                return False
        return True

class AuditLogger:
    _LOG_HMAC_KEY_ENV = "AUDIT_LOG_HMAC_KEY"

    def __init__(self, log_path="state/audit.log"):
        self.log_path = log_path
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def _hmac_key(self) -> bytes:
        key = os.environ.get(self._LOG_HMAC_KEY_ENV)
        if not key:
            try:
                from secret_store import SecretStore
                key = SecretStore.get_secret(self._LOG_HMAC_KEY_ENV)
            except Exception:
                pass
        if not key:
            import secrets as _sec
            key = _sec.token_hex(32)
            try:
                from secret_store import SecretStore
                SecretStore.set_secret(self._LOG_HMAC_KEY_ENV, key)
            except Exception:
                os.environ[self._LOG_HMAC_KEY_ENV] = key
        return key.encode() if isinstance(key, str) else key

    def _last_chain_hash(self) -> str:
        """Return the _chain value of the last log entry, or 'GENESIS'."""
        if not os.path.exists(self.log_path):
            return "GENESIS"
        last_hash = "GENESIS"
        try:
            with open(self.log_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entry = json.loads(line)
                            last_hash = entry.get("_chain", last_hash)
                        except json.JSONDecodeError:
                            pass
        except OSError:
            pass
        return last_hash

    def verify_chain(self) -> bool:
        """
        Validate the entire HMAC chain of the audit log.
        Returns False if any entry has been tampered with or if the chain is broken.
        """
        if not os.path.exists(self.log_path):
            return True # Nothing to verify

        expected_prev_hash = "GENESIS"
        try:
            with open(self.log_path, "r") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line: continue
                    
                    entry = json.loads(line)
                    stored_chain = entry.pop("_chain", None)
                    if not stored_chain:
                        print(f"[!] Audit Failure: Missing signature at line {line_num}")
                        return False
                    
                    # Recompute HMAC
                    entry_body = json.dumps(entry, sort_keys=True)
                    chain_input = f"{expected_prev_hash}:{entry_body}".encode()
                    computed_hash = hmac.new(self._hmac_key(), chain_input, hashlib.sha256).hexdigest()
                    
                    if not hmac.compare_digest(stored_chain, computed_hash):
                        print(f"[!] Audit Failure: Signature mismatch at line {line_num}")
                        return False
                    
                    expected_prev_hash = stored_chain
            return True
        except Exception as e:
            print(f"[!] Audit Verification Error: {str(e)}")
            return False

    def log_event(self, source: str, target: str, payload: str, status: str, reason: str = ""):
        """
        Log a security event with cryptographic chaining and PII redaction.
        """
        # Tier 4: Forensic Privacy - Redact before hashing/chaining
        redacted_payload = PrivacyGuard.redact(payload)
        
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "target": target,
            "payload": redacted_payload,
            "status": status,
            "reason": reason,
        }

        # HMAC chain: each entry's _chain covers (prev_chain + this_event_json)
        prev_hash = self._last_chain_hash()
        event_body = json.dumps(event, sort_keys=True)
        chain_input = f"{prev_hash}:{event_body}".encode()
        event["_chain"] = hmac.new(self._hmac_key(), chain_input, hashlib.sha256).hexdigest()

        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(event) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            # Tier 4: Fail-Closed Architecture
            raise RuntimeError(f"AUDIT FAILURE: Unable to write to forensic log. Error: {str(e)}")

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
