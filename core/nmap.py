"""core/nmap.py — validate an nmap scan request (target + args).

Single validation implementation shared by three callers so there is no
duplicated logic:
  * the `nmap` CLI command (main.py, via PentesterRecon.run_nmap),
  * the webdash POST /api/nmap route (boundary 400 before a background run
    launches), and
  * PentesterRecon's agent-side guard (`_validate_nmap_*` delegate here).

SECURITY — nmap is a Tier 4 dangerous op. These validators are the
command-injection boundary:
  * the target must be a valid IP, CIDR, or RFC-1123 hostname — not a
    shell fragment; and
  * args are shlex-tokenized and any token carrying a shell metacharacter is
    rejected, so a crafted --args string can never break out of the argv list
    into a shell.
This only guarantees the command line is well-formed. Execution still runs
sterile (PentesterOS), behind the kill-switch, and behind the RoE scope gate.
"""

from __future__ import annotations

import ipaddress
import re
import shlex

# RFC 1123 hostname (labels 1-63 chars, alnum + hyphen, no leading/trailing hyphen).
_HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)
_SHELL_META = re.compile(r"[;&|`$<>!\\]")


def validate_nmap_target(target: str) -> str:
    """Return `target` if it is a valid IP, CIDR, or hostname; else raise ValueError."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        ipaddress.ip_network(target, strict=False)
        return target
    except ValueError:
        pass
    if _HOSTNAME_RE.match(target) and len(target) <= 253:
        return target
    raise ValueError(
        f"Invalid nmap target '{target}'. Must be a valid IP, CIDR, or hostname."
    )


def validate_nmap_args(nmap_args: str) -> list[str]:
    """Tokenize nmap args, rejecting any token with a shell metacharacter."""
    tokens = shlex.split(nmap_args)
    for tok in tokens:
        if _SHELL_META.search(tok):
            raise ValueError(f"Disallowed character in nmap argument: {tok!r}")
    return tokens


def validate_nmap_request(target: str, nmap_args: str = "-sV") -> dict:
    """Validate target and args together. Returns normalized request metadata.

    Raises ValueError on invalid input; HTTP callers map that to 400 at the
    boundary before any scan is launched.
    """
    return {
        "target": validate_nmap_target(target),
        "nmap_args": nmap_args,
        "args_tokens": validate_nmap_args(nmap_args),
    }
