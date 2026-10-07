"""core/msf.py — validate + build a sterile Metasploit console command.

Single implementation shared by three callers so there is no duplicated logic:
  * the `msf` CLI command (main.py),
  * the webdash POST /api/msf route (boundary 400 before a background run
    launches), and
  * the background runner (webdash/runner.py) that executes the built command.

SECURITY — msf is a Tier 4 dangerous op. This builder is the
command-construction + injection boundary:
  * the target must be a valid IP or CIDR (not a shell fragment), and
  * the target and the user-supplied extra commands are each shlex-quoted into
    a single-quoted argv token inside the `msfconsole -x` string, so neither
    can break out of the intended command list into the host shell.
This only guarantees the command line is well-formed. Execution still runs
sterile (PentesterOS), behind the kill-switch, and behind the RoE scope gate.
"""

from __future__ import annotations

import ipaddress
import re
import shlex

_DEFAULT_MSF_EXTRA = "show options"


def validate_msf_target(target: str) -> str:
    """Return `target` if it is a valid IP or CIDR; else raise ValueError.

    msf RHOSTS is IP/CIDR only here (CLI parity) — hostnames are rejected.
    """
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
    raise ValueError(
        f"Invalid msf target '{target}': must be a valid IP address or CIDR range."
    )


def build_msf_command(target: str, msf_extra: str | None = None, stealth: bool = False) -> dict:
    """Validate target and build a sterile msfconsole command string.

    Returns {"target", "msf_extra", "stealth", "command"}. Raises ValueError on
    an invalid target; HTTP callers map that to 400 before launching a run.
    """
    validate_msf_target(target)
    extra = msf_extra or _DEFAULT_MSF_EXTRA

    if stealth:
        # Throttle scanner threads. Inject before quoting so the substitution
        # operates on the plain string, not on shell-quoted output.
        extra = re.sub(r"\brun\b", "set THREADS 1; run", extra, flags=re.IGNORECASE)
        extra = re.sub(r"\bexploit\b", "set THREADS 1; exploit", extra, flags=re.IGNORECASE)

    safe_target = shlex.quote(target)
    safe_extra = shlex.quote(extra)
    command = f"msfconsole -q -x 'set RHOSTS {safe_target}; {safe_extra}; exit'"
    return {"target": target, "msf_extra": extra, "stealth": stealth, "command": command}
