"""Unit tests for core/msf.py — pure Metasploit-command validation + building.

validate_msf_target / build_msf_command are the single implementation shared by
the CLI `msf` command and the webdash POST /api/msf route (boundary 400 before a
background run launches). They are the command-construction + injection boundary
for a Tier 4 dangerous op: the target must be a valid IP or CIDR, and both the
target and the user-supplied extra commands are shlex-quoted into the
`msfconsole -x` string so neither can break out of the intended command list.
"""

from __future__ import annotations

import shlex

import pytest

from core.msf import build_msf_command, validate_msf_target


def test_valid_ip_and_cidr_accepted():
    assert validate_msf_target("10.0.0.5") == "10.0.0.5"
    assert validate_msf_target("10.0.0.0/24") == "10.0.0.0/24"


def test_malformed_target_rejected():
    # Hostnames are not valid msf RHOSTS targets here (IP/CIDR only, CLI parity).
    with pytest.raises(ValueError):
        validate_msf_target("scanme.example.com")


def test_injection_in_target_rejected():
    with pytest.raises(ValueError):
        validate_msf_target("10.0.0.1; rm -rf /")


def test_default_extra_is_show_options():
    built = build_msf_command("10.0.0.5")
    assert built["msf_extra"] == "show options"
    assert built["target"] == "10.0.0.5"


def test_command_includes_rhosts_and_quoted_extra():
    built = build_msf_command("10.0.0.5", "use scanner/portscan/tcp; run")
    assert "set RHOSTS 10.0.0.5" in built["command"]
    # The whole extra is single-quoted into one argv token.
    assert shlex.quote("use scanner/portscan/tcp; run") in built["command"]
    assert built["command"].startswith("msfconsole -q -x ")


def test_stealth_injects_thread_throttle():
    built = build_msf_command("10.0.0.5", "exploit", stealth=True)
    assert built["stealth"] is True
    assert "set THREADS 1; exploit" in built["msf_extra"]


def test_injection_in_extra_is_quoted_not_executed():
    # A shell metacharacter in the extra must survive as a quoted literal, never
    # break out of the msfconsole -x single-quoted argument.
    evil = "run; cat /etc/passwd"
    built = build_msf_command("10.0.0.5", evil)
    assert shlex.quote(built["msf_extra"]) in built["command"]
