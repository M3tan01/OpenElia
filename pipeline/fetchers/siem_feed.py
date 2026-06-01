#!/usr/bin/env python3
"""SIEM alert/event feed fetcher.

mock : load pipeline/fixtures/siem_alerts.json.
live : query Splunk SPL / Elastic KQL via SecretStore creds. Stubbed until a
       live SIEM instance exists.

Record schema (normalized): {"rule","severity","host","user","raw","ts"}.
"""
from . import load_fixture


def fetch(mode: str) -> list[dict]:
    if mode == "mock":
        return load_fixture("siem_alerts.json")
    if mode == "live":
        # TODO(live): run the configured query set against Splunk/Elastic
        # (SIEM creds + endpoint from SecretStore), normalize hits.
        raise NotImplementedError(
            "siem_feed live mode not wired yet — needs SIEM endpoint + creds in keyring"
        )
    raise ValueError(f"unknown mode: {mode!r}")
