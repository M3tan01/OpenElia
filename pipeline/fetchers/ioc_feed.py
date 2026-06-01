#!/usr/bin/env python3
"""IOC feed fetcher.

mock : load pipeline/fixtures/ioc_feed.json (list of {"ioc","source"}).
live : pull from a threat feed. Stubbed until a feed URL/creds are wired —
       raises so a misconfigured live run fails loud instead of silently
       returning nothing.
"""
from . import load_fixture


def fetch(mode: str) -> list[dict]:
    if mode == "mock":
        return load_fixture("ioc_feed.json")
    if mode == "live":
        # TODO(live): pull from configured feed (e.g. MISP/OTX/abuse.ch) via
        # SecretStore-held creds, normalize to [{"ioc","source"}].
        raise NotImplementedError(
            "ioc_feed live mode not wired yet — needs feed URL + creds in keyring"
        )
    raise ValueError(f"unknown mode: {mode!r}")
