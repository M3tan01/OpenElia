#!/usr/bin/env python3
"""Log / EVTX source fetcher.

mock : load pipeline/fixtures/sample_events.json (normalized event dicts).
live : ingest new files from a watch dir; EVTX parsed via python-evtx (a
       deferred install — see plan). Stubbed until that is wired.

Record schema (normalized): {"event_id","source","message","host","user","ts"}.
"""
from . import load_fixture


def fetch(mode: str) -> list[dict]:
    if mode == "mock":
        return load_fixture("sample_events.json")
    if mode == "live":
        # TODO(live): scan watch dir for new logs/EVTX since last run, parse
        # (python-evtx for .evtx, json/syslog otherwise), normalize.
        raise NotImplementedError(
            "log_source live mode not wired yet — needs watch dir + python-evtx"
        )
    raise ValueError(f"unknown mode: {mode!r}")
