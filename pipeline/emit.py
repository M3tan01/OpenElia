#!/usr/bin/env python3
"""Staging JSON writer — the handoff boundary between the deterministic Python
layer and the Claude-native cron commands.

Writes ``staging/<stage>-<UTC YYYY-MM-DD-HHMM>.json`` atomically (temp file +
rename) so a reader never sees a half-written file.
"""
import datetime
import json
import os
import tempfile

_STAGING_DIR = os.path.join(os.path.dirname(__file__), "staging")


def _utc_stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d-%H%M")


def write(stage: str, records: list[dict], mode: str, meta: dict | None = None) -> str:
    """Write a staging blob for ``stage`` and return its absolute path.

    The envelope is stable across stages so the slash commands can parse one shape:
        {schema, stage, mode, generated, count, meta, records}
    """
    os.makedirs(_STAGING_DIR, exist_ok=True)
    payload = {
        "schema": "openelia.pipeline/v1",
        "stage": stage,
        "mode": mode,
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "count": len(records),
        "meta": meta or {},
        "records": records,
    }
    path = os.path.join(_STAGING_DIR, f"{stage}-{_utc_stamp()}.json")

    fd, tmp = tempfile.mkstemp(dir=_STAGING_DIR, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return path


def latest(stage: str) -> str | None:
    """Return the most recent staging file path for ``stage``, or None."""
    if not os.path.isdir(_STAGING_DIR):
        return None
    matches = sorted(
        f for f in os.listdir(_STAGING_DIR)
        if f.startswith(f"{stage}-") and f.endswith(".json")
    )
    return os.path.join(_STAGING_DIR, matches[-1]) if matches else None
