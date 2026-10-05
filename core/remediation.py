"""core/remediation.py — validate an execute-remediation request.

Single implementation shared by both callers so there is no duplicated logic:
  * the `execute-remediation` CLI command (main.py), and
  * the webdash POST /api/execute-remediation route (boundary 400 before a
    background run launches).

execute-remediation runs a previously approved response action by its DB row
id. This validator is the boundary check that the id is a usable positive
integer before the (dangerous, Tier 4) action is dispatched. The
command-execution allowlist itself lives in DefenderRes.execute_remediation and
still gates the actual subprocess; this module does not touch the DB or run
anything.
"""

from __future__ import annotations


def validate_action_id(action_id: object) -> int:
    """Return `action_id` coerced to a positive int; else raise ValueError.

    Accepts an int or a numeric string (CLI/JSON parity). Rejects non-numeric
    values, None, and ids <= 0 — response-action row ids are 1-based. HTTP
    callers map the ValueError to 400 before launching a run.
    """
    try:
        aid = int(action_id)  # type: ignore[arg-type]  # str/int accepted; others raise
    except (TypeError, ValueError):
        raise ValueError(
            f"Invalid action_id {action_id!r}: must be an integer."
        )
    if aid <= 0:
        raise ValueError(
            f"Invalid action_id {aid}: must be a positive integer."
        )
    return aid
