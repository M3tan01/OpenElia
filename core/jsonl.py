"""
core/jsonl.py — shared JSONL tail-read helper.

Used by both the presentation layer (webdash/data.py) and infra-layer MCP
servers (mcp_servers/siem/server.py) to read the last N parsed objects from
an append-only JSONL file. Lives in core/ rather than webdash/ so infra code
never has to import the presentation layer to reuse it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


def tail_jsonl(path: str | os.PathLike, limit: int) -> list[dict]:
    """Last `limit` parsed JSON objects from a JSONL file. Skips bad lines."""
    p = Path(path)
    if not p.exists():
        return []
    out: list[dict] = []
    for line in p.read_text(errors="replace").splitlines()[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
