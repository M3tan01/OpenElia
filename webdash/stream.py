"""
webdash/stream.py — WebSocket live feed at /api/stream.

Sends an initial state snapshot, then pushes new audit-log and task-result lines
as they are appended (offset tail). Token is passed as a query param (?token=…)
since browsers can't set WebSocket Authorization headers.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import WebSocket, WebSocketDisconnect

from webdash.data import get_data
from webdash.security import verify

_POLL_SECONDS = 1.0


def _read_new(path: Path, offset: int) -> tuple[list[dict], int]:
    """Parsed JSON lines appended since `offset`; returns (records, new_offset).

    Resets to 0 if the file shrank (rotation/truncation)."""
    if not path.exists():
        return [], 0
    size = path.stat().st_size
    if size < offset:  # rotated/truncated
        offset = 0
    if size == offset:
        return [], offset
    records: list[dict] = []
    with path.open("r", errors="replace") as fh:
        fh.seek(offset)
        chunk = fh.read()
        new_offset = fh.tell()
    for line in chunk.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records, new_offset


async def stream_endpoint(websocket: WebSocket) -> None:
    # Prefer the token via Sec-WebSocket-Protocol (kept out of URLs/access logs);
    # fall back to the ?token= query param for compatibility.
    subprotocols = websocket.scope.get("subprotocols", [])
    token = subprotocols[0] if subprotocols else websocket.query_params.get("token", "")
    if not verify(token):
        await websocket.close(code=1008)  # policy violation
        return

    # Echo the negotiated subprotocol so the browser handshake completes.
    await websocket.accept(subprotocol=subprotocols[0] if subprotocols else None)
    data = get_data()
    audit_off = data.audit_log.stat().st_size if data.audit_log.exists() else 0
    tasks_off = data.tasks_log.stat().st_size if data.tasks_log.exists() else 0

    try:
        await websocket.send_json({"type": "snapshot", "state": data.state()})
        while True:
            await asyncio.sleep(_POLL_SECONDS)

            new_audit, audit_off = _read_new(data.audit_log, audit_off)
            for rec in new_audit:
                await websocket.send_json({"type": "audit", "event": rec})

            new_tasks, tasks_off = _read_new(data.tasks_log, tasks_off)
            for rec in new_tasks:
                await websocket.send_json({"type": "task", "event": rec})
    except WebSocketDisconnect:
        return
