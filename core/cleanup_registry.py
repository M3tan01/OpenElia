"""
core/cleanup_registry.py — register-before-execute rollback for offensive/response
actions, run in reverse (LIFO) on abort / kill-switch.

Design (mirrors a stigmergic-swarm cleanup registry, adapted to OpenElia's safety
model):
  - Before an action that changes target/host state, the caller registers an *undo*:
    a Python callable (the real reversal) PLUS a descriptive ``undo_command`` string
    and ``target``/``source`` for audit and crash recovery.
  - The intent is persisted to engagement.db (table ``cleanup_actions``) so a crash
    leaves a recoverable trail.
  - ``run_all`` fires pending undos LIFO. Each undo is first passed through
    ``security_manager.enforce_security_gate`` (scope + Semantic Firewall); a refused
    undo is recorded and skipped, never executed.
  - Zero-trust: a persisted ``undo_command`` whose in-memory callable was lost (e.g.
    after a crash) is NEVER auto-executed. It is surfaced via ``pending`` for an
    operator to action manually. We do not autonomously shell out persisted strings.
"""

from __future__ import annotations

import sqlite3
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

# Module-level so run_all's security gate is patchable in tests. No import cycle:
# security_manager does not import this module (cleanup_registry is only ever
# imported lazily by state_manager / main).
from security_manager import enforce_security_gate

_STATUS_PENDING = "pending"
_STATUS_EXECUTED = "executed"
_STATUS_REFUSED = "refused"   # blocked by the security gate
_STATUS_FAILED = "failed"     # callable raised


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class CleanupRegistry:
    """Engagement-scoped registry of reversible actions, persisted to engagement.db."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # In-memory map id -> undo callable. Not persisted (callables can't be).
        self._callables: dict[str, Callable[[], None]] = {}
        self._init_table()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_table(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cleanup_actions (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT,
                    description TEXT,
                    undo_command TEXT,
                    target TEXT,
                    source TEXT,
                    status TEXT,
                    registered_at TEXT,
                    executed_at TEXT
                );
                """
            )
            conn.commit()

    def register(
        self,
        engagement_id: str,
        description: str,
        undo_command: str,
        target: str,
        source: str,
        undo: Callable[[], None] | None = None,
    ) -> str:
        """Record a pending undo BEFORE the forward action runs. Returns the action id."""
        action_id = f"CLN-{int(time.time())}-{uuid.uuid4().hex[:4].upper()}"
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO cleanup_actions
                    (id, engagement_id, description, undo_command, target, source,
                     status, registered_at, executed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (action_id, engagement_id, description, undo_command, target, source,
                 _STATUS_PENDING, _now()),
            )
            conn.commit()
        if undo is not None:
            self._callables[action_id] = undo
        return action_id

    def _mark(self, action_id: str, status: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE cleanup_actions SET status = ?, executed_at = ? WHERE id = ?",
                (status, _now(), action_id),
            )
            conn.commit()

    def run_all(self, engagement_id: str, reverse: bool = True) -> list[dict]:
        """Fire pending undos for an engagement (LIFO by default).

        Each undo is gated by enforce_security_gate before running. Returns a summary
        list of {id, status}. Undos whose callable is missing (post-crash) are left
        pending and never auto-executed.
        """
        # Two fully-literal queries (no string interpolation) keep this off the SQL
        # static-analysis radar; reverse=LIFO is the default rollback order.
        if reverse:
            sql = ("SELECT id, undo_command, target, source FROM cleanup_actions "
                   "WHERE engagement_id = ? AND status = ? ORDER BY registered_at DESC")
        else:
            sql = ("SELECT id, undo_command, target, source FROM cleanup_actions "
                   "WHERE engagement_id = ? AND status = ? ORDER BY registered_at ASC")
        with self._conn() as conn:
            rows = conn.execute(sql, (engagement_id, _STATUS_PENDING)).fetchall()

        summary: list[dict] = []
        for row in rows:
            aid = row["id"]
            # 1. Security gate — never run an out-of-scope or destructive undo.
            try:
                enforce_security_gate(row["source"], row["target"], row["undo_command"])
            except PermissionError:
                self._mark(aid, _STATUS_REFUSED)
                summary.append({"id": aid, "status": _STATUS_REFUSED})
                continue
            except Exception:  # noqa: BLE001 — gate-infra failure must not abort the
                # whole rollback; fail this one undo closed and keep going.
                self._mark(aid, _STATUS_FAILED)
                summary.append({"id": aid, "status": _STATUS_FAILED})
                continue

            # 2. Execute the in-memory callable. A recovered row with no callable is
            #    left pending for manual operator recovery (never auto-shelled).
            undo = self._callables.get(aid)
            if undo is None:
                summary.append({"id": aid, "status": _STATUS_PENDING})
                continue
            try:
                undo()
                self._mark(aid, _STATUS_EXECUTED)
                summary.append({"id": aid, "status": _STATUS_EXECUTED})
            except Exception:  # noqa: BLE001 — record failure, keep firing the rest
                self._mark(aid, _STATUS_FAILED)
                summary.append({"id": aid, "status": _STATUS_FAILED})
        return summary

    def pending(self, engagement_id: str) -> list[dict]:
        """Pending undos for an engagement — recovery view. Read-only, never executes."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, description, undo_command, target, source, status, registered_at "
                "FROM cleanup_actions WHERE engagement_id = ? AND status = ? "
                "ORDER BY registered_at DESC",
                (engagement_id, _STATUS_PENDING),
            ).fetchall()
        return [dict(r) for r in rows]
