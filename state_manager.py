"""
state_manager.py — SQLite-backed Multi-Target State Manager for OpenElia.

Supports:
- Campaign Orchestration (isolated state per engagement_id)
- Global Kill-Switch (is_locked flag)
- Strategic Message Bus (messages table)
"""

import json
import os
import sqlite3
import uuid
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


PHASE_ORDER = ["recon", "vuln", "exploit", "lateral", "exfil"]

_JSON_MAX_BYTES = 5_000_000  # 5 MB hard cap per stored JSON blob


def _safe_json_loads(data: str | None, fallback: dict | None = None) -> dict:
    """Deserialize JSON with a size guard. Returns fallback on failure."""
    if fallback is None:
        fallback = {}
    if not data:
        return fallback
    if len(data) > _JSON_MAX_BYTES:
        raise ValueError(f"JSON payload exceeds size limit ({len(data)} > {_JSON_MAX_BYTES} bytes)")
    return json.loads(data)

_DEFAULT_DB_FILE = os.getenv("STATE_FILE", "state/engagement.db").replace(".json", ".db")


class StateManager:
    def __init__(self, db_path: str = _DEFAULT_DB_FILE, engagement_id: str = None):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self.active_engagement_id = engagement_id or self._get_last_active_id()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        # Elite Efficiency: Enable WAL mode for high concurrency (Swarm Mode)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize SQLite tables with multi-agent coordination support."""
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS engagement (
                    id TEXT PRIMARY KEY,
                    target TEXT,
                    scope TEXT,
                    started TEXT,
                    authorized INTEGER,
                    current_phase TEXT,
                    is_active INTEGER DEFAULT 1,
                    is_locked INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS phases (
                    engagement_id TEXT,
                    name TEXT,
                    status TEXT,
                    data TEXT,
                    PRIMARY KEY (engagement_id, name),
                    FOREIGN KEY(engagement_id) REFERENCES engagement(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT,
                    severity TEXT,
                    title TEXT,
                    description TEXT,
                    evidence TEXT,
                    mitre_ttp TEXT,
                    timestamp TEXT,
                    FOREIGN KEY(engagement_id) REFERENCES engagement(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS blue_alerts (
                    id TEXT PRIMARY KEY,
                    engagement_id TEXT,
                    type TEXT,
                    description TEXT,
                    severity TEXT,
                    source TEXT,
                    timestamp TEXT,
                    escalated INTEGER DEFAULT 0,
                    escalated_at TEXT,
                    FOREIGN KEY(engagement_id) REFERENCES engagement(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS blue_analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id TEXT,
                    alert_id TEXT,
                    verdict TEXT,
                    severity TEXT,
                    reasoning TEXT,
                    escalate INTEGER,
                    data TEXT,
                    timestamp TEXT,
                    FOREIGN KEY(engagement_id) REFERENCES engagement(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS response_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id TEXT,
                    action_type TEXT,
                    target TEXT,
                    command TEXT,
                    rationale TEXT,
                    requires_approval INTEGER,
                    logged_at TEXT,
                    FOREIGN KEY(engagement_id) REFERENCES engagement(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id TEXT,
                    sender TEXT,
                    recipient TEXT,
                    content TEXT,
                    timestamp TEXT,
                    is_read INTEGER DEFAULT 0,
                    FOREIGN KEY(engagement_id) REFERENCES engagement(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS metadata (
                    engagement_id TEXT,
                    key TEXT,
                    value TEXT,
                    PRIMARY KEY (engagement_id, key),
                    FOREIGN KEY(engagement_id) REFERENCES engagement(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS pivot_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    engagement_id TEXT,
                    type TEXT,
                    target TEXT,
                    local_port INTEGER,
                    remote_target TEXT,
                    remote_port INTEGER,
                    status TEXT DEFAULT 'active',
                    created_at TEXT,
                    FOREIGN KEY(engagement_id) REFERENCES engagement(id) ON DELETE CASCADE
                );
            """)
            conn.commit()

    def _get_last_active_id(self) -> Optional[str]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT id FROM engagement WHERE is_active = 1 ORDER BY started DESC LIMIT 1").fetchone()
            return row["id"] if row else None

    # ------------------------------------------------------------------ #
    # Kill-Switch Logic
    # ------------------------------------------------------------------ #

    def set_locked(self, locked: bool, engagement_id: str = None):
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            conn.execute("UPDATE engagement SET is_locked = ? WHERE id = ?", (1 if locked else 0, eid))
            conn.commit()

    def is_locked(self, engagement_id: str = None) -> bool:
        eid = engagement_id or self.active_engagement_id
        if not eid: return False
        with self._get_conn() as conn:
            row = conn.execute("SELECT is_locked FROM engagement WHERE id = ?", (eid,)).fetchone()
            return bool(row["is_locked"]) if row else False

    # ------------------------------------------------------------------ #
    # Message Bus Logic
    # ------------------------------------------------------------------ #

    def send_message(self, sender: str, content: str, recipient: str = "ALL", engagement_id: str = None):
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            conn.execute("""
                INSERT INTO messages (engagement_id, sender, recipient, content, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (eid, sender, recipient, content, datetime.now(timezone.utc).isoformat()))
            conn.commit()

    def get_messages(self, recipient: str = "ALL", engagement_id: str = None) -> List[dict]:
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            query = "SELECT * FROM messages WHERE engagement_id = ? AND (recipient = ? OR recipient = 'ALL')"
            return [dict(row) for row in conn.execute(query, (eid, recipient))]

    # ------------------------------------------------------------------ #
    # Core read / write
    # ------------------------------------------------------------------ #

    def read(self, engagement_id: str = None) -> dict:
        eid = engagement_id or self.active_engagement_id
        if not eid: return {}
        
        state = {}
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM engagement WHERE id = ?", (eid,)).fetchone()
            if not row: return {}
            
            state["engagement"] = {
                "id": row["id"],
                "target": row["target"],
                "scope": row["scope"],
                "started": row["started"],
                "authorized": bool(row["authorized"]),
                "is_locked": bool(row["is_locked"])
            }
            state["current_phase"] = row["current_phase"]

            for row in conn.execute("SELECT * FROM phases WHERE engagement_id = ?", (eid,)):
                state[row["name"]] = {
                    "status": row["status"],
                    "data": _safe_json_loads(row["data"])
                }

            state["findings"] = [dict(r) for r in conn.execute("SELECT * FROM findings WHERE engagement_id = ? ORDER BY timestamp DESC", (eid,))]
            
            state["blue_alerts"] = []
            for row in conn.execute("SELECT * FROM blue_alerts WHERE engagement_id = ? ORDER BY timestamp DESC", (eid,)):
                d = dict(row)
                d["escalated"] = bool(d["escalated"])
                state["blue_alerts"].append(d)

            state["blue_analyses"] = []
            for row in conn.execute("SELECT * FROM blue_analyses WHERE engagement_id = ? ORDER BY timestamp DESC", (eid,)):
                d = _safe_json_loads(row["data"])
                d.update({
                    "alert_id": row["alert_id"],
                    "verdict": row["verdict"],
                    "severity": row["severity"],
                    "reasoning": row["reasoning"],
                    "escalate": bool(row["escalate"]),
                    "timestamp": row["timestamp"]
                })
                state["blue_analyses"].append(d)

            state["response_actions"] = []
            for row in conn.execute("SELECT * FROM response_actions WHERE engagement_id = ? ORDER BY logged_at DESC", (eid,)):
                d = dict(row)
                d["requires_approval"] = bool(d["requires_approval"])
                state["response_actions"].append(d)

            for row in conn.execute("SELECT * FROM metadata WHERE engagement_id = ?", (eid,)):
                state[row["key"]] = _safe_json_loads(row["value"])

        return state

    def write(self, state: dict) -> None:
        """Backward compatibility write."""
        with self._get_conn() as conn:
            eng = state.get("engagement", {})
            if eng:
                conn.execute("""
                    INSERT OR REPLACE INTO engagement (id, target, scope, started, authorized, current_phase, is_locked)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (eng.get("id"), eng.get("target"), eng.get("scope"), 
                      eng.get("started"), 1 if eng.get("authorized") else 0, 
                      state.get("current_phase", "recon"), 1 if eng.get("is_locked") else 0))

            for p in PHASE_ORDER:
                if p in state:
                    conn.execute("""
                        INSERT OR REPLACE INTO phases (engagement_id, name, status, data)
                        VALUES (?, ?, ?, ?)
                    """, (eng.get("id"), p, state[p].get("status"), json.dumps(state[p].get("data", {}))))

            conn.commit()

    # ------------------------------------------------------------------ #
    # Engagement lifecycle
    # ------------------------------------------------------------------ #

    def initialize_engagement(self, target: str, scope: str) -> dict:
        eid = f"ENG-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        with self._get_conn() as conn:
            conn.execute("UPDATE engagement SET is_active = 0")
            conn.execute("""
                INSERT INTO engagement (id, target, scope, started, authorized, current_phase, is_active, is_locked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (eid, target, scope, datetime.now(timezone.utc).isoformat(), 1, "recon", 1, 0))
            
            for p in PHASE_ORDER:
                status = "pending" if p in ["recon", "vuln", "exploit"] else "dormant"
                conn.execute("INSERT INTO phases (engagement_id, name, status, data) VALUES (?, ?, ?, ?)", (eid, p, status, "{}"))
            
            conn.commit()
        self.active_engagement_id = eid
        return self.read(eid)

    def clear(self, engagement_id: str = None) -> None:
        eid = engagement_id or self.active_engagement_id
        if not eid: return
        with self._get_conn() as conn:
            conn.execute("DELETE FROM engagement WHERE id = ?", (eid,))
            conn.commit()
        if eid == self.active_engagement_id:
            self.active_engagement_id = self._get_last_active_id()

    # ------------------------------------------------------------------ #
    # Phase management
    # ------------------------------------------------------------------ #

    def get_phase_status(self, phase: str, engagement_id: str = None) -> str:
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            row = conn.execute("SELECT status FROM phases WHERE engagement_id = ? AND name = ?", (eid, phase)).fetchone()
            return row["status"] if row else "unknown"

    def is_phase_complete(self, phase: str, engagement_id: str = None) -> bool:
        return self.get_phase_status(phase, engagement_id) == "complete"

    def unlock_phase(self, phase: str, engagement_id: str = None) -> None:
        """Transition a dormant phase to pending, making it eligible to run."""
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            conn.execute(
                "UPDATE phases SET status = 'pending' WHERE engagement_id = ? AND name = ? AND status = 'dormant'",
                (eid, phase),
            )
            conn.commit()

    def set_metadata(self, key: str, value, engagement_id: str = None) -> None:
        """Persist arbitrary key/value metadata for an engagement."""
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO metadata (engagement_id, key, value) VALUES (?, ?, ?)",
                (eid, key, json.dumps(value)),
            )
            conn.commit()

    def get_metadata(self, key: str, engagement_id: str = None):
        """Retrieve metadata by key. Returns None if not found."""
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT value FROM metadata WHERE engagement_id = ? AND key = ?", (eid, key)
            ).fetchone()
            return _safe_json_loads(row["value"]) if row else None

    def update_phase_status(self, phase: str, status: str, engagement_id: str = None) -> None:
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            conn.execute("UPDATE phases SET status = ? WHERE engagement_id = ? AND name = ?", (status, eid, phase))
            if status == "running":
                conn.execute("UPDATE engagement SET current_phase = ? WHERE id = ?", (phase, eid))
            conn.commit()

    def get_phase_data(self, phase: str, engagement_id: str = None) -> dict:
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            row = conn.execute("SELECT data FROM phases WHERE engagement_id = ? AND name = ?", (eid, phase)).fetchone()
            return _safe_json_loads(row["data"] if row else None)

    def write_agent_result(self, phase: str, result_key: str, data, engagement_id: str = None) -> None:
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            current_data = self.get_phase_data(phase, eid)
            current_data[result_key] = data
            current_data["_updated"] = datetime.now(timezone.utc).isoformat()
            conn.execute("UPDATE phases SET data = ? WHERE engagement_id = ? AND name = ?", (json.dumps(current_data), eid, phase))
            conn.commit()

    def add_finding(self, severity: str, title: str, description: str, evidence: str, mitre_ttp: str, engagement_id: str = None) -> None:
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            f_id = f"FIND-{int(time.time())}-{uuid.uuid4().hex[:4].upper()}"
            conn.execute("""
                INSERT INTO findings (id, engagement_id, severity, title, description, evidence, mitre_ttp, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (f_id, eid, severity, title, description, evidence, mitre_ttp, datetime.now(timezone.utc).isoformat()))
            conn.commit()

    def add_blue_alert(self, alert_type: str, description: str, severity: str, source: str, engagement_id: str = None) -> None:
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            a_id = f"ALERT-{int(time.time())}-{uuid.uuid4().hex[:4].upper()}"
            conn.execute("""
                INSERT INTO blue_alerts (id, engagement_id, type, description, severity, source, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (a_id, eid, alert_type, description, severity, source, datetime.now(timezone.utc).isoformat()))
            conn.commit()

    def mark_alert_escalated(self, alert_id: str, engagement_id: str = None) -> None:
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            conn.execute("""
                UPDATE blue_alerts SET escalated = 1, escalated_at = ? WHERE engagement_id = ? AND id = ?
            """, (datetime.now(timezone.utc).isoformat(), eid, alert_id))
            conn.commit()

    def add_blue_analysis(self, analysis_data: dict, engagement_id: str = None) -> None:
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            alert_id = analysis_data.pop("alert_id", None)
            verdict = analysis_data.pop("verdict", None)
            severity = analysis_data.pop("severity", None)
            reasoning = analysis_data.pop("reasoning", None)
            escalate = 1 if analysis_data.pop("escalate", False) else 0
            ts = datetime.now(timezone.utc).isoformat()
            
            conn.execute("""
                INSERT INTO blue_analyses (engagement_id, alert_id, verdict, severity, reasoning, escalate, data, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (eid, alert_id, verdict, severity, reasoning, escalate, json.dumps(analysis_data), ts))
            conn.commit()

    def add_response_action(self, action_data: dict, engagement_id: str = None) -> None:
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            ts = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                INSERT INTO response_actions (engagement_id, action_type, target, command, rationale, requires_approval, logged_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (eid, action_data.get("action_type"), action_data.get("target"), 
                  action_data.get("command"), action_data.get("rationale"),
                  1 if action_data.get("requires_approval") else 0, ts))
            conn.commit()

    def add_pivot(self, pivot_type: str, target: str, local_port: int, remote_target: str = None, remote_port: int = None, engagement_id: str = None) -> int:
        """Record a new pivot tunnel or SOCKS proxy. Returns the row id."""
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            cur = conn.execute(
                """INSERT INTO pivot_sessions (engagement_id, type, target, local_port, remote_target, remote_port, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, 'active', ?)""",
                (eid, pivot_type, target, local_port, remote_target, remote_port, datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()
            return cur.lastrowid

    def list_pivots(self, engagement_id: str = None) -> list[dict]:
        """Return all pivot sessions for the active engagement."""
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            return [dict(row) for row in conn.execute(
                "SELECT * FROM pivot_sessions WHERE engagement_id = ? ORDER BY created_at DESC", (eid,)
            )]

    def set_thehive_case(self, case_data: dict, engagement_id: str = None) -> None:
        eid = engagement_id or self.active_engagement_id
        with self._get_conn() as conn:
            conn.execute("INSERT OR REPLACE INTO metadata (engagement_id, key, value) VALUES (?, ?, ?)", (eid, "thehive_case", json.dumps(case_data)))
            conn.commit()
