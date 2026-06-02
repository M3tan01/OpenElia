"""
webdash/data.py — read adapters over OpenElia's existing state.

Reuses StateManager / GraphManager / CostTracker / ModelManager / core.audit_chain
rather than reimplementing any logic. Every reader points at an explicit state
directory so tests can target a tmp_path.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import networkx as nx


def _parse_ts(s: object) -> datetime | None:
    """Parse an ISO-8601 timestamp to a UTC-aware datetime, else None.

    Tolerates a trailing 'Z', missing offset (assumed UTC), and varying
    sub-second precision so callers can compare timestamps from different
    writers safely.
    """
    if not isinstance(s, str) or not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

# Mirrors orchestrator._RED_AGENTS / _BLUE_AGENTS (+ reporter). Used by the
# ModelSelector to offer per-agent overrides. Keep in sync with orchestrator.py.
AGENT_REGISTRY: dict[str, list[str]] = {
    "red": ["pentester_recon", "pentester_vuln", "pentester_exploit", "pentester_lat", "pentester_ex"],
    "blue": ["defender_mon", "defender_ana", "defender_hunt", "defender_res"],
    "reporter": ["reporter_agent"],
}


def _tail_jsonl(path: Path, limit: int) -> list[dict]:
    """Last `limit` parsed JSON objects from a JSONL file. Skips bad lines."""
    if not path.exists():
        return []
    out: list[dict] = []
    for line in path.read_text(errors="replace").splitlines()[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


class DashboardData:
    """Read-only views of engagement state, all rooted at one state directory."""

    def __init__(self, state_dir: str | os.PathLike = "state") -> None:
        self.dir = Path(state_dir)
        self.audit_log = self.dir / "audit.log"
        self.tasks_log = self.dir / "task_results.jsonl"
        self.graph_path = self.dir / "attack_surface.json"
        self.costs_path = self.dir / "costs.json"
        self.db_path = self.dir / "engagement.db"

    # --- engagement state -------------------------------------------------- #
    def state(self) -> dict:
        from state_manager import StateManager

        return StateManager(db_path=str(self.db_path)).read()

    # --- audit log (HMAC-chained) ----------------------------------------- #
    def audit(self, limit: int = 200) -> dict:
        from core.audit_chain import verify_detailed

        events = _tail_jsonl(self.audit_log, limit)
        status, msg = verify_detailed(self.audit_log)
        # "legacy" = pre-chain prefix, unverifiable but not tampered → not an alarm.
        return {
            "events": events,
            "count": len(events),
            "chain_ok": status in ("ok", "legacy", "empty"),
            "chain_status": status,
            "chain_msg": msg,
        }

    # --- task results ------------------------------------------------------ #
    def tasks(self, limit: int = 200) -> list[dict]:
        """Task results for the ACTIVE engagement only.

        task_results.jsonl is append-only and engagement-agnostic, so the panel
        would otherwise show lifetime totals. Scope by the active engagement's
        `started` timestamp — written in the same ISO-8601 UTC format as each
        row's `completed_at`, so a lexical compare is chronological. No active
        engagement → no current activity (idle).
        """
        start_dt = _parse_ts(self.state().get("engagement", {}).get("started"))
        if start_dt is None:
            return []
        rows = _tail_jsonl(self.tasks_log, limit)
        return [
            r for r in rows
            if (ts := _parse_ts(r.get("completed_at"))) is not None and ts >= start_dt
        ]

    # --- attack-surface graph --------------------------------------------- #
    def graph(self) -> dict:
        from graph_manager import GraphManager

        gm = GraphManager(db_path=str(self.graph_path))
        link_data = nx.node_link_data(gm.graph)
        return {
            "summary": gm.get_summary(),
            "nodes": link_data.get("nodes", []),
            "links": link_data.get("links", link_data.get("edges", [])),
        }

    # --- MITRE ATT&CK heatmap --------------------------------------------- #
    def heatmap(self) -> dict:
        from graph_manager import GraphManager

        findings = self.state().get("findings", [])
        return GraphManager(db_path=str(self.graph_path)).get_mitre_heatmap(findings)

    # --- cost / budget ----------------------------------------------------- #
    def cost(self) -> dict:
        from cost_tracker import CostTracker

        summary = CostTracker(log_path=str(self.costs_path)).get_summary()
        series: list[dict] = []
        if self.costs_path.exists():
            try:
                history = json.loads(self.costs_path.read_text())
                series = [{"session": k, **v} for k, v in sorted(history.items())]
            except (json.JSONDecodeError, OSError):
                series = []
        return {"summary": summary, "series": series}

    # --- model / brain configuration (no secrets) ------------------------- #
    def models(self) -> dict:
        from model_manager import ModelManager

        # get_config() holds only mode + model names + overrides — never api keys.
        return {"config": ModelManager.get_config(), "agents": AGENT_REGISTRY}


def get_data() -> DashboardData:
    """FastAPI dependency. State dir from OPENELIA_STATE_DIR (default 'state')."""
    return DashboardData(os.getenv("OPENELIA_STATE_DIR", "state"))


# --- RoE (Rules of Engagement) read adapter --------------------------------- #

_ROE_WHITELIST: frozenset[str] = frozenset(
    {"authorized_subnets", "blacklisted_ips", "prohibited_tools", "quiet_hours"}
)

_ROE_SENTINEL: dict = {
    "authorized_subnets": [],
    "blacklisted_ips": [],
    "prohibited_tools": [],
    "quiet_hours": None,
}


def roe() -> dict:
    """
    Read the RoE JSON and return ONLY whitelisted keys.

    Path resolution: OPENELIA_ROE_PATH env (absolute or relative). Relative
    paths are resolved from the working directory (same convention the engine
    uses — roe.json sits in the project root). Missing / unreadable file →
    sentinel dict, never raises.
    """
    raw_path = os.getenv("OPENELIA_ROE_PATH", "roe.json")
    roe_path = Path(raw_path)

    if not roe_path.is_absolute():
        roe_path = Path(os.getcwd()) / roe_path

    try:
        raw: dict = json.loads(roe_path.read_text())
    except (OSError, json.JSONDecodeError):
        return dict(_ROE_SENTINEL)

    # Backfill the sentinel so all whitelisted keys are always present — a
    # partial roe.json must not yield missing keys (the frontend treats them
    # as required arrays). Whitelist still drops any non-whitelisted key.
    return {**_ROE_SENTINEL, **{k: raw[k] for k in _ROE_WHITELIST if k in raw}}
