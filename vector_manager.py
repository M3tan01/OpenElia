#!/usr/bin/env python3
"""
vector_manager.py — engagement memory + LLM response cache.

Backed by stdlib sqlite3 (FTS5 full-text search), not chromadb. This keeps
recall of prior findings and an LLM response cache without pulling ~270 MB of
transitive deps (onnxruntime, sympy, grpc, kubernetes) or a local embedding
model runtime.

Two responsibilities:
  1. Event memory   — index_event / search  (FTS5 keyword recall)
  2. LLM cache      — cache_response / get_cached_response

The cache is **exact-match** (SHA-256 of the prompt fingerprint), not fuzzy.
An offensive tool loop must never be served a *different* prompt's cached
answer on a similarity collision — exact match removes that wrong-answer risk.

Public methods return chromadb-shaped dicts ({"documents": [[...]], ...}) so
existing callers (agents/base_agent.py, mcp_servers/memory/server.py) need no
change. Read paths never raise: any backend error yields an empty result.
"""
import os
import re
import json
import hashlib
import sqlite3
from datetime import datetime, timezone


def _fts5_available(conn: sqlite3.Connection) -> bool:
    """True if this sqlite build has the FTS5 extension compiled in."""
    try:
        conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS _fts5_probe USING fts5(x)")
        conn.execute("DROP TABLE IF EXISTS _fts5_probe")
        return True
    except sqlite3.OperationalError:
        return False


def _to_match_query(query: str) -> str:
    """
    Turn a free-text query into a safe FTS5 MATCH expression.

    Raw user/agent text ("CVSS:3.1/AV:N", "10.0.0.1", "-flag") contains
    characters that are FTS5 operators and would raise a syntax error. Extract
    word tokens, quote each, OR them together for keyword recall.
    """
    tokens = re.findall(r"\w+", query or "")
    if not tokens:
        return ""
    return " OR ".join(f'"{t}"' for t in tokens)


class VectorManager:
    def __init__(self, db_path="state/vector_db"):
        # db_path kept for signature compatibility; store one sqlite file under it.
        self.db_path = db_path
        self._conn = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            os.makedirs(self.db_path, exist_ok=True)
            self._conn = sqlite3.connect(os.path.join(self.db_path, "memory.sqlite"))
            self._conn.row_factory = sqlite3.Row
            self._init_schema(self._conn)
        return self._conn

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        self._has_fts5 = _fts5_available(conn)
        if self._has_fts5:
            conn.execute(
                "CREATE VIRTUAL TABLE IF NOT EXISTS events USING fts5("
                "content, source UNINDEXED, type UNINDEXED, "
                "timestamp UNINDEXED, metadata UNINDEXED)"
            )
        else:
            # Fallback: plain table + LIKE search when FTS5 is absent.
            conn.execute(
                "CREATE TABLE IF NOT EXISTS events ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT, "
                "source TEXT, type TEXT, timestamp TEXT, metadata TEXT)"
            )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS llm_cache ("
            "key TEXT PRIMARY KEY, response TEXT NOT NULL)"
        )
        conn.commit()

    def index_event(self, source, event_type, content, metadata=None):
        timestamp = datetime.now(timezone.utc).isoformat()
        if metadata is None:
            metadata = {}
        metadata.update({"source": source, "type": event_type, "timestamp": timestamp})
        self.conn.execute(
            "INSERT INTO events (content, source, type, timestamp, metadata) "
            "VALUES (?, ?, ?, ?, ?)",
            (content, source, event_type, timestamp, json.dumps(metadata)),
        )
        self.conn.commit()

    def search(self, query, limit=5):
        """Keyword recall. Returns chromadb-shaped dict; never raises."""
        empty = {"documents": [[]], "metadatas": [[]], "distances": [[]]}
        try:
            if getattr(self, "_has_fts5", None) is None:
                _ = self.conn  # trigger schema init to set _has_fts5
            if self._has_fts5:
                match = _to_match_query(query)
                if not match:
                    return empty
                rows = self.conn.execute(
                    "SELECT content, metadata FROM events WHERE events MATCH ? "
                    "ORDER BY rank LIMIT ?",
                    (match, limit),
                ).fetchall()
            else:
                like = f"%{query}%"
                rows = self.conn.execute(
                    "SELECT content, metadata FROM events WHERE content LIKE ? "
                    "ORDER BY id DESC LIMIT ?",
                    (like, limit),
                ).fetchall()
        except sqlite3.Error as e:
            print(f"Memory search failed: {e}")
            return empty

        docs = [r["content"] for r in rows]
        metas = [json.loads(r["metadata"] or "{}") for r in rows]
        # distances unused by callers but kept for shape parity.
        return {"documents": [docs], "metadatas": [metas], "distances": [[0.0] * len(docs)]}

    def get_cached_response(self, prompt: str, threshold: float = 0.0):
        """
        Exact-match cache lookup. `threshold` is accepted for signature
        compatibility but ignored — lookup is by SHA-256 of the prompt, so a
        hit is only ever the response cached for this exact prompt. Never
        raises: a DB error is a cache miss (None).
        """
        try:
            key = hashlib.sha256((prompt or "").encode("utf-8")).hexdigest()
            row = self.conn.execute(
                "SELECT response FROM llm_cache WHERE key = ?", (key,)
            ).fetchone()
            return row["response"] if row else None
        except sqlite3.Error as e:
            print(f"Cache lookup failed: {e}")
            return None

    def cache_response(self, prompt: str, response: str):
        key = hashlib.sha256((prompt or "").encode("utf-8")).hexdigest()
        self.conn.execute(
            "INSERT OR REPLACE INTO llm_cache (key, response) VALUES (?, ?)",
            (key, response),
        )
        self.conn.commit()
