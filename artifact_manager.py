#!/usr/bin/env python3
import os
import hashlib
import shutil
import json
import sqlite3
from datetime import datetime
from security_manager import AuditLogger

class ArtifactManager:
    def __init__(self, base_dir="artifacts", audit_log_path="state/audit.log", db_path="state/forensic_timeline.db"):
        self.base_dir = base_dir
        self.audit_logger = AuditLogger(log_path=audit_log_path)
        self.db_path = db_path
        os.makedirs(self.base_dir, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initialize the forensic timeline database."""
        os.chmod(self.db_path, 0o600) if os.path.exists(self.db_path) else None
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chain_of_custody (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    source_agent TEXT,
                    filename TEXT,
                    sha256 TEXT,
                    status TEXT,
                    metadata TEXT
                )
            """)
            conn.commit()

    def store_artifact(self, source_agent, filename, content, metadata=None):
        """
        Store a file artifact, calculate its hash, log it to the audit trail,
        and update the forensic timeline (Chain of Custody).
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{timestamp}_{filename}"
        file_path = os.path.join(self.base_dir, safe_filename)
        iso_ts = datetime.utcnow().isoformat() + "Z"

        # Write file with owner-only permissions (0o600)
        mode = "wb" if isinstance(content, bytes) else "w"
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(file_path, flags, 0o600)
        try:
            with os.fdopen(fd, mode) as f:
                f.write(content)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

        # Calculate SHA-256
        sha256_hash = hashlib.sha256()
        if isinstance(content, bytes):
            sha256_hash.update(content)
        else:
            sha256_hash.update(content.encode('utf-8'))
        file_hash = sha256_hash.hexdigest()

        # 1. Update Forensic Timeline (Chain of Custody)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO chain_of_custody (timestamp, source_agent, filename, sha256, status, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (iso_ts, source_agent, safe_filename, file_hash, "ACQUIRED", json.dumps(metadata or {})))
            conn.commit()

        # 2. Audit Log Entry
        log_payload = {
            "artifact_name": safe_filename,
            "original_name": filename,
            "sha256": file_hash,
            "size_bytes": os.path.getsize(file_path),
            "metadata": metadata or {}
        }
        
        self.audit_logger.log_event(
            source=source_agent,
            target="ARTIFACT_VAULT",
            payload=json.dumps(log_payload),
            status="STORED",
            reason="Artifact Lifecycle Management"
        )

        return {
            "path": file_path,
            "sha256": file_hash,
            "status": "stored"
        }

    def get_chain_of_custody(self):
        """Retrieve the full forensic timeline."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM chain_of_custody ORDER BY timestamp ASC")
            return [dict(row) for row in cursor.fetchall()]

    def list_artifacts(self):
        return os.listdir(self.base_dir)
