#!/usr/bin/env python3
import os
import hashlib
import shutil
import json
import sqlite3
from datetime import datetime
from security_manager import AuditLogger

from cryptography.fernet import Fernet
from secret_store import SecretStore

class ArtifactManager:
    _ENC_KEY_NAME = "ARTIFACT_ENCRYPTION_KEY"

    def __init__(self, base_dir="artifacts", audit_log_path="state/audit.log", db_path="state/forensic_timeline.db"):
        self.base_dir = base_dir
        self.audit_logger = AuditLogger(log_path=audit_log_path)
        self.db_path = db_path
        os.makedirs(self.base_dir, exist_ok=True)
        self._init_db()
        self._fernet = self._get_cipher()

    def _get_cipher(self):
        """Initialize or retrieve the master encryption key from the secure vault."""
        key = SecretStore.get_secret(self._ENC_KEY_NAME)
        if not key:
            key = Fernet.generate_key().decode()
            SecretStore.set_secret(self._ENC_KEY_NAME, key)
        return Fernet(key.encode())

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self):
        """Initialize the forensic timeline database."""
        os.chmod(self.db_path, 0o600) if os.path.exists(self.db_path) else None
        with self._get_conn() as conn:
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
        Encrypt and store a file artifact, update forensic timeline.
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{timestamp}_{filename}.enc"
        file_path = os.path.join(self.base_dir, safe_filename)
        iso_ts = datetime.utcnow().isoformat() + "Z"

        # Content preparation (ensure bytes)
        raw_data = content if isinstance(content, bytes) else content.encode('utf-8')
        
        # Tier 4: Encryption-at-Rest
        encrypted_data = self._fernet.encrypt(raw_data)

        # Write file with owner-only permissions
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(file_path, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(encrypted_data)
        except Exception:
            os.close(fd)
            raise

        # SHA-256 of the RAW data (for forensic validation post-decryption)
        file_hash = hashlib.sha256(raw_data).hexdigest()

        # 1. Update Forensic Timeline (Chain of Custody)
        with self._get_conn() as conn:
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
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM chain_of_custody ORDER BY timestamp ASC")
            return [dict(row) for row in cursor.fetchall()]

    def list_artifacts(self):
        return os.listdir(self.base_dir)
