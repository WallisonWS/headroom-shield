"""
Reversible Compress-Cache-Retrieve (CCR) SQLite Store.
Schema mirrors Headroom's production SQLite WAL design observed via REA
(`ccr_entries(hash, entry_json, created_at, ttl)` + `idx_ccr_expiry_deadline`)
upgraded with optional zlib payload compression and zero-telemetry local storage.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import time
import zlib
from pathlib import Path
from typing import Any, Dict, Optional


class CCRStore:
    def __init__(self, db_path: str | Path = ":memory:", default_ttl: int = 3600) -> None:
        self.db_path = str(db_path)
        self.default_ttl = default_ttl
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        if self.db_path != ":memory:":
            cur.execute("PRAGMA journal_mode=WAL;")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS ccr_entries (
                hash TEXT PRIMARY KEY,
                entry_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                ttl INTEGER NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ccr_expiry_deadline
            ON ccr_entries (created_at + ttl)
            """
        )
        self._conn.commit()

    def store(self, payload: Any, metadata: Optional[Dict[str, Any]] = None, ttl: Optional[int] = None) -> str:
        raw_str = json.dumps(payload, ensure_ascii=False, sort_keys=True) if not isinstance(payload, str) else payload
        short_hash = hashlib.sha256(raw_str.encode("utf-8")).hexdigest()[:12]
        compressed_b64 = base64.b64encode(zlib.compress(raw_str.encode("utf-8"), level=6)).decode("ascii")
        envelope = json.dumps({
            "encoding": "zlib+b64",
            "data": compressed_b64,
            "metadata": metadata or {},
        })
        now = time.time()
        entry_ttl = ttl if ttl is not None else self.default_ttl
        self._conn.execute(
            "INSERT OR REPLACE INTO ccr_entries (hash, entry_json, created_at, ttl) VALUES (?, ?, ?, ?)",
            (short_hash, envelope, now, entry_ttl),
        )
        self._conn.commit()
        return short_hash

    def retrieve(self, short_hash: str) -> Optional[Dict[str, Any]]:
        now = time.time()
        row = self._conn.execute(
            "SELECT entry_json, created_at, ttl FROM ccr_entries WHERE hash = ?",
            (short_hash,),
        ).fetchone()
        if not row:
            return None
        entry_json, created_at, ttl = row
        if created_at + ttl < now:
            self._conn.execute("DELETE FROM ccr_entries WHERE hash = ?", (short_hash,))
            self._conn.commit()
            return None
        env = json.loads(entry_json)
        if env.get("encoding") == "zlib+b64":
            raw_text = zlib.decompress(base64.b64decode(env["data"])).decode("utf-8")
        else:
            raw_text = env.get("data", "")
        return {"hash": short_hash, "content": raw_text, "metadata": env.get("metadata", {})}

    def prune_expired(self) -> int:
        now = time.time()
        cur = self._conn.execute("DELETE FROM ccr_entries WHERE (created_at + ttl) < ?", (now,))
        self._conn.commit()
        return cur.rowcount

    def stats(self) -> Dict[str, Any]:
        count = self._conn.execute("SELECT COUNT(*) FROM ccr_entries").fetchone()[0]
        return {"entries_stored": count, "db_path": self.db_path}
