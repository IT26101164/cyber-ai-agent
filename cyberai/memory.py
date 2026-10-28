"""Small SQLite memory store for user-approved notes."""
from __future__ import annotations
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

class MemoryStore:
    def __init__(self, db_path: str | Path = "data/memory.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS memories (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    category TEXT NOT NULL,
                    content TEXT NOT NULL
                )
            """)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def remember(self, content: str, category: str = "note") -> int:
        content = content.strip()
        category = category.strip()[:40] or "note"
        if not content:
            raise ValueError("Memory content cannot be empty.")
        if len(content) > 8000:
            raise ValueError("Memory content must be 8000 characters or fewer.")
        with self._connect() as con:
            cur = con.execute(
                "INSERT INTO memories(created_at, category, content) VALUES (?, ?, ?)",
                (utc_now(), category, content),
            )
            return int(cur.lastrowid)

    def search(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        words = [w for w in query.lower().split() if w][:8]
        if not words:
            return []
        limit = max(1, min(int(limit), 20))
        clauses = " AND ".join("lower(content) LIKE ?" for _ in words)
        params: list[Any] = [f"%{word}%" for word in words]
        params.append(limit)
        with self._connect() as con:
            rows = con.execute(
                f"SELECT id, created_at, category, content FROM memories "
                f"WHERE {clauses} ORDER BY id DESC LIMIT ?",
                params,
            ).fetchall()
        return [
            {"id": r[0], "created_at": r[1], "category": r[2], "content": r[3]}
            for r in rows
        ]
