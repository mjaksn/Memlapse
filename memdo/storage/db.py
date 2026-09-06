"""SQLite connection helpers.

WAL mode lets a collector write recordings while the UI reads for playback.
The schema is applied idempotently on connect, so opening a fresh file just
works. Wired for Phase 3 (recording), not yet used by the live monitor.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

_SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def default_db_path() -> Path:
    """Per-user data location: %LOCALAPPDATA%\\MemDo\\memdo.db (or ~/.memdo)."""
    import os

    base = os.environ.get("LOCALAPPDATA")
    root = Path(base) / "MemDo" if base else Path.home() / ".memdo"
    root.mkdir(parents=True, exist_ok=True)
    return root / "memdo.db"


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Open (creating if needed) a MemDo database with the schema applied."""
    path = Path(db_path) if db_path is not None else default_db_path()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn
