"""SQLite connection helpers.

WAL mode lets a collector write recordings while the UI reads for playback.
The schema is applied idempotently on connect, so opening a fresh file just
works. Used by the recording sampler to write and by the playback engine to
read; the live monitor does not touch it.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

_SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def default_db_path() -> Path:
    """Per-user data location: %LOCALAPPDATA%\\Memlapse\\memlapse.db (or ~/.memlapse)."""
    import os

    base = os.environ.get("LOCALAPPDATA")
    root = Path(base) / "Memlapse" if base else Path.home() / ".memlapse"
    root.mkdir(parents=True, exist_ok=True)
    return root / "memlapse.db"


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Open (creating if needed) a Memlapse database with the schema applied."""
    path = Path(db_path) if db_path is not None else default_db_path()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn
