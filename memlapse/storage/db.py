"""SQLite connection helpers.

WAL mode lets a collector write recordings while the UI reads for playback.
The schema is applied idempotently on connect, so opening a fresh file just
works, and the one shape change the schema has had so far (the head_hash
column on region_snapshot) is applied to older databases the same way. Used
by the recording sampler to write and by the playback engine to read; the
live monitor does not touch it.
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


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring a database created under an older schema up to the current one.

    Only additive changes, and each guarded by a look at the table it would
    change, because two connections (the sampler's and the GUI's) can open the
    same file at once and both run this. Rows written under the old shape are
    left as they are; the DAO reads them through their legacy table.
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(region_snapshot)")}
    if "head_hash" not in columns:
        try:
            conn.execute("ALTER TABLE region_snapshot ADD COLUMN head_hash BLOB")
        except sqlite3.OperationalError as error:
            # The other connection got there first, which is fine.
            if "duplicate column" not in str(error):
                raise


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Open (creating if needed) a Memlapse database with the schema applied."""
    path = Path(db_path) if db_path is not None else default_db_path()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA_PATH.read_text(encoding="utf-8"))
    _migrate(conn)
    return conn
