"""SQLite connection helpers.

WAL mode lets a collector write recordings while the UI reads for playback.
The schema is applied idempotently on connect, so opening a fresh file just
works: a table added since a database was created (recording_allowlist, most
recently) appears on the next open. Only a change to an existing table needs
more, and there have been four: head_hash on region_snapshot, then can_read
and created_ft on process_snapshot, then allowlist_recorded on recording.
Used by the recording sampler to write and by the playback engine to read;
the live monitor does not touch it.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

_SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def default_db_path() -> Path:
    """Per-user data location: %LOCALAPPDATA%\\memlapse\\memlapse.db (or ~/.memlapse)."""
    import os

    base = os.environ.get("LOCALAPPDATA")
    root = Path(base) / "memlapse" if base else Path.home() / ".memlapse"
    root.mkdir(parents=True, exist_ok=True)
    return root / "memlapse.db"


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring a database created under an older schema up to the current one.

    Only additive changes, and each guarded by a look at the table it would
    change, because two connections (the sampler's and the GUI's) can open the
    same file at once and both run this. Rows written under the old shape are
    left as they are; the DAO reads them through their legacy table.
    """
    _add_column(conn, "region_snapshot", "head_hash", "BLOB")
    # Recorded from the sample's own handle and not derivable later: whether it
    # could read memory, and which instance of the pid it held. Left NULL on an
    # older recording, which reads as "not recorded" rather than as 0.
    _add_column(conn, "process_snapshot", "can_read", "INTEGER")
    _add_column(conn, "process_snapshot", "created_ft", "INTEGER")
    # Whether this recording wrote down the allowlist it was made under. NULL
    # on an older recording, which is not the same as having excused nothing.
    _add_column(conn, "recording", "allowlist_recorded", "INTEGER")


def _add_column(conn: sqlite3.Connection, table: str, column: str,
                decl: str) -> None:
    """Add one column if it is missing, tolerating a concurrent addition."""
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column in columns:
        return
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")
    except sqlite3.OperationalError as error:
        # The other connection got there first, which is fine.
        if "duplicate column" not in str(error):
            raise


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Open (creating if needed) a memlapse database with the schema applied."""
    path = Path(db_path) if db_path is not None else default_db_path()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA_PATH.read_text(encoding="utf-8"))
    _migrate(conn)
    return conn
