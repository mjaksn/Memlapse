"""Tests for connection setup and the default DB location."""

from pathlib import Path

from memlapse.storage import connect, default_db_path
from memlapse.storage.db import _SCHEMA_PATH


def test_connect_applies_schema_and_pragmas(tmp_db):
    conn = connect(tmp_db)
    try:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"recording", "process_snapshot", "region_snapshot",
                "mem_event", "thread", "region_blob"} <= tables
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        conn.close()


def test_connect_is_idempotent(tmp_db):
    connect(tmp_db).close()
    # Re-opening an existing DB must not raise (schema uses IF NOT EXISTS).
    conn = connect(tmp_db)
    conn.close()


def test_schema_file_exists():
    assert _SCHEMA_PATH.exists()


def test_default_db_path_uses_localappdata(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    path = default_db_path()
    assert path == tmp_path / "Memlapse" / "memlapse.db"
    assert path.parent.is_dir()


def test_default_db_path_falls_back_to_home(tmp_path, monkeypatch):
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    path = default_db_path()
    assert path == tmp_path / ".memlapse" / "memlapse.db"
    assert path.parent.is_dir()


# --- migration of databases created before head deduplication --------------
import sqlite3  # noqa: E402

import pytest  # noqa: E402

import memlapse.storage.db as dbmod  # noqa: E402
from memlapse.storage.dao import Dao  # noqa: E402


def _old_shape_db(path):
    """A database as the schema wrote it before the head table existed."""
    conn = sqlite3.connect(path)
    conn.executescript(
        "CREATE TABLE recording (id INTEGER PRIMARY KEY, target_pid INTEGER NOT NULL,"
        " target_name TEXT NOT NULL, started_utc INTEGER NOT NULL, ended_utc INTEGER,"
        " note TEXT);"
        "CREATE TABLE process_snapshot (id INTEGER PRIMARY KEY, recording_id INTEGER"
        " NOT NULL, ts_us INTEGER NOT NULL, pid INTEGER NOT NULL, wset_bytes INTEGER"
        " NOT NULL, priv_bytes INTEGER NOT NULL, thread_count INTEGER NOT NULL);"
        "CREATE TABLE region_snapshot (id INTEGER PRIMARY KEY, recording_id INTEGER"
        " NOT NULL, ts_us INTEGER NOT NULL, base_addr INTEGER NOT NULL, size INTEGER"
        " NOT NULL, protect INTEGER NOT NULL, state INTEGER NOT NULL,"
        " type INTEGER NOT NULL);"
        "CREATE TABLE region_blob (region_snapshot_id INTEGER PRIMARY KEY REFERENCES"
        " region_snapshot(id) ON DELETE CASCADE, content BLOB NOT NULL);"
        "INSERT INTO recording VALUES (1, 1000, 'p', 0, NULL, NULL);"
        "INSERT INTO process_snapshot VALUES (1, 1, 1000, 1000, 1, 1, 1);"
        "INSERT INTO region_snapshot VALUES (1, 1, 1000, 65536, 4096, 32, 4096, 131072);"
        "INSERT INTO region_blob VALUES (1, X'4D5A');"
    )
    conn.commit()
    conn.close()


def test_connect_migrates_old_database(tmp_db):
    _old_shape_db(tmp_db)
    conn = connect(tmp_db)
    try:
        columns = {r[1] for r in conn.execute("PRAGMA table_info(region_snapshot)")}
        assert "head_hash" in columns
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        assert "head" in tables
        # The old recording still reads back through the legacy table, and
        # carries no hash for the detector to mistake for a change.
        dao = Dao(conn)
        assert dao.heads_at(1, 1000) == {65536: b"MZ"}
        assert dao.head_hashes_at(1, 1000) == {}
    finally:
        conn.close()


def test_connect_twice_after_migration_is_quiet(tmp_db):
    _old_shape_db(tmp_db)
    connect(tmp_db).close()
    conn = connect(tmp_db)  # column already present: nothing to do
    try:
        columns = [r[1] for r in conn.execute("PRAGMA table_info(region_snapshot)")]
        assert columns.count("head_hash") == 1
    finally:
        conn.close()


class _RacingConn:
    """A connection whose ALTER loses a race with another connection."""

    def __init__(self, message):
        self.message = message

    def execute(self, sql, *args):
        if sql.startswith("PRAGMA table_info"):
            return iter([])  # reports no columns, so the ALTER is attempted
        raise sqlite3.OperationalError(self.message)


def test_migrate_tolerates_a_duplicate_column_from_the_other_connection():
    dbmod._migrate(_RacingConn("duplicate column name: head_hash"))  # must not raise


def test_migrate_reraises_other_errors():
    with pytest.raises(sqlite3.OperationalError, match="locked"):
        dbmod._migrate(_RacingConn("database is locked"))
