"""Tests for connection setup and the default DB location."""

from pathlib import Path

from memdo.storage import connect, default_db_path
from memdo.storage.db import _SCHEMA_PATH


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
    assert path == tmp_path / "MemDo" / "memdo.db"
    assert path.parent.is_dir()


def test_default_db_path_falls_back_to_home(tmp_path, monkeypatch):
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    path = default_db_path()
    assert path == tmp_path / ".memdo" / "memdo.db"
    assert path.parent.is_dir()
