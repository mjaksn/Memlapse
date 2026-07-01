"""Tests for PlaybackEngine."""

import pytest

from memdo.services import PlaybackEngine
from memdo.storage import connect
from memdo.storage.dao import Dao, ProcState


@pytest.fixture
def seeded_db(tmp_db, sample_regions):
    conn = connect(tmp_db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 1_000)
    dao.add_sample(rid, 1_000, ProcState(1_000, 1000, 100, 50, 3), sample_regions)
    dao.add_sample(rid, 2_000, ProcState(2_000, 1000, 200, 60, 4), sample_regions)
    dao.end_recording(rid, 3_000)
    conn.close()
    return tmp_db, rid


def test_list_and_open(seeded_db):
    db, rid = seeded_db
    engine = PlaybackEngine(db_path=db)
    try:
        assert [r.id for r in engine.list_recordings()] == [rid]
        times = engine.open(rid)
        assert times == [1_000, 2_000]
        assert engine.recording_id == rid
    finally:
        engine.close()


def test_seek_returns_state_and_regions(seeded_db):
    db, rid = seeded_db
    engine = PlaybackEngine(db_path=db)
    try:
        engine.open(rid)
        state, regions = engine.seek(2_000)
        assert state.wset_bytes == 200
        assert state.thread_count == 4
        assert len(regions) == 2
    finally:
        engine.close()


def test_seek_before_open_returns_empty(seeded_db):
    db, _ = seeded_db
    engine = PlaybackEngine(db_path=db)
    try:
        assert engine.seek(1_000) == (None, [])
    finally:
        engine.close()
