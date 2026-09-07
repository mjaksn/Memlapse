"""Tests for PlaybackEngine."""

import pytest

from memlapse.services import PlaybackEngine
from memlapse.storage import connect
from memlapse.storage.dao import Dao, ProcState


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


def test_heads_before_open_returns_empty(seeded_db):
    db, _ = seeded_db
    engine = PlaybackEngine(db_path=db)
    try:
        assert engine.heads(1_000) == {}  # recording_id is None
    finally:
        engine.close()


def test_heads_returns_captured_bytes(tmp_db, sample_regions):
    conn = connect(tmp_db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 0)
    captured = {sample_regions[0].base_addr: b"MZ\x90\x90"}
    dao.add_sample(rid, 1_000, ProcState(1_000, 1000, 1, 1, 1),
                   sample_regions, captured)
    conn.close()
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(rid)
        assert engine.heads(1_000) == captured
    finally:
        engine.close()


# --- rewritten(): the content-change detector over consecutive samples -------
from memlapse.model.region import (  # noqa: E402
    MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ, Region,
)


def test_rewritten_before_open_is_empty(seeded_db):
    db, _ = seeded_db
    engine = PlaybackEngine(db_path=db)
    try:
        assert engine.rewritten(1_000) == set()  # recording_id is None
    finally:
        engine.close()


def test_rewritten_with_no_previous_sample_is_empty(seeded_db):
    db, rid = seeded_db
    engine = PlaybackEngine(db_path=db)
    try:
        engine.open(rid)
        assert engine.rewritten(1) == set()      # before the first sample
        assert engine.rewritten(1_000) == set()  # at the first sample
    finally:
        engine.close()


def test_rewritten_reports_the_region_whose_head_changed(tmp_db):
    exec_region = Region(0x10000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    conn = connect(tmp_db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 0)
    for ts, head in ((1_000, b"aaa"), (2_000, b"aaa"), (3_000, b"bbb")):
        dao.add_sample(rid, ts, ProcState(ts, 1000, 1, 1, 1), [exec_region],
                       {0x10000: head})
    conn.close()
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(rid)
        assert engine.rewritten(2_000) == set()        # same bytes as before
        assert engine.rewritten(3_000) == {0x10000}    # changed in place
        assert engine.rewritten(3_500) == {0x10000}    # anchored to the 3_000 sample
    finally:
        engine.close()
