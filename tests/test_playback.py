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


def test_open_carries_the_recorded_image_name(seeded_db):
    """The name is what an allowlist entry is keyed on.

    Without it a replay scores against an empty allowlist while the watch it
    replays scored against the real one, which is the disagreement the whole
    lookup exists to prevent. Nothing else in the engine reads this, so only
    an assertion here stops it being dropped in a refactor.
    """
    db, rid = seeded_db
    engine = PlaybackEngine(db_path=db)
    try:
        assert engine.target_name == ""      # nothing open yet
        engine.open(rid)
        assert engine.target_name == "proc.exe"
    finally:
        engine.close()


def test_open_on_an_unknown_recording_leaves_the_name_empty(seeded_db):
    """An id with no row must not inherit the last recording's name."""
    db, rid = seeded_db
    engine = PlaybackEngine(db_path=db)
    try:
        engine.open(rid)
        engine.open(rid + 999)
        assert engine.target_name == ""
        assert engine.sample_times == []
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


# --- regions a thread starts in --------------------------------------------
def test_thread_start_regions_before_open_is_empty(seeded_db):
    db, _ = seeded_db
    engine = PlaybackEngine(db_path=db)
    try:
        assert engine.thread_start_regions(1_000) == set()
    finally:
        engine.close()


def test_thread_start_regions_matches_the_recorded_addresses(tmp_db):
    from memlapse.model.region import (
        MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ, Region,
    )
    region = Region(0x40000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    conn = connect(tmp_db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "p.exe", 0)
    dao.add_sample(rid, 1_000, ProcState(1_000, 1000, 1, 1, 1), [region],
                   None, {5: 0x40100})
    conn.close()
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(rid)
        assert engine.thread_start_regions(1_000) == {0x40000}
        assert engine.thread_start_regions(1) == set()   # before the first sample
    finally:
        engine.close()


# --- entropy falling to code-like values -----------------------------------
def test_unpacked_reports_a_region_that_decrypted_itself(tmp_db):
    from memlapse.model.region import (
        MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ, Region,
    )
    packed, code = bytes(range(256)), b"\x48\x8b\x05\x01" * 64
    region = Region(0x40000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    conn = connect(tmp_db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "p.exe", 0)
    for ts, head in ((1_000, packed), (2_000, code)):
        dao.add_sample(rid, ts, ProcState(ts, 1000, 1, 1, 1), [region],
                       {0x40000: head})
    conn.close()
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(rid)
        changed = engine.rewritten(2_000)
        assert changed == {0x40000}
        assert engine.unpacked(2_000, changed) == {0x40000}
        assert engine.unpacked(2_000, set()) == set()   # nothing changed, no reads
        assert engine.unpacked(1_000, {0x40000}) == set()  # no previous sample
    finally:
        engine.close()


def test_unpacked_before_open_is_empty(seeded_db):
    db, _ = seeded_db
    engine = PlaybackEngine(db_path=db)
    try:
        assert engine.unpacked(1_000, {0x40000}) == set()
    finally:
        engine.close()


def test_open_loads_the_allowlist_the_recording_was_made_under(tmp_db):
    """A replay scores with the recording's list, not the reader's.

    That is what makes a recording checkable by someone else: open it on
    another machine and the same rules are excused, whatever that machine
    has configured.
    """
    from memlapse.analytics import Allowlist, AllowlistEntry, RULE_PRIVATE_EXEC
    conn = connect(tmp_db)
    try:
        dao = Dao(conn)
        rid = dao.create_recording(1, "jit.exe", 1_000, allowlist=Allowlist(
            [AllowlistEntry("jit.exe", RULE_PRIVATE_EXEC, "JIT host")]))
        dao.add_sample(rid, 1_000, ProcState(1_000, 1000, 1, 1, 1), [])
    finally:
        conn.close()

    engine = PlaybackEngine(tmp_db)
    try:
        engine.open(rid)
        assert engine.allowlist is not None
        assert engine.allowlist.rules_for("jit.exe") == {RULE_PRIVATE_EXEC}
    finally:
        engine.close()


def test_open_reports_none_when_the_recording_wrote_no_allowlist(tmp_db):
    """Not an empty allowlist. The caller has to fall back, not excuse nothing."""
    conn = connect(tmp_db)
    try:
        dao = Dao(conn)
        rid = dao.create_recording(1, "p", 1_000)
        dao.add_sample(rid, 1_000, ProcState(1_000, 1000, 1, 1, 1), [])
    finally:
        conn.close()

    engine = PlaybackEngine(tmp_db)
    try:
        engine.open(rid)
        assert engine.allowlist is None
    finally:
        engine.close()


def test_open_keeps_a_recorded_empty_allowlist(tmp_db):
    """Falsy but present, so a caller testing for truth would lose it."""
    from memlapse.analytics import Allowlist
    conn = connect(tmp_db)
    try:
        dao = Dao(conn)
        rid = dao.create_recording(1, "p", 1_000, allowlist=Allowlist())
        dao.add_sample(rid, 1_000, ProcState(1_000, 1000, 1, 1, 1), [])
    finally:
        conn.close()

    engine = PlaybackEngine(tmp_db)
    try:
        engine.open(rid)
        assert engine.allowlist is not None and not engine.allowlist
    finally:
        engine.close()
