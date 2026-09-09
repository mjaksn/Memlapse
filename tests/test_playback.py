"""Tests for PlaybackEngine."""

import pytest

from memlapse.services import PlaybackEngine, describe_rewrites
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


# --- rewrite_history(): what the whole recording knows ----------------------
from memlapse.analytics import region_identity  # noqa: E402

#: The region every fixture below records, and the identity its rewrites are
#: filed under. An address alone is not a region: see `region_identity`.
EXEC_REGION = Region(0x10000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
EXEC_IDENTITY = region_identity(EXEC_REGION)


def _rewrite_db(tmp_db, heads_by_ts, region=None):
    """Record one executable region with the given head at each timestamp."""
    region = region or EXEC_REGION
    conn = connect(tmp_db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 0)
    for ts, head in heads_by_ts:
        dao.add_sample(rid, ts, ProcState(ts, 1000, 1, 1, 1), [region],
                       None if head is None else {region.base_addr: head})
    conn.close()
    return rid


def test_rewrite_history_is_the_per_sample_flags_gathered(tmp_db):
    """The history and the flags have to be the same detector.

    They are reached by different routes: :meth:`rewritten` anchors one sample
    and reads its regions and hashes through two queries with their own MAX
    subqueries, while the history walks every row once and groups them. Two
    routes to one answer is worth an assertion, because the tooltip that
    reports the count sits beside the flag that reports the moment, and an
    analyst who scrubs to the time the tooltip names has to find the flag
    there. The expectation is built from the other route rather than written
    out, so this fails if either route drifts from the other.
    """
    rid = _rewrite_db(tmp_db, [(1_000, b"aaa"), (2_000, b"bbb"),
                               (3_000, b"bbb"), (4_000, b"ccc")])
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(rid)
        by_sample: dict[tuple[int, int, int, int], list[int]] = {}
        for ts in engine.sample_times:
            _, regions = engine.seek(ts)
            shown = {r.base_addr: r for r in regions}
            for base in engine.rewritten(ts):
                by_sample.setdefault(region_identity(shown[base]), []).append(ts)
        assert by_sample == {EXEC_IDENTITY: [2_000, 4_000]}  # the route checked
        assert engine.rewrite_history(rid) == by_sample
    finally:
        engine.close()


def test_open_computes_the_history_once(tmp_db):
    """``rewrites`` is filled by open, and by nothing else.

    Playback reads it on the GUI thread for every tooltip, so it has to be
    the pass that already ran rather than a query per row.
    """
    rid = _rewrite_db(tmp_db, [(1_000, b"aaa"), (2_000, b"bbb")])
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        assert engine.rewrites == {}          # nothing open yet
        engine.open(rid)
        assert engine.rewrites == {EXEC_IDENTITY: [2_000]}
        engine.open(rid + 999)                # an id with no rows
        assert engine.rewrites == {}          # and no leftovers from the last
    finally:
        engine.close()


def test_rewrite_history_orders_the_times_and_omits_the_quiet(tmp_db):
    """Two regions, one rewritten twice and one never touched."""
    quiet = Region(0x20000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    loud = Region(0x10000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    conn = connect(tmp_db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 0)
    for ts, head in ((1_000, b"aaa"), (2_000, b"bbb"), (3_000, b"ccc")):
        dao.add_sample(rid, ts, ProcState(ts, 1000, 1, 1, 1), [loud, quiet],
                       {0x10000: head, 0x20000: b"same"})
    conn.close()
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(rid)
        assert engine.rewrites == {EXEC_IDENTITY: [2_000, 3_000]}
    finally:
        engine.close()


def test_rewrite_history_needs_a_head_on_both_sides(tmp_db):
    """A sample that captured no head cannot show a change, either way.

    A missing head means the comparison could not be made, which is the same
    allowance :meth:`rewritten` makes and the reason a recording of a process
    that denied reads reports no rewrites rather than reporting them all.
    """
    rid = _rewrite_db(tmp_db, [(1_000, None), (2_000, b"bbb"), (3_000, None),
                               (4_000, b"ddd")])
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(rid)
        assert engine.rewrites == {}
    finally:
        engine.close()


def test_rewrite_history_will_not_join_a_region_across_a_sample_it_missed(tmp_db):
    """A region that left the map and came back was not rewritten in place.

    It is a new allocation carrying whatever it carries, which is the
    allocation signal's business and not this one's. The pass has to compare
    consecutive samples rather than consecutive rows for one address, and the
    difference only shows when something else keeps the middle sample alive:
    with the region simply absent from every row of that tick there would be
    no sample there at all. So a second region stays throughout, and the
    per-sample detector is asked the same question as a witness.
    """
    gone = Region(0x10000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    stays = Region(0x20000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    conn = connect(tmp_db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 0)
    dao.add_sample(rid, 1_000, ProcState(1_000, 1000, 1, 1, 1), [gone, stays],
                   {0x10000: b"aaa", 0x20000: b"same"})
    dao.add_sample(rid, 2_000, ProcState(2_000, 1000, 1, 1, 1), [stays],
                   {0x20000: b"same"})
    dao.add_sample(rid, 3_000, ProcState(3_000, 1000, 1, 1, 1), [gone, stays],
                   {0x10000: b"zzz", 0x20000: b"same"})
    conn.close()
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(rid)
        assert engine.rewritten(3_000) == set()   # the flag agrees
        assert engine.rewrites == {}
    finally:
        engine.close()


def test_rewrite_history_does_not_compare_across_a_pid_reuse(tmp_db):
    """Two processes under one pid are not one process that rewrote itself.

    The sampler opens a fresh handle every tick, so a target that exits can
    have its number taken mid-recording and a stranger's map appended to the
    same recording. Differencing the two maps would report the stranger's
    memory as executable code overwritten in place, which is the loudest
    thing this tool says. The live view refuses the same comparison by ending
    the watch; a recording declines the one comparison instead.

    The whole-run surface needs this more than the flag does. A count and a
    tick are shown at every sample, including the ones before the reuse,
    where the header's warning about it is not shown yet.
    """
    conn = connect(tmp_db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 0)
    for ts, created, head in ((1_000, 111, b"aaa"), (2_000, 111, b"aaa"),
                              (3_000, 222, b"zzz"), (4_000, 222, b"zzz")):
        dao.add_sample(rid, ts,
                       ProcState(ts, 1000, 1, 1, 1, created_ft=created),
                       [EXEC_REGION], {0x10000: head})
    conn.close()
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(rid)
        assert engine.instance_changes == [3_000]   # the recording noticed
        assert engine.rewrites == {}                # and the history did too
        assert engine.rewritten(3_000) == set()     # both routes still agree
    finally:
        engine.close()


def test_rewrite_history_does_not_lend_an_address_to_the_next_allocation(tmp_db):
    """A region that inherits an address does not inherit its past.

    Windows reuses virtual addresses, so a region freed and another allocated
    at the same base later in the same recording is ordinary. Filing a
    rewrite under the address alone would show the first one's history on the
    second one's row, which is the whole run's version of a tick pointing at
    a sample where nothing happened.
    """
    from memlapse.model.region import MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ
    later = Region(0x10000, 64 * 1024, MEM_COMMIT, PAGE_EXECUTE_READ,
                   MEM_PRIVATE)
    conn = connect(tmp_db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 0)
    for ts, head in ((1_000, b"aaa"), (2_000, b"bbb")):      # rewritten at 2000
        dao.add_sample(rid, ts, ProcState(ts, 1000, 1, 1, 1), [EXEC_REGION],
                       {0x10000: head})
    dao.add_sample(rid, 3_000, ProcState(3_000, 1000, 1, 1, 1), [])  # freed
    dao.add_sample(rid, 4_000, ProcState(4_000, 1000, 1, 1, 1), [later],
                   {0x10000: b"ccc"})                        # a different one
    conn.close()
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(rid)
        assert engine.rewrites == {EXEC_IDENTITY: [2_000]}
        assert region_identity(later) not in engine.rewrites
    finally:
        engine.close()


def test_rewrite_history_of_a_recording_with_no_samples_is_empty(seeded_db):
    db, rid = seeded_db
    engine = PlaybackEngine(db_path=db)
    try:
        assert engine.rewrite_history(rid + 999) == {}
    finally:
        engine.close()


# --- the line the tooltip shows --------------------------------------------
def test_describe_rewrites_says_nothing_about_nothing():
    assert describe_rewrites([], 0) == ""


def test_describe_rewrites_counts_and_clocks():
    origin = 1_000_000_000
    assert (describe_rewrites([origin + 251_000_000], origin)
            == "rewritten once in this recording, at 00:04:11")
    assert (describe_rewrites([origin, origin + 60_000_000,
                               origin + 251_900_000], origin)
            == "rewritten 3 times in this recording, most recently at 00:04:11")


def test_describe_rewrites_carries_past_an_hour():
    """A long recording still reads as a clock, and the seconds truncate.

    Truncating is what puts the reader on the sample: a rewrite 11.9 seconds
    into the minute belongs to the sample at 11 seconds, and rounding up would
    name a second the timeline has nothing at.
    """
    assert (describe_rewrites([3_671_900_000], 0)
            == "rewritten once in this recording, at 01:01:11")


def test_a_restart_on_a_sample_with_no_map_still_stops_the_comparison(tmp_db):
    """The restart need not land on the sample being scored.

    An anchor comes from region_snapshot and a restart timestamp from
    process_snapshot, so a reuse recorded on a sample whose map came back
    empty sits between the two samples being differenced without equalling
    either end. Asking only whether the anchor is itself a restart lets that
    pair through, and the two halves belong to different processes.
    """
    conn = connect(tmp_db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 0)
    dao.add_sample(rid, 1_000, ProcState(1_000, 1000, 1, 1, 1, created_ft=111),
                   [EXEC_REGION], {0x10000: b"aaa"})
    # The reuse is noticed on a sample that carries no regions.
    dao.add_sample(rid, 2_000, ProcState(2_000, 1000, 1, 1, 1, created_ft=222),
                   [])
    dao.add_sample(rid, 3_000, ProcState(3_000, 1000, 1, 1, 1, created_ft=222),
                   [EXEC_REGION], {0x10000: b"zzz"})
    conn.close()

    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(rid)
        assert engine.instance_changes == [2_000]
        # 1_000 and 3_000 are the anchor pair, and 2_000 is neither of them.
        assert engine.rewritten(3_000) == set()
        assert engine.rewrites == {}
    finally:
        engine.close()
