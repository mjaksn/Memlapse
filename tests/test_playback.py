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


# --- one identity, two allocations ------------------------------------------
def _two_spell_db(tmp_db):
    """The region goes away for a sample and comes back the same shape.

    Base, size, protection and state all match, so the structural identity is
    the same on both sides of the gap and nothing but the gap says these are
    two allocations. Another region keeps the middle sample non-empty, since
    a sample with no map at all is "nothing was seen", not "everything was
    freed".
    """
    other = Region(0x90000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    conn = connect(tmp_db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 0)
    for ts, region, head in ((1_000, EXEC_REGION, b"aaa"),
                             (2_000, EXEC_REGION, b"bbb"),   # rewrite here
                             (3_000, other, b"xxx"),         # ours is gone
                             (4_000, EXEC_REGION, b"ccc"),   # a new one
                             (5_000, EXEC_REGION, b"ddd")):  # rewrite here
        dao.add_sample(rid, ts, ProcState(ts, 1000, 1, 1, 1), [region],
                       {region.base_addr: head})
    conn.close()
    return rid


def test_a_row_is_shown_its_own_allocations_rewrites(tmp_db):
    """The second allocation does not inherit the first one's history.

    Both spells share an identity, so a lookup that ignored the gap would
    show a row at 2,000 a rewrite that had not happened yet and a row at
    5,000 one made by an allocation that no longer exists.
    """
    rid = _two_spell_db(tmp_db)
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(rid)
        assert engine.rewrites_at(2_000) == {EXEC_IDENTITY: [2_000]}
        assert engine.rewrites_at(5_000) == {EXEC_IDENTITY: [5_000]}
    finally:
        engine.close()


def test_the_scrubber_still_marks_every_rewrite_in_the_recording(tmp_db):
    """The marks answer for the run, so they keep both spells.

    The two surfaces want different things from one walk: a row wants the
    allocation it is looking at, the scrubber wants every moment worth
    scrubbing to.
    """
    rid = _two_spell_db(tmp_db)
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(rid)
        assert engine.rewrites == {EXEC_IDENTITY: [2_000, 5_000]}
    finally:
        engine.close()


def test_a_seek_between_samples_reads_the_sample_it_shows(tmp_db):
    """Resolved against the anchor, not the raw time.

    A seek at 2,500 shows the sample at 2,000, so it has to answer with that
    sample's spell. Resolving against the raw time would fall in the gap and
    answer with nothing at all.
    """
    rid = _two_spell_db(tmp_db)
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(rid)
        assert engine.rewrites_at(2_500) == {EXEC_IDENTITY: [2_000]}
    finally:
        engine.close()


def test_rewrites_at_is_empty_with_nothing_open(tmp_db):
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        assert engine.rewrites_at(1_000) == {}
        engine.open(_two_spell_db(tmp_db))
        assert engine.rewrites_at(0) == {}      # before the first sample
    finally:
        engine.close()


def test_a_sample_that_saw_nothing_does_not_end_an_allocation(tmp_db):
    """"Nothing was seen" is not "everything was freed".

    A sample whose map came back empty is what an unelevated target produces,
    and treating it as a free would cut the region's history in two at every
    such sample and show the later half as a fresh allocation. The region
    here is never observed to go away, so its rewrites stay one run.
    """
    conn = connect(tmp_db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 0)
    for ts, regions, head in ((1_000, [EXEC_REGION], b"aaa"),
                              (2_000, [EXEC_REGION], b"bbb"),  # rewrite here
                              (3_000, [], None),               # saw nothing
                              (4_000, [EXEC_REGION], b"bbb"),
                              (5_000, [EXEC_REGION], b"ccc")):  # rewrite here
        dao.add_sample(rid, ts, ProcState(ts, 1000, 1, 1, 1), regions,
                       None if head is None else {EXEC_REGION.base_addr: head})
    conn.close()

    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(rid)
        assert engine.rewrites_at(5_000) == {EXEC_IDENTITY: [2_000, 5_000]}
    finally:
        engine.close()


def test_a_new_process_does_not_continue_the_old_one_s_allocation(tmp_db):
    """A pid reuse ends every spell, not just the one comparison.

    Declining the comparison at the reuse keeps a stranger's bytes from being
    called a rewrite. It does not, on its own, stop the spell that was open
    before the reuse from running on into the new process, and a row in the
    new process would then be shown the old one's rewrites at every sample.
    """
    conn = connect(tmp_db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 0)
    for ts, created, head in ((1_000, 111, b"aaa"), (2_000, 111, b"bbb"),
                              (3_000, 222, b"ccc"), (4_000, 222, b"ddd")):
        dao.add_sample(rid, ts, ProcState(ts, 1000, 1, 1, 1, created_ft=created),
                       [EXEC_REGION], {EXEC_REGION.base_addr: head})
    conn.close()

    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(rid)
        assert engine.instance_changes == [3_000]
        # 2_000 belongs to the process that is gone, and 3_000 is the reuse,
        # where the comparison is declined outright.
        assert engine.rewrites_at(4_000) == {EXEC_IDENTITY: [4_000]}
        assert engine.rewrites_at(2_000) == {EXEC_IDENTITY: [2_000]}
    finally:
        engine.close()


# --- the whole-run walk runs off the GUI thread ------------------------------
import memlapse.services.playback as playback_mod  # noqa: E402


def test_the_walk_goes_to_the_qt_pool_by_default():
    """The app runs it on a pool thread; only the tests run it inline.

    Every test here substitutes an inline pool, so without this the real
    factory would never run and the thing being claimed about the app would
    be the one thing untested.
    """
    from PySide6.QtCore import QThreadPool
    assert isinstance(playback_mod._history_pool(), QThreadPool)


def test_a_walk_that_lands_after_the_analyst_moved_on_is_dropped(tmp_db):
    """A slow recording must not overwrite the one now on screen.

    The walk is linear in the recording, so a long one can still be going
    when the analyst opens a short one. Its answer arrives addressed to the
    question it was asked, and by then that is not the question.
    """
    slow = _rewrite_db(tmp_db, [(1_000, b"aaa"), (2_000, b"bbb")])
    quiet = _rewrite_db(tmp_db, [(3_000, b"ccc"), (4_000, b"ccc")])
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(quiet)
        assert engine.rewrites == {}
        landed = []
        engine.rewrites_ready.connect(lambda: landed.append(True))
        # A worker for the recording opened before this one, finishing now.
        stale = playback_mod._HistoryWorker(tmp_db, slow, engine._sequence - 1)
        stale.signals.done.connect(engine._history_walked)
        stale.run()
        assert engine.rewrites == {}      # not the slow recording's rewrite
        assert landed == []               # and nothing was told to redraw
    finally:
        engine.close()


def test_the_worker_walks_what_the_engine_would_have(tmp_db):
    """The worker's own connection has to reach the same answer.

    It opens its own database handle, since SQLite connections cannot cross
    threads, so nothing but a test says it reads the same recording the same
    way.
    """
    rid = _two_spell_db(tmp_db)
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        expected = engine.rewrite_spells(rid)
        got = []
        worker = playback_mod._HistoryWorker(tmp_db, rid, 1)
        worker.signals.done.connect(lambda seq, spells: got.append((seq, spells)))
        worker.run()
        assert got == [(1, expected)]
    finally:
        engine.close()


def test_closing_retires_a_walk_that_is_still_running(tmp_db):
    """Its connection is gone, so its answer is about nothing.

    Closing is what happens when the analyst leaves playback, and a walk
    started before that can still be going. Taking its result would put a
    closed recording's history back on an engine nobody is looking at, and
    announce it.
    """
    rid = _rewrite_db(tmp_db, [(1_000, b"aaa"), (2_000, b"bbb")])
    engine = PlaybackEngine(db_path=tmp_db)
    engine.open(rid)
    in_flight = playback_mod._HistoryWorker(tmp_db, rid, engine._sequence)
    in_flight.signals.done.connect(engine._history_walked)
    engine.close()

    landed = []
    engine.rewrites_ready.connect(lambda: landed.append(True))
    in_flight.run()
    assert landed == []


def test_a_protection_flip_ends_the_spell_even_alone_in_the_map(tmp_db):
    """Seen and not comparable is not the same as not seen.

    The region is the only executable one in this process, so when it turns
    writable for a sample the comparable set is empty, exactly as it is when
    a map could not be read at all. Treating the two alike keeps the spell
    open across a protection change and hands the returning region the
    rewrites its predecessor made, which is the thing `region_identity`
    exists to prevent: a fresh identity gets a fresh history.
    """
    from memlapse.model.region import PAGE_READWRITE
    writable = Region(EXEC_REGION.base_addr, EXEC_REGION.size, MEM_COMMIT,
                      PAGE_READWRITE, MEM_PRIVATE)
    conn = connect(tmp_db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "proc.exe", 0)
    for ts, region, head in ((1_000, EXEC_REGION, b"aaa"),
                             (2_000, EXEC_REGION, b"bbb"),   # rewrite here
                             (3_000, writable, b"bbb"),      # seen, not exec
                             (4_000, EXEC_REGION, b"ccc"),
                             (5_000, EXEC_REGION, b"ddd")):  # rewrite here
        dao.add_sample(rid, ts, ProcState(ts, 1000, 1, 1, 1), [region],
                       {region.base_addr: head})
    conn.close()

    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(rid)
        # The map was seen at 3_000, so the executable identity was gone.
        assert engine.rewrites_at(5_000) == {EXEC_IDENTITY: [5_000]}
        assert engine.rewrites_at(2_000) == {EXEC_IDENTITY: [2_000]}
    finally:
        engine.close()


def test_a_walk_that_cannot_run_says_so(tmp_db):
    """Silence would be read as "this recording holds no rewrites".

    That is a claim about the process. The truth would be that nobody
    managed to look, and the two have to be told apart or an analyst reads a
    failed scan as a clean one.
    """
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        failures, walks = [], []
        engine.history_failed.connect(failures.append)
        engine.rewrites_ready.connect(lambda: walks.append(True))
        engine.open(_rewrite_db(tmp_db, [(1_000, b"aaa")]))
        walks.clear()
        # A path no connection can be opened on, which is what a locked or
        # deleted database looks like from the pool thread.
        broken = playback_mod._HistoryWorker(
            tmp_db + "/no/such/dir/x.db", 1, engine._sequence)
        broken.signals.failed.connect(engine._history_gave_up)
        broken.signals.done.connect(engine._history_walked)
        broken.run()
        assert len(failures) == 1 and failures[0]
        assert walks == []
    finally:
        engine.close()


def test_a_failure_from_a_walk_nobody_is_waiting_for_is_dropped(tmp_db):
    """The staleness rule is the same for a failure as for an answer."""
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(_rewrite_db(tmp_db, [(1_000, b"aaa")]))
        failures = []
        engine.history_failed.connect(failures.append)
        engine._history_gave_up(engine._sequence - 1, "from a recording since closed")
        assert failures == []
    finally:
        engine.close()


class _RecordingPool:
    """A pool that queues rather than runs, so retirement can be observed."""

    def __init__(self, takeable=True):
        self.started, self.taken, self._takeable = [], [], takeable

    def start(self, runnable):
        self.started.append(runnable)

    def tryTake(self, runnable):
        if not self._takeable:
            return False
        self.taken.append(runnable)
        return True


def test_opening_another_recording_takes_the_first_walk_off_the_pool(tmp_db,
                                                                    monkeypatch):
    """Dropping the answer is not the same as not doing the work.

    Switching recordings would otherwise queue a full scan of each one, and
    the recording the analyst is waiting for would sit behind scans nobody
    wants any more.
    """
    pool = _RecordingPool()
    monkeypatch.setattr(playback_mod.PlaybackEngine, "pool_factory",
                        staticmethod(lambda: pool))
    first = _rewrite_db(tmp_db, [(1_000, b"aaa"), (2_000, b"bbb")])
    second = _rewrite_db(tmp_db, [(3_000, b"ccc")])
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(first)
        engine.open(second)
        assert len(pool.started) == 2
        assert pool.taken == [pool.started[0]]      # the first, never run
    finally:
        engine.close()


def test_a_walk_already_running_is_asked_to_stop(tmp_db, monkeypatch):
    """It cannot be taken back, so it is told to give up at the next sample."""
    pool = _RecordingPool(takeable=False)
    monkeypatch.setattr(playback_mod.PlaybackEngine, "pool_factory",
                        staticmethod(lambda: pool))
    engine = PlaybackEngine(db_path=tmp_db)
    try:
        engine.open(_rewrite_db(tmp_db, [(1_000, b"aaa"), (2_000, b"bbb")]))
        running = pool.started[0]
        engine.close()
        assert running._stopped is True
    finally:
        pass


def test_a_stopped_walk_reads_no_further(tmp_db, monkeypatch):
    """And brings nothing back, since nobody is waiting for a half answer."""
    pool = _RecordingPool(takeable=False)
    monkeypatch.setattr(playback_mod.PlaybackEngine, "pool_factory",
                        staticmethod(lambda: pool))
    engine = PlaybackEngine(db_path=tmp_db)
    rid = _rewrite_db(tmp_db, [(1_000, b"aaa"), (2_000, b"bbb")])
    try:
        engine.open(rid)
        worker = pool.started[0]
        worker.stop()
        got = []
        worker.signals.done.connect(lambda seq, spells: got.append(spells))
        worker.run()
        assert got == [{}]      # abandoned, not a walk that found nothing
    finally:
        engine.close()
