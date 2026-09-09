"""Tests for the storage DAO round-trip and playback reads."""

import pytest

from memlapse.storage import connect
from memlapse.storage.dao import Dao, ProcState


@pytest.fixture
def dao(tmp_db):
    conn = connect(tmp_db)
    d = Dao(conn)
    yield d
    conn.close()


def _state(ts, pid=1000, wset=100, priv=50, threads=3):
    return ProcState(ts_us=ts, pid=pid, wset_bytes=wset, priv_bytes=priv,
                     thread_count=threads)


def test_create_and_list_recording(dao):
    rid = dao.create_recording(1000, "proc.exe", 1_000, note="hi")
    recs = dao.list_recordings()
    assert len(recs) == 1
    assert recs[0].id == rid
    assert recs[0].target_pid == 1000
    assert recs[0].target_name == "proc.exe"
    assert recs[0].note == "hi"
    assert recs[0].ended_utc is None


def test_end_recording_sets_timestamp(dao):
    rid = dao.create_recording(1, "p", 1_000)
    dao.end_recording(rid, 5_000)
    assert dao.list_recordings()[0].ended_utc == 5_000


def test_recordings_sorted_newest_first(dao):
    old = dao.create_recording(1, "old", 1_000)
    new = dao.create_recording(2, "new", 9_000)
    assert [r.id for r in dao.list_recordings()] == [new, old]


def test_add_sample_and_sample_times(dao, sample_regions):
    rid = dao.create_recording(1000, "p", 1_000)
    dao.add_sample(rid, 1_000, _state(1_000), sample_regions)
    dao.add_sample(rid, 2_000, _state(2_000), sample_regions)
    assert dao.sample_times(rid) == [1_000, 2_000]


def test_state_at_returns_latest_before(dao, sample_regions):
    rid = dao.create_recording(1000, "p", 0)
    dao.add_sample(rid, 1_000, _state(1_000, wset=111), sample_regions)
    dao.add_sample(rid, 2_000, _state(2_000, wset=222), sample_regions)
    # Between samples -> the earlier one wins (latest <= ts).
    assert dao.state_at(rid, 1_500).wset_bytes == 111
    assert dao.state_at(rid, 2_000).wset_bytes == 222
    assert dao.state_at(rid, 9_999).wset_bytes == 222


def test_state_at_before_first_is_none(dao, sample_regions):
    rid = dao.create_recording(1000, "p", 0)
    dao.add_sample(rid, 5_000, _state(5_000), sample_regions)
    assert dao.state_at(rid, 1_000) is None


def test_regions_at_returns_matching_sample(dao, sample_regions):
    rid = dao.create_recording(1000, "p", 0)
    dao.add_sample(rid, 1_000, _state(1_000), sample_regions[:1])
    dao.add_sample(rid, 2_000, _state(2_000), sample_regions)  # 2 regions
    at1 = dao.regions_at(rid, 1_500)
    at2 = dao.regions_at(rid, 2_500)
    assert len(at1) == 1
    assert len(at2) == 2
    # Field integrity survives the round-trip.
    assert at2[0].base_addr == sample_regions[0].base_addr
    assert at2[1].protect == sample_regions[1].protect


def test_regions_at_before_first_is_empty(dao, sample_regions):
    rid = dao.create_recording(1000, "p", 0)
    dao.add_sample(rid, 5_000, _state(5_000), sample_regions)
    assert dao.regions_at(rid, 1_000) == []


def test_add_sample_with_no_regions(dao):
    rid = dao.create_recording(1000, "p", 0)
    dao.add_sample(rid, 1_000, _state(1_000), [])
    assert dao.sample_times(rid) == [1_000]
    assert dao.regions_at(rid, 1_000) == []


# --- region head blobs -----------------------------------------------------
def test_add_sample_stores_heads_for_matching_regions(dao, sample_regions):
    rid = dao.create_recording(1000, "p", 0)
    # Head provided for the first region only; the second gets no blob.
    heads = {sample_regions[0].base_addr: b"MZ\x90\x90"}
    dao.add_sample(rid, 1_000, _state(1_000), sample_regions, heads)
    assert dao.heads_at(rid, 1_000) == {sample_regions[0].base_addr: b"MZ\x90\x90"}


def test_heads_at_empty_when_no_heads_recorded(dao, sample_regions):
    rid = dao.create_recording(1000, "p", 0)
    dao.add_sample(rid, 1_000, _state(1_000), sample_regions)  # no heads arg
    assert dao.heads_at(rid, 1_000) == {}


def test_heads_at_before_first_sample_is_empty(dao, sample_regions):
    rid = dao.create_recording(1000, "p", 0)
    dao.add_sample(rid, 5_000, _state(5_000), sample_regions, {0x10000: b"x"})
    assert dao.heads_at(rid, 1_000) == {}


def test_heads_at_uses_latest_sample_before(dao, sample_regions):
    rid = dao.create_recording(1000, "p", 0)
    dao.add_sample(rid, 1_000, _state(1_000), sample_regions, {0x10000: b"old"})
    dao.add_sample(rid, 2_000, _state(2_000), sample_regions, {0x10000: b"new"})
    assert dao.heads_at(rid, 1_500) == {0x10000: b"old"}
    assert dao.heads_at(rid, 9_999) == {0x10000: b"new"}


# --- head deduplication, hashes and sample anchors -------------------------
from memlapse.analytics import head_hash  # noqa: E402


def _head_rows(dao):
    return dao.conn.execute("SELECT COUNT(*) FROM head").fetchone()[0]


def test_add_sample_stores_each_distinct_head_once(dao, sample_regions):
    rid = dao.create_recording(1000, "p", 0)
    dao.add_sample(rid, 1_000, _state(1_000), sample_regions, {0x10000: b"same"})
    dao.add_sample(rid, 2_000, _state(2_000), sample_regions,
                   {0x10000: b"same", 0x20000: b"other"})
    # Two distinct contents across three captured heads: two rows, not three.
    assert _head_rows(dao) == 2
    assert dao.heads_at(rid, 1_000) == {0x10000: b"same"}
    assert dao.heads_at(rid, 2_000) == {0x10000: b"same", 0x20000: b"other"}


def test_head_hashes_at_maps_base_to_digest(dao, sample_regions):
    rid = dao.create_recording(1000, "p", 0)
    dao.add_sample(rid, 1_000, _state(1_000), sample_regions, {0x10000: b"MZ"})
    assert dao.head_hashes_at(rid, 1_000) == {0x10000: head_hash(b"MZ")}


def test_head_hashes_at_before_first_sample_is_empty(dao, sample_regions):
    rid = dao.create_recording(1000, "p", 0)
    dao.add_sample(rid, 5_000, _state(5_000), sample_regions, {0x10000: b"x"})
    assert dao.head_hashes_at(rid, 1_000) == {}


def test_sample_at_and_previous_sample_ts(dao, sample_regions):
    rid = dao.create_recording(1000, "p", 0)
    dao.add_sample(rid, 1_000, _state(1_000), sample_regions)
    dao.add_sample(rid, 2_000, _state(2_000), sample_regions)
    assert dao.sample_at(rid, 500) is None
    assert dao.sample_at(rid, 1_500) == 1_000
    assert dao.sample_at(rid, 2_000) == 2_000
    assert dao.previous_sample_ts(rid, 1_000) is None
    assert dao.previous_sample_ts(rid, 2_000) == 1_000
    assert dao.previous_sample_ts(rid, 9_999) == 2_000


def test_heads_at_reads_legacy_region_blob_rows(dao, sample_regions):
    # A recording made before heads were deduplicated: the row has no hash and
    # its bytes sit in region_blob. It must still read back, and it must not
    # pretend to have a hash the detector could compare.
    rid = dao.create_recording(1000, "p", 0)
    dao.add_sample(rid, 1_000, _state(1_000), sample_regions)
    row_id = dao.conn.execute(
        "SELECT id FROM region_snapshot WHERE recording_id=? AND base_addr=?",
        (rid, 0x10000),
    ).fetchone()[0]
    dao.conn.execute(
        "INSERT INTO region_blob(region_snapshot_id, content) VALUES (?, ?)",
        (row_id, b"old"),
    )
    dao.conn.commit()
    assert dao.heads_at(rid, 1_000) == {0x10000: b"old"}
    assert dao.head_hashes_at(rid, 1_000) == {}


# --- thread start addresses ------------------------------------------------
def test_add_sample_stores_thread_starts_and_reads_them_back(tmp_db):
    from memlapse.model.region import (
        MEM_COMMIT, MEM_PRIVATE, PAGE_EXECUTE_READ, Region,
    )
    region = Region(0x40000, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, MEM_PRIVATE)
    conn = connect(tmp_db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "p.exe", 0)
    dao.add_sample(rid, 1_000, ProcState(1_000, 1000, 1, 1, 2), [region],
                   None, {77: 0x7FF000, 12: 0x140000})
    # A sample that could query no thread is normal, and is not "no sample".
    dao.add_sample(rid, 2_000, ProcState(2_000, 1000, 1, 1, 2), [region])
    assert dao.thread_starts_at(rid, 1_000) == [0x140000, 0x7FF000]  # by tid
    assert dao.thread_starts_at(rid, 2_000) == []
    conn.close()


def test_thread_starts_at_before_any_sample_is_empty(tmp_db):
    conn = connect(tmp_db)
    dao = Dao(conn)
    rid = dao.create_recording(1000, "p.exe", 0)
    assert dao.thread_starts_at(rid, 1_000) == []
    conn.close()


# --- can_read and created_ft: recorded, because a replay cannot infer them ---
def test_can_read_and_created_ft_round_trip(dao):
    rid = dao.create_recording(1000, "p.exe", 0)
    dao.add_sample(rid, 1_000,
                   ProcState(1_000, 1000, 1, 1, 1, can_read=False,
                             created_ft=132_000_000_000_000_001),
                   [])
    got = dao.state_at(rid, 1_000)
    assert got.can_read is False                      # not 0, not None
    assert got.created_ft == 132_000_000_000_000_001


def test_can_read_true_round_trips_as_true(dao):
    rid = dao.create_recording(1000, "p.exe", 0)
    dao.add_sample(rid, 1_000,
                   ProcState(1_000, 1000, 1, 1, 1, can_read=True), [])
    assert dao.state_at(rid, 1_000).can_read is True


def test_a_recording_written_without_the_columns_reads_as_unknown(dao):
    """The legacy path: NULL means nobody asked, not that reads were denied.

    Reporting None as False would tell an analyst a recording was taken
    blind when in truth it was taken before the column existed, which is
    exactly the kind of confident wrong statement the band rule avoids.
    """
    rid = dao.create_recording(1000, "p.exe", 0)
    # Write the row the way a pre-column build would have.
    dao.conn.execute(
        "INSERT INTO process_snapshot"
        "(recording_id, ts_us, pid, wset_bytes, priv_bytes, thread_count) "
        "VALUES (?, ?, ?, ?, ?, ?)", (rid, 1_000, 1000, 1, 1, 1))
    state = dao.state_at(rid, 1_000)
    assert state.can_read is None and state.created_ft is None
    assert state.can_read is not False


def test_instance_changes_finds_a_reused_pid(dao):
    """The sampler opens a fresh handle each time, so this can really happen."""
    rid = dao.create_recording(1000, "p.exe", 0)
    for ts, created in ((1_000, 111), (2_000, 111), (3_000, 222), (4_000, 222)):
        dao.add_sample(rid, ts, ProcState(ts, 1000, 1, 1, 1, created_ft=created), [])
    assert dao.instance_changes(rid) == [3_000]


def test_instance_changes_is_empty_for_one_instance(dao):
    rid = dao.create_recording(1000, "p.exe", 0)
    for ts in (1_000, 2_000, 3_000):
        dao.add_sample(rid, ts, ProcState(ts, 1000, 1, 1, 1, created_ft=111), [])
    assert dao.instance_changes(rid) == []


def test_instance_changes_ignores_samples_with_no_identity(dao):
    """An older recording has no creation times, which is not a change."""
    rid = dao.create_recording(1000, "p.exe", 0)
    for ts in (1_000, 2_000):
        dao.add_sample(rid, ts, ProcState(ts, 1000, 1, 1, 1), [])
    assert dao.instance_changes(rid) == []


# --- the allowlist the recording was made under ----------------------------
# Three states, not two. None means nobody wrote a list down and the caller
# falls back to what is in force now; an Allowlist with no entries means this
# recording excused nothing and the replay must excuse nothing either. Zero
# rows in recording_allowlist cannot tell those apart, which is what
# recording.allowlist_recorded is for.


def _entries():
    from memlapse.analytics import AllowlistEntry, RULE_PRIVATE_EXEC, RULE_RWX
    return [AllowlistEntry("jit.exe", RULE_PRIVATE_EXEC, "JIT host"),
            AllowlistEntry("jit.exe", RULE_RWX, "same host, second rule"),
            AllowlistEntry("other.exe", RULE_RWX, "")]


def test_allowlist_round_trips_with_its_notes(dao):
    from memlapse.analytics import Allowlist, RULE_PRIVATE_EXEC, RULE_RWX
    rid = dao.create_recording(1, "jit.exe", 1_000, allowlist=Allowlist(_entries()))
    back = dao.allowlist_for(rid)
    assert back is not None
    assert back.rules_for("jit.exe") == {RULE_PRIVATE_EXEC, RULE_RWX}
    assert back.rules_for("other.exe") == {RULE_RWX}
    # The note travels: an exemption nobody can justify later is one nobody
    # dares delete, so it is stored rather than thrown away with the lookup.
    assert [e.note for e in back.entries] == [
        "JIT host", "same host, second rule", ""]


def test_a_recorded_empty_allowlist_is_not_none(dao):
    """The distinction the whole flag exists for.

    Both this recording and one made before the column carry zero rows in
    recording_allowlist. Only the flag says which happened, and they score
    differently: this one excuses nothing, that one defers to the allowlist
    in force at replay time.
    """
    from memlapse.analytics import Allowlist
    rid = dao.create_recording(1, "p", 1_000, allowlist=Allowlist())
    back = dao.allowlist_for(rid)
    assert back is not None
    assert back.entries == ()
    assert not back  # falsy, and still an answer: test with "is None"


def test_no_allowlist_given_records_none(dao):
    rid = dao.create_recording(1, "p", 1_000)
    assert dao.allowlist_for(rid) is None
    flag = dao.conn.execute(
        "SELECT allowlist_recorded FROM recording WHERE id=?", (rid,)).fetchone()
    assert flag[0] is None


def test_allowlist_for_an_unknown_recording_is_none(dao):
    assert dao.allowlist_for(4242) is None


def test_entries_are_scoped_to_their_recording(dao):
    from memlapse.analytics import Allowlist, RULE_RWX
    mine = dao.create_recording(1, "jit.exe", 1_000,
                                allowlist=Allowlist(_entries()))
    theirs = dao.create_recording(2, "jit.exe", 2_000, allowlist=Allowlist())
    assert dao.allowlist_for(theirs).entries == ()
    assert dao.allowlist_for(mine).rules_for("other.exe") == {RULE_RWX}
