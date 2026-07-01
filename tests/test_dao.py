"""Tests for the storage DAO round-trip and playback reads."""

import pytest

from memdo.storage import connect
from memdo.storage.dao import Dao, ProcState


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
