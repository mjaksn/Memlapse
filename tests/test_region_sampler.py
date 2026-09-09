"""Tests for the RegionSampler recording collector.

run() is invoked directly (not via start()) so it executes synchronously on the
test thread, a slot on ``sampled`` stops it after the first sample, making the
loop deterministic without real threading.
"""

import os

import psutil

import memlapse.collectors.region as region_mod
from memlapse.collectors.region import RegionSampler
from memlapse.storage import connect
from memlapse.storage.dao import Dao


def test_run_records_samples(qapp, tmp_db):
    s = RegionSampler(os.getpid(), "me", 0.01, db_path=tmp_db)
    events = {"started": [], "sampled": [], "finished": []}
    s.started.connect(events["started"].append)
    s.sampled.connect(lambda ts, c: (events["sampled"].append((ts, c)), s.stop()))
    s.finished_recording.connect(events["finished"].append)

    s.run()  # synchronous; stops itself after the first sample

    assert events["started"] == [s.recording_id]
    assert len(events["sampled"]) == 1
    ts, count = events["sampled"][0]
    assert count > 0 and ts > 1_000_000_000_000_000  # real 64-bit epoch µs
    assert events["finished"] == ["stopped"]

    # The recording is persisted and closed out.
    conn = connect(tmp_db)
    dao = Dao(conn)
    try:
        recs = dao.list_recordings()
        assert len(recs) == 1 and recs[0].ended_utc is not None
        assert len(dao.sample_times(recs[0].id)) == 1
    finally:
        conn.close()


def test_run_stops_when_sample_raises(qapp, tmp_db, monkeypatch):
    s = RegionSampler(os.getpid(), "me", 0.01, db_path=tmp_db)
    finished = []
    s.finished_recording.connect(finished.append)

    def boom(*a, **k):
        raise psutil.NoSuchProcess(pid=os.getpid())
    monkeypatch.setattr(s, "_sample_once", boom)

    s.run()
    assert finished == ["target process exited or became inaccessible"]


def test_run_stops_when_access_is_denied(qapp, tmp_db, monkeypatch):
    s = RegionSampler(os.getpid(), "me", 0.01, db_path=tmp_db)
    finished = []
    s.finished_recording.connect(finished.append)

    def denied(*a, **k):
        raise psutil.AccessDenied(pid=os.getpid())
    monkeypatch.setattr(s, "_sample_once", denied)

    s.run()
    assert finished == ["target process exited or became inaccessible"]


def test_run_stops_when_process_missing(qapp, tmp_db, monkeypatch):
    s = RegionSampler(123456, "gone", 0.01, db_path=tmp_db)
    finished = []
    s.finished_recording.connect(finished.append)
    # psutil.Process(...) at loop entry raises -> outer handler.
    monkeypatch.setattr(region_mod.psutil, "Process",
                        lambda pid: (_ for _ in ()).throw(psutil.NoSuchProcess(pid=pid)))
    s.run()
    assert finished == ["target process exited or became inaccessible"]


def test_stop_sets_flag():
    s = RegionSampler(1, "x", 1.0)
    s._running = True
    s.stop()
    assert s._running is False


def test_sleep_remaining_runs_and_exits(qapp):
    import time
    s = RegionSampler(1, "x", 0.02)
    s._running = True
    start = time.monotonic()
    s._sleep_remaining(start)  # loops at least once, then exits when time is up
    assert time.monotonic() - start >= 0.01


# --- read_heads ------------------------------------------------------------
from memlapse.model.region import (  # noqa: E402
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, Region,
)


class _FakePM:
    """Minimal ProcessMemory stand-in for read_heads."""

    def __init__(self, can_read, data=b"\x90\x90"):
        self.can_read = can_read
        self._data = data
        self.reads: list[tuple[int, int]] = []

    def read(self, addr, size):
        self.reads.append((addr, size))
        return self._data


def _exec(base):
    return Region(base, 4096, MEM_COMMIT, PAGE_EXECUTE_READ, 0x20000)


def test_read_heads_empty_when_no_read_access():
    pm = _FakePM(can_read=False)
    assert region_mod.read_heads(pm, [_exec(0x1000)]) == {}
    assert pm.reads == []  # never attempted a read


def test_read_heads_captures_executable_readable_regions():
    pm = _FakePM(can_read=True, data=b"MZ\x90")
    regions = [
        _exec(0x1000),                                          # exec + readable
        Region(0x2000, 4096, MEM_COMMIT, PAGE_READWRITE, 0x20000),  # not exec
        Region(0x3000, 4096, MEM_RESERVE, PAGE_EXECUTE_READ, 0x20000),  # not readable
    ]
    heads = region_mod.read_heads(pm, regions)
    assert heads == {0x1000: b"MZ\x90"}
    assert pm.reads == [(0x1000, 256)]  # only the qualifying region was read


def test_read_heads_skips_regions_that_read_empty():
    pm = _FakePM(can_read=True, data=b"")
    assert region_mod.read_heads(pm, [_exec(0x1000)]) == {}


# --- thread start addresses are recorded with the sample -------------------
def test_the_thread_walk_happens_while_the_process_handle_is_open(qapp, tmp_db,
                                                                  monkeypatch):
    """One pinned instance has to supply the whole sample, or the map and the
    thread starts can come from two different processes sharing a pid."""
    open_handles = []
    real_pm = region_mod.ProcessMemory

    class TrackingPM(real_pm):
        def close(self):
            open_handles.append(False)
            super().close()

    monkeypatch.setattr(region_mod, "ProcessMemory", TrackingPM)
    monkeypatch.setattr(region_mod, "start_addresses",
                        lambda pid: open_handles.append(True) or {9: 0x7FF123})
    s = RegionSampler(os.getpid(), "me", 0.01, db_path=tmp_db)
    s.sampled.connect(lambda *_: s.stop())
    s.run()
    # True (thread walk) before False (handle closed), for the one sample taken.
    assert open_handles[:2] == [True, False]


def test_sample_records_thread_start_addresses(qapp, tmp_db, monkeypatch):
    monkeypatch.setattr(region_mod, "start_addresses", lambda pid: {9: 0x7FF123})
    s = RegionSampler(os.getpid(), "me", 0.01, db_path=tmp_db)
    s.sampled.connect(lambda *_: s.stop())
    s.run()
    conn = connect(tmp_db)
    try:
        rows = conn.execute(
            "SELECT tid, start_addr FROM thread_snapshot").fetchall()
        assert [tuple(r) for r in rows] == [(9, 0x7FF123)]
    finally:
        conn.close()


# --- the sample records what only the sample can know ----------------------
def test_a_sample_records_read_access_and_the_process_instance(qapp, tmp_db,
                                                               monkeypatch):
    """Both come from the handle that took the sample and cannot be recovered.

    An empty head set on replay is ambiguous between "reads were refused" and
    "nothing executable to read"; only can_read separates them. The creation
    time is what lets a replay notice the pid was reused between two samples.
    """
    monkeypatch.setattr(region_mod, "start_addresses", lambda pid: {})
    s = RegionSampler(os.getpid(), "me", 0.01, db_path=tmp_db)
    s.sampled.connect(lambda *_: s.stop())
    s.run()
    conn = connect(tmp_db)
    try:
        row = conn.execute(
            "SELECT can_read, created_ft FROM process_snapshot").fetchone()
        assert row[0] == 1                       # our own process reads fine
        assert row[1] > 132_000_000_000_000_000  # a real FILETIME, after 2020
    finally:
        conn.close()


def test_a_sample_survives_a_process_that_will_not_say_when_it_started(
        qapp, tmp_db, monkeypatch):
    """Losing the map over a missing identity would throw away the reading.

    creation_time() raising is what a target on its way out produces, and the
    map taken a moment earlier is still worth keeping.
    """
    monkeypatch.setattr(region_mod, "start_addresses", lambda pid: {})
    real_pm = region_mod.ProcessMemory

    class NoIdentityPM(real_pm):
        def creation_time(self):
            raise region_mod.ProcessAccessError("gone")

    monkeypatch.setattr(region_mod, "ProcessMemory", NoIdentityPM)
    s = RegionSampler(os.getpid(), "me", 0.01, db_path=tmp_db)
    s.sampled.connect(lambda *_: s.stop())
    s.run()
    conn = connect(tmp_db)
    try:
        row = conn.execute(
            "SELECT can_read, created_ft FROM process_snapshot").fetchone()
        assert row is not None                   # the sample was still written
        assert row[0] == 1 and row[1] is None    # identity unknown, reads fine
        assert conn.execute(
            "SELECT COUNT(*) FROM region_snapshot").fetchone()[0] > 0
    finally:
        conn.close()


def test_the_sample_records_the_allowlist_it_was_started_with(qapp, tmp_db):
    """Written once, at the start, from what was in force when Record was hit.

    The sampler is the only writer holding a connection on the right thread,
    which is why the entries travel down to it rather than being written from
    the window.
    """
    from memlapse.analytics import Allowlist, AllowlistEntry, RULE_RWX
    book = Allowlist([AllowlistEntry("me.exe", RULE_RWX, "test host")])
    s = RegionSampler(os.getpid(), "me", 0.01, db_path=tmp_db, allowlist=book)
    s.sampled.connect(lambda ts, c: s.stop())
    s.run()

    conn = connect(tmp_db)
    try:
        back = Dao(conn).allowlist_for(s.recording_id)
        assert back is not None
        assert back.rules_for("me.exe") == {RULE_RWX}
        assert [e.note for e in back.entries] == ["test host"]
    finally:
        conn.close()


def test_without_an_allowlist_the_recording_records_none(qapp, tmp_db):
    """Not an empty one: a replay must fall back, not claim nothing was excused."""
    s = RegionSampler(os.getpid(), "me", 0.01, db_path=tmp_db)
    s.sampled.connect(lambda ts, c: s.stop())
    s.run()

    conn = connect(tmp_db)
    try:
        assert Dao(conn).allowlist_for(s.recording_id) is None
    finally:
        conn.close()
