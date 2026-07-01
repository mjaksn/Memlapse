"""Tests for the RegionSampler recording collector.

run() is invoked directly (not via start()) so it executes synchronously on the
test thread — a slot on ``sampled`` stops it after the first sample, making the
loop deterministic without real threading.
"""

import os

import psutil

import memdo.collectors.region as region_mod
from memdo.collectors.region import RegionSampler
from memdo.storage import connect
from memdo.storage.dao import Dao


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
    assert finished == ["target process exited"]


def test_run_stops_when_process_missing(qapp, tmp_db, monkeypatch):
    s = RegionSampler(123456, "gone", 0.01, db_path=tmp_db)
    finished = []
    s.finished_recording.connect(finished.append)
    # psutil.Process(...) at loop entry raises -> outer handler.
    monkeypatch.setattr(region_mod.psutil, "Process",
                        lambda pid: (_ for _ in ()).throw(psutil.NoSuchProcess(pid=pid)))
    s.run()
    assert finished == ["target process exited"]


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
