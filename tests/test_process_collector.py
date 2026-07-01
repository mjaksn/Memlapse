"""Tests for the live process collector."""

from types import SimpleNamespace

import psutil

import memdo.collectors.process as proc_mod
from memdo.collectors.process import ProcessCollector


class FakeProc:
    def __init__(self, info):
        self._info = info

    @property
    def info(self):
        if self._info is None:
            raise psutil.AccessDenied(pid=1)
        return self._info


def _patch_iter(monkeypatch, procs):
    monkeypatch.setattr(proc_mod.psutil, "process_iter", lambda attrs=None: procs)


def test_poll_maps_fields(monkeypatch):
    minfo = SimpleNamespace(wset=100, private=50, rss=1, vms=2)
    _patch_iter(monkeypatch, [FakeProc({
        "pid": 7, "name": "p.exe", "username": "DOMAIN\\bob",
        "num_threads": 3, "memory_info": minfo})])
    rows = ProcessCollector._poll()
    assert len(rows) == 1
    r = rows[0]
    assert r.pid == 7 and r.wset_bytes == 100 and r.private_bytes == 50
    assert r.username == "bob"  # domain prefix stripped


def test_poll_falls_back_to_rss_vms(monkeypatch):
    minfo = SimpleNamespace(rss=11, vms=22)  # no wset/private
    _patch_iter(monkeypatch, [FakeProc({
        "pid": 1, "name": None, "username": None,
        "num_threads": None, "memory_info": minfo})])
    r = ProcessCollector._poll()[0]
    assert r.wset_bytes == 11 and r.private_bytes == 22
    assert r.name == "?" and r.username == "" and r.num_threads == 0


def test_poll_skips_inaccessible(monkeypatch):
    good = FakeProc({"pid": 1, "name": "ok", "username": "u",
                     "num_threads": 1, "memory_info": SimpleNamespace(wset=1, private=1)})
    _patch_iter(monkeypatch, [FakeProc(None), good])  # first raises AccessDenied
    rows = ProcessCollector._poll()
    assert [r.pid for r in rows] == [1]


def test_run_loop_emits_and_stops(qtbot, monkeypatch):
    c = ProcessCollector(interval=0.01)
    monkeypatch.setattr(c, "_poll", lambda: ["SENTINEL"])
    with qtbot.waitSignal(c.updated, timeout=1000) as sig:
        c.start()
    c.stop()
    c.wait(1000)
    assert sig.args == [["SENTINEL"]]
    assert not c.isRunning()
