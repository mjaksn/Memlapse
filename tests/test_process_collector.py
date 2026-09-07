"""Tests for the live process collector."""

import psutil

import memlapse.collectors.process as proc_mod
from memlapse.collectors.process import ProcessCollector
from memlapse.win32.processes import SystemProcess


def _sp(pid, name="p.exe", threads=3, wset=100, private=50, created=1, parent=0):
    return SystemProcess(pid=pid, name=name, num_threads=threads,
                         wset_bytes=wset, private_bytes=private,
                         create_time=created, parent_pid=parent)


class FakePsProcess:
    """Stand-in for psutil.Process: records lookups, can deny access."""

    calls: list[int] = []
    denied: set[int] = set()

    def __init__(self, pid):
        self.pid = pid
        FakePsProcess.calls.append(pid)

    def username(self):
        if self.pid in FakePsProcess.denied:
            raise psutil.AccessDenied(pid=self.pid)
        return f"DOMAIN\\user{self.pid}"


def _patch(monkeypatch, procs):
    FakePsProcess.calls = []
    FakePsProcess.denied = set()
    monkeypatch.setattr(proc_mod, "list_processes", lambda: procs)
    monkeypatch.setattr(proc_mod.psutil, "Process", FakePsProcess)


def test_poll_maps_fields(qapp, monkeypatch):
    _patch(monkeypatch, [_sp(7, "p.exe", threads=3, wset=100, private=50)])
    rows = ProcessCollector()._poll()
    assert len(rows) == 1
    r = rows[0]
    assert r.pid == 7 and r.name == "p.exe" and r.num_threads == 3
    assert r.wset_bytes == 100 and r.private_bytes == 50
    assert r.username == "user7"  # domain prefix stripped


def test_poll_unnamed_process_shows_placeholder(qapp, monkeypatch):
    _patch(monkeypatch, [_sp(1, name="")])
    assert ProcessCollector()._poll()[0].name == "?"


def test_poll_denied_username_is_empty(qapp, monkeypatch):
    _patch(monkeypatch, [_sp(1)])
    FakePsProcess.denied = {1}
    assert ProcessCollector()._poll()[0].username == ""


def test_username_cached_per_process_instance(qapp, monkeypatch):
    _patch(monkeypatch, [_sp(1, created=10), _sp(2, created=20)])
    c = ProcessCollector()
    c._poll()
    c._poll()
    assert FakePsProcess.calls == [1, 2]  # second poll served from the cache

    # pid 1 is reused by a new process (different creation time): re-queried.
    # pid 2 exited: its cache entry is dropped.
    monkeypatch.setattr(proc_mod, "list_processes", lambda: [_sp(1, created=11)])
    c._poll()
    assert FakePsProcess.calls == [1, 2, 1]
    assert set(c._usernames) == {(1, 11)}


def test_run_loop_emits_and_stops(qtbot, monkeypatch):
    c = ProcessCollector(interval=0.01)
    monkeypatch.setattr(c, "_poll", lambda: ["SENTINEL"])
    with qtbot.waitSignal(c.updated, timeout=1000) as sig:
        c.start()
    c.stop()
    c.wait(1000)
    assert sig.args == [["SENTINEL"]]
    assert not c.isRunning()


def test_poll_carries_the_parent_pid(monkeypatch):
    """The bulk table already knows the creator; the model keeps it."""
    monkeypatch.setattr(proc_mod, "list_processes", lambda: [_sp(10, parent=600)])
    monkeypatch.setattr(proc_mod.psutil, "Process", FakePsProcess)
    rows = ProcessCollector()._poll()
    assert rows[0].parent_pid == 600
