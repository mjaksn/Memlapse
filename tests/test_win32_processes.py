"""Tests for the bulk NtQuerySystemInformation process enumerator.

The integration test compares our own process against psutil; the failure
and growth branches are driven by swapping the module-level ntdll shim for a
fake that fills the caller's buffer from the same ctypes structure.
"""

import ctypes
import os

import psutil
import pytest

import memlapse.win32.processes as procs
from memlapse.win32.processes import (
    STATUS_INFO_LENGTH_MISMATCH, SYSTEM_PROCESS_INFORMATION, list_processes,
)


def test_structure_matches_x64_layout():
    assert ctypes.sizeof(SYSTEM_PROCESS_INFORMATION) == 256


def test_lists_own_process_consistently_with_psutil():
    rows = list_processes()
    me = next(r for r in rows if r.pid == os.getpid())
    ref = psutil.Process(os.getpid())
    mem = ref.memory_info()
    assert me.name == ref.name()
    assert abs(me.num_threads - ref.num_threads()) <= 2
    assert me.wset_bytes == pytest.approx(mem.wset, rel=0.5)
    assert me.private_bytes == pytest.approx(mem.private, rel=0.5)
    assert me.create_time > 0
    # The idle process is reported under psutil's conventional name.
    assert any(r.pid == 0 and r.name == "System Idle Process" for r in rows)


# --- fake ntdll ------------------------------------------------------------
def _entries(specs):
    """Pack SYSTEM_PROCESS_INFORMATION entries; returns (bytes, keepalive)."""
    keep = []
    size = ctypes.sizeof(SYSTEM_PROCESS_INFORMATION)
    raw = bytearray()
    for i, (pid, name, threads, wset, pagefile, created, *rest) in enumerate(specs):
        e = SYSTEM_PROCESS_INFORMATION()
        e.NextEntryOffset = 0 if i == len(specs) - 1 else size
        e.NumberOfThreads = threads
        e.WorkingSetSize = wset
        e.PagefileUsage = pagefile
        e.CreateTime = created
        e.UniqueProcessId = pid or None
        e.InheritedFromUniqueProcessId = (rest[0] if rest else 0) or None
        if name:
            wbuf = ctypes.create_unicode_buffer(name)
            keep.append(wbuf)
            e.ImageName.Length = len(name) * 2
            e.ImageName.MaximumLength = (len(name) + 1) * 2
            e.ImageName.Buffer = ctypes.addressof(wbuf)
        raw += bytes(e)
    return bytes(raw), keep


class FakeNtdll:
    def __init__(self, statuses, payload=b"", needed=0):
        self.statuses = list(statuses)
        self.payload = payload
        self.needed = needed
        self.sizes = []

    def NtQuerySystemInformation(self, info_class, buf, size, needed):
        self.sizes.append(size)
        status = self.statuses.pop(0)
        needed.value = self.needed
        if status == 0:
            ctypes.memmove(buf, self.payload, len(self.payload))
        return status


def test_parses_entries_after_growing_buffer(monkeypatch):
    payload, _keep = _entries([
        (0, "", 4, 8192, 0, 0),
        (4242, "fake.exe", 7, 1_000_000, 2_000_000, 123456789, 600),
    ])
    fake = FakeNtdll([STATUS_INFO_LENGTH_MISMATCH, 0], payload, needed=len(payload))
    monkeypatch.setattr(procs, "_ntdll", fake)
    rows = list_processes()
    assert [r.pid for r in rows] == [0, 4242]
    assert rows[0].name == "System Idle Process"
    assert rows[1].name == "fake.exe"
    assert rows[1].num_threads == 7
    assert rows[1].wset_bytes == 1_000_000 and rows[1].private_bytes == 2_000_000
    assert rows[1].create_time == 123456789
    assert rows[1].parent_pid == 600 and rows[0].parent_pid == 0
    # Second attempt used the reported size plus slack.
    assert fake.sizes[1] == len(payload) + procs._SLACK


def test_unnamed_nonidle_process_has_empty_name(monkeypatch):
    payload, _keep = _entries([(99, "", 1, 1, 1, 1)])
    monkeypatch.setattr(procs, "_ntdll", FakeNtdll([0], payload))
    assert list_processes()[0].name == ""


def test_buffer_doubles_when_no_size_reported_then_gives_up(monkeypatch):
    fake = FakeNtdll([STATUS_INFO_LENGTH_MISMATCH] * procs._MAX_ATTEMPTS, needed=0)
    monkeypatch.setattr(procs, "_ntdll", fake)
    with pytest.raises(OSError, match="kept growing"):
        list_processes()
    assert fake.sizes[1] == fake.sizes[0] * 2


def test_other_failure_status_raises(monkeypatch):
    monkeypatch.setattr(procs, "_ntdll", FakeNtdll([0xC0000022]))  # ACCESS_DENIED
    with pytest.raises(OSError, match="0xc0000022"):
        list_processes()
