"""Tests for the per-thread Win32 start address query.

The bulk table walk is driven from a packed fake buffer; the handle and query
calls are faked so every refusal path is covered without needing another user's
process. One test runs against this process for real, which is the only way to
know the structure layout and the information class are right.
"""

import ctypes
import os

import memlapse.win32.threads as threads_mod
from memlapse.win32.processes import SYSTEM_PROCESS_INFORMATION
from memlapse.win32.threads import (
    SYSTEM_THREAD_INFORMATION, start_addresses, thread_ids,
)


def test_struct_layouts_match_the_x64_table():
    """A silent layout error would hand back garbage addresses, not an error."""
    assert ctypes.sizeof(SYSTEM_PROCESS_INFORMATION) == 256
    assert ctypes.sizeof(SYSTEM_THREAD_INFORMATION) == 80


def _table(specs):
    """Pack (pid, [tid, ...]) entries the way the system table lays them out."""
    entry_size = ctypes.sizeof(SYSTEM_PROCESS_INFORMATION)
    thread_size = ctypes.sizeof(SYSTEM_THREAD_INFORMATION)
    raw = bytearray()
    for i, (pid, tids) in enumerate(specs):
        entry = SYSTEM_PROCESS_INFORMATION()
        entry.UniqueProcessId = pid or None
        entry.NumberOfThreads = len(tids)
        entry.NextEntryOffset = (
            0 if i == len(specs) - 1 else entry_size + len(tids) * thread_size
        )
        raw += bytes(entry)
        for tid in tids:
            thread = SYSTEM_THREAD_INFORMATION()
            thread.ClientId.UniqueThread = tid or None
            raw += bytes(thread)
    return ctypes.create_string_buffer(bytes(raw), len(raw))


def test_thread_ids_reads_the_array_after_the_matching_entry(monkeypatch):
    buf = _table([(10, [1, 2]), (20, [7, 8, 9])])
    monkeypatch.setattr(threads_mod, "_query_buffer", lambda: buf)
    assert thread_ids(20) == [7, 8, 9]
    assert thread_ids(10) == [1, 2]


def test_thread_ids_of_an_absent_process_is_empty(monkeypatch):
    buf = _table([(10, [1])])
    monkeypatch.setattr(threads_mod, "_query_buffer", lambda: buf)
    assert thread_ids(999) == []


class _FakeKernel32:
    """OpenThread hands out the handles it was given; 0 means denied."""

    def __init__(self, handles):
        self.handles = handles
        self.opened: list[tuple[int, int]] = []
        self.closed: list[int] = []

    def OpenThread(self, access, inherit, tid):
        self.opened.append((access, tid))
        return self.handles.get(tid, 0)

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return True


class _FakeNtdll:
    """NtQueryInformationThread returns a canned (status, address) per handle."""

    def __init__(self, results):
        self.results = results
        self.classes: list[int] = []

    def NtQueryInformationThread(self, handle, info_class, buf, size, returned):
        self.classes.append(info_class)
        status, value = self.results[handle]
        if status == 0:
            ctypes.memmove(buf, ctypes.byref(ctypes.c_size_t(value)), size)
        return status


def _fake_calls(monkeypatch, tids, handles, results):
    monkeypatch.setattr(threads_mod, "thread_ids", lambda pid: tids)
    k32 = _FakeKernel32(handles)
    ntdll = _FakeNtdll(results)
    monkeypatch.setattr(threads_mod, "_kernel32", k32)
    monkeypatch.setattr(threads_mod, "_ntdll", ntdll)
    return k32, ntdll


def test_start_addresses_returns_the_queried_addresses(monkeypatch):
    k32, ntdll = _fake_calls(monkeypatch, [1, 2], {1: 100, 2: 200},
                             {100: (0, 0x7FF000), 200: (0, 0x140000)})
    assert start_addresses(4242) == {1: 0x7FF000, 2: 0x140000}
    assert ntdll.classes == [threads_mod.ThreadQuerySetWin32StartAddress] * 2
    # The limited access right is refused for this class, so it is not used.
    assert {access for access, _ in k32.opened} == {
        threads_mod.THREAD_QUERY_INFORMATION
    }


def test_start_addresses_skips_a_thread_that_will_not_open(monkeypatch):
    """Another user's thread without elevation: unknown, not zero."""
    k32, _ = _fake_calls(monkeypatch, [1, 2], {2: 200}, {200: (0, 0x1000)})
    assert start_addresses(4242) == {2: 0x1000}
    assert k32.closed == [200]  # nothing to close for the refused open


def test_start_addresses_skips_a_refused_query(monkeypatch):
    k32, _ = _fake_calls(monkeypatch, [1], {1: 100}, {100: (0xC0000022, 0)})
    assert start_addresses(4242) == {}
    assert k32.closed == [100]  # the handle is still released


def test_start_addresses_skips_a_zero_address(monkeypatch):
    _fake_calls(monkeypatch, [1], {1: 100}, {100: (0, 0)})
    assert start_addresses(4242) == {}


def test_start_addresses_survives_a_failed_table_query(monkeypatch):
    """A table query that fails means no thread is known, not that the map is."""
    def boom(pid):
        raise OSError("NtQuerySystemInformation failed (NTSTATUS 0xc0000004)")
    monkeypatch.setattr(threads_mod, "thread_ids", boom)
    assert start_addresses(4242) == {}


def test_start_addresses_of_this_process_are_real():
    """The layout and information class have to be right for this to pass."""
    found = start_addresses(os.getpid())
    assert found  # we own these threads, so they open
    assert all(tid > 0 and address > 0x10000 for tid, address in found.items())
