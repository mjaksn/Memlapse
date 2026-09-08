"""Tests for the ctypes ProcessMemory wrapper.

Real reads run against the test's own process; failure branches are driven by
swapping the module-level kernel32 shim.
"""

import os

import pytest

import memlapse.win32.memory as memory
from memlapse.win32.memory import (
    PROCESS_VM_READ, ProcessAccessError, ProcessMemory, enumerate_regions,
)


# --- real integration against our own process ------------------------------
def test_open_and_enumerate_self():
    with ProcessMemory(os.getpid()) as pm:
        assert pm.can_read
        regions = pm.regions()
        assert len(regions) > 0
        readable = next(r for r in regions if r.is_readable)
        data = pm.read(readable.base_addr, 32)
        assert isinstance(data, bytes) and len(data) > 0


def test_creation_time_identifies_this_instance():
    """Real call: the layout has to be right, and the value has to be sane."""
    with ProcessMemory(os.getpid()) as pm:
        created = pm.creation_time()
    # FILETIME ticks (100 ns since 1601). Anything after 2020 clears this.
    assert created > 132_000_000_000_000_000
    with ProcessMemory(os.getpid(), want_read=False) as limited:
        assert limited.creation_time() == created  # the query-limited handle too


def test_creation_time_failure_raises(monkeypatch):
    monkeypatch.setattr(memory, "_kernel32", FakeKernel(lambda access: 4321))
    with ProcessMemory(1234) as pm:
        with pytest.raises(ProcessAccessError):
            pm.creation_time()


def test_map_only_cannot_read():
    with ProcessMemory(os.getpid(), want_read=False) as pm:
        assert not pm.can_read
        assert pm.read(0x1000, 16) == b""


def test_enumerate_regions_helper_and_include_free():
    all_regions = enumerate_regions(os.getpid(), include_free=True)
    committed_only = enumerate_regions(os.getpid(), include_free=False)
    assert len(all_regions) >= len(committed_only)


def test_open_invalid_pid_raises():
    with pytest.raises(ProcessAccessError):
        ProcessMemory(999_999_999)


# --- failure branches via a fake kernel32 ----------------------------------
class FakeKernel:
    def __init__(self, open_result):
        self._open_result = open_result

    def OpenProcess(self, access, inherit, pid):
        return self._open_result(access)

    def VirtualQueryEx(self, handle, addr, buf, size):
        return 0  # ends region enumeration immediately

    def ReadProcessMemory(self, handle, addr, buf, size, read_out):
        return 0  # simulated read failure

    def CloseHandle(self, handle):
        return 1

    def GetCurrentProcess(self):
        return 1

    def GetProcessTimes(self, handle, created, exited, kernel, user):
        return 0  # simulated query failure


def test_fallback_to_query_limited(monkeypatch):
    # VM_READ open fails; query-limited open succeeds -> map-only handle.
    monkeypatch.setattr(memory, "_kernel32",
                        FakeKernel(lambda access: 0 if access & PROCESS_VM_READ else 4321))
    with ProcessMemory(1234) as pm:
        assert not pm.can_read
        assert pm.regions() == []
        assert pm.read(0x1000, 8) == b""


def test_read_failure_returns_empty(monkeypatch):
    # Handle opens with read access, but ReadProcessMemory fails.
    monkeypatch.setattr(memory, "_kernel32", FakeKernel(lambda access: 4321))
    with ProcessMemory(1234) as pm:
        assert pm.can_read
        assert pm.read(0x1000, 8) == b""


def test_open_all_fail_raises(monkeypatch):
    monkeypatch.setattr(memory, "_kernel32", FakeKernel(lambda access: 0))
    with pytest.raises(ProcessAccessError):
        ProcessMemory(1234)


def test_double_close_is_safe(monkeypatch):
    monkeypatch.setattr(memory, "_kernel32", FakeKernel(lambda access: 4321))
    pm = ProcessMemory(1234)
    pm.close()
    pm.close()  # second close must be a no-op
