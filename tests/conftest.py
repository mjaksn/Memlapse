"""Shared test fixtures and fakes.

The offscreen Qt platform is selected before any PySide6 import so widget
tests run headless in CI.
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QObject, Signal

from memlapse.model.process import ProcessInfo
from memlapse.model.region import (
    MEM_COMMIT, MEM_IMAGE, MEM_PRIVATE, PAGE_NOACCESS, PAGE_READWRITE, Region,
)


# --- data factories --------------------------------------------------------
@pytest.fixture
def make_process():
    def _make(pid=1000, name="proc.exe", username="me", num_threads=4,
              wset_bytes=2048, private_bytes=1024, parent_pid=0):
        return ProcessInfo(pid=pid, name=name, username=username,
                           num_threads=num_threads, wset_bytes=wset_bytes,
                           private_bytes=private_bytes, parent_pid=parent_pid)
    return _make


@pytest.fixture
def make_region():
    def _make(base_addr=0x10000, size=4096, state=MEM_COMMIT,
              protect=PAGE_READWRITE, type=MEM_PRIVATE):
        return Region(base_addr=base_addr, size=size, state=state,
                     protect=protect, type=type)
    return _make


@pytest.fixture
def sample_regions():
    return [
        Region(0x10000, 4096, MEM_COMMIT, PAGE_READWRITE, MEM_PRIVATE),
        Region(0x20000, 8192, MEM_COMMIT, PAGE_NOACCESS, MEM_IMAGE),
    ]


@pytest.fixture
def tmp_db(tmp_path):
    return str(tmp_path / "memlapse_test.db")


# --- fakes used across service/UI tests ------------------------------------
class FakeSampler(QObject):
    """Stand-in for RegionSampler: emits on start, no real thread or DB."""

    started = Signal(int)
    sampled = Signal("qlonglong", int)
    finished_recording = Signal(str)

    instances: list["FakeSampler"] = []

    def __init__(self, pid, name, interval, db_path=None):
        super().__init__()
        self.pid = pid
        self.name = name
        self.interval = interval
        self.db_path = db_path
        self._running = False
        FakeSampler.instances.append(self)

    def start(self):
        self._running = True
        self.started.emit(1)
        self.sampled.emit(1_782_000_000_000_000, 5)

    def stop(self):
        if self._running:
            self._running = False
            self.finished_recording.emit("stopped")

    def wait(self, ms=0):
        return True

    def isRunning(self):
        return self._running


class FakeCollector(QObject):
    """Stand-in for ProcessCollector: no real polling thread."""

    updated = Signal(list)

    def __init__(self, interval=1.0, parent=None):
        super().__init__(parent)
        self.interval = interval
        self.started_flag = False
        self.skipped = 0  # the real collector counts dropped polls here

    def start(self):
        self.started_flag = True

    def stop(self):
        self.started_flag = False

    def wait(self, ms=0):
        return True


@pytest.fixture
def fake_sampler_cls():
    FakeSampler.instances.clear()
    yield FakeSampler
    FakeSampler.instances.clear()
