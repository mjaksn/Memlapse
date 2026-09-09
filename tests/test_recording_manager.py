"""Tests for RecordingManager lifecycle, using fake samplers."""

import pytest
from PySide6.QtCore import QObject, Signal

from memlapse.collectors import RegionSampler
from memlapse.services import RecordingManager
from memlapse.services.recording import DEFAULT_INTERVAL, _default_factory


def test_default_factory_builds_region_sampler(qapp):
    from memlapse.analytics import Allowlist, AllowlistEntry, RULE_RWX
    book = Allowlist([AllowlistEntry("jit.exe", RULE_RWX, "JIT host")])
    sampler = _default_factory(1234, "proc.exe", 0.5, None, book)
    assert isinstance(sampler, RegionSampler)
    assert sampler.pid == 1234 and sampler.interval == 0.5
    # The real factory has to carry it too, or only the fakes would.
    assert sampler.allowlist is book


def test_start_creates_sampler_and_reemits(qapp, fake_sampler_cls):
    mgr = RecordingManager(sampler_factory=fake_sampler_cls)
    started, sampled = [], []
    mgr.started.connect(started.append)
    mgr.sampled.connect(lambda ts, c: sampled.append((ts, c)))

    mgr.start(1000, "proc.exe", 0.5)

    assert mgr.is_recording
    assert started == [1]
    assert sampled == [(1_782_000_000_000_000, 5)]
    assert len(fake_sampler_cls.instances) == 1
    s = fake_sampler_cls.instances[0]
    assert (s.pid, s.name, s.interval) == (1000, "proc.exe", 0.5)


def test_double_start_is_ignored(qapp, fake_sampler_cls):
    mgr = RecordingManager(sampler_factory=fake_sampler_cls)
    mgr.start(1, "a")
    mgr.start(2, "b")  # already recording -> ignored
    assert len(fake_sampler_cls.instances) == 1


def test_stop_emits_stopped_and_clears(qapp, fake_sampler_cls):
    mgr = RecordingManager(sampler_factory=fake_sampler_cls)
    stopped = []
    mgr.stopped.connect(stopped.append)
    mgr.start(1, "a")
    mgr.stop()
    assert stopped == ["stopped"]
    assert not mgr.is_recording


def test_stop_without_recording_is_noop(qapp, fake_sampler_cls):
    mgr = RecordingManager(sampler_factory=fake_sampler_cls)
    mgr.stop()  # must not raise
    assert not mgr.is_recording


def test_can_restart_after_stop(qapp, fake_sampler_cls):
    mgr = RecordingManager(sampler_factory=fake_sampler_cls)
    mgr.start(1, "a")
    mgr.stop()
    mgr.start(2, "b")
    assert mgr.is_recording
    assert len(fake_sampler_cls.instances) == 2


# The conftest FakeSampler emits finished_recording synchronously from stop().
# A real RegionSampler is a QThread whose queued finished_recording is delivered
# only when the GUI event loop next runs, after RecordingManager.stop() has
# returned; wait() does not process events. This fake defers the emit to wait()
# so that a stop() which forgot to wait would fail here.
class _QThreadLikeSampler(QObject):
    """Fake sampler whose finished_recording arrives after stop() returns.

    stop() only lowers the running flag; finished_recording is emitted from
    wait(), standing in for a real QThread whose queued signal arrives only once
    the caller is back in the event loop. It also counts the calls, so a stop()
    that forgot to wait would fail here rather than pass unnoticed.
    """

    started = Signal(int)
    sampled = Signal("qlonglong", int)
    finished_recording = Signal(str)

    instances: list["_QThreadLikeSampler"] = []

    def __init__(self, pid, name, interval, db_path=None, allowlist=None):
        super().__init__()
        self.pid, self.name, self.interval, self.db_path = pid, name, interval, db_path
        self.allowlist = allowlist
        self._running = False
        self.stop_calls = 0
        self.wait_calls = 0
        _QThreadLikeSampler.instances.append(self)

    def start(self):
        self._running = True
        self.started.emit(1)

    def stop(self):
        self.stop_calls += 1
        self._running = False

    def wait(self, ms=0):
        self.wait_calls += 1
        # stands in for the queued signal arriving later
        self.finished_recording.emit("stopped")
        return True

    def isRunning(self):
        return self._running


@pytest.fixture
def qthread_like_cls():
    _QThreadLikeSampler.instances.clear()
    yield _QThreadLikeSampler
    _QThreadLikeSampler.instances.clear()


def test_is_recording_false_before_start(qapp, fake_sampler_cls):
    mgr = RecordingManager(sampler_factory=fake_sampler_cls)
    assert mgr.is_recording is False


def test_start_uses_default_interval(qapp, fake_sampler_cls):
    mgr = RecordingManager(sampler_factory=fake_sampler_cls)
    mgr.start(1, "p")
    assert fake_sampler_cls.instances[0].interval == DEFAULT_INTERVAL


def test_start_passes_the_db_path_through(qapp, fake_sampler_cls):
    mgr = RecordingManager(db_path="x.db", sampler_factory=fake_sampler_cls)
    mgr.start(1234, "proc.exe")
    assert fake_sampler_cls.instances[0].db_path == "x.db"


def test_stop_delegates_and_waits(qapp, qthread_like_cls):
    """stop() must both stop the sampler and wait for it to join."""
    mgr = RecordingManager(sampler_factory=qthread_like_cls)
    reasons: list[str] = []
    mgr.stopped.connect(reasons.append)

    mgr.start(1, "p")
    mgr.stop()

    sampler = qthread_like_cls.instances[0]
    assert sampler.stop_calls == 1
    assert sampler.wait_calls == 1
    assert reasons == ["stopped"]
    assert mgr.is_recording is False


def test_finish_signal_clears_active_sampler(qapp, fake_sampler_cls):
    """A sampler finishing on its own, when the target exits, clears state."""
    mgr = RecordingManager(sampler_factory=fake_sampler_cls)
    reasons: list[str] = []
    mgr.stopped.connect(reasons.append)

    mgr.start(1, "p")
    fake_sampler_cls.instances[0].finished_recording.emit("target process exited")

    assert reasons == ["target process exited"]
    assert mgr.is_recording is False


def test_start_passes_the_allowlist_to_the_sampler(qapp, fake_sampler_cls):
    from memlapse.analytics import Allowlist, AllowlistEntry, RULE_RWX
    book = Allowlist([AllowlistEntry("jit.exe", RULE_RWX, "JIT host")])
    mgr = RecordingManager(sampler_factory=fake_sampler_cls)
    mgr.start(1234, "jit.exe", allowlist=book)
    assert fake_sampler_cls.instances[0].allowlist is book


def test_start_without_an_allowlist_passes_none(qapp, fake_sampler_cls):
    """None and an empty Allowlist are different instructions to the replay."""
    mgr = RecordingManager(sampler_factory=fake_sampler_cls)
    mgr.start(1234, "jit.exe")
    assert fake_sampler_cls.instances[0].allowlist is None
