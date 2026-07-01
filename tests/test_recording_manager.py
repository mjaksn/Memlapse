"""Tests for RecordingManager lifecycle, using a fake sampler."""

from memdo.collectors import RegionSampler
from memdo.services import RecordingManager
from memdo.services.recording import _default_factory


def test_default_factory_builds_region_sampler(qapp):
    sampler = _default_factory(1234, "proc.exe", 0.5, None)
    assert isinstance(sampler, RegionSampler)
    assert sampler.pid == 1234 and sampler.interval == 0.5


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
