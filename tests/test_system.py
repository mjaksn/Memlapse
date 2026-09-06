"""Tests for the system-wide memory model and collector."""

from types import SimpleNamespace

import memlapse.collectors.system as system_mod
from memlapse.collectors.system import SystemCollector
from memlapse.model.system import SystemSample


def test_system_sample_gb_properties():
    s = SystemSample(ts_us=1, total=2 * 1024**3, available=1024**3,
                     used=1024**3, percent=50.0, swap_total=0, swap_used=0,
                     swap_percent=0.0)
    assert s.total_gb == 2.0
    assert s.used_gb == 1.0


def test_poll_maps_psutil_fields(monkeypatch):
    vm = SimpleNamespace(total=16, available=8, used=8, percent=50.0)
    sw = SimpleNamespace(total=4, used=1, percent=25.0)
    monkeypatch.setattr(system_mod.psutil, "virtual_memory", lambda: vm)
    monkeypatch.setattr(system_mod.psutil, "swap_memory", lambda: sw)

    sample = SystemCollector._poll()
    assert isinstance(sample, SystemSample)
    assert sample.total == 16 and sample.available == 8 and sample.used == 8
    assert sample.percent == 50.0
    assert sample.swap_total == 4 and sample.swap_used == 1
    assert sample.swap_percent == 25.0
    assert sample.ts_us > 1_000_000_000_000_000  # 64-bit epoch microseconds


def test_run_loop_emits_and_stops(qtbot, monkeypatch):
    sentinel = SystemSample(1, 1, 1, 1, 1.0, 0, 0, 0.0)
    c = SystemCollector(interval=0.01)
    monkeypatch.setattr(c, "_poll", lambda: sentinel)
    with qtbot.waitSignal(c.updated, timeout=1000) as sig:
        c.start()
    c.stop()
    c.wait(1000)
    assert sig.args == [sentinel]
    assert not c.isRunning()


def test_stop_sets_flag():
    c = SystemCollector()
    c._running = True
    c.stop()
    assert c._running is False
