"""Smoke test for the system-wide memory collector.

Exercises the static ``_poll`` (no thread, no QApplication needed) against the
real host so we know the psutil wiring produces a well-formed SystemSample.
"""

from memdo.collectors import SystemCollector
from memdo.model import SystemSample


def test_poll_returns_valid_sample():
    s = SystemCollector._poll()
    assert isinstance(s, SystemSample)
    assert s.total > 0
    assert 0 <= s.used <= s.total
    assert 0.0 <= s.percent <= 100.0
    assert 0.0 <= s.swap_percent <= 100.0
    assert s.ts_us > 0
