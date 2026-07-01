"""Unit tests for the SystemSample model."""

from memdo.model import SystemSample


def _sample() -> SystemSample:
    gb = 1024 ** 3
    return SystemSample(
        ts_us=1,
        total=16 * gb,
        available=8 * gb,
        used=8 * gb,
        percent=50.0,
        swap_total=4 * gb,
        swap_used=1 * gb,
        swap_percent=25.0,
    )


def test_fields_and_derived_gb():
    s = _sample()
    assert s.percent == 50.0
    assert round(s.total_gb) == 16
    assert round(s.used_gb) == 8


def test_is_frozen():
    s = _sample()
    try:
        s.percent = 99.0  # type: ignore[misc]
    except (AttributeError, TypeError):
        return
    raise AssertionError("SystemSample should be immutable")
