"""Tests for the dependency-free analytics helpers."""

import pytest

from memdo.analytics import (
    Mover, SeriesBuffer, leak_rate_bytes_per_sec, linreg_slope, top_movers,
    zscore,
)


# --- SeriesBuffer ----------------------------------------------------------
def test_series_buffer_requires_positive_capacity():
    with pytest.raises(ValueError):
        SeriesBuffer(0)


def test_series_buffer_append_and_accessors():
    b = SeriesBuffer(3)
    assert len(b) == 0
    assert b.latest() is None
    b.append(1, 10.0)
    b.append(2, 20.0)
    assert len(b) == 2
    assert b.times() == [1, 2]
    assert b.values() == [10.0, 20.0]
    assert b.latest() == 20.0


def test_series_buffer_evicts_oldest():
    b = SeriesBuffer(2)
    b.append(1, 1.0)
    b.append(2, 2.0)
    b.append(3, 3.0)  # evicts (1, 1.0)
    assert b.times() == [2, 3]


# --- linreg_slope ----------------------------------------------------------
def test_linreg_slope_normal():
    assert linreg_slope([0, 1, 2], [0, 2, 4]) == pytest.approx(2.0)


def test_linreg_slope_degenerate_cases():
    assert linreg_slope([1], [1]) == 0.0            # < 2 points
    assert linreg_slope([1, 2], [1]) == 0.0         # mismatched lengths
    assert linreg_slope([5, 5, 5], [1, 2, 3]) == 0.0  # no spread in xs


# --- leak_rate_bytes_per_sec ----------------------------------------------
def test_leak_rate_normal():
    times = [0, 1_000_000, 2_000_000]  # microseconds -> 0,1,2 s
    used = [0.0, 100.0, 200.0]
    assert leak_rate_bytes_per_sec(times, used) == pytest.approx(100.0)


def test_leak_rate_too_few_points():
    assert leak_rate_bytes_per_sec([0], [1.0]) == 0.0


# --- zscore ----------------------------------------------------------------
def test_zscore_default_latest():
    # values [0,0,0,3]: mean 0.75, population var 1.6875, std ~1.299
    assert zscore([0.0, 0.0, 0.0, 3.0]) == pytest.approx((3 - 0.75) / (1.6875 ** 0.5))


def test_zscore_explicit_latest():
    assert zscore([1.0, 2.0, 3.0], latest=2.0) == pytest.approx(0.0)


def test_zscore_degenerate_cases():
    assert zscore([1.0]) == 0.0             # < 2 points
    assert zscore([5.0, 5.0, 5.0]) == 0.0   # zero variance


# --- top_movers ------------------------------------------------------------
def test_top_movers_sorted_by_absolute_delta():
    prev = {1: ("a", 100), 2: ("b", 100), 3: ("c", 100)}
    curr = {1: ("a", 150), 2: ("b", 40), 3: ("c", 100)}  # +50, -60, 0
    movers = top_movers(prev, curr)
    assert [m.pid for m in movers] == [2, 1]  # |−60| > |+50|; pid 3 unchanged dropped
    assert movers[0] == Mover(2, "b", -60)


def test_top_movers_ignores_new_pids_and_limits():
    prev = {i: ("p", 0) for i in range(10)}
    curr = {i: ("p", i + 1) for i in range(10)}
    curr[999] = ("new", 500)  # not in prev -> ignored
    movers = top_movers(prev, curr, n=3)
    assert len(movers) == 3
    assert all(m.pid != 999 for m in movers)
