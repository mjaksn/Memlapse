"""Unit tests for the selection-window stats helper."""

from memlapse.analytics import WindowStats, window_stats


def test_empty_window_is_all_zero():
    assert window_stats([]) == WindowStats(0, 0.0, 0.0, 0.0)


def test_basic_stats():
    st = window_stats([10.0, 20.0, 30.0, 40.0])
    assert st.count == 4
    assert st.minimum == 10.0
    assert st.maximum == 40.0
    assert st.average == 25.0


def test_single_value():
    st = window_stats([7.5])
    assert st == WindowStats(1, 7.5, 7.5, 7.5)
