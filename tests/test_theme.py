"""Tests for the dashboard theme helpers."""

from memlapse.ui import theme
from memlapse.ui.theme import configure_pyqtgraph, heat_color


def test_heat_color_endpoints_and_clamping():
    # Clamped below 0 -> pure green (OK); above 1 -> pure red (DANGER).
    assert heat_color(-1.0) == (0x3d, 0xdc, 0x84)
    assert heat_color(2.0) == (0xff, 0x4d, 0x4d)


def test_heat_color_midpoint_is_amber():
    assert heat_color(0.5) == (0xff, 0xb0, 0x20)


def test_heat_color_both_ramp_halves():
    lo = heat_color(0.25)   # green -> amber half
    hi = heat_color(0.75)   # amber -> red half
    assert lo[0] < hi[0] or lo != hi  # distinct colors along the ramp
    assert all(0 <= c <= 255 for c in lo + hi)


def test_configure_pyqtgraph_runs():
    configure_pyqtgraph()  # must not raise


def test_dashboard_qss_has_palette_colors():
    assert theme.BG in theme.DASHBOARD_QSS
    assert theme.ACCENT in theme.DASHBOARD_QSS
