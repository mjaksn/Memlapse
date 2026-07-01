"""Tests for the animated gauge widget.

paintEvent is exercised by grabbing the widget to a pixmap (which forces a
repaint) under the offscreen Qt platform.
"""

import pytest

from memdo.ui.gauges import AnimatedGauge


@pytest.fixture
def gauge(qtbot):
    g = AnimatedGauge(title="RAM")
    qtbot.addWidget(g)
    g.resize(160, 160)
    return g


def test_set_target_clamps(gauge):
    gauge.set_target(150.0)
    assert gauge._target == 100.0
    gauge.set_target(-20.0)
    assert gauge._target == 0.0


def test_animate_eases_toward_target(gauge):
    gauge.set_target(100.0)
    gauge.animate_step()
    assert 0.0 < gauge._value < 100.0  # eased partway, not snapped


def test_animate_snaps_when_close(gauge):
    gauge.set_target(100.0)
    gauge._value = 99.95  # within 0.1 of target
    gauge.animate_step()
    assert gauge._value == 100.0


def test_animate_noop_when_settled(gauge):
    gauge.set_target(50.0)
    gauge._value = 50.0
    gauge.animate_step()  # diff == 0 -> early return, no change
    assert gauge._value == 50.0


def test_paint_event_runs_with_and_without_subtitle(gauge):
    gauge.set_target(75.0, subtitle="12.3 GB")
    gauge._value = 75.0
    assert not gauge.grab().isNull()  # triggers paintEvent (subtitle branch)

    gauge.set_target(30.0, subtitle="")
    gauge._value = 30.0
    assert not gauge.grab().isNull()  # title-only branch
