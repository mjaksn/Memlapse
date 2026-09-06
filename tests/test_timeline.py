"""Tests for the timeline scrubber widget."""

import pytest

from memlapse.ui.timeline import TimelineWidget, _fmt_elapsed


def test_fmt_elapsed():
    assert _fmt_elapsed(0) == "00:00.000"
    assert _fmt_elapsed(1_500_000) == "00:01.500"
    assert _fmt_elapsed(65_000_000) == "01:05.000"


@pytest.fixture
def timeline(qtbot):
    w = TimelineWidget()
    qtbot.addWidget(w)
    return w


def test_empty_disables_controls(timeline):
    timeline.set_sample_times([])
    assert not timeline.slider.isEnabled()
    assert not timeline.play_btn.isEnabled()
    assert timeline.time_label.text() == "--:--.---"


def test_set_times_emits_initial_seek(timeline, qtbot):
    times = [1_000, 2_000, 3_000]
    with qtbot.waitSignal(timeline.seek, timeout=500) as sig:
        timeline.set_sample_times(times)
    assert sig.args == [1_000]
    assert timeline.slider.isEnabled()
    assert timeline.slider.maximum() == 2


def test_slider_move_emits_seek(timeline):
    timeline.set_sample_times([1_000, 2_000, 3_000])
    seen = []
    timeline.seek.connect(seen.append)
    timeline.slider.setValue(2)
    assert seen[-1] == 3_000
    assert "[3/3]" in timeline.time_label.text()


def test_play_pause_toggle(timeline):
    timeline.set_sample_times([1_000, 2_000])
    timeline._toggle_play()
    assert timeline._timer.isActive()
    assert timeline.play_btn.text() == "⏸"
    timeline._toggle_play()
    assert not timeline._timer.isActive()
    assert timeline.play_btn.text() == "▶"


def test_advance_steps_and_stops_at_end(timeline):
    timeline.set_sample_times([1_000, 2_000, 3_000])
    timeline._toggle_play()
    timeline._advance()
    assert timeline.slider.value() == 1
    timeline._advance()  # now at last index
    assert timeline.slider.value() == 2
    timeline._advance()  # past end -> stops
    assert not timeline._timer.isActive()


def test_on_slider_with_no_times_is_noop(timeline):
    # Guard path: sliding with an empty timeline must not raise or emit.
    seen = []
    timeline.seek.connect(seen.append)
    timeline._on_slider(0)
    assert seen == []


def test_toggle_play_with_no_times(timeline):
    timeline.set_sample_times([])
    timeline._toggle_play()  # elif self._times is False -> no timer
    assert not timeline._timer.isActive()


def test_play_from_end_restarts(timeline):
    timeline.set_sample_times([1_000, 2_000])
    timeline.slider.setValue(1)  # at end
    timeline._toggle_play()
    assert timeline.slider.value() == 0  # restarted
    assert timeline._timer.isActive()
